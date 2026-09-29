"""The evidence ledger: an append-only hash chain with external timestamps.

Every consequential act in a sandbox participation is an entry: the plan being
signed, an artifact or dataset being committed, every gate decision including the
denials, every run, every halt, suspension, key destruction and report. The chain is
what makes "this is every run" a checkable claim rather than an assurance.

Three properties:

* **Append-only, enforced by the database.** Not by convention and not by the
  application. SQLite triggers reject UPDATE and DELETE; the Postgres schema in
  ``postgres.sql`` does the same with revoked grants. An operator who wants to
  rewrite history has to change the schema, which is itself visible.
* **Chained.** Each entry carries the hash of the previous one, so removing or
  altering an entry in the middle breaks every entry after it.
* **Timestamped externally.** The chain proves nothing was removed; the timestamps
  are what stop an operator rebuilding the whole chain. See :mod:`histor.crypto.timestamps`
  for why the development authority is not that.

A production ledger is Postgres. This ships a SQLite implementation as the default
and the Postgres DDL alongside, because the chain logic is the part worth testing and
a test that needs a database server is a test that runs rarely.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from histor.crypto.timestamps import TimestampAuthority, TimestampToken
from histor.obs.logs import get_logger

GENESIS = "sha256:" + "0" * 64

ENTRY_TYPES = frozenset(
    {
        "plan_signed",
        # One party's signature through their own IdP (histor/identity/signature.py). A
        # plan_signed entry follows once both parties have signed the same digest.
        "plan_signature",
        # The provider says which model to test; a proposal until the plan pins it.
        "model_configured",
        # A model brought up alone, with no data, before any run: whether it came up
        # and passed the inference profile, and the digest of the log the provider saw.
        "model_preflight",
        # At an HPC centre: the signed pair, OCI digest to SIF digest, for each pinned
        # image converted there, and the public key of whoever signs the run's isolation
        # evidence: the centre's own, or the sandbox operator's.
        "image_converted",
        "hpc_centre_key",
        "hpc_operator_key",
        # The job the courier submitted: its Slurm id, its script's digest, and how long
        # a lease lasts. Renewals are not recorded; there are too many of them.
        "job_submitted",
        # The key broker released a run's keys to one job's public key after checking
        # its measurements, recorded before the sealed keys are delivered; or refused
        # to, which is an incident.
        "key_released",
        "key_release_refused",
        # The provider's releaser sealed the weights key to the same job key, or
        # refused to; either way the provider's signed receipt or refusal is in the body.
        "weights_key_released",
        "weights_key_release_refused",
        "artifact_committed",
        "dataset_committed",
        "gate_decision",
        "run_started",
        "run_attestation",
        "run_halted",
        "suspended",
        "resumed",
        # The public key that signs one kind of statement (the control plane's
        # attestations; on the local backend the harness's measurements), recorded
        # before any run, so the verifier takes it from the chained, timestamped
        # ledger and not from the bundle's public-keys.json (spec/run-attestation.md §1c).
        "signing_key_registered",
        # The public half of the harness's signing key for this participation, which
        # the key broker provisions per participation and destroys at exit.
        "harness_key_provisioned",
        # The scorer's, when a run's scoring is kept off an HPC centre
        # (histor/harness/scorer.py): it signs the measurements where the labels are.
        "scorer_key_provisioned",
        # The root certificate of the RFC 3161 authority that stamps this ledger, so a
        # bundle exported from the ledger alone can verify its timestamps.
        "timestamp_authority",
        "keys_destroyed",
        "report_generated",
        # The regulator's signature over the exit report, through their own IdP, as a
        # plan_signature is over the plan (histor/identity/signature.py).
        "report_signature",
        "bundle_verified",
        # The authority's own acts and the participant's consent (draft implementing
        # act Art. 6 and 8), each recorded through the gate by the person who did it.
        # Art. 6(3)(a) and (c): regulatory issues, recommendations, lessons learned.
        "findings_recorded",
        # AI Act Art. 3(49) and 73, reported by any party to the plan.
        "serious_incident",
        # Art. 6(5): the participant agrees, or refuses, to publish the exit report.
        "publication_consent",
        # Art. 6(4): the signed exit report reached the participant.
        "report_delivered",
        # Art. 8(2): the regulator told the AI Office of a suspension.
        "ai_office_notified",
        # AI Act Annex VII point 4.4 (histor/plan/nbtests.py): the notified body proposes
        # a test; an approver the plan names approves it with an IdP signature over the
        # proposal's digest, or declines it with a reason.
        "nb_test_proposed",
        "nb_test_approved",
        "nb_test_declined",
    }
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox_id  TEXT NOT NULL,
    entry_type  TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    body        TEXT NOT NULL,
    timestamp   TEXT,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL UNIQUE
);

-- Append-only, enforced here rather than in the application. An application-level
-- rule is a rule until someone writes a migration script.
CREATE TRIGGER IF NOT EXISTS entries_no_update
BEFORE UPDATE ON entries
BEGIN
    SELECT RAISE(ABORT, 'ledger entries are append-only: UPDATE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS entries_no_delete
BEFORE DELETE ON entries
BEGIN
    SELECT RAISE(ABORT, 'ledger entries are append-only: DELETE is not permitted');
END;
"""


@dataclass(frozen=True)
class Entry:
    seq: int
    sandbox_id: str
    entry_type: str
    recorded_at: str
    body: dict[str, Any]
    prev_hash: str
    entry_hash: str
    timestamp: dict[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "seq": self.seq,
            "sandbox_id": self.sandbox_id,
            "entry_type": self.entry_type,
            "recorded_at": self.recorded_at,
            "body": self.body,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }
        if self.timestamp is not None:
            payload["timestamp"] = self.timestamp
        return payload


def compute_hash(
    seq: int, sandbox_id: str, entry_type: str, recorded_at: str, body: dict[str, Any], prev: str
) -> str:
    """The chain link.

    Over a canonical serialisation of everything that identifies the entry, so
    reformatting the stored JSON cannot change the hash and changing any field must.
    """
    canonical = json.dumps(
        {
            "seq": seq,
            "sandbox_id": sandbox_id,
            "entry_type": entry_type,
            "recorded_at": recorded_at,
            "body": body,
            "prev_hash": prev,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


class StampingError(ValueError):
    """An append would mix stamped and unstamped entries in one ledger.

    A timestamp token covers its entry's hash, but the hash does not cover the token,
    so the verifier cannot tell a token that was never issued from one that was
    deleted. It therefore requires a ledger to be stamped from its first entry to its
    last, or not at all (docs/verifier.md, ``timestamps``), and a writer that opened
    the ledger with the wrong authority is stopped here rather than there.
    """


def check_stamping(first_is_stamped: bool | None, authority: TimestampAuthority | None) -> None:
    """Refuse an append whose stamping differs from the ledger's first entry's.

    ``first_is_stamped`` is None for an empty ledger, which any writer may start.
    """
    if first_is_stamped is None or first_is_stamped == (authority is not None):
        return
    if first_is_stamped:
        raise StampingError(
            "this ledger's entries are timestamped and this writer has no timestamp "
            "authority: open it with the authority that stamps it (--tsa)"
        )
    raise StampingError(
        "this ledger's entries carry no timestamps; stamping only the later ones would "
        "leave the earlier ones unanchored. Start a new ledger with the authority"
    )


_log = get_logger("ledger")


def log_appended(entry: Entry, store: str) -> None:
    """The operational line for an entry just written: its type, sequence number and
    hash, never its body, which is evidence and goes only into the ledger."""
    _log.info(
        "ledger entry appended",
        sandbox_id=entry.sandbox_id,
        ledger_seq=entry.seq,
        entry_type=entry.entry_type,
        entry_hash=entry.entry_hash,
        stamped=entry.timestamp is not None,
        store=store,
    )


class Ledger:
    """SQLite-backed append-only ledger."""

    def __init__(self, path: Path | str, authority: TimestampAuthority | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.authority = authority
        # A SQLite connection belongs to the thread that opened it, and the console
        # serves every request on a new one. A connection per thread rather than
        # check_same_thread=False: sharing one across threads appears to work until
        # two requests arrive together.
        self._local = threading.local()
        self._append_lock = threading.Lock()
        connection = self.connection
        connection.executescript(SCHEMA)
        connection.commit()

    @property
    def connection(self) -> sqlite3.Connection:
        existing: sqlite3.Connection | None = getattr(self._local, "connection", None)
        if existing is None:
            existing = sqlite3.connect(self.path)
            existing.row_factory = sqlite3.Row
            self._local.connection = existing
        return existing

    def close(self) -> None:
        """Close this thread's connection.

        Other threads keep theirs. There is nothing to close them from here, and a
        process on its way out does not need to.
        """
        existing: sqlite3.Connection | None = getattr(self._local, "connection", None)
        if existing is not None:
            existing.close()
            self._local.connection = None

    def __enter__(self) -> Ledger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def head(self) -> str:
        row = self.connection.execute(
            "SELECT entry_hash FROM entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return str(row["entry_hash"]) if row else GENESIS

    def head_entry(self) -> dict[str, Any]:
        """The head as ``{"seq", "entry_hash"}``: what a report signature commits to, and
        what a regulator keeps to check a bundle against (``histor verify --expect-head``)."""
        row = self.connection.execute(
            "SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (
            {"seq": int(row["seq"]), "entry_hash": str(row["entry_hash"])}
            if row
            else {"seq": 0, "entry_hash": GENESIS}
        )

    def append(self, sandbox_id: str, entry_type: str, body: dict[str, Any]) -> Entry:
        if entry_type not in ENTRY_TYPES:
            raise ValueError(f"unknown entry type {entry_type!r}")
        # Read-then-write: two appends racing would compute the same prev_hash and
        # the same sequence number, and the chain would fork. One at a time: the lock
        # covers this process's threads, and BEGIN IMMEDIATE the other processes on
        # the same file (the console halting a run the demo script is writing).
        with self._append_lock:
            connection = self.connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                entry = self._append(sandbox_id, entry_type, body)
            except BaseException:
                connection.rollback()
                raise
        log_appended(entry, "sqlite")
        return entry

    def _append(self, sandbox_id: str, entry_type: str, body: dict[str, Any]) -> Entry:
        first = self.connection.execute(
            "SELECT timestamp IS NOT NULL AS stamped FROM entries ORDER BY seq LIMIT 1"
        ).fetchone()
        check_stamping(bool(first["stamped"]) if first else None, self.authority)
        prev = self.head()
        row = self.connection.execute("SELECT COALESCE(MAX(seq), 0) AS m FROM entries").fetchone()
        seq = int(row["m"]) + 1
        recorded_at = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        entry_hash = compute_hash(seq, sandbox_id, entry_type, recorded_at, body, prev)

        token: TimestampToken | None = None
        if self.authority is not None:
            token = self.authority.stamp(entry_hash)

        self.connection.execute(
            "INSERT INTO entries (seq, sandbox_id, entry_type, recorded_at, body, timestamp,"
            " prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                seq,
                sandbox_id,
                entry_type,
                recorded_at,
                json.dumps(body, sort_keys=True),
                json.dumps(token.to_json()) if token else None,
                prev,
                entry_hash,
            ),
        )
        self.connection.commit()
        return Entry(
            seq=seq,
            sandbox_id=sandbox_id,
            entry_type=entry_type,
            recorded_at=recorded_at,
            body=body,
            prev_hash=prev,
            entry_hash=entry_hash,
            timestamp=token.to_json() if token else None,
        )

    def entries(self, sandbox_id: str | None = None) -> Iterator[Entry]:
        if sandbox_id is None:
            rows = self.connection.execute("SELECT * FROM entries ORDER BY seq")
        else:
            rows = self.connection.execute(
                "SELECT * FROM entries WHERE sandbox_id = ? ORDER BY seq", (sandbox_id,)
            )
        for row in rows:
            yield Entry(
                seq=int(row["seq"]),
                sandbox_id=str(row["sandbox_id"]),
                entry_type=str(row["entry_type"]),
                recorded_at=str(row["recorded_at"]),
                body=json.loads(row["body"]),
                prev_hash=str(row["prev_hash"]),
                entry_hash=str(row["entry_hash"]),
                timestamp=json.loads(row["timestamp"]) if row["timestamp"] else None,
            )

    def of_type(self, entry_type: str, sandbox_id: str | None = None) -> list[Entry]:
        return [e for e in self.entries(sandbox_id) if e.entry_type == entry_type]

    def next_run_number(self, sandbox_id: str) -> int:
        """One more than the highest run started. Monotonic and contiguous by
        construction, which is what the verifier's gap check reads."""
        numbers = [
            int(e.body.get("run_number", 0))
            for e in self.entries(sandbox_id)
            if e.entry_type in {"run_started", "run_attestation"}
        ]
        return (max(numbers) + 1) if numbers else 1


def open_ledger(location: str | Path, authority: TimestampAuthority | None = None) -> Ledger:
    """A ledger at ``location``: a SQLite file, or a libpq connection string
    (``histor/ledger/postgres.py``). The chain, the entries and the bundles are the same."""
    if is_postgres(location):
        from histor.ledger.postgres import PostgresLedger

        return PostgresLedger(str(location), authority)
    return Ledger(location, authority)


def is_postgres(location: str | Path) -> bool:
    """Whether ``location`` names a Postgres database rather than a SQLite file."""
    text = str(location)
    # Both libpq forms: a URL, or key=value pairs. A key=value string is never a
    # plausible file name, and taking it for one would quietly write to SQLite.
    return text.startswith(("postgresql://", "postgres://")) or "dbname=" in text
