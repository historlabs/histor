"""The checks, plus what they refuse to assume.

Input is an evidence bundle; output is a verdict. No network, no data, no trust in
the operator who produced the bundle.

Two design rules run through all of it:

* **Recompute, never re-read.** Where the bundle states a conclusion — a threshold
  held, a run passed, a chain is intact — the verifier derives it again from the
  underlying numbers and compares. A verifier that reads ``"outcome": "pass"`` and
  reports a pass is a formatting tool.
* **Say what was not checked.** A bundle can be internally perfect and still prove
  very little: development timestamps prove no time, ``local_process`` isolation
  proves no isolation. Those are reported as prominently as failures, because a
  green tick on a bundle that establishes nothing is the worst output this tool
  could produce.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from histor.crypto import namespace, signing, weights
from histor.crypto.timestamps import parse as parse_timestamp
from histor.crypto.timestamps import verify_token
from histor.ledger.bundle import (
    BUNDLE_VERSION,
    CATALOGUE_FILE,
    LEGACY_BUNDLE_VERSIONS,
    RUN_LOGS,
    SUPPORTED_BUNDLE_VERSIONS,
    Bundle,
    sha256_text,
)
from histor.ledger.store import GENESIS, compute_hash
from histor.plan import digest as plan_digest
from histor.verifier.anchors import NAMES as ANCHOR_NAMES
from histor.verifier.anchors import Anchors

PASS, FAIL, WARN = "pass", "fail", "warn"

# What every ledger line carries (histor.ledger.store.Entry.to_json); the timestamp is optional.
LEDGER_FIELDS = frozenset(
    {"seq", "sandbox_id", "entry_type", "recorded_at", "body", "prev_hash", "entry_hash"}
)


@dataclass
class CheckResult:
    id: str
    question: str
    outcome: str
    detail: str = ""

    def to_json(self) -> dict[str, str]:
        return {
            "id": self.id,
            "question": self.question,
            "outcome": self.outcome,
            "detail": self.detail,
        }


@dataclass
class Verdict:
    results: list[CheckResult] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    # Which trust anchors were given from outside the bundle, and which were read from it.
    anchors: dict[str, list[str]] = field(default_factory=dict)

    def add(self, result: CheckResult) -> CheckResult:
        self.results.append(result)
        return result

    @property
    def failures(self) -> list[CheckResult]:
        return [r for r in self.results if r.outcome == FAIL]

    @property
    def warnings(self) -> list[CheckResult]:
        return [r for r in self.results if r.outcome == WARN]

    @property
    def verified(self) -> bool:
        return not self.failures

    def to_json(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "counts": {
                outcome: sum(1 for r in self.results if r.outcome == outcome)
                for outcome in (PASS, FAIL, WARN)
            },
            "results": [r.to_json() for r in self.results],
            "caveats": self.caveats,
            "anchors": self.anchors,
        }


# --- 1. signing keys and signatures -----------------------------------------
#
# Every file a bundle carries is written by whoever assembled it, the operator
# included, and ``public-keys.json`` is one of them. A key read from there vouches for
# whatever was signed with it. So a key is taken from the ledger, where it was recorded
# before the runs, chained and timestamped, or from the verifier's own anchors. And
# every signed statement the bundle carries must be the one the ledger recorded with
# its run, compared by digest (spec/run-attestation.md §1c).

# Who signs which statements, and the ledger entries that can record their public key.
# ``signing_key_registered`` names the key id in its body; the key broker's own entries
# are for one signer each.
KEY_ENTRIES = {
    "control-plane": ("signing_key_registered",),
    "harness": ("signing_key_registered", "harness_key_provisioned"),
    "scorer": ("signing_key_registered", "scorer_key_provisioned"),
}
# What each signs, as a reader is told.
KEY_ROLES = {
    "control-plane": "the run attestations",
    "harness": "the harness's measurements",
    "scorer": "the scorer's measurements",
}


@dataclass
class SigningKeys:
    """The public keys each statement signer is checked under, by key id, and where
    they came from: ``anchor`` (given by the verifier), ``ledger``, or ``bundle``
    (public-keys.json alone). A signer whose key is rotated has one key id per version
    (``control-plane@v1``, ``control-plane@v2``); each signature names the one it was
    made with, and verifies under that key or not at all."""

    keys: dict[str, dict[str, str]] = field(default_factory=dict)
    source: dict[str, str] = field(default_factory=dict)
    registered_at: dict[str, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    def of(self, signer: str) -> dict[str, str]:
        """The keys ``signer``'s statements are checked under, by key id, and no other."""
        return dict(self.keys.get(signer, {}))


def signer_of(key_id: str) -> str:
    """Who a key id names: ``control-plane`` for ``control-plane`` and for any version
    of it, ``control-plane@v2``."""
    return str(key_id).split("@", 1)[0]


def _raw_key(pem: Any) -> bytes | None:
    from cryptography.hazmat.primitives import serialization

    try:
        return signing.load_public(str(pem)).public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    except (ValueError, TypeError, AttributeError, UnicodeError):
        return None


def resolve_signing_keys(
    entries: list[dict[str, Any]], public_keys: dict[str, str], anchors: Anchors
) -> SigningKeys:
    """The key for each statement signer: yours if you gave one, else the ledger's.

    ``public-keys.json`` is used alone only when neither holds one, as a bundle made
    before bundle_version 0.3 needs, and :func:`check_signing_keys` says so. Where two
    sources hold a key for the same signer, they must be the same key.
    """
    out = SigningKeys()
    for signer, kinds in KEY_ENTRIES.items():
        recorded: dict[str, tuple[int, str]] = {}
        for entry in entries:
            body = entry["body"]
            if entry["entry_type"] not in kinds:
                continue
            # The broker's entries are one signer's each, under a path of its own.
            key_id = (
                str(body.get("key_id"))
                if entry["entry_type"] == "signing_key_registered"
                else signer
            )
            if signer_of(key_id) != signer:
                continue
            pem = body.get("public_key")
            if _raw_key(pem) is None:
                out.problems.append(f"the ledger records a {key_id} key that is not an Ed25519 key")
            elif key_id in recorded and _raw_key(recorded[key_id][1]) != _raw_key(pem):
                out.problems.append(
                    f"the ledger records two different keys as {key_id}: nothing says which "
                    f"one signed {KEY_ROLES[signer]}"
                )
            else:
                recorded.setdefault(key_id, (int(entry["seq"]), str(pem)))
        anchored = {k: pem for k, pem in anchors.signing_keys if signer_of(k) == signer}
        bundled = {k: str(pem) for k, pem in public_keys.items() if signer_of(k) == signer and pem}
        ledgered = {k: pem for k, (_, pem) in recorded.items()}
        if anchored:
            keys, source = anchored, "anchor"
        elif ledgered:
            keys, source = ledgered, "ledger"
        elif bundled:
            keys, source = bundled, "bundle"
        else:
            continue
        for other, where in ((ledgered, "the ledger's"), (bundled, "public-keys.json's")):
            for key_id, pem in sorted(other.items()):
                if key_id in keys and _raw_key(pem) != _raw_key(keys[key_id]):
                    out.problems.append(
                        f"{where} {key_id} key is not the "
                        + ("one you gave" if source == "anchor" else "one the ledger recorded")
                        + f": {KEY_ROLES[signer]} were checked under one key and could have "
                        "been signed with another"
                    )
        out.keys[signer], out.source[signer] = keys, source
        if recorded:
            out.registered_at[signer] = min(seq for seq, _ in recorded.values())
    return out


def _keys_used(statements: list[dict[str, Any]]) -> list[str]:
    used = {"control-plane"}
    for statement in statements:
        predicate = statement.get("predicate") or {}
        if predicate.get("driver_statement_digest"):
            used |= {"scorer", "harness"}
        elif predicate.get("harness_statement_digest"):
            used.add("harness")
    return [key_id for key_id in KEY_ENTRIES if key_id in used]


def check_signing_keys(
    keys: SigningKeys,
    entries: list[dict[str, Any]],
    statements: list[dict[str, Any]],
    anchored: bool,
) -> CheckResult:
    """Were the statements checked under keys fixed before the runs, or given by you?

    A key that only ``public-keys.json`` holds warns loudly, and fails when you gave
    any anchor: you asked for the bundle to be held to something from outside it, and
    that key is not."""
    question = (
        "was every statement checked under a key the ledger recorded or you gave, not one "
        "read from public-keys.json alone?"
    )
    problems = list(keys.problems)
    used = _keys_used(statements)
    first_attested = min(
        (int(e["seq"]) for e in entries if e["entry_type"] == "run_attestation"), default=0
    )
    for key_id in used:
        if key_id not in keys.keys:
            problems.append(f"no key for {key_id}, which signs {KEY_ROLES[key_id]}")
    seq = keys.registered_at.get("control-plane", 0)
    if keys.source.get("control-plane") == "ledger" and first_attested and seq > first_attested:
        problems.append(
            f"the control-plane key was recorded at seq {seq}, after the attestation at seq "
            f"{first_attested} it verifies: it was not fixed before the runs"
        )
    if problems:
        return CheckResult("signing_keys", question, FAIL, "; ".join(problems))
    unanchored = [k for k in used if keys.source.get(k) == "bundle"]
    if unanchored:
        detail = (
            f"KEYS NOT ANCHORED: the {', '.join(unanchored)} key(s), which sign "
            f"{' and '.join(KEY_ROLES[k] for k in unanchored)}, came only from the bundle's "
            "public-keys.json. Whoever assembled the bundle wrote that file, so statements "
            "they re-signed with keys of their own would verify. The ledger records no key "
            "for them, as in a bundle from before bundle_version 0.3. Give them with "
            "--signing-key."
        )
        return CheckResult("signing_keys", question, FAIL if anchored else WARN, detail)
    sources = ", ".join(
        f"{', '.join(sorted(keys.keys[k]))} ("
        + ("given by you" if keys.source[k] == "anchor" else f"ledger seq {keys.registered_at[k]}")
        + ")"
        for k in used
    )
    return CheckResult("signing_keys", question, PASS, sources)


def check_signatures(
    bundle: Bundle, entries: list[dict[str, Any]], keys: SigningKeys
) -> tuple[CheckResult, list[dict[str, Any]]]:
    """Each attestation in the bundle is the envelope its ``run_attestation`` entry
    recorded, one for one and in order, and verifies under the control plane's key and
    no other."""
    question = "is every attestation the one the ledger recorded, signed by the control plane?"
    try:
        envelopes = bundle.read_jsonl("attestations.jsonl")
    except (OSError, ValueError) as error:
        return CheckResult("signatures", question, FAIL, f"bundle unreadable: {error}"), []
    if not envelopes:
        return CheckResult("signatures", question, FAIL, "bundle carries no attestations"), []
    recorded = [e for e in entries if e["entry_type"] == "run_attestation"]
    if len(envelopes) != len(recorded):
        return (
            CheckResult(
                "signatures",
                question,
                FAIL,
                f"the bundle carries {len(envelopes)} attestation(s) but the ledger records "
                f"{len(recorded)}: each attestation must be the one its run's entry recorded",
            ),
            [],
        )

    statements: list[dict[str, Any]] = []
    for index, (envelope, entry) in enumerate(zip(envelopes, recorded, strict=True)):
        ledgered = entry["body"].get("envelope")
        where = f"seq {entry['seq']} (run {entry['body'].get('run_number')})"
        if not isinstance(ledgered, dict):
            problem = f"the ledger's run_attestation at {where} does not carry its envelope"
        elif not isinstance(envelope, dict) or _canonical_digest(envelope) != _canonical_digest(
            ledgered
        ):
            problem = (
                f"attestation {index} is not the envelope the ledger recorded at {where}: it "
                "was put in the bundle in place of the one written when the run ended"
            )
        else:
            try:
                statement = signing.verify_json(envelope, keys.of("control-plane"))
            except signing.VerificationError as error:
                problem = f"attestation {index}: {error}"
            else:
                run = (statement.get("predicate") or {}).get("run_number")
                if str(run) == str(entry["body"].get("run_number")):
                    statements.append(statement)
                    continue
                problem = (
                    f"attestation {index} is for run {run}, not the run of the entry at {where}"
                )
        return CheckResult("signatures", question, FAIL, problem), statements

    return (
        CheckResult(
            "signatures",
            question,
            PASS,
            f"{len(statements)} attestation(s), each the one the ledger recorded for its run, "
            "verify under the control plane's key",
        ),
        statements,
    )


# --- 2. hash chain ----------------------------------------------------------


def check_hash_chain(entries: list[dict[str, Any]]) -> CheckResult:
    question = "is the ledger hash chain intact, with no gaps?"
    if not entries:
        return CheckResult("hash_chain", question, FAIL, "ledger is empty")

    previous = GENESIS
    for position, entry in enumerate(entries):
        expected_seq = position + 1
        if int(entry["seq"]) != expected_seq:
            return CheckResult(
                "hash_chain",
                question,
                FAIL,
                f"sequence jumps from {expected_seq - 1} to {entry['seq']}: an entry was removed",
            )
        if entry["prev_hash"] != previous:
            return CheckResult(
                "hash_chain",
                question,
                FAIL,
                f"entry {entry['seq']} claims prev_hash {entry['prev_hash'][:19]}…, "
                f"but the previous entry hashes to {previous[:19]}…",
            )
        recomputed = compute_hash(
            int(entry["seq"]),
            entry["sandbox_id"],
            entry["entry_type"],
            entry["recorded_at"],
            entry["body"],
            entry["prev_hash"],
        )
        if recomputed != entry["entry_hash"]:
            return CheckResult(
                "hash_chain",
                question,
                FAIL,
                f"entry {entry['seq']} ({entry['entry_type']}) does not hash to its stated "
                "entry_hash: its contents were altered after it was written",
            )
        previous = str(entry["entry_hash"])

    return CheckResult("hash_chain", question, PASS, f"{len(entries)} entries, chain intact")


# --- 3. run numbers ---------------------------------------------------------


def check_run_numbers(
    entries: list[dict[str, Any]], statements: list[dict[str, Any]]
) -> CheckResult:
    """Every run the gate started, once, ended in the ledger, and no other run.

    The gate records ``run_started`` before a run and ``run_attestation`` (or
    ``run_halted``) after it. Counting only the attestations would miss a run that was
    started and never reported, say because it failed and was run again under the same
    number: that attempt is the evidence."""
    question = "was every run started once, and ended in the ledger, with no unrecorded runs?"
    started: dict[int, list[int]] = {}
    ended: dict[int, list[int]] = {}
    attested: dict[int, list[int]] = {}
    for entry in entries:
        body = entry["body"]
        if "run_number" not in body:
            continue
        run, seq = int(body["run_number"]), int(entry["seq"])
        if entry["entry_type"] == "run_started":
            started.setdefault(run, []).append(seq)
        elif entry["entry_type"] in {"run_attestation", "run_halted"}:
            ended.setdefault(run, []).append(seq)
            if entry["entry_type"] == "run_attestation":
                attested.setdefault(run, []).append(seq)
    attested_runs = sorted(int(s["predicate"]["run_number"]) for s in statements)
    if not attested_runs:
        return CheckResult("run_numbers", question, FAIL, "no runs attested")

    problems = []
    twice = {run: seqs for run, seqs in started.items() if len(seqs) > 1}
    if twice:
        problems += [
            f"run {run} was started {len(seqs)} times (seq {', '.join(map(str, seqs))}): "
            "an attempt that ended unreported is hidden under the number of the one reported"
            for run, seqs in sorted(twice.items())
        ]
    expected = list(range(1, len(started) + 1))
    if sorted(started) != expected:
        problems.append(f"the runs started are {sorted(started)}, not contiguous from 1")
    for run, seqs in sorted(attested.items()):
        if len(seqs) > 1:
            problems.append(f"run {run} is attested {len(seqs)} times")
        if run not in started or min(started[run]) > min(seqs):
            problems.append(f"run {run} is attested but was never started through the gate")
    exited = any(
        e["entry_type"] == "gate_decision"
        and e["body"].get("action") == "exit"
        and e["body"].get("allow")
        for e in entries
    )
    last = max(started, default=0)
    open_runs = [
        run
        for run, seqs in sorted(started.items())
        if not any(seq > min(seqs) for seq in ended.get(run, []))
    ]
    unreported = [run for run in open_runs if exited or run != last]
    if unreported:
        problems.append(
            f"run(s) {unreported} were started and never attested or halted: a run was "
            "performed and not reported"
        )
    if sorted(attested) != attested_runs:
        problems.append(
            f"the ledger attests runs {sorted(attested)} but the bundle carries attestations "
            f"for {attested_runs}"
        )
    if problems:
        return CheckResult("run_numbers", question, FAIL, "; ".join(problems))
    if open_runs:
        return CheckResult(
            "run_numbers",
            question,
            WARN,
            f"runs {sorted(started)} started once each; run {open_runs[0]} has not ended, and "
            "the ledger ends while it runs",
        )
    return CheckResult(
        "run_numbers",
        question,
        PASS,
        f"runs {sorted(started)}, contiguous, each started once and ended in the ledger",
    )


# --- 4. artifact digests ----------------------------------------------------


def check_artifact_digests(
    plans: dict[str, dict[str, Any]], statements: list[dict[str, Any]]
) -> CheckResult:
    """Each run is checked against the plan version it cites, not against the final one.

    A plan may be amended mid-participation, signed by both parties (Art. 57(5)) —
    the demo does exactly that when the provider fixes the bias and pins a new model
    digest. Checking every run against the last version would fail every earlier run
    for having run what it was actually told to run. So the run names its plan
    digest, and that version has to be in the bundle: a run citing a plan nobody can
    produce is worse than a mismatch, because there is nothing to check it against.
    """
    question = "do the artifacts in every run match the pins of the plan it cites?"
    for statement in statements:
        predicate = statement["predicate"]
        run = predicate["run_number"]
        cited = predicate.get("plan_digest", "")
        plan = plans.get(cited)
        if plan is None:
            return CheckResult(
                "artifact_digests",
                question,
                FAIL,
                f"run {run} was judged against plan {cited[:19]}…, which is not in the "
                "bundle: there is nothing to check it against",
            )
        artifacts = plan.get("artifacts", {})
        expected = {
            "model-image": artifacts.get("model_image_digest", ""),
            "harness-image": artifacts.get("harness_image_digest", ""),
            "relay-image": artifacts.get("relay_image_digest", ""),
        }
        subjects = {s["name"]: "sha256:" + s["digest"]["sha256"] for s in statement["subject"]}
        for name, pinned in expected.items():
            actual = subjects.get(name)
            if actual is None:
                return CheckResult(
                    "artifact_digests", question, FAIL, f"run {run} names no {name} subject"
                )
            if actual != pinned:
                return CheckResult(
                    "artifact_digests",
                    question,
                    FAIL,
                    f"run {run}: {name} is {actual[:19]}… but the plan pins {pinned[:19]}…; "
                    "the system tested is not the system the plan describes",
                )
    return CheckResult(
        "artifact_digests", question, PASS, f"{len(statements)} run(s) match the plan's pins"
    )


def check_dataset_commitments(
    entries: list[dict[str, Any]],
    statements: list[dict[str, Any]],
    plans: dict[str, dict[str, Any]] | None = None,
) -> CheckResult:
    """Every dataset a run used was committed in the ledger before the run started, at
    the digest it was used at, and at the commitment the plan the run cites pins for
    it (``datasets[].commitment``): one value, pinned by the plan, recorded by the gate
    and named by the run (spec/dataset-commitment.md)."""
    question = "was every dataset used committed before the run that used it?"
    commitments: dict[str, tuple[int, str]] = {}
    for entry in entries:
        if entry["entry_type"] == "dataset_committed":
            body = entry["body"]
            commitments[body["dataset_id"]] = (int(entry["seq"]), body["commitment"])

    # When each run started: its first run_started entry, and nothing later.
    run_seq: dict[int, int] = {}
    for e in entries:
        if e["entry_type"] == "run_started" and "run_number" in e["body"]:
            run_seq.setdefault(int(e["body"]["run_number"]), int(e["seq"]))

    for statement in statements:
        run = int(statement["predicate"]["run_number"])
        for subject in statement["subject"]:
            if not subject["name"].startswith("dataset:"):
                continue
            dataset_id = subject["name"].removeprefix("dataset:")
            used = "sha256:" + subject["digest"]["sha256"]
            if dataset_id not in commitments:
                return CheckResult(
                    "dataset_commitments",
                    question,
                    FAIL,
                    f"run {run} used dataset {dataset_id!r}, which was never committed",
                )
            committed_seq, committed = commitments[dataset_id]
            if committed != used:
                return CheckResult(
                    "dataset_commitments",
                    question,
                    FAIL,
                    f"run {run} used {dataset_id!r} at {used[:19]}… but it was committed at "
                    f"{committed[:19]}…: the data was changed after commitment",
                )
            if run in run_seq and committed_seq > run_seq[run]:
                return CheckResult(
                    "dataset_commitments",
                    question,
                    FAIL,
                    f"dataset {dataset_id!r} was committed after run {run} started: "
                    "a commitment made after the fact commits to nothing",
                )
            plan = (plans or {}).get(str(statement["predicate"].get("plan_digest")))
            listed = (plan or {}).get("datasets")
            if isinstance(listed, list):
                pinned = next(
                    (d for d in listed if isinstance(d, dict) and d.get("id") == dataset_id), None
                )
                if pinned is None:
                    return CheckResult(
                        "dataset_commitments",
                        question,
                        FAIL,
                        f"run {run} used dataset {dataset_id!r}, which the plan it cites does "
                        "not admit",
                    )
                if pinned.get("commitment") != committed:
                    return CheckResult(
                        "dataset_commitments",
                        question,
                        FAIL,
                        f"the plan run {run} cites pins {dataset_id!r} at "
                        f"{str(pinned.get('commitment'))[:19]}…, but the ledger committed it at "
                        f"{committed[:19]}…: the data used is not the data the parties agreed",
                    )
    return CheckResult("dataset_commitments", question, PASS, f"{len(commitments)} committed")


def check_plan_versions(
    entries: list[dict[str, Any]],
    plans: dict[str, dict[str, Any]],
    current: dict[str, Any] | None = None,
) -> CheckResult:
    """Was every plan version the ledger records a signing of actually carried?

    An amendment the ledger mentions but the bundle omits would let an operator
    record a signature over terms nobody can read. And each version is hashed again
    from its contents, not trusted by its file name: other terms filed under the
    digest the parties signed are a different plan, whether or not the recipient
    pinned that digest with ``--expect-plan-digest``.
    """
    question = "is every plan version the ledger records present in the bundle?"
    for named, plan in sorted(plans.items()):
        actual = plan_digest(plan)
        if actual != named:
            return CheckResult(
                "plan_versions",
                question,
                FAIL,
                f"the plan filed as {named[:19]}… hashes to {actual[:19]}…: its terms are "
                "not the ones that digest names",
            )
    signed = [
        str(e["body"]["plan_digest"])
        for e in entries
        if e["entry_type"] == "plan_signed" and "plan_digest" in e["body"]
    ]
    if not signed:
        return CheckResult("plan_versions", question, FAIL, "no plan_signed entry in the ledger")
    missing = [digest for digest in signed if digest not in plans]
    if missing:
        return CheckResult(
            "plan_versions",
            question,
            FAIL,
            f"the ledger records {len(signed)} signed plan version(s); "
            f"{len(missing)} are not in the bundle: {[d[:19] + '…' for d in missing]}",
        )
    if current is not None and plan_digest(current) != signed[-1]:
        return CheckResult(
            "plan_versions",
            question,
            FAIL,
            f"plan.json, which the manifest calls the plan the runs were judged against, "
            f"hashes to {plan_digest(current)[:19]}…, not to the version last put in force "
            f"({signed[-1][:19]}…): its terms are not ones anybody signed",
        )
    note = f"{len(set(signed))} version(s)"
    if len(set(signed)) > 1:
        note += " — the plan was amended during the participation"
    return CheckResult("plan_versions", question, PASS, note)


# --- 5. isolation -----------------------------------------------------------


# Who may sign an ``hpc_centre`` claim: the key id their envelopes name, the ledger
# entry that records their public key, and how the verifier's output names them.
SIGNERS = {
    "centre": ("hpc-centre", "hpc_centre_key", "the centre"),
    "sandbox_operator": ("sandbox-operator", "hpc_operator_key", "the sandbox operator"),
}
# The plan's OCI pins, and the component each is converted into a SIF for.
PINNED_COMPONENTS = {
    "model_image_digest": "model",
    "relay_image_digest": "relay",
    "harness_image_digest": "harness",
}


def _signer(record: dict[str, Any]) -> str:
    """Who signed a claim or a conversion. Without ``signed_by`` it predates the field,
    from when only a centre signed."""
    return str(record.get("signed_by") or "centre")


def _signature(record: dict[str, Any], signer: str) -> Any:
    """The signature, from ``signature``, or for the centre alone from the older
    ``centre_signature``. An operator's claim cannot borrow the centre's field."""
    if record.get("signature"):
        return record["signature"]
    return record.get("centre_signature") if signer == "centre" else None


def _envelope(value: Any) -> dict[str, Any]:
    """A DSSE envelope as it is carried: the object itself (in a ledger entry's body), or
    base64 of its JSON (in the isolation arm)."""
    if isinstance(value, dict):
        return value
    decoded = json.loads(base64.b64decode(str(value), validate=True))
    if not isinstance(decoded, dict):
        raise ValueError("the signature is not a DSSE envelope")
    return decoded


@dataclass(frozen=True)
class _HpcKey:
    """The keys a signer of HPC evidence is checked under, where they came from
    (``anchor``: your ``--centre-keys``; ``ledger``: its ``hpc_centre_key`` or
    ``hpc_operator_key`` entry; ``bundle``: public-keys.json alone), and the seq of the
    ledger entry that recorded them."""

    pems: tuple[str, ...]
    source: str
    recorded_at: int = 0


def _signer_key(
    signer: str,
    public_keys: dict[str, str],
    entries: list[dict[str, Any]],
    centre: str | None = None,
    centre_keys: tuple[tuple[str, str], ...] = (),
) -> tuple[_HpcKey | None, str]:
    """The public key for a signer, or why there is none.

    For the centre, the keys you gave (``--centre-keys``) under the centre's name or
    ``hpc-centre`` are the only ones used, and the ledger's record must be one of them.
    Otherwise the ledger's entry is the record, chained and timestamped;
    ``public-keys.json`` is where a bundle made before the entry was read carried it.
    When both are present they must be the same key.
    """
    key_id, entry_type, name = SIGNERS[signer]
    recorded = [
        (int(e.get("seq") or 0), str(e["body"]["public_key"]))
        for e in entries
        if e.get("entry_type") == entry_type
        and isinstance(e.get("body"), dict)
        and e["body"].get("public_key")
        and (centre is None or e["body"].get("centre") in (None, centre))
    ]
    bundled = public_keys.get(key_id)
    if signer == "centre" and centre_keys:
        given = tuple(pem for kid, pem in centre_keys if kid in (centre, key_id))
        if not given:
            return None, (
                f"you gave no key for {centre!r} (--centre-keys names "
                f"{sorted({kid for kid, _ in centre_keys})})"
            )
        held = {_raw_key(pem) for pem in given}
        for where, pem in [*((entry_type, p) for _, p in recorded), ("public-keys.json", bundled)]:
            if pem and _raw_key(pem) not in held:
                return None, (
                    f"the bundle's {where} key for {centre!r} is not a key you hold for it: "
                    "the evidence could have been signed by whoever recorded that key"
                )
        return _HpcKey(given, "anchor"), ""
    if recorded and bundled and recorded[-1][1].strip() != bundled.strip():
        return None, (
            f"the ledger's {entry_type} and the bundle's {key_id!r} key are different keys, "
            f"so nothing says which one is {name}'s"
        )
    if recorded:
        return _HpcKey((recorded[-1][1],), "ledger", recorded[-1][0]), ""
    if bundled is None:
        return None, f"the bundle carries no key for {name}, so its signature cannot be checked"
    return _HpcKey((bundled,), "bundle"), ""


def _verify_under(envelope: Any, key_id: str, key: _HpcKey) -> dict[str, Any]:
    """The payload of ``envelope`` signed under ``key_id`` by one of ``key``'s keys."""
    error: Exception = signing.VerificationError("no key")
    for pem in key.pems:
        try:
            return signing.verify_json(_envelope(envelope), {key_id: pem})
        except signing.VerificationError as failed:
            error = failed
    raise error


@dataclass
class _Conversions:
    """The verified OCI-to-SIF pairs, by OCI digest, and who signed them."""

    sif: dict[str, str] = field(default_factory=dict)
    signers: set[str] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)
    sources: set[tuple[str, str]] = field(default_factory=set)  # (signer, key source)


def _conversions(
    public_keys: dict[str, str],
    entries: list[dict[str, Any]],
    centre_keys: tuple[tuple[str, str], ...] = (),
) -> _Conversions:
    """Every ``image_converted`` entry, each verified under the key of whoever it says
    signed it. A later conversion of the same image replaces an earlier one."""
    out = _Conversions()
    for entry in entries:
        if entry.get("entry_type") != "image_converted":
            continue
        body = entry.get("body") or {}
        seq = entry.get("seq")
        signer = _signer(body)
        if signer not in SIGNERS:
            out.problems.append(f"an image conversion (seq {seq}) names an unknown signer")
            continue
        key_id, _, name = SIGNERS[signer]
        centre = str(body["centre"]) if body.get("centre") else None
        key, missing = _signer_key(signer, public_keys, entries, centre, centre_keys)
        if key is None:
            out.problems.append(f"image conversion (seq {seq}): {missing}")
            continue
        if key.source == "ledger" and seq is not None and key.recorded_at > int(seq):
            out.problems.append(
                f"image conversion (seq {seq}) is signed under {name}'s key, which the ledger "
                f"recorded only later (seq {key.recorded_at})"
            )
            continue
        try:
            pair = _verify_under(_signature(body, signer), key_id, key)
            oci, sif = str(pair["oci_digest"]), str(pair["sif_digest"])
        except (signing.VerificationError, ValueError, KeyError, TypeError):
            out.problems.append(f"an image conversion (seq {seq}) is not {name}'s")
            continue
        if body.get("oci_digest", oci) != oci or body.get("sif_digest", sif) != sif:
            out.problems.append(
                f"an image conversion (seq {seq}) records digests other than the ones {name} signed"
            )
            continue
        out.sif[oci] = sif
        out.signers.add(signer)
        out.sources.add((signer, key.source))
    return out


def _of_run(entries: list[dict[str, Any]], entry_type: str, run: int) -> list[dict[str, Any]]:
    """The ledger's entries of one type that name this run."""
    out = []
    for entry in entries:
        body = entry.get("body")
        if entry.get("entry_type") != entry_type or not isinstance(body, dict):
            continue
        if str(body.get("run_number")) == str(run):
            out.append(entry)
    return out


def _release_problems(
    run: int,
    outcome: str,
    plan: dict[str, Any],
    conversions: _Conversions,
    entries: list[dict[str, Any]],
) -> tuple[list[str], str]:
    """Whether a run's keys went to the job that was measured, and a sentence saying
    what the release shows.

    The broker checked this before it sealed anything. It is checked again here from
    the ``key_released`` entry, because the verifier takes nobody's word for it, the
    broker's included.
    """
    released = _of_run(entries, "key_released", run)
    if not released:
        if _of_run(entries, "key_release_refused", run) and outcome == "halted":
            # The broker failed closed and the run stopped: nothing was opened in it.
            return [], f"run {run} was refused its keys and halted, so no data was opened"
        return [
            "no key_released entry for this run: nothing shows its keys went to the job "
            "that was measured"
        ], ""
    problems = []
    if len(released) > 1:
        problems.append(
            f"keys were released {len(released)} times for this run; a release is once per run"
        )
    entry = released[-1]
    body = entry["body"]
    measurements = body.get("measurements")
    measurements = measurements if isinstance(measurements, dict) else {}
    measured = measurements.get("sif")
    measured = measured if isinstance(measured, dict) else {}
    for pin, component in PINNED_COMPONENTS.items():
        oci = plan.get("artifacts", {}).get(pin)
        expected = conversions.sif.get(str(oci)) if oci else None
        if expected is None:
            continue  # said already, as a pin with no signed conversion
        if measured.get(component) != expected:
            problems.append(
                f"the job measured its {component} SIF as {str(measured.get(component))[:19]}… "
                f"but the conversion of the pinned image recorded {expected[:19]}…: the keys "
                "went to a job running something else"
            )
    probe = measurements.get("probe")
    if not isinstance(probe, list) or not probe:
        problems.append("the release records no probe from the model's namespace")
    else:
        reached = [
            str(attempt.get("target", "?")) if isinstance(attempt, dict) else str(attempt)
            for attempt in probe
            if not (
                isinstance(attempt, dict) and str(attempt.get("result", "")).startswith("blocked")
            )
        ]
        if reached:
            problems.append(f"the probe from the model's namespace was not blocked: {reached}")
    links = measurements.get("netns_links")
    if links != ["lo"]:
        problems.append(f"the model's namespace held {links}, not loopback alone")
    submitted = _of_run(entries, "job_submitted", run)
    if submitted and str(submitted[-1]["body"].get("slurm_job_id")) != str(
        body.get("slurm_job_id")
    ):
        problems.append(
            f"keys were released to job {body.get('slurm_job_id')}, but job "
            f"{submitted[-1]['body'].get('slurm_job_id')} was the one submitted"
        )
    attested = [int(e.get("seq", 0)) for e in _of_run(entries, "run_attestation", run)]
    if attested and int(entry.get("seq", 0)) > min(attested):
        problems.append("the key release is recorded after the run's attestation")
    return problems, (
        f"run {run}'s keys were released once, to a key (digest "
        f"{str(body.get('job_public_key_digest'))[:19]}…) held by Slurm job "
        f"{body.get('slurm_job_id')}, after that job's measured SIF digests matched the "
        "conversions, every probe from the model's namespace was blocked and that "
        f"namespace held only loopback (ledger seq {entry.get('seq')})"
    )


def _weights_problems(
    run: int, outcome: str, plan: dict[str, Any], entries: list[dict[str, Any]]
) -> tuple[list[str], str]:
    """Whether the provider's own releaser released the weights key for this run to
    the job that got the data keys, and a sentence saying so.

    Checked from the provider's signed receipt, under the releaser key the plan pins,
    so this does not rest on the control plane's word that the provider agreed. A plan
    that pins no encrypted weights is read as before, and the note says the weights
    were in the model's image.
    """
    pin = weights.pin_of(plan)
    if pin is None:
        return [], (
            f"run {run}'s plan pins no encrypted weights, so the model's weights were in its "
            "image and passed through the sandbox with it"
        )
    try:
        weights.check_pin(pin)
    except weights.WeightsError as error:
        return [f"the plan's weights pin does not hold: {error}"], ""
    released = _of_run(entries, "weights_key_released", run)
    if not released:
        refused = _of_run(entries, "weights_key_release_refused", run) or _of_run(
            entries, "key_release_refused", run
        )
        if refused and outcome == "halted":
            return [], f"run {run} was refused the weights key and halted, so the model never ran"
        return [
            "no weights_key_released entry for this run: nothing shows the provider released "
            "its weights to the job"
        ], ""
    problems = []
    if len(released) > 1:
        problems.append(
            f"the weights key was released {len(released)} times for this run; a release is "
            "once per run"
        )
    entry = released[-1]
    body = entry["body"]
    try:
        receipt = signing.verify_json(
            body.get("receipt"), {weights.RELEASER_KEY_ID: str(pin["releaser_public_key"])}
        )
    except (signing.VerificationError, ValueError, TypeError) as error:
        problems.append(
            "the provider's receipt for the weights key does not verify under the releaser "
            f"key the plan pins: {error}"
        )
        return problems, ""
    if receipt.get("format") != weights.RECEIPT_FORMAT:
        problems.append(f"the provider's receipt is not an {weights.RECEIPT_FORMAT}")
    differing = [f for f in weights.RECEIPT_FIELDS if str(receipt.get(f)) != str(body.get(f))]
    if differing:
        problems.append(
            f"the ledger's weights release differs from the provider's receipt in {differing}"
        )
    for name in ("ciphertext_digest", "plaintext_digest"):
        if receipt.get(name) != pin.get(name):
            problems.append(f"the provider released a key for other weights ({name}) than the pin")
    max_runs = (plan.get("limits") or {}).get("max_runs")
    try:
        over = max_runs is not None and int(receipt.get("runs_released", 0)) > int(max_runs)
    except (TypeError, ValueError):
        over = True
    if over:
        problems.append(
            f"the provider's receipt counts {receipt.get('runs_released')} runs, beyond the "
            f"plan's max_runs of {max_runs}"
        )
    data = _of_run(entries, "key_released", run)
    if data:
        data_body = data[-1]["body"]
        for name in ("request_digest", "job_public_key_digest"):
            if data_body.get(name) != receipt.get(name):
                problems.append(
                    f"the data keys and the weights key answer different {name}s: they did not "
                    "go to the same job key"
                )
    attested = [int(e.get("seq", 0)) for e in _of_run(entries, "run_attestation", run)]
    if attested and int(entry.get("seq", 0)) > min(attested):
        problems.append("the weights release is recorded after the run's attestation")
    return problems, (
        f"the provider's own releaser released run {run}'s weights key (its receipt verifies "
        f"under the releaser key the plan pins; run {receipt.get('runs_released')} of "
        f"{receipt.get('max_runs')}) to the same job key as the data keys (digest "
        f"{str(receipt.get('job_public_key_digest'))[:19]}…, ledger seq {entry.get('seq')}), "
        "and only the weights' ciphertext passed through the sandbox"
    )


def _refusals(entries: list[dict[str, Any]]) -> list[str]:
    """Every refused key release, as an incident, in the words the ledger records.

    A refusal is the broker failing closed, which is the control working, so it does
    not fail the bundle. It is still an incident: a second request for one run, or a
    job whose measurements did not match, is what an attempt on the keys looks like.
    So it is never left out of the verdict.
    """
    out = []
    for entry in entries:
        kind = entry.get("entry_type")
        if kind not in {"key_release_refused", "weights_key_release_refused"}:
            continue
        body = entry.get("body") or {}
        reasons = body.get("reasons") or body.get("reason") or "no reason recorded"
        if isinstance(reasons, list):
            reasons = "; ".join(str(r) for r in reasons)
        job = f", job {body['slurm_job_id']}" if body.get("slurm_job_id") else ""
        who = (
            "the weights key was not released"
            if kind == "weights_key_release_refused"
            else "the key broker refused a key release"
        )
        out.append(
            f"INCIDENT: {who} for run {body.get('run_number')}{job} (ledger seq "
            f"{entry.get('seq')}): {reasons}"
        )
    return out


def _centre_problems(
    evidence: dict[str, Any],
    plan: dict[str, Any],
    public_keys: dict[str, str],
    entries: list[dict[str, Any]],
    run: int = 0,
    outcome: str = "",
    centre_keys: tuple[tuple[str, str], ...] = (),
    sources: set[tuple[str, str]] | None = None,
) -> tuple[list[str], list[str]]:
    """What is wrong with an ``hpc_centre`` claim, and what a sound one shows. Where
    each signer's key came from is added to ``sources`` as ``(signer, source)``, for
    :func:`check_isolation` to hold to the anchors you gave.

    Four things: the signature, under the key of whoever ``signed_by`` names; the chain
    from the plan's OCI pins to the SIF images that ran; the key release bound to the
    job; and, where the plan pins encrypted weights, the provider's release of the
    weights key to the same job key. A bundle made before the release existed, with no
    ``signed_by`` in the claim and no ``key_released`` entry anywhere in its ledger, is
    read as it was then, and the verdict says what it lacks.
    """
    signer = _signer(evidence)
    if signer not in SIGNERS:
        return [f"the claim names an unknown signer {signer!r}"], []
    key_id, _, name = SIGNERS[signer]
    signature = _signature(evidence, signer)
    if not signature:
        return [f"it claims isolation at a centre with no signature from {name}"], []
    centre = str(evidence["centre"]) if evidence.get("centre") else None
    key, missing = _signer_key(signer, public_keys, entries, centre, centre_keys)
    if key is None:
        return [missing], []
    try:
        signed = _verify_under(signature, key_id, key)
    except (signing.VerificationError, ValueError, KeyError, TypeError) as error:
        return [f"{name}'s signature does not verify: {error}"], []
    problems = []
    attested = [int(e.get("seq", 0)) for e in _of_run(entries, "run_attestation", run)]
    if key.source == "ledger" and attested and key.recorded_at > min(attested):
        problems.append(
            f"{name}'s key was recorded in the ledger at seq {key.recorded_at}, after the run's "
            "attestation: it was not fixed before the run"
        )
    if sources is not None:
        sources.add((signer, key.source))
    # signed_by is inside what was signed, so who signed cannot be changed afterwards.
    claimed = {k: v for k, v in evidence.items() if k not in {"signature", "centre_signature"}}
    if signed != claimed:
        problems.append(f"{name} signed something other than the evidence the run carries")

    conversions = _conversions(public_keys, entries, centre_keys)
    problems += conversions.problems
    if sources is not None:
        sources |= conversions.sources
    for pin in PINNED_COMPONENTS:
        oci = plan.get("artifacts", {}).get(pin)
        if oci and oci not in conversions.sif:
            problems.append(f"no signed conversion of the pinned {pin} {str(oci)[:19]}…")

    notes = []
    others = conversions.signers - {signer}
    if others:
        notes.append(
            "the image conversions were signed by "
            + " and ".join(SIGNERS[s][2] for s in sorted(others))
        )
    legacy = "signed_by" not in evidence and not any(
        e.get("entry_type") == "key_released" for e in entries
    )
    if legacy:
        notes.append(
            f"run {run} predates keys released to the job: there is no key_released entry, "
            "so nothing shows its keys went only to the job that was measured"
        )
    else:
        found, released = _release_problems(run, outcome, plan, conversions, entries)
        problems += found
        if released:
            notes.append(released)
        found, released = _weights_problems(run, outcome, plan, entries)
        problems += found
        if released:
            notes.append(released)
    return problems, notes


def _undertaking_problems(
    run: int, evidence: dict[str, Any], plan: dict[str, Any], entries: list[dict[str, Any]]
) -> tuple[str | None, list[str]]:
    """The undertaking that covered a run at a centre, or what is wrong.

    The gate names the agreement in ``run_started`` when it authorises a run at a
    centre. A run whose evidence names another centre, or whose start names no
    agreement, ran where no confidentiality undertaking in the plan reached."""
    centre = str(evidence.get("centre"))
    started = next(
        (
            e["body"]
            for e in entries
            if e.get("entry_type") == "run_started" and e["body"].get("run_number") == run
        ),
        None,
    )
    if started is None or not started.get("agreement"):
        return None, [
            f"the run was not authorised as a run at {centre!r}, so no confidentiality "
            "undertaking covered it there"
        ]
    if started.get("centre") != centre:
        return None, [
            f"the run was authorised at {started.get('centre')!r} but its evidence is from "
            f"{centre!r}"
        ]
    named = started["agreement"]
    pinned = next((a for a in plan.get("agreements") or [] if a.get("id") == named.get("id")), None)
    if pinned is None:
        return None, [f"the run names undertaking {named.get('id')!r}, which its plan lacks"]
    if pinned.get("centre") != centre or pinned.get("document_sha256") != named.get(
        "document_sha256"
    ):
        return None, [
            f"undertaking {named.get('id')!r} in the plan is not the one the run names, "
            f"or is not from {centre!r}"
        ]
    return str(named["id"]), []


# Each backend can produce exactly one kind of isolation evidence. A predicate whose
# ``backend`` and ``isolation_evidence.type`` disagree claims more (or other) than
# happened, whichever of the two is true: "kubernetes" beside ``local_process`` names
# an isolated platform the run never touched.
ISOLATION_BY_BACKEND = {
    "kubernetes": "cilium",
    "slurm": "hpc_centre",
    "local": "local_process",
}


def check_isolation(
    plans: dict[str, dict[str, Any]],
    statements: list[dict[str, Any]],
    public_keys: dict[str, str] | None = None,
    entries: list[dict[str, Any]] | None = None,
    centre_keys: tuple[tuple[str, str], ...] = (),
    anchored: bool = False,
) -> CheckResult:
    """``centre_keys`` are the centres' keys you gave (``--centre-keys``); ``anchored``
    that you gave any anchor, under which a centre's word checked under a key only the
    bundle names fails: whoever assembled the bundle could have recorded its own key as
    the centre's."""
    question = "is isolation evidence present and does it match the plan's policy?"

    kinds: set[str] = set()
    # hpc_centre runs, by who signed their evidence: (run, centre).
    vouched: dict[str, list[tuple[Any, str]]] = {}
    # Where each signer's key came from, over every hpc_centre run.
    sources: set[tuple[str, str]] = set()
    centre_notes: list[str] = []
    undertakings: list[str] = []
    egress: list[str] = []
    for statement in statements:
        predicate = statement["predicate"]
        run = predicate["run_number"]
        plan = plans.get(predicate.get("plan_digest", ""), {})
        pinned = plan.get("artifacts", {}).get("network_policy_digest")
        evidence = predicate.get("isolation_evidence") or {}
        kind = str(evidence.get("type"))
        kinds.add(kind)

        backend = str(predicate.get("backend"))
        expected = ISOLATION_BY_BACKEND.get(backend)
        if expected is None:
            return CheckResult(
                "isolation", question, FAIL, f"run {run} names unknown backend {backend!r}"
            )
        if kind != expected:
            return CheckResult(
                "isolation",
                question,
                FAIL,
                f"run {run} says it ran on the {backend} backend but carries {kind} "
                f"isolation evidence; the {backend} backend produces {expected}. The "
                "attestation contradicts itself, so neither claim can be relied on",
            )

        if kind == "cilium":
            if evidence.get("network_policy_digest") != pinned:
                return CheckResult(
                    "isolation",
                    question,
                    FAIL,
                    f"run {run} ran under network policy "
                    f"{str(evidence.get('network_policy_digest'))[:19]}… but the plan pins "
                    f"{str(pinned)[:19]}…: the results are from a different experiment",
                )
            if not evidence.get("drop_log_digest"):
                return CheckResult(
                    "isolation", question, FAIL, f"run {run} carries no drop log digest"
                )
        elif kind == "hpc_centre":
            problems, notes = _centre_problems(
                evidence,
                plan,
                public_keys or {},
                entries or [],
                int(run),
                str(predicate.get("outcome", "")),
                centre_keys,
                sources,
            )
            undertaking, uncovered = _undertaking_problems(run, evidence, plan, entries or [])
            problems.extend(uncovered)
            if problems:
                return CheckResult(
                    "isolation", question, FAIL, f"run {run}: " + "; ".join(problems)
                )
            vouched.setdefault(_signer(evidence), []).append((run, str(evidence.get("centre"))))
            centre_notes += notes
            undertakings.append(str(undertaking))
        elif kind == "local_process":
            if evidence.get("model_egress"):
                egress.append(f"run {run} -> {evidence['model_egress']}")
            continue  # reported as a caveat, below; not a failure of the bundle
        else:
            return CheckResult(
                "isolation", question, FAIL, f"run {run} carries unknown isolation type {kind!r}"
            )

    # A hosted model is the one case where the data is known to have left the host,
    # not merely able to. That is said outright, beside the caveat.
    sent = (
        " THE TEST DATA WAS SENT TO A HOSTED MODEL OUTSIDE THE HOST: " + "; ".join(egress) + "."
        if egress
        else ""
    )
    # A refused key release is an incident wherever it happened, and is always said.
    incidents = _refusals(entries or [])
    reported = (" " + " ".join(incidents)) if incidents else ""
    if kinds == {"local_process"}:
        return CheckResult(
            "isolation",
            question,
            WARN,
            "NO ISOLATION WAS ENFORCED. Every run in this bundle was executed as "
            "ordinary processes on one host. The results describe what the model "
            "answered; they establish nothing about whether it could have reached the "
            "data or the network. This bundle is a development artefact and is not "
            "sandbox evidence." + sent + reported,
        )
    if "local_process" in kinds:
        return CheckResult(
            "isolation",
            question,
            WARN,
            "some runs in this bundle were executed with no isolation enforced "
            "(isolation_evidence.type = local_process); those runs are not evidence."
            + sent
            + reported,
        )
    if vouched:
        # The centre's word is worth its key, and a key only the bundle names is
        # whoever assembled the bundle's to name: under any anchor that fails.
        unanchored = sorted(
            f"{SIGNERS[signer][2]}'s (from "
            + ("the ledger's own record" if source == "ledger" else "public-keys.json alone")
            + ")"
            for signer, source in sources
            if source != "anchor" and (signer == "centre" or source == "bundle")
        )
        if unanchored and anchored:
            return CheckResult(
                "isolation",
                question,
                FAIL,
                f"KEYS NOT ANCHORED: the HPC evidence was checked under {', '.join(unanchored)} "
                "key, which only the bundle names: whoever assembled it could have recorded a "
                "key of its own as the centre's. Give the centre's key with --centre-keys, "
                "obtained from the centre",
            )
        caveat = (
            f" The HPC evidence was checked under {', '.join(unanchored)} key, which only the "
            "bundle names; give the centre's key with --centre-keys."
            if unanchored
            else ""
        )
        # A different trust model, and said so rather than given the same tick; and
        # whose word it is, since the operator's is not the centre's.
        covered = caveat + (
            " Root on the compute node could read the model while it ran; what covered that "
            "is a contract, the centre's confidentiality undertaking "
            f"({', '.join(sorted(set(undertakings)))}), not cryptography."
        )
        return CheckResult(
            "isolation", question, WARN, _vouched(vouched, centre_notes) + covered + reported
        )
    if incidents:
        return CheckResult(
            "isolation", question, WARN, f"isolation evidence: {sorted(kinds)}." + reported
        )
    return CheckResult("isolation", question, PASS, f"isolation evidence: {sorted(kinds)}")


def _vouched(vouched: dict[str, list[tuple[Any, str]]], notes: list[str]) -> str:
    """What a sound ``hpc_centre`` claim rests on, by who signed it."""
    sentences = []
    for signer, runs in sorted(vouched.items()):
        numbers = ", ".join(str(run) for run, _ in runs)
        centres = ", ".join(sorted({centre for _, centre in runs}))
        if signer == "centre":
            sentences.append(
                f"isolation vouched for by {centres} (run {numbers}): the centre's signature "
                "over its job record and node configuration verifies, and every pinned image "
                "has a signed conversion to the SIF that ran. This rests on the centre's word, "
                "not on a network policy anyone can hash and a drop log anyone can read."
            )
        else:
            sentences.append(
                f"isolation at {centres} (run {numbers}) vouched for by the sandbox operator: "
                "the operator's signature over the job record and node configuration its "
                "courier observed verifies, and every pinned image has a signed conversion to "
                "the SIF that ran. This rests on the sandbox operator's word: the party that "
                "runs the sandbox, vouching for its own run. That is weaker than a centre's "
                "word, and neither is a network policy anyone can hash or a drop log anyone "
                "can read."
            )
    return " ".join(sentences) + "".join(f" {note[0].upper()}{note[1:]}." for note in notes)


# --- 5b. hardware attestation of the key release ------------------------------
#
# A run's keys can be released to a trusted execution environment on the strength of an
# attestation report (docs/roadmap-hardware-attestation.md). The key broker and the
# provider's releaser checked it before they released; the ledger's key_released holds
# the report, its collateral and what it was bound to, and the check below does the same
# again, offline, with the same code (histor.crypto.tee.verify), at the time the release
# was stamped, against the plan's tee_policy and any vendor roots the verifier holds.


def _tee_policy(plan: dict[str, Any]) -> Any:
    return (plan.get("artifacts") or {}).get("tee_policy")


def tee_evidence_present(
    plans: dict[str, dict[str, Any]],
    statements: list[dict[str, Any]],
    entries: list[dict[str, Any]],
) -> bool:
    """Whether a bundle has anything for ``tee_attestation`` to check: a plan with a
    tee_policy, a release recording TEE evidence, or a run naming a report."""
    return (
        any(_tee_policy(plan) is not None for plan in plans.values())
        or any(
            e["entry_type"] in {"key_released", "weights_key_released"} and "tee" in e["body"]
            for e in entries
        )
        or any(
            isinstance(s["predicate"].get("isolation_evidence"), dict)
            and "tee" in s["predicate"]["isolation_evidence"]
            for s in statements
        )
    )


def _signed_instant(
    entry: dict[str, Any], public_keys: dict[str, str]
) -> tuple[datetime.datetime | None, str]:
    """The time an entry's timestamp signs, and the kind of timestamp; the entry's own
    ``recorded_at`` when it has no timestamp that verifies (``timestamps`` says why)."""
    stamp = entry.get("timestamp")
    if stamp:
        try:
            token = parse_timestamp(stamp)
            attested = verify_token(stamp, public_keys)
            signed = _instant(
                attested.get("time") if token.kind == "rfc3161" else attested.get("timestamp")
            )
            if signed is not None:
                return signed, token.kind
        except (signing.VerificationError, NotImplementedError, KeyError, TypeError, ValueError):
            pass
    return _instant(entry.get("recorded_at")), "recorded_at"


def check_tee_attestation(
    plans: dict[str, dict[str, Any]],
    statements: list[dict[str, Any]],
    entries: list[dict[str, Any]],
    public_keys: dict[str, str] | None = None,
    vendor_roots: tuple[str, ...] = (),
) -> CheckResult:
    """Was each run's key released to hardware-attested code the plan pins?

    For every run: under a plan with a tee_policy, the run's ``key_released`` must hold
    TEE evidence; wherever it holds some, the report is checked again: its chain to a
    root the policy lists (and, with ``--vendor-roots``, to one of those), the
    collateral valid and nothing revoked at the time the entry was stamped, its
    signature, the measurement, launch configuration and minimum TCB of the policy,
    debug off, and its ``report_data`` against the key the ledger says the keys were
    sealed to, for this run of this plan. The run's ``isolation_evidence.tee`` and the
    provider's receipt must name the same report. The mock platform always warns.
    """
    from histor.crypto.tee import TeeBinding, TeeError, TeeEvidence
    from histor.crypto.tee.verify import UNVERIFIED_IMPLEMENTATIONS, verify_evidence

    question = "was each run's key released to hardware-attested code the plan pins?"
    problems: list[str] = []
    notes: list[str] = []
    verified: list[str] = []
    mocks: list[int] = []
    unverified: dict[str, list[int]] = {}
    for statement in statements:
        predicate = statement["predicate"]
        run = int(predicate["run_number"])
        cited = str(predicate.get("plan_digest", ""))
        policy = _tee_policy(plans.get(cited, {}))
        evidence_field = predicate.get("isolation_evidence")
        summary = evidence_field.get("tee") if isinstance(evidence_field, dict) else None
        released = [e for e in _of_run(entries, "key_released", run) if "tee" in e["body"]]
        if not released:
            refused = _of_run(entries, "key_release_refused", run)
            if policy is not None and refused and predicate.get("outcome") == "halted":
                notes.append(f"run {run} was refused its keys and halted")
            elif policy is not None:
                problems.append(
                    f"run {run}: the plan's tee_policy requires hardware attestation evidence "
                    "for the key release, and the ledger records none: the keys went to code "
                    "no hardware vouched for"
                )
            elif summary is not None:
                problems.append(
                    f"run {run}'s attestation names TEE report "
                    f"{str(summary.get('report_digest'))[:19]}…, which no key_released entry "
                    "records"
                )
            continue
        if len(released) > 1:
            problems.append(f"run {run}: keys were released {len(released)} times to a TEE")
        entry = released[-1]
        body = entry["body"]
        try:
            evidence = TeeEvidence.from_json(body["tee"])
            binding = TeeBinding.from_json(body.get("tee_binding"))
        except TeeError as error:
            problems.append(f"run {run}: the recorded TEE evidence is malformed: {error}")
            continue
        if binding.plan_digest != cited or binding.run_number != run:
            problems.append(
                f"run {run}: the report was bound to run {binding.run_number} of plan "
                f"{binding.plan_digest[:19]}…, not to this run of the plan it cites"
            )
        try:
            key_digest = binding.public_key_digest
        except TeeError as error:
            key_digest = f"({error})"
        if key_digest != body.get("job_public_key_digest"):
            problems.append(
                f"run {run}: the report binds key {key_digest[:19]}…, but the keys were sealed "
                f"to {str(body.get('job_public_key_digest'))[:19]}…: a key substituted after "
                "the report was made"
            )
        at, kind = _signed_instant(entry, public_keys or {})
        if at is None:
            problems.append(f"run {run}: the key release has no time to check its collateral at")
            continue
        verification = verify_evidence(
            evidence, policy, at, binding=binding, anchored_roots=vendor_roots
        )
        found = verification.problems
        if policy is None:
            found = [p for p in found if not p.startswith("no vendor root")]
            notes.append(
                f"run {run} carries TEE evidence but its plan pins no tee_policy, so the "
                "report is held to no pinned measurement"
                + ("" if vendor_roots else " and its chain to no root you hold")
            )
        problems += [f"run {run}: {p}" for p in found]
        if summary is not None and summary != evidence.summary():
            problems.append(
                f"run {run}: the attestation's isolation_evidence.tee is not the report the "
                "ledger recorded"
            )
        for weights_entry in _of_run(entries, "weights_key_released", run):
            named = weights_entry["body"].get("tee")
            if named is not None and (
                not isinstance(named, dict) or named.get("report_digest") != evidence.report_digest
            ):
                problems.append(
                    f"run {run}: the provider's releaser checked another report than the one "
                    "the data keys were released on"
                )
        if kind != "rfc3161":
            notes.append(
                f"run {run}'s collateral was checked at the time "
                + (
                    "a development timestamp signs, which the operator could have chosen"
                    if kind == "dev"
                    else "the entry records, which nothing signs"
                )
            )
        if evidence.platform == "mock":
            mocks.append(run)
        elif evidence.platform in UNVERIFIED_IMPLEMENTATIONS:
            unverified.setdefault(evidence.platform, []).append(run)
        verified.append(
            f"run {run}: {evidence.platform} report {evidence.report_digest[:19]}… (ledger seq "
            f"{entry.get('seq')}) chains to root {str(verification.root_sha256)[:19]}…, meets the "
            "policy and binds the key the keys were sealed to"
        )

    said = "".join(f" {note[0].upper()}{note[1:]}." for note in notes)
    if problems:
        return CheckResult("tee_attestation", question, FAIL, "; ".join(problems) + said)
    if not verified:
        return CheckResult(
            "tee_attestation", question, PASS, "no key release names TEE evidence." + said
        )
    detail = "; ".join(verified) + "." + said
    if mocks:
        return CheckResult(
            "tee_attestation",
            question,
            WARN,
            f"MOCK PLATFORM: NOT HARDWARE EVIDENCE (run {', '.join(map(str, mocks))}). The "
            "reports are software made under a test root, and whoever holds that root's key "
            "can make one saying anything. The flow checks out; nothing here shows the "
            "harness ran in a TEE. " + detail,
        )
    if unverified:
        platforms = ", ".join(sorted(unverified))
        return CheckResult(
            "tee_attestation",
            question,
            WARN,
            f"UNVERIFIED IMPLEMENTATION: this verifier's {platforms} checks have been tested "
            "on synthetic structures only, not yet on reports from real hardware. " + detail,
        )
    return CheckResult("tee_attestation", question, PASS, detail)


# --- 6. thresholds ----------------------------------------------------------


COMPARISONS = {
    "lte": lambda observed, limit: observed <= limit,
    "gte": lambda observed, limit: observed >= limit,
    "lt": lambda observed, limit: observed < limit,
    "gt": lambda observed, limit: observed > limit,
}


# Two-sided normal critical values for the levels a plan may set. Restated rather than
# imported from the harness: the verifier checks the harness's arithmetic, so it does
# not borrow it.
_Z = {0.80: 1.281552, 0.90: 1.644854, 0.95: 1.959964, 0.98: 2.326348, 0.99: 2.575829}
# Measurements are rounded to six places in the predicate.
_ROUNDING = 2e-6


def _wilson_bounds(successes: int, n: int, level: float) -> tuple[float, float]:
    z = _Z[min(_Z, key=lambda known: abs(known - level))]
    p = successes / n
    denominator = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denominator
    margin = z * (p * (1 - p) / n + z**2 / (4 * n**2)) ** 0.5 / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def _wilson_problems(label: str, measurement: dict[str, Any]) -> tuple[int | None, list[str]]:
    """The success count a Wilson measurement implies, and anything that does not add
    up: a rate that is not a count over n, or an interval that is not its interval."""
    n = int(measurement.get("n", 0))
    if n <= 0:
        return 0, []
    value = float(measurement["value"])
    successes = round(value * n)
    problems = []
    if abs(successes / n - value) > _ROUNDING:
        problems.append(f"{label} = {value} is not a count over n={n}")
    if measurement.get("ci_low") is not None and measurement.get("ci_high") is not None:
        low, high = _wilson_bounds(successes, n, float(measurement.get("confidence_level", 0.95)))
        if (
            abs(low - float(measurement["ci_low"])) > _ROUNDING
            or abs(high - float(measurement["ci_high"])) > _ROUNDING
        ):
            problems.append(
                f"{label}: interval {measurement['ci_low']}-{measurement['ci_high']} is not the "
                f"Wilson interval for {successes}/{n} ({low:.6f}-{high:.6f})"
            )
    return successes, problems


def _worst_scored(groups: dict[str, dict[str, Any]], skip: str | None = None) -> float:
    return max(
        (
            float(m["value"])
            for attribute, values in groups.items()
            if attribute != skip
            for m in values.values()
            if not m.get("insufficient_sample")
        ),
        default=0.0,
    )


# Test type -> (headline rate metric, the attribute holding its conditions, threshold
# name -> how its observed value follows from the reported measurements). Per-group
# limits are named <metric>.max_per_group, as accuracy_by_group names them, whatever
# the plan's key: the console reads that name to find the groups.
_RECOMPUTED: dict[str, tuple[str, str, dict[str, Any]]] = {
    "adversarial_robustness": (
        "attack_success_rate",
        "attack",
        {
            "max_attack_success_rate": lambda r: r["metrics"]["attack_success_rate"]["value"],
            "max_attack_success_rate_ci_high": lambda r: r["metrics"]["attack_success_rate"].get(
                "ci_high", 1.0
            ),
            "attack_success_rate.max_per_group": lambda r: _worst_scored(
                r.get("by_group", {}).get("attack_success_rate", {}), skip="attack"
            ),
        },
    ),
    "fail_safe": (
        "approval_rate",
        "input_kind",
        {
            "max_approval_rate": lambda r: r["metrics"]["approval_rate"]["value"],
            "approval_rate.max_per_group": lambda r: _worst_scored(
                r.get("by_group", {}).get("approval_rate", {})
            ),
            "max_mean_confidence": lambda r: r["metrics"]["mean_confidence"]["value"],
        },
    ),
}


def recompute_observed(result: dict[str, Any]) -> list[str]:
    """For the test types whose thresholds are functions of their reported rates,
    derive every ``observed`` again from the measurements, and check the rates are
    counts that add up, rather than taking the harness's word for either.

    Adversarial robustness: the headline rate is the union across attacks, so it can
    be no lower than any one attack's rate and no higher than their sum, and the
    per-group counts must add up to it. Fail-safe: the per-kind counts must add up
    to the overall approval rate.
    """
    kind = result.get("type")
    if kind not in _RECOMPUTED:
        return []
    metric, conditions_attribute, observed_from = _RECOMPUTED[kind]
    problems: list[str] = []
    headline = (result.get("metrics") or {}).get(metric)
    if headline is None:
        return [f"reports no {metric}, which its thresholds are computed from"]

    total, found = _wilson_problems(metric, headline)
    problems += found
    groups = (result.get("by_group") or {}).get(metric, {})
    for attribute, values in groups.items():
        counts = []
        for value, measurement in values.items():
            successes, found = _wilson_problems(f"{metric}[{attribute}={value}]", measurement)
            problems += found
            counts.append((successes or 0, int(measurement.get("n", 0))))
        if not counts or total is None:
            continue
        if attribute == conditions_attribute and kind == "adversarial_robustness":
            largest = max(s for s, _ in counts)
            if not largest <= total <= sum(s for s, _ in counts):
                problems.append(
                    f"{metric} counts {total} items broken, but the attacks broke "
                    f"{sorted(s for s, _ in counts)}; a union lies between the largest and the sum"
                )
        elif sum(s for s, _ in counts) != total or sum(n for _, n in counts) != headline["n"]:
            problems.append(
                f"{metric} by {attribute} adds up to {sum(s for s, _ in counts)}/"
                f"{sum(n for _, n in counts)}, not the {total}/{headline['n']} reported overall"
            )

    for evaluation in result.get("thresholds_evaluated", []):
        derive = observed_from.get(evaluation["name"])
        if derive is None:
            problems.append(f"threshold {evaluation['name']!r} is not one this test type sets")
            continue
        try:
            expected = float(derive(result))
        except KeyError as missing:
            problems.append(f"threshold {evaluation['name']!r}: no {missing} to compute it from")
            continue
        if abs(expected - float(evaluation["observed"])) > _ROUNDING:
            problems.append(
                f"threshold {evaluation['name']!r} states observed {evaluation['observed']}, "
                f"but the reported measurements give {expected:.6f}"
            )
    return problems


def check_thresholds(statements: list[dict[str, Any]]) -> CheckResult:
    question = "does every stated outcome follow from the numbers reported with it?"
    problems = []
    for statement in statements:
        predicate = statement["predicate"]
        run = predicate["run_number"]
        for result in predicate["results"]:
            problems += [
                f"run {run} {result['test_id']}: {problem}"
                for problem in recompute_observed(result)
            ]
            evaluations = result.get("thresholds_evaluated", [])
            for evaluation in evaluations:
                compare = COMPARISONS.get(evaluation["comparison"])
                if compare is None:
                    problems.append(
                        f"run {run} {result['test_id']}: unknown comparison "
                        f"{evaluation['comparison']!r}"
                    )
                    continue
                recomputed = compare(float(evaluation["observed"]), float(evaluation["limit"]))
                if recomputed != bool(evaluation["held"]):
                    problems.append(
                        f"run {run} {result['test_id']} {evaluation['name']}: bundle says "
                        f"held={evaluation['held']} but {evaluation['observed']} "
                        f"{evaluation['comparison']} {evaluation['limit']} is {recomputed}"
                    )
            if evaluations:
                expected = "pass" if all(e["held"] for e in evaluations) else "fail"
                if result["outcome"] != expected:
                    problems.append(
                        f"run {run} {result['test_id']}: outcome is {result['outcome']!r} but its "
                        f"thresholds imply {expected!r}"
                    )
        test_outcomes = {r["outcome"] for r in predicate["results"]}
        if predicate["outcome"] == "pass" and "fail" in test_outcomes:
            problems.append(f"run {run}: reported pass with at least one failing test")

    if problems:
        return CheckResult("thresholds", question, FAIL, "; ".join(problems[:5]))
    return CheckResult("thresholds", question, PASS, "recomputed and consistent")


def check_sample_sizes(statements: list[dict[str, Any]]) -> CheckResult:
    """A check on the evidence's strength, not its integrity. A pass on a group of
    four items is arithmetically correct and evidentially worthless, and the verifier is the last
    place anyone looks before relying on the number."""
    question = "were any thresholds passed on samples too small to mean anything?"
    thin = []
    for statement in statements:
        predicate = statement["predicate"]
        run = predicate["run_number"]
        for result in predicate["results"]:
            for metric, attributes in (result.get("by_group") or {}).items():
                for attribute, values in attributes.items():
                    for value, measurement in values.items():
                        if measurement.get("insufficient_sample"):
                            thin.append(
                                f"run {run} {result['test_id']} {metric} "
                                f"{attribute}={value} (n={measurement['n']})"
                            )
    if thin:
        return CheckResult(
            "sample_sizes",
            question,
            WARN,
            f"{len(thin)} group(s) fell below the plan's minimum and were not scored: "
            + ", ".join(thin[:5]),
        )
    return CheckResult("sample_sizes", question, PASS, "every scored group met the plan's minimum")


# --- 7. deletion ------------------------------------------------------------


def check_deletion(entries: list[dict[str, Any]]) -> CheckResult:
    question = "were keys destroyed after exit?"
    # An exit the gate allowed; a refused request to exit is not an exit.
    exits = [
        e
        for e in entries
        if e["entry_type"] == "gate_decision"
        and e["body"].get("action") == "exit"
        and e["body"].get("allow") is True
    ]
    destroyed = [e for e in entries if e["entry_type"] == "keys_destroyed"]

    if not exits:
        if destroyed:
            return CheckResult(
                "deletion", question, FAIL, "keys were destroyed but no exit was recorded"
            )
        return CheckResult(
            "deletion", question, WARN, "the participation has not exited; deletion is not yet due"
        )
    if not destroyed:
        return CheckResult(
            "deletion",
            question,
            FAIL,
            "exit was recorded but no keys_destroyed entry followed: "
            "Art. 59(1)(g) deletion is unproven",
        )
    if min(int(e["seq"]) for e in destroyed) < min(int(e["seq"]) for e in exits):
        return CheckResult(
            "deletion", question, FAIL, "keys were destroyed before exit was requested"
        )
    scopes = sorted({s for e in destroyed for s in e["body"].get("key_scopes", [])})
    return CheckResult("deletion", question, PASS, f"keys destroyed after exit: {scopes}")


def check_completeness(
    bundle: Bundle, entries: list[dict[str, Any]], anchored: bool, in_progress: bool
) -> CheckResult:
    """Does the ledger end the way a participation that has ended does?

    The hash chain and the timestamps say nothing about the end of the ledger: cut
    after any entry, what is left is intact. So the end is checked for what an ended
    participation must have written, in order: the regulator's exit, the keys'
    destruction, the exit report, and the regulator's signature over it. And the last
    ``report_generated`` entry names the digest of the bundle as it was when the report
    was generated, which is recomputed here: every file as it is now, the ledger up to
    the entry before. A bundle cut short, or with files changed since the report,
    shows. Missing ends warn, and fail when you gave any anchor, unless you said the
    participation is still in progress (``--in-progress``).
    """
    question = "does the ledger end as a participation that has ended does?"
    last = entries[-1] if entries else {"seq": 0, "entry_type": "nothing"}
    exits = [
        int(e["seq"])
        for e in entries
        if e["entry_type"] == "gate_decision"
        and e["body"].get("action") == "exit"
        and e["body"].get("allow")
    ]
    destroyed = [int(e["seq"]) for e in entries if e["entry_type"] == "keys_destroyed"]
    reports = [e for e in entries if e["entry_type"] == "report_generated"]
    missing = []
    if not exits:
        missing.append("the regulator's exit")
    if not [s for s in destroyed if exits and s > exits[0]]:
        missing.append("the keys' destruction after it")
    if not [r for r in reports if destroyed and int(r["seq"]) > destroyed[0]]:
        missing.append("an exit report after that")
    if reports:
        report = reports[-1]
        latest = report["body"].get("report_sha256")
        signed = [
            e
            for e in entries
            if e["entry_type"] == "report_signature"
            and e["body"].get("report_sha256") == latest
            and e["body"].get("party") == "regulator"
            and int(e["seq"]) > int(report["seq"])
        ]
        if not signed:
            missing.append("the regulator's signature over the last report")
        index = entries.index(report)
        then = bundle.digest(ledger_lines=index)
        if report["body"].get("bundle_digest") != then:
            return CheckResult(
                "completeness",
                question,
                FAIL,
                f"the report at seq {report['seq']} was generated over bundle "
                f"{str(report['body'].get('bundle_digest'))[:19]}…, but this bundle, up to the "
                f"entry before it, is {then[:19]}…: files were changed after the report",
            )
    if not missing:
        return CheckResult(
            "completeness",
            question,
            PASS,
            f"exit, keys destroyed, the report and the regulator's signature over it, and "
            f"the report's bundle digest matches this bundle up to seq {reports[-1]['seq'] - 1}",
        )
    detail = (
        f"INCOMPLETE: the ledger ends at seq {last['seq']} ({last['entry_type']}) without "
        f"{', '.join(missing)}. Either the participation has not ended, or the ledger was "
        "cut short and nothing inside it can show that"
    )
    if in_progress:
        return CheckResult(
            "completeness",
            question,
            WARN,
            detail + "; you said it is in progress. What shows it was not cut is a head you "
            "hold from outside the bundle (--expect-head, --checkpoint)",
        )
    return CheckResult("completeness", question, FAIL if anchored else WARN, detail)


# --- 8. timestamps ----------------------------------------------------------


# How far the time an authority signed may lie from the entry's ``recorded_at``. The
# ledger writes ``recorded_at`` and then asks the authority for a token before the entry
# is stored (ledger.store.Ledger._append), so the two differ by the round trip and the
# two clocks' skew. Ten minutes allows a slow authority and a badly set clock; it does
# not allow an entry written, or a ledger rebuilt, at another time than it claims.
RECORDED_AT_TOLERANCE = datetime.timedelta(minutes=10)
# How far one entry's signed time may lie before the previous entry's. One authority's
# clock only moves forward; two authorities (a failover) may disagree by a second or so.
ORDER_TOLERANCE = datetime.timedelta(seconds=5)
# How long before the entry recording it an IdP login may have been made. A console
# records a signature within seconds of the login; an hour is generous, and a login
# older than that is not the act the entry records.
LOGIN_BEFORE_RECORDING = datetime.timedelta(hours=1)


def _instant(value: Any) -> datetime.datetime | None:
    """An ISO 8601 time, as the ledger and the tokens write it, or None."""
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=datetime.UTC)


def _stamp(value: datetime.datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def signed_time_problem(
    entry: dict[str, Any],
    stated: Any,
    signed: Any,
    previous: datetime.datetime | None,
) -> str | None:
    """The genTime rules for one stamped entry, or None when it keeps them.

    ``stated`` is the ``timestamp`` written beside the token (outside its signature),
    ``signed`` the time the authority signed (an RFC 3161 ``genTime``, a development
    token's signed ``timestamp``), ``previous`` the latest signed time of the entries
    before it. The stated time must be the signed one; the signed time must lie within
    :data:`RECORDED_AT_TOLERANCE` of the entry's ``recorded_at``, and not before
    ``previous`` by more than :data:`ORDER_TOLERANCE`. One implementation, used by
    :func:`check_timestamps` and by ``histor ledger verify-db``
    (:func:`histor.ledger.tools.verify`)."""
    where = f"entry {entry.get('seq')} ({entry.get('entry_type')})"
    signed_at, stated_at = _instant(signed), _instant(stated)
    recorded = _instant(entry.get("recorded_at"))
    if signed_at is None or recorded is None or stated_at is None:
        return f"{where}: its times do not parse"
    if stated_at != signed_at:
        return (
            f"{where} states it was stamped at {stated}, but the authority signed "
            f"{_stamp(signed_at)}: the stated time is not the authority's"
        )
    if abs(signed_at - recorded) > RECORDED_AT_TOLERANCE:
        return (
            f"{where} says it was recorded at {entry.get('recorded_at')}, but the authority "
            f"stamped it at {_stamp(signed_at)}, more than "
            f"{int(RECORDED_AT_TOLERANCE.total_seconds() // 60)} minutes apart: it was "
            "written, or the ledger rebuilt, at another time than it says"
        )
    if previous is not None and signed_at < previous - ORDER_TOLERANCE:
        return (
            f"{where} was stamped at {_stamp(signed_at)}, before the entry preceding it "
            f"({_stamp(previous)}): the chain was not stamped in its order"
        )
    return None


def check_timestamps(entries: list[dict[str, Any]], public_keys: dict[str, str]) -> CheckResult:
    """Every entry stamped, over its own hash, by a token that verifies; and the time
    each token *signs* (an RFC 3161 token's ``genTime``, a development token's signed
    ``timestamp``) is the one that counts. The ``timestamp`` field beside the token is
    written by whoever assembled the bundle, so it must equal the signed time, the
    signed times must not go backwards along the chain (by more than
    :data:`ORDER_TOLERANCE`), and each must be within :data:`RECORDED_AT_TOLERANCE` of
    the entry's ``recorded_at``. A ledger rebuilt later and stamped afresh carries the
    later times, whatever its JSON says."""
    question = "are the timestamps valid, ordered, and external?"
    stamped = [e for e in entries if e.get("timestamp")]
    if not stamped:
        return CheckResult(
            "timestamps",
            question,
            FAIL,
            "no ledger entry carries a timestamp: the chain proves ordering but nothing "
            "anchors it to a clock",
        )

    # A token covers its entry's hash, but the hash does not cover the token: deleting
    # a token leaves the chain intact. So the rule is whole-ledger. A ledger is stamped
    # from its first entry to its last or not at all, and one unstamped entry among
    # stamped ones is a token removed, or an entry written around the authority.
    unstamped = [e for e in entries if not e.get("timestamp")]
    if unstamped:
        first = unstamped[0]
        return CheckResult(
            "timestamps",
            question,
            FAIL,
            f"{len(unstamped)} of {len(entries)} ledger entries carry no timestamp, the "
            f"first at entry {first['seq']} ({first['entry_type']}): in a stamped ledger "
            "every entry is stamped, so a token was removed or the entry was written "
            "around the timestamp authority",
        )

    kinds = set()
    anchors: set[str] = set()
    previous: datetime.datetime | None = None
    earliest: datetime.datetime | None = None
    for entry in stamped:
        token = parse_timestamp(entry["timestamp"])
        kinds.add(token.kind)
        if token.digest != entry["entry_hash"]:
            return CheckResult(
                "timestamps",
                question,
                FAIL,
                f"entry {entry['seq']} is timestamped over {token.digest[:19]}… but hashes to "
                f"{entry['entry_hash'][:19]}…",
            )
        try:
            attested = verify_token(entry["timestamp"], public_keys)
            if token.kind == "rfc3161":
                anchors.add(f"{token.authority} (root sha256:{attested['root_sha256'][:16]}…)")
        except (signing.VerificationError, NotImplementedError) as error:
            return CheckResult(
                "timestamps", question, FAIL, f"entry {entry['seq']} timestamp: {error}"
            )
        if token.kind == "dev" and attested.get("digest") != entry["entry_hash"]:
            # An RFC 3161 token's imprint is checked against its entry by
            # verify_rfc3161; a development token's signed digest is checked here.
            return CheckResult(
                "timestamps",
                question,
                FAIL,
                f"entry {entry['seq']}'s development timestamp signs "
                f"{str(attested.get('digest'))[:19]}…, not the entry's hash: it was issued "
                "over another entry",
            )
        signed_text = attested.get("time") if token.kind == "rfc3161" else attested.get("timestamp")
        problem = signed_time_problem(entry, token.timestamp, signed_text, previous)
        if problem:
            return CheckResult("timestamps", question, FAIL, problem)
        signed = _instant(signed_text) or datetime.datetime.min.replace(tzinfo=datetime.UTC)
        previous = signed if previous is None else max(previous, signed)
        earliest = earliest or signed

    if kinds == {"dev"}:
        return CheckResult(
            "timestamps",
            question,
            WARN,
            "every timestamp was issued by the sandbox operator's own development "
            "authority, not by a third party. The ordering is self-consistent and "
            "anchors nothing: an operator able to rebuild this ledger could reissue "
            "these timestamps with it.",
        )
    if kinds == {"rfc3161"}:
        span = f"{_stamp(earliest)} to {_stamp(previous)}" if earliest and previous else "?"
        return CheckResult(
            "timestamps",
            question,
            PASS,
            f"{len(stamped)} RFC 3161 timestamps from {', '.join(sorted(anchors))}, stamped "
            f"from {span} in chain order, each signed over its entry's hash within "
            f"{int(RECORDED_AT_TOLERANCE.total_seconds() // 60)} minutes of its recorded_at "
            "and chained to the pinned root",
        )
    return CheckResult(
        "timestamps",
        question,
        WARN,
        f"{len(stamped)} timestamps of mixed kinds {sorted(kinds)}: the development ones "
        "anchor nothing",
    )


def check_tsa_revocation(
    entries: list[dict[str, Any]], public_keys: dict[str, str], tsa_roots: tuple[str, ...]
) -> CheckResult:
    """Was the authority's certificate unrevoked when each token was stamped?

    The stamping code keeps the CA's answer beside each token (an OCSP response or a
    CRL, ``token["revocation"]``), fetched when it stamped. It is checked here offline:
    signed by the issuer in the token's own chain (or a responder it delegated to),
    about the signer certificate, current at the stamped time, and not saying revoked.
    A token without it warns: nothing shows the certificate was good then."""
    from histor.crypto.timestamps import TSA_ROOT_PREFIX, revocation_problem, verify_rfc3161

    question = "was the timestamp authority's certificate unrevoked when it stamped?"
    roots = list(tsa_roots) or [
        pem for key, pem in public_keys.items() if key.startswith(TSA_ROOT_PREFIX)
    ]
    tokens = [
        e for e in entries if isinstance(e.get("timestamp"), dict) and e["timestamp"].get("kind")
    ]
    external = [e for e in tokens if e["timestamp"]["kind"] == "rfc3161"]
    if not external:
        return CheckResult(
            "tsa_revocation",
            question,
            WARN,
            "no RFC 3161 timestamp in this ledger, so no authority certificate whose "
            "revocation could be checked: development timestamps carry none",
        )
    missing: list[int] = []
    kinds: set[str] = set()
    for entry in external:
        timestamp = entry["timestamp"]
        evidence = (timestamp.get("token") or {}).get("revocation")
        if evidence is None:
            missing.append(int(entry["seq"]))
            continue
        try:
            attested = verify_rfc3161(
                base64.b64decode(timestamp["token"]["der"]), timestamp["digest"], roots
            )
        except (signing.VerificationError, KeyError, TypeError, ValueError):
            continue  # timestamps (or anchor_tsa_root) says what is wrong with the token
        at = _instant(attested["time"])
        problem = (
            revocation_problem(evidence, attested["chain_der"], at)
            if at is not None
            else "its time does not parse"
        )
        if problem is not None:
            return CheckResult(
                "tsa_revocation",
                question,
                FAIL,
                f"entry {entry['seq']} ({entry['entry_type']}): {problem}",
            )
        kinds.add(str(evidence.get("kind")).upper())
    checked = len(external) - len(missing)
    if missing:
        return CheckResult(
            "tsa_revocation",
            question,
            WARN,
            f"{len(missing)} of {len(external)} RFC 3161 timestamps carry no revocation "
            f"evidence (the first at entry {missing[0]}): nothing shows the authority's "
            "certificate had not been revoked when it stamped them"
            + (
                f"; the other {checked} show it good ({', '.join(sorted(kinds))})"
                if checked
                else ""
            ),
        )
    return CheckResult(
        "tsa_revocation",
        question,
        PASS,
        f"each of {checked} RFC 3161 timestamps carries the CA's answer "
        f"({', '.join(sorted(kinds))}), signed by the authority certificate's issuer, "
        "current when it stamped, and not revoked",
    )


# --- 9. who signed the plan -----------------------------------------------


def _login_time_problems(entry: dict[str, Any]) -> list[str]:
    """Whether the IdP login behind a signature is of the time its entry was recorded.

    The token's ``iat`` is signed by the IdP; ``recorded_at`` is held to the
    timestamp authority's time (``timestamps``). A login from long before, or one dated
    after the entry that records it, is not the act the entry records: an old login
    replayed into a rebuilt ledger, for one."""
    from histor.identity import jose

    recorded = _instant(entry.get("recorded_at"))
    try:
        issued = int(jose.parse(str(entry["body"]["id_token"])).claims["iat"])
    except (KeyError, TypeError, ValueError, jose.JoseError):
        return []  # signature.verify says what is wrong with the token
    if recorded is None:
        return []
    login = datetime.datetime.fromtimestamp(issued, datetime.UTC)
    if login > recorded + RECORDED_AT_TOLERANCE:
        return [f"the login is dated {_stamp(login)}, after the entry that records it"]
    if login < recorded - LOGIN_BEFORE_RECORDING:
        return [
            f"the login was at {_stamp(login)}, more than an hour before the entry that "
            f"records it ({entry.get('recorded_at')})"
        ]
    return []


# The parties whose agreement a plan needs (Art. 57(5)), and who signs the report.
SIGNING_PARTIES = ("provider", "regulator")


def _claims(body: dict[str, Any]) -> dict[str, Any]:
    """The claims of a recorded ID token; empty if it does not parse (``signature.verify``
    says so)."""
    from histor.identity import jose

    try:
        return dict(jose.parse(str(body["id_token"])).claims)
    except (KeyError, TypeError, jose.JoseError):
        return {}


def _names(member: Any, claims: dict[str, Any]) -> bool:
    """Does a person the plan's ``roles`` block names match a verified token?

    The forms ``gate.rbac.member_matches`` accepts, matched against the token's own
    claims and never the record's: a bare email against ``email``; an object with an
    ``issuer`` against ``iss`` (the IdP's URL, since the name a console gave an IdP is
    not in the token), then ``subject`` against ``sub`` or Entra's ``oid``, or
    ``email`` against ``email``.
    """
    email = str(claims.get("email") or "").lower()
    if isinstance(member, str):
        return bool(email) and member.lower() == email
    if not isinstance(member, dict):
        return False
    issuer = member.get("issuer")
    if issuer and str(issuer).rstrip("/") != str(claims.get("iss", "")).rstrip("/"):
        return False
    if member.get("subject") is not None:
        return member["subject"] in {claims.get("sub"), claims.get("oid")}
    if member.get("email") is not None:
        return bool(email) and str(member["email"]).lower() == email
    return False


def _describe(member: Any) -> str:
    """A plan member as a person would read it (as ``gate.rbac.describe``)."""
    if isinstance(member, dict):
        who = member.get("email") or member.get("subject") or "?"
        return f"{who} via {member['issuer']}" if member.get("issuer") else str(who)
    return str(member)


def _party_problems(
    body: dict[str, Any], plan: dict[str, Any] | None, anchors: Anchors
) -> tuple[list[str], list[str]]:
    """Whether a signature is the party's it is recorded as: what is wrong, and what
    binds it only weakly.

    ``party`` is a field of the ledger entry, which the operator writes. What says
    who signed is the token: its ``iss`` with its ``sub`` or ``email``, which must
    match someone the signed plan names in ``roles`` for that party. And the token
    must have been issued to the audience you hold (``--expect-audience``), so a login
    to some other application cannot be recorded as a signature.

    A party the plan names by email only binds weakly: that warns, and fails when you
    gave any anchor unless the plan pins the IdP (``{issuer, email}``) and the token
    says the email was verified (``email_verified: true``).
    """
    from histor.identity import jose
    from histor.identity import signature as signature_module

    anchored = bool(anchors.external())
    claims = _claims(body)
    party = body.get("party")
    who = f"{claims.get('email') or claims.get('sub')} at {claims.get('iss')}"
    problems: list[str] = []
    weak: list[str] = []
    if anchors.audience:
        try:
            jose.check_audience(claims, anchors.audience)
        except jose.JoseError as error:
            problems.append(f"the login was not to the application you hold: {error}")
    if party not in SIGNING_PARTIES:
        return [*problems, f"it is recorded as signed by {party!r}, not a party to the plan"], []
    roles = (plan or {}).get("roles")
    members = (roles.get(party) if isinstance(roles, dict) else None) or []
    matched = [m for m in members if _names(m, claims)]
    if plan is None:
        problems.append(
            f"the plan it signs is not in the bundle, so nothing says who the {party} is"
        )
    elif not members:
        problems.append(f"the plan names nobody as the {party}, so nothing binds {who} to it")
    elif not matched:
        problems.append(
            f"{who} signed as the {party}, but the plan names "
            f"{', '.join(_describe(m) for m in members)} as the {party}"
        )
    elif named := [
        str(a)
        for m in matched
        if isinstance(m, dict) and m.get("audience")
        for a in (m["audience"] if isinstance(m["audience"], list) else [m["audience"]])
    ]:
        # The plan, which both parties signed, names the console's client id at this
        # party's IdP: the login must be to it, with or without --expect-audience.
        try:
            jose.check_audience(claims, tuple(named))
        except jose.JoseError as error:
            problems.append(f"the login was not to the application the plan names: {error}")
    if (
        matched
        and not problems
        and not any(isinstance(m, dict) and m.get("subject") is not None for m in matched)
    ):
        # Named by email only. An email is an IdP's assertion about an address, which
        # it may not have checked, and which any IdP whose key is accepted can make
        # unless the plan pins the issuer. The stable binding is iss + sub.
        pinned = any(isinstance(m, dict) and m.get("issuer") for m in matched)
        verified = claims.get("email_verified") is True
        development = str(claims.get("iss", "")).rstrip("/") == signature_module.DEV_ISSUER
        lacking = [
            *([] if pinned else ["the plan does not pin the IdP (issuer)"]),
            *([] if verified else ["the token does not say the email was verified"]),
        ]
        said = (
            f"the plan names the {party} ({claims.get('email')}) by email only, not by "
            "issuer and subject"
        )
        if lacking and anchored and not development:
            # The development IdP's signatures are said to identify nobody already.
            problems.append(f"{said}, and {' and '.join(lacking)}")
        else:
            weak.append(
                f"{said}" + (f" ({'; '.join(lacking)})" if lacking else "") + ": an email can "
                "be reassigned, and only a subject is the IdP's stable name for a person; "
                "name them as {issuer: <iss>, subject: <sub>}"
            )
    return problems, weak


def _principal(body: dict[str, Any]) -> tuple[str, str]:
    claims = _claims(body)
    return str(claims.get("iss", "")).rstrip("/"), str(claims.get("sub", ""))


def _signed_digests(digest: str, plans: dict[str, dict[str, Any]], earlier: list[str]) -> list[str]:
    """The digests the parties may have signed for the plan filed as ``digest``: the
    plan without its signatures (``sandbox.plan.unsigned_digest``); and, as bundles
    before 0.3 signed an amendment, the plan with an earlier version's signatures
    still in it."""
    from histor.plan import unsigned_digest

    plan = plans.get(digest)
    if plan is None:
        return []
    unsigned = {key: value for key, value in plan.items() if key != "signatures"}
    candidates = [unsigned_digest(plan)]
    for previous in earlier:
        signatures = (plans.get(previous) or {}).get("signatures")
        if signatures is not None:
            candidates.append(plan_digest({**unsigned, "signatures": signatures}))
    return candidates


def _recorded_signature_problems(
    entry: dict[str, Any],
    recorded: list[dict[str, Any]],
    public_keys: dict[str, str],
    signed_digests: list[str],
) -> list[str]:
    """What is wrong with the ``signatures`` a ``plan_signed`` entry records, for a plan
    not signed through the parties' IdPs.

    Two forms are written. The demo scripts sign the digest in the plan file with each
    party's key (``{"provider": "<base64 sig>", ...}``): each must verify, as a DSSE
    signature over ``{"plan_digest": <digest>}``, under that party's key. The gate's
    record of IdP signatures (``{"provider": {"seq": n, ...}, ...}``) must name
    ``plan_signature`` entries by that party over this digest.
    """
    digest = str(entry["body"].get("plan_digest"))
    signatures = entry["body"].get("signatures")
    if not isinstance(signatures, dict) or not signatures:
        return ["it carries no signature"]
    payloads = [
        json.dumps({"plan_digest": d}, sort_keys=True, separators=(",", ":"))
        for d in signed_digests
    ]
    problems = []
    for party in SIGNING_PARTIES:
        value = signatures.get(party)
        if isinstance(value, dict):
            named = [
                e
                for e in recorded
                if e["seq"] == value.get("seq")
                and e["body"].get("party") == party
                and e["body"].get("plan_digest") == digest
            ]
            if not named:
                problems.append(f"the {party}'s signature it names is not in the ledger")
            continue
        if not isinstance(value, str) or not value:
            problems.append(f"it carries no signature by the {party}")
            continue
        key = {party: public_keys[party]} if party in public_keys else {}
        if not any(_verifies(payload, party, value, key) for payload in payloads):
            problems.append(
                f"the {party}'s signature does not verify under the {party}'s key over the "
                "plan it is recorded for"
            )
    return problems


def _verifies(payload: str, key_id: str, sig: str, key: dict[str, str]) -> bool:
    envelope = {
        "payloadType": signing.PAYLOAD_TYPE,
        "payload": base64.b64encode(payload.encode()).decode(),
        "signatures": [{"keyid": key_id, "sig": sig}],
    }
    try:
        signing.verify(envelope, key)
    except signing.VerificationError:
        return False
    return True


def check_plan_signatures(
    entries: list[dict[str, Any]],
    plans: dict[str, dict[str, Any]] | None = None,
    anchors: Anchors | None = None,
    public_keys: dict[str, str] | None = None,
    statements: list[dict[str, Any]] | None = None,
) -> CheckResult:
    """Was the plan agreed by the people the plan names for each party?

    A signature made through the console is an ID token from the signer's own IdP
    whose nonce commits to the plan digest (`histor.identity.signature`). Each is checked
    here from the token alone: its signature against the recorded key, the nonce
    against the digest, the issuer and subject against the record, and the freshness
    of the login. Then who signed: the token's issuer and subject or email must be
    someone the plan it signs names for the party the entry says, and the provider's
    and the regulator's signatures must be different people. What cannot be checked
    offline is that the recorded key was the IdP's; that rests on the console having
    fetched it from the IdP, and on ``--idp-keys``.
    """
    from histor.identity import signature

    anchors = anchors or Anchors()
    # Without plans (a caller checking the tokens alone), who signed is not checked.
    question = "was the plan signed by each party, through their own identity provider?"
    recorded = [e for e in entries if e["entry_type"] == "plan_signature"]
    weak: list[str] = []
    for entry in recorded:
        body = entry["body"]
        problems = signature.verify(body) + _login_time_problems(entry)
        if not problems and plans is not None:
            found, loose = _party_problems(body, plans.get(str(body.get("plan_digest"))), anchors)
            problems += found
            weak += [w for w in loose if w not in weak]
        if problems:
            return CheckResult(
                "plan_signatures",
                question,
                FAIL,
                f"entry {entry['seq']} ({body.get('party')}): {'; '.join(problems)}",
            )
    for digest in sorted({str(e["body"].get("plan_digest")) for e in recorded}):
        by_party = {
            party: {
                _principal(e["body"])
                for e in recorded
                if e["body"].get("party") == party and e["body"].get("plan_digest") == digest
            }
            for party in SIGNING_PARTIES
        }
        if by_party["provider"] & by_party["regulator"]:
            return CheckResult(
                "plan_signatures",
                question,
                FAIL,
                f"plan {digest[:19]}… is signed for the provider and for the regulator by the "
                "same person: one login is not two parties' agreement",
            )
    # Every version put in force carries the signatures the first one did, whatever its
    # plan_signed entry says about its method (the operator writes that field): an
    # amendment is agreed by both parties as the original was (Art. 57(5)).
    signings = [e for e in entries if e["entry_type"] == "plan_signed"]
    by_idp: list[bool] = []
    for entry in signings:
        digest = str(entry["body"].get("plan_digest"))
        parties = {
            e["body"].get("party")
            for e in recorded
            if e["body"].get("plan_digest") == digest and int(e["seq"]) < int(entry["seq"])
        }
        missing = sorted(set(SIGNING_PARTIES) - parties)
        by_idp.append(not missing)
        if not missing:
            continue
        where = f"plan {digest[:19]}… (seq {entry['seq']})"
        if by_idp[0] or entry["body"].get("method") == "idp" or anchors.idp_keys:
            because = (
                ", as the original plan was"
                if by_idp[0] and len(by_idp) > 1
                else "; you gave IdP keys"
                if anchors.idp_keys
                else ""
            )
            return CheckResult(
                "plan_signatures",
                question,
                FAIL,
                f"{where} was put in force without a signature by {missing} through their "
                f"identity provider{because}",
            )
        earlier = [str(e["body"].get("plan_digest")) for e in signings[: len(by_idp) - 1]]
        problems = _recorded_signature_problems(
            entry, recorded, public_keys or {}, _signed_digests(digest, plans or {}, earlier)
        )
        if problems:
            return CheckResult(
                "plan_signatures",
                question,
                FAIL,
                f"{where} is recorded as signed, but {'; '.join(problems)}",
            )
    in_force = {str(e["body"].get("plan_digest")): int(e["seq"]) for e in reversed(signings)}
    for statement in statements or []:
        predicate = statement.get("predicate") or {}
        cited = str(predicate.get("plan_digest"))
        run: Any = predicate.get("run_number")
        # The run began when the gate started it; a plan put in force while it was
        # under way did not govern it. A bundle with no run_started (before the gate
        # recorded it) is held to the attestation.
        began = [int(e["seq"]) for e in _of_run(entries, "run_started", run)] or [
            int(e["seq"]) for e in _of_run(entries, "run_attestation", run)
        ]
        if cited not in in_force or (began and in_force[cited] > min(began)):
            return CheckResult(
                "plan_signatures",
                question,
                FAIL,
                f"run {run} was judged under plan {cited[:19]}…, which the ledger does not "
                "record as signed before the run started",
            )
    if not recorded:
        return CheckResult(
            "plan_signatures",
            question,
            WARN,
            "the plan was signed with keys the sandbox holds, not through the parties' "
            "identity providers: the bundle shows that the sandbox signed it, not who "
            "agreed to it",
        )
    development = [e for e in recorded if signature.is_development(e["body"])]
    if development:
        return CheckResult(
            "plan_signatures",
            question,
            WARN,
            f"{len(development)} of {len(recorded)} signature(s) came from the development "
            "IdP, which issues a token for anyone: they identify nobody",
        )
    idps = sorted({str(e["body"].get("idp")) for e in recorded})
    detail = (
        f"{len(recorded)} signature(s) via {idps} verify, commit to the plan digest and are "
        "by the people the plan names for each party; that each key was its IdP's rests on "
        "the console's fetch of the IdP's key set"
    )
    if not anchors.audience:
        detail += (
            "; the audience each login was for was not checked against one you hold "
            "(--expect-audience)"
        )
    if weak:
        return CheckResult("plan_signatures", question, WARN, detail + ". But " + "; ".join(weak))
    return CheckResult("plan_signatures", question, PASS, detail)


# --- 10. who signed the report ----------------------------------------------


def _plan_in_force(
    entries: list[dict[str, Any]], plans: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    """The plan version the last ``plan_signed`` entry put in force."""
    signed = [
        str(e["body"].get("plan_digest")) for e in entries if e["entry_type"] == "plan_signed"
    ]
    return plans.get(signed[-1]) if signed else None


def _report_head_problems(entry: dict[str, Any], entries: list[dict[str, Any]]) -> list[str]:
    """Whether the ledger head a report signature commits to is in this ledger, before
    the signature and at or after the report it signs.

    The IdP's signature covers the head (``histor.identity.signature``); the head's hash
    covers every entry before it. So a ledger rewritten or cut before that point, the
    ``report_generated`` entry and its bundle digest included, no longer holds the
    entry the regulator signed over."""
    head = entry["body"].get("ledger_head")
    if head is None:
        return []
    seq, hash_ = head.get("seq"), head.get("entry_hash")
    at = next((e for e in entries if e["seq"] == seq), None)
    if at is None or at["entry_hash"] != hash_:
        return [
            f"the regulator signed over the ledger as it stood at seq {seq} "
            f"({str(hash_)[:19]}…), and this ledger holds another entry there, or none: it "
            "is not the ledger the regulator signed"
        ]
    if int(seq) >= int(entry["seq"]):
        return [f"the ledger head it commits to, seq {seq}, is not before the signature"]
    report = entry["body"].get("report_sha256")
    generated = [
        int(e["seq"])
        for e in entries
        if e["entry_type"] == "report_generated"
        and e["body"].get("report_sha256") == report
        and int(e["seq"]) < int(entry["seq"])
    ]
    if generated and int(seq) < max(generated):
        return [
            f"the ledger head it commits to, seq {seq}, precedes the report it signs "
            f"(seq {max(generated)})"
        ]
    return []


def check_report_signature(
    entries: list[dict[str, Any]],
    plans: dict[str, dict[str, Any]] | None = None,
    anchors: Anchors | None = None,
) -> CheckResult:
    """Did the regulator sign the report the ledger says was generated?

    Art. 57(7). The signature is checked as a plan signature is, from the token
    alone, with the nonce recomputed over the report's sha256 under the report's own
    domain, and the signer must be someone the plan in force names as the regulator.
    The report file is not in the bundle; its hash is, in the ``report_generated``
    entry, and anyone holding the report can hash it and compare.
    """
    from histor.identity import signature

    anchors = anchors or Anchors()
    plan = _plan_in_force(entries, plans) if plans is not None else None
    question = "was the exit report signed by the regulator, through their own identity provider?"
    reports = [e for e in entries if e["entry_type"] == "report_generated"]
    recorded = [e for e in entries if e["entry_type"] == "report_signature"]
    if not reports:
        if recorded:
            return CheckResult(
                "report_signature", question, FAIL, "a report signature with no report"
            )
        return CheckResult(
            "report_signature", question, WARN, "no report has been generated in this bundle"
        )
    weak: list[str] = []
    for entry in recorded:
        body = entry["body"]
        problems = signature.verify(body) + _login_time_problems(entry)
        if not problems:
            problems += _report_head_problems(entry, entries)
        if body.get("party") != "regulator":
            problems.append(f"signed by the {body.get('party')}, not the regulator")
        elif not problems and plans is not None:
            found, loose = _party_problems(body, plan, anchors)
            problems += found
            weak += [w for w in loose if w not in weak]
        if problems:
            return CheckResult(
                "report_signature",
                question,
                FAIL,
                f"entry {entry['seq']}: {'; '.join(problems)}",
            )
    latest = str(reports[-1]["body"].get("report_sha256"))
    over = [e for e in recorded if e["body"].get("report_sha256") == latest]
    if not over:
        return CheckResult(
            "report_signature",
            question,
            WARN,
            f"report {latest[:19]}… was generated but nobody has signed it: it is a draft",
        )
    body = over[-1]["body"]
    if signature.is_development(body):
        return CheckResult(
            "report_signature",
            question,
            WARN,
            f"report {latest[:19]}… is signed through the development IdP, which issues a "
            "token for anyone: the signature identifies nobody",
        )
    detail = (
        f"report {latest[:19]}… signed by {_claims(body).get('email') or body.get('subject')} "
        f"via {body.get('idp')}, whom the plan names as the regulator; the token verifies "
        "and commits to the report's sha256"
    )
    head = body.get("ledger_head")
    if isinstance(head, dict):
        detail += (
            f" and to the ledger head at signing, seq {head.get('seq')} "
            f"({str(head.get('entry_hash'))[:19]}…), which this ledger holds"
        )
    else:
        weak.append(
            "the signature does not commit to the ledger head, as signatures made before "
            "2026-09-28 do not: the entries before it are held by the chain and the "
            "timestamps alone"
        )
    if weak:
        return CheckResult("report_signature", question, WARN, detail + ". But " + "; ".join(weak))
    return CheckResult("report_signature", question, PASS, detail)


# --- run logs ---------------------------------------------------------------


def check_run_logs(bundle: Bundle, statements: list[dict[str, Any]]) -> CheckResult:
    """Each attestation carries digests of the logs behind it; the logs themselves,
    when the bundle carries them, must hash to exactly those digests.

    A digest with no log behind it cannot be checked by anyone, so a missing log is a
    warning. A log that does not match its digest is a failure: either the log or the
    attestation is not what was produced.
    """
    question = "do the run logs in the bundle match the digests their attestations carry?"
    mismatched, missing, matched = [], [], 0
    for stmt in statements:
        predicate = stmt.get("predicate", {})
        run = predicate.get("run_number")
        for name, path in RUN_LOGS.items():
            value: Any = predicate
            for key in path:
                value = value.get(key) if isinstance(value, dict) else None
            if not value:
                continue  # this run makes no claim about this log
            text = bundle.run_log(int(run), name) if run is not None else None
            if text is None:
                missing.append(f"run {run} {name}")
            elif sha256_text(text) != value:
                mismatched.append(f"run {run} {name}")
            else:
                matched += 1
    if mismatched:
        return CheckResult(
            "run_logs", question, FAIL, "altered or substituted: " + ", ".join(mismatched)
        )
    if missing:
        return CheckResult(
            "run_logs",
            question,
            WARN,
            f"{matched} logs match their digests; not carried, so their digests cannot be "
            "checked: " + ", ".join(missing),
        )
    return CheckResult("run_logs", question, PASS, f"{matched} logs match their digests")


# --- harness statements -----------------------------------------------------


def _canonical_digest(envelope: dict[str, Any]) -> str:
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _decision_log_coverage(stdout: str, request_ids: list[str]) -> float | None:
    logged = set()
    for line in stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            logged.add(entry.get("request_id"))
    if not request_ids:
        return None
    return sum(1 for request_id in request_ids if request_id in logged) / len(request_ids)


DRIVER_TYPE = namespace.DRIVER_TYPE
# Results whose count of calls is the relay's, for the segments they came from.
RELAY_COUNTED = frozenset({"adversarial_robustness", "fail_safe"})


def _driver_problems(
    run: Any,
    predicate: dict[str, Any],
    measured: dict[str, Any],
    envelope: dict[str, Any] | None,
    harness_key: dict[str, str],
) -> tuple[list[str], dict[str, Any] | None]:
    """For a run scored off the centre (spec/run-attestation.md, section 1b):
    whether the scorer's measurements were computed from exactly what the
    driver observed. The verifier holds no labels, so it cannot score the responses
    again; it checks that both statements name the same responses, the same package,
    the same relay log and request ids, and that the counts a result states are the
    ones the driver saw. Returns the problems and the driver's statement, if it
    verified."""
    if envelope is None:
        return [f"run {run}: cites a driver statement the bundle does not carry"], None
    try:
        # Signed in the job with the key released to it, and no other.
        statement = signing.verify_json(envelope, harness_key)
    except (signing.VerificationError, KeyError) as error:
        return [f"run {run}: the driver's statement does not verify: {error}"], None
    if not namespace.is_type(statement.get("predicateType"), DRIVER_TYPE):
        return [f"run {run}: the statement cited as the driver's is not one"], None
    observed = statement.get("predicate", {})
    problems = []
    for key in ("sandbox_id", "plan_digest", "run_number", "relay_log_digest"):
        if observed.get(key) != predicate.get(key):
            problems.append(f"run {run}: {key} differs from what the driver observed")
    if measured.get("driver_statement_digest") != predicate.get("driver_statement_digest"):
        problems.append(f"run {run}: the scorer's statement cites another driver statement")
    for key, what in (("responses_digest", "responses"), ("work_digest", "work package")):
        if not observed.get(key) or measured.get(key) != observed.get(key):
            problems.append(
                f"run {run}: the scorer computed its results from other {what} than the "
                "driver observed"
            )
    if measured.get("request_ids") != observed.get("request_ids"):
        problems.append(f"run {run}: the request ids differ from the ones the driver observed")
    if observed.get("outcome") == "halted" and predicate.get("outcome") != "halted":
        problems.append(f"run {run}: the driver was halted; the attestation says otherwise")

    segments = observed.get("segments") or {}
    by_test = measured.get("segments") or {}
    for result in measured.get("results", []):
        test_id = result.get("test_id")
        ids = by_test.get(test_id) if isinstance(by_test, dict) else None
        if not ids:
            problems.append(f"run {run}: {test_id} names no observations it was computed from")
            continue
        if any(not (segments.get(s) or {}).get("complete") for s in ids):
            problems.append(
                f"run {run}: {test_id} was computed from observations the driver did not complete"
            )
            continue
        if result.get("type") in RELAY_COUNTED:
            stated = (result.get("metrics", {}).get("queries_sent") or {}).get("value")
            counted = sum(int(segments[s].get("relay_records", 0)) for s in ids)
            if stated is None or float(stated) != float(counted):
                problems.append(
                    f"run {run}: {test_id} states {stated} queries sent, the driver's relay "
                    f"counted {counted}"
                )
        else:
            answered = sum(int(segments[s].get("answered", 0)) for s in ids)
            if int(result.get("items_evaluated", 0)) > answered:
                problems.append(
                    f"run {run}: {test_id} evaluates {result.get('items_evaluated')} items, "
                    f"but the driver saw only {answered} answers"
                )
    return problems, observed


def check_harness_statements(
    bundle: Bundle,
    statements: list[dict[str, Any]],
    keys: SigningKeys,
    entries: list[dict[str, Any]],
    anchored: bool = False,
) -> CheckResult:
    """The control plane completes and signs each attestation; the harness signs what
    it measured, in segment A, with a key released to it alone. The attestation cites
    the harness's statement by digest, and the two must agree: the measured results,
    the relay log, the run. An operator who changed a number after the run would have
    to forge the harness's signature to hide it.

    The harness also signs the request ids the relay issued, so the decision-logging
    result the control plane scored can be recomputed here from the model's log.

    A run at a centre whose scoring was kept off it cites two statements: the
    driver's, signed in the job with the harness key, and the scorer's, signed where
    the labels are with the ``scorer`` key. There the measurements must verify under
    ``scorer``, and agree with the driver's (:func:`_driver_problems`).
    """
    question = "did the harness sign what it measured, and does the attestation agree?"
    path = bundle.root / "harness-statements.jsonl"
    signed = {}
    if path.is_file():
        for envelope in bundle.read_jsonl("harness-statements.jsonl"):
            signed[_canonical_digest(envelope)] = envelope
    unsigned, problems, agreed, scored_off_centre = [], [], 0, 0
    # Every statement the bundle carries must be one the ledger recorded with a run's
    # attestation. The attestation is the ledger's own (check_signatures), so the one
    # it cites is too.
    ledgered = {
        _canonical_digest(e["body"][name])
        for e in entries
        if e["entry_type"] == "run_attestation"
        for name in ("harness_statement", "driver_statement")
        if isinstance(e["body"].get(name), dict)
    }
    for digest in signed:
        if digest not in ledgered:
            problems.append(
                f"harness statement {digest[:19]}… is not one the ledger recorded with any "
                "run's attestation: it was added or replaced after the run"
            )
    for stmt in statements:
        predicate = stmt.get("predicate", {})
        run = predicate.get("run_number")
        cited = predicate.get("harness_statement_digest")
        if not cited:
            unsigned.append(str(run))
            continue
        envelope = signed.get(cited)
        if envelope is None:
            problems.append(f"run {run}: cites a harness statement the bundle does not carry")
            continue
        driver_cited = predicate.get("driver_statement_digest")
        # The harness's key and no other: a statement the control plane signed for the
        # harness would prove nothing. Scored off a centre, the scorer's.
        signer = "scorer" if driver_cited else "harness"
        try:
            measured = signing.verify_json(envelope, keys.of(signer))["predicate"]
        except (signing.VerificationError, KeyError) as error:
            problems.append(f"run {run}: {signer} statement does not verify: {error}")
            continue
        request_ids = measured.get("request_ids", [])
        if driver_cited:
            found, observed = _driver_problems(
                run, predicate, measured, signed.get(str(driver_cited)), keys.of("harness")
            )
            problems += found
            if observed is not None:
                request_ids = observed.get("request_ids", [])
            scored_off_centre += 1
        for key in ("sandbox_id", "plan_digest", "run_number", "relay_log_digest"):
            if measured.get(key) != predicate.get(key):
                problems.append(f"run {run}: {key} differs from what the harness signed")
        # Every result the harness signed appears unchanged; any other result is
        # decision logging, which is scored where the model's log can be read.
        signed_results = measured.get("results", [])
        stated = predicate["results"]
        if [r for r in stated if r in signed_results] != signed_results or any(
            r.get("type") != "decision_logging" for r in stated if r not in signed_results
        ):
            problems.append(f"run {run}: the results differ from what the harness measured")
        scored_outside = [r for r in stated if r.get("type") == "decision_logging"]
        if measured.get("outcome") == "halted" and predicate.get("outcome") != "halted":
            problems.append(f"run {run}: the harness was halted; the attestation says otherwise")
        stdout = bundle.run_log(int(run), "model-stdout.log") if run is not None else None
        for result in scored_outside:
            coverage = _decision_log_coverage(stdout or "", request_ids)
            stated = result.get("metrics", {}).get("log_coverage", {}).get("value")
            checkable = stdout is not None and coverage is not None and stated is not None
            # Stated values are rounded to six places.
            if checkable and abs(float(coverage or 0) - float(stated)) > 1e-5:
                problems.append(
                    f"run {run}: log coverage is {coverage:.4f} from the harness's request "
                    f"ids and the model's log, not the {stated} stated"
                )
        agreed += 1

    if problems:
        return CheckResult("harness_statements", question, FAIL, "; ".join(problems))
    if unsigned:
        # The control plane is the operator's: its signature alone can say anything.
        return CheckResult(
            "harness_statements",
            question,
            FAIL if anchored else WARN,
            f"runs {', '.join(unsigned)} carry no harness statement: their results are signed "
            "by whoever completed the attestation alone, the operator's control plane"
            + (f"; {agreed} other run(s) agree with their harness's statement" if agreed else ""),
        )
    return CheckResult(
        "harness_statements",
        question,
        PASS,
        f"{agreed} run(s): the harness signed its measurements and the attestation agrees"
        + (
            f"; {scored_off_centre} scored off the centre, from the driver's signed "
            "observations, which the scorer's statement agrees with"
            if scored_off_centre
            else ""
        ),
    )


# --- 11. external anchors ---------------------------------------------------
#
# Every check above measures the bundle against what the bundle itself carries: its
# plan, its public keys, its timestamp authority's root, the keys its IdPs signed
# with. An operator who rebuilt a bundle end to end could replace all of those
# consistently, and it would still verify. These checks pin it to anchors the
# verifier was given from outside (`histor.verifier.anchors`), and fail on any mismatch.


def _named(value: str) -> str:
    return value if len(value) <= 19 else value[:19] + "…"


def check_anchor_plan_digest(
    expected: tuple[str, ...],
    entries: list[dict[str, Any]],
    plans: dict[str, dict[str, Any]],
    statements: list[dict[str, Any]],
) -> CheckResult:
    """Is every plan the bundle names one the verifier holds a digest of?

    Each plan version is hashed again rather than trusted by its file name, so a
    bundle cannot carry other terms under the digest the regulator signed.
    """
    from histor.plan import digest as plan_digest

    question = "is every plan in the bundle one whose digest you hold?"
    for named, plan in plans.items():
        if plan_digest(plan) != named:
            return CheckResult(
                "anchor_plan_digest",
                question,
                FAIL,
                f"the bundle files a plan under {_named(named)}, but it hashes to "
                f"{_named(plan_digest(plan))}",
            )
    cited = {
        "a plan version in the bundle": set(plans),
        "a plan_signed entry": {
            str(e["body"]["plan_digest"])
            for e in entries
            if e["entry_type"] in {"plan_signed", "plan_signature"} and "plan_digest" in e["body"]
        },
        "a run": {str(s["predicate"].get("plan_digest")) for s in statements},
    }
    for where, digests in cited.items():
        unknown = sorted(digests - set(expected))
        if unknown:
            return CheckResult(
                "anchor_plan_digest",
                question,
                FAIL,
                f"{where} names plan {_named(unknown[0])}, which is not a digest you gave: "
                "the bundle was judged against terms other than the ones you signed",
            )
    if not plans:
        return CheckResult("anchor_plan_digest", question, FAIL, "the bundle carries no plan")
    return CheckResult(
        "anchor_plan_digest",
        question,
        PASS,
        f"{len(plans)} plan version(s), every signing and every run match the digest(s) you gave",
    )


def check_anchor_sandbox_id(
    expected: str,
    manifest: dict[str, Any],
    entries: list[dict[str, Any]],
    plans: dict[str, dict[str, Any]],
    statements: list[dict[str, Any]],
) -> CheckResult:
    question = "is this bundle the participation you were told it is?"
    found = [("the manifest", manifest.get("sandbox_id"))]
    found += [(f"ledger entry {e['seq']}", e.get("sandbox_id")) for e in entries]
    found += [(f"plan {_named(d)}", p.get("sandbox_id")) for d, p in plans.items()]
    found += [
        (f"run {s['predicate'].get('run_number')}", s["predicate"]["sandbox_id"])
        for s in statements
        if "sandbox_id" in s["predicate"]
    ]
    for where, value in found:
        if value != expected:
            return CheckResult(
                "anchor_sandbox_id",
                question,
                FAIL,
                f"{where} is for sandbox {value!r}, not {expected!r}",
            )
    return CheckResult(
        "anchor_sandbox_id", question, PASS, f"manifest, ledger, plans and runs: {expected}"
    )


def check_anchor_tsa_root(roots: tuple[str, ...], entries: list[dict[str, Any]]) -> CheckResult:
    """Does every timestamp chain to a root the verifier was given?

    The bundle's own pinned roots are ignored: a root the operator chose vouches for
    whatever the operator had it sign.
    """
    from histor.crypto.timestamps import verify_rfc3161

    question = "does every timestamp chain to a timestamp authority root you gave?"
    stamped = [e for e in entries if e.get("timestamp")]
    if not stamped:
        return CheckResult("anchor_tsa_root", question, FAIL, "no ledger entry carries a timestamp")
    for entry in stamped:
        token = parse_timestamp(entry["timestamp"])
        if token.kind != "rfc3161":
            return CheckResult(
                "anchor_tsa_root",
                question,
                FAIL,
                f"entry {entry['seq']} carries a {token.kind!r} timestamp, not one from a "
                "timestamp authority: nothing in it chains to the root you gave",
            )
        try:
            verify_rfc3161(
                base64.b64decode(entry["timestamp"]["token"]["der"]),
                entry["entry_hash"],
                list(roots),
            )
        except (signing.VerificationError, ValueError, KeyError, TypeError) as error:
            return CheckResult(
                "anchor_tsa_root", question, FAIL, f"entry {entry['seq']} timestamp: {error}"
            )
    return CheckResult(
        "anchor_tsa_root",
        question,
        PASS,
        f"{len(stamped)} timestamp(s) chain to the root(s) you gave",
    )


def check_anchor_idp_keys(
    keys: tuple[dict[str, Any], ...], entries: list[dict[str, Any]]
) -> CheckResult:
    """Was every IdP-bound signature made with a key from the key set the verifier
    was given? That is the one thing `check_plan_signatures` says it cannot establish
    offline: that the recorded key was the IdP's."""
    from histor.identity import jose

    question = "was every plan and report signature made with a key from the key set you gave?"
    known = {jose.thumbprint(key) for key in keys}
    signed = [e for e in entries if e["entry_type"] in {"plan_signature", "report_signature"}]
    if not signed:
        return CheckResult(
            "anchor_idp_keys",
            question,
            FAIL,
            "no signature in the bundle was made through an identity provider, so none can "
            "be held to the keys you gave",
        )
    for entry in signed:
        try:
            thumbprint = jose.thumbprint(dict(entry["body"]["jwk"]))
        except (KeyError, TypeError, jose.JoseError):
            thumbprint = ""
        if thumbprint not in known:
            return CheckResult(
                "anchor_idp_keys",
                question,
                FAIL,
                f"entry {entry['seq']} ({entry['body'].get('party')}) was signed with a key "
                "that is not in the key set you gave",
            )
    return CheckResult(
        "anchor_idp_keys",
        question,
        PASS,
        f"{len(signed)} signature(s), each with a key from the key set you gave",
    )


def _pinned_everywhere(
    anchor: str,
    question: str,
    expected: str,
    pin: str,
    plans: dict[str, dict[str, Any]],
    runs: list[tuple[Any, Any]],
) -> CheckResult:
    """``pin`` in every plan version, and each run's own record of it, against ``expected``."""
    for named, plan in plans.items():
        pinned = plan.get("artifacts", {}).get(pin)
        if pinned != expected:
            return CheckResult(
                anchor,
                question,
                FAIL,
                f"plan {_named(named)} pins {pin} {_named(str(pinned))}, not {_named(expected)}",
            )
    for run, actual in runs:
        if actual != expected:
            return CheckResult(
                anchor,
                question,
                FAIL,
                f"run {run} records {_named(str(actual))}, not {_named(expected)}",
            )
    if not plans:
        return CheckResult(anchor, question, FAIL, "the bundle carries no plan")
    return CheckResult(
        anchor,
        question,
        PASS,
        f"{len(plans)} plan version(s) and {len(runs)} run record(s) match {_named(expected)}",
    )


def check_anchor_policy_digest(
    expected: str, plans: dict[str, dict[str, Any]], statements: list[dict[str, Any]]
) -> CheckResult:
    runs = [
        (
            s["predicate"].get("run_number"),
            s["predicate"]["isolation_evidence"]["network_policy_digest"],
        )
        for s in statements
        if "network_policy_digest" in (s["predicate"].get("isolation_evidence") or {})
    ]
    return _pinned_everywhere(
        "anchor_policy_digest",
        "is the network policy the one whose digest you hold?",
        expected,
        "network_policy_digest",
        plans,
        runs,
    )


def check_anchor_harness_digest(
    expected: str, plans: dict[str, dict[str, Any]], statements: list[dict[str, Any]]
) -> CheckResult:
    runs = [
        (s["predicate"].get("run_number"), "sha256:" + str(subject["digest"].get("sha256")))
        for s in statements
        for subject in s["subject"]
        if subject.get("name") == "harness-image"
    ]
    return _pinned_everywhere(
        "anchor_harness_digest",
        "is the harness image the one whose digest you hold?",
        expected,
        "harness_image_digest",
        plans,
        runs,
    )


def _extends(
    seq: int, entry_hash: str, entries: list[dict[str, Any]], what: str
) -> tuple[dict[str, Any] | None, str]:
    """The entry at ``seq`` if it hashes to ``entry_hash``, or why the ledger does not
    extend that head."""
    last = int(entries[-1]["seq"]) if entries else 0
    at = next((e for e in entries if e["seq"] == seq), None)
    if at is None:
        if last < seq:
            return None, (
                f"the ledger ends at seq {last}, before {what} at seq {seq}: "
                f"{seq - last} or more entries were cut from its end"
            )
        return None, f"the ledger holds no entry at seq {seq}, which {what} names"
    if at["entry_hash"] != entry_hash:
        return None, (
            f"entry {seq} hashes to {str(at['entry_hash'])[:19]}…, not {entry_hash[:19]}… as "
            f"{what} says: this is another ledger from that point on"
        )
    return at, ""


def _beyond(seq: int, entries: list[dict[str, Any]]) -> str:
    last = int(entries[-1]["seq"]) if entries else 0
    return "and ends there" if last == seq else f"and extends it by {last - seq} entries"


def check_anchor_ledger_head(head: tuple[int, str], entries: list[dict[str, Any]]) -> CheckResult:
    """Does the ledger hold the head you hold? The hash chain and the timestamps say
    nothing about where a ledger ends; a head recorded outside the operator's reach
    does: a ledger cut before it, or rewritten from before it, does not hold it."""
    question = "does the ledger hold the head you hold?"
    seq, entry_hash = head
    at, problem = _extends(seq, entry_hash, entries, "the head you hold")
    if at is None:
        return CheckResult("anchor_ledger_head", question, FAIL, problem)
    return CheckResult(
        "anchor_ledger_head",
        question,
        PASS,
        f"the ledger holds seq {seq} ({entry_hash[:19]}…) {_beyond(seq, entries)}",
    )


def check_anchor_checkpoints(
    checkpoints: tuple[dict[str, Any], ...],
    entries: list[dict[str, Any]],
    manifest: dict[str, Any],
    keys: SigningKeys,
    public_keys: dict[str, str],
    tsa_roots: tuple[str, ...],
) -> CheckResult:
    """Does the ledger extend every head checkpoint you were given?

    Each checkpoint (``histor.ledger.checkpoint``) is the head as it stood when it was
    made, signed by the control plane under the key the ledger recorded (or you gave)
    and stamped by a timestamp authority: under the root you gave, if you gave one.
    The ledger must hold that entry, recorded before the checkpoint was made. A ledger
    cut short after a checkpoint, or rewritten from before it, fails."""
    from histor.crypto.timestamps import TSA_ROOT_PREFIX
    from histor.ledger import checkpoint as checkpoints_module

    question = "does the ledger extend every head checkpoint you were given?"
    timestamp_keys = dict(public_keys)
    if tsa_roots:
        timestamp_keys = {
            k: v for k, v in public_keys.items() if not k.startswith(TSA_ROOT_PREFIX)
        } | {f"{TSA_ROOT_PREFIX}given-{i}": pem for i, pem in enumerate(tsa_roots)}
    sandbox = manifest.get("sandbox_id")
    heads: list[str] = []
    development: list[str] = []
    latest = 0
    for given in checkpoints:
        name = given.get("file", "a checkpoint")
        try:
            body, kind = checkpoints_module.verify(given, keys.of("control-plane"), timestamp_keys)
        except checkpoints_module.CheckpointError as error:
            return CheckResult("anchor_checkpoints", question, FAIL, f"{name}: {error}")
        if body.get("sandbox_id") != sandbox:
            return CheckResult(
                "anchor_checkpoints",
                question,
                FAIL,
                f"{name} is of {body.get('sandbox_id')!r}, not this bundle's {sandbox!r}",
            )
        seq, head_hash = int(body["seq"]), str(body["head_hash"])
        what = f"the checkpoint made at {body.get('time')} ({name})"
        at, problem = _extends(seq, head_hash, entries, what)
        if at is None:
            return CheckResult("anchor_checkpoints", question, FAIL, problem)
        made, recorded = _instant(body.get("time")), _instant(at.get("recorded_at"))
        if made is None or recorded is None or recorded > made + RECORDED_AT_TOLERANCE:
            return CheckResult(
                "anchor_checkpoints",
                question,
                FAIL,
                f"entry {seq} was recorded at {at.get('recorded_at')}, after {what}",
            )
        heads.append(f"seq {seq} at {body.get('time')}")
        if kind != "rfc3161":
            development.append(name)
        latest = max(latest, seq)
    detail = (
        f"the ledger holds the head of each of {len(heads)} checkpoint(s) "
        f"({', '.join(heads)}), each signed by the control plane and stamped, "
        f"{_beyond(latest, entries)}"
    )
    if development:
        return CheckResult(
            "anchor_checkpoints",
            question,
            WARN,
            detail + f"; but {', '.join(development)} carry development timestamps, which "
            "anchor nothing: the operator could have made them at any time",
        )
    return CheckResult("anchor_checkpoints", question, PASS, detail)


def _situational_anchors(
    statements: list[dict[str, Any]],
    entries: list[dict[str, Any]] | None = None,
    plans: dict[str, dict[str, Any]] | None = None,
) -> tuple[str, ...]:
    """The anchors only some bundles are checked against that this one is: the
    centres' keys, when a centre signed isolation evidence; the TEE vendors' roots,
    when there is TEE evidence or a plan that asks for it."""
    needed: list[str] = []
    for statement in statements:
        evidence = (statement.get("predicate") or {}).get("isolation_evidence")
        if (
            isinstance(evidence, dict)
            and evidence.get("type") == "hpc_centre"
            and _signer(evidence) == "centre"
        ):
            needed.append("centre_keys")
            break
    if entries is not None and tee_evidence_present(plans or {}, statements, entries):
        needed.append("vendor_roots")
    return tuple(needed)


def check_anchors(
    anchors: Anchors,
    manifest: dict[str, Any],
    entries: list[dict[str, Any]],
    plans: dict[str, dict[str, Any]],
    statements: list[dict[str, Any]],
    needed: tuple[str, ...] = (),
) -> list[CheckResult]:
    """One check per anchor given, then a warning naming those taken from the bundle."""
    results = []
    if anchors.plan_digest:
        results.append(check_anchor_plan_digest(anchors.plan_digest, entries, plans, statements))
    if anchors.sandbox_id:
        results.append(
            check_anchor_sandbox_id(anchors.sandbox_id, manifest, entries, plans, statements)
        )
    if anchors.tsa_root:
        results.append(check_anchor_tsa_root(anchors.tsa_root, entries))
    if anchors.idp_keys:
        results.append(check_anchor_idp_keys(anchors.idp_keys, entries))
    if anchors.policy_digest:
        results.append(check_anchor_policy_digest(anchors.policy_digest, plans, statements))
    if anchors.harness_digest:
        results.append(check_anchor_harness_digest(anchors.harness_digest, plans, statements))
    if anchors.ledger_head:
        results.append(check_anchor_ledger_head(anchors.ledger_head, entries))

    internal = anchors.from_bundle(needed)
    if internal:
        results.append(
            CheckResult(
                "anchors",
                "were the trust anchors given from outside the bundle?",
                WARN,
                f"{', '.join(ANCHOR_NAMES[name] for name in internal)} came from the bundle "
                "itself: the checks against them show that the bundle agrees with itself, "
                "not that it is the one you signed. An operator who rebuilt it could have "
                "replaced them all consistently. Pass them from outside, with --anchors or "
                "the --expect-* options.",
            )
        )
    else:
        results.append(
            CheckResult(
                "anchors",
                "were the trust anchors given from outside the bundle?",
                PASS,
                "every anchor was given from outside the bundle",
            )
        )
    return results


# --- statement types ----------------------------------------------------------


def _statement_type(envelope: Any) -> Any:
    try:
        return json.loads(base64.b64decode(envelope["payload"])).get("predicateType")
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def check_statement_types(bundle: Bundle, statements: list[dict[str, Any]]) -> CheckResult:
    """Is every signed statement of a type this verifier knows?

    Run attestations must be :data:`histor.crypto.namespace.RUN_TYPE`; the harness's and the
    driver's statements, their own types. The same types under the working-title
    namespace (``https://sandbox-mvp.dev/``) are what every bundle made before the
    rename to Histor carries. They are read as they are, since evidence is not
    rewritten, and warn, so a reader knows why the URIs differ from the spec's.
    """
    question = "is every signed statement of a type this verifier knows?"
    found: list[tuple[str, Any, tuple[str, ...]]] = [
        (f"attestation {index}", stmt.get("predicateType"), (namespace.RUN_TYPE,))
        for index, stmt in enumerate(statements)
    ]
    if (bundle.root / "harness-statements.jsonl").is_file():
        try:
            envelopes = bundle.read_jsonl("harness-statements.jsonl")
        except (OSError, ValueError) as error:
            return CheckResult("statement_types", question, FAIL, f"unreadable: {error}")
        found += [
            (
                f"harness statement {index}",
                _statement_type(envelope),
                (namespace.MEASUREMENT_TYPE, namespace.DRIVER_TYPE),
            )
            for index, envelope in enumerate(envelopes)
        ]
    unknown = [
        f"{where} is of type {kind!r}"
        for where, kind, allowed in found
        if not any(namespace.is_type(kind, uri) for uri in allowed)
    ]
    if unknown:
        return CheckResult(
            "statement_types",
            question,
            FAIL,
            "; ".join(unknown) + f" (expected types under {namespace.NAMESPACE})",
        )
    legacy = sorted({str(kind) for _, kind, _ in found if namespace.is_legacy(kind)})
    if legacy:
        return CheckResult(
            "statement_types",
            question,
            WARN,
            f"{sum(1 for _, kind, _ in found if namespace.is_legacy(kind))} statement(s) use "
            f"the legacy namespace {namespace.LEGACY_NAMESPACE} ({', '.join(legacy)}), from "
            f"before the rename to Histor; they are read as the same types under "
            f"{namespace.NAMESPACE}",
        )
    return CheckResult(
        "statement_types",
        question,
        PASS,
        f"{len(found)} statement(s), each of a known type under {namespace.NAMESPACE}",
    )


# --- personal data ------------------------------------------------------------


def _personal_data_summary(found: dict[str, Any]) -> str:
    categories = found["categories"]
    held = [
        f"{name.replace('_', ' ')} ({entry['count']}, in {', '.join(entry['files'])})"
        for name, entry in categories.items()
    ]
    return ("personal data: " + "; ".join(held)) if held else "no personal data"


# Languages a rendering reads no catalogue for: English is the source, and the
# pseudo-locale is generated from it (histor.i18n). Named here, not imported, so the
# verifier loads nothing that translates.
UNTRANSLATED_LANGUAGES = frozenset({"en", "en-xa"})


def check_i18n_catalogues(bundle: Bundle, entries: list[dict[str, Any]]) -> CheckResult:
    """Does the bundle carry the catalogue each translated rendering was made with?

    A rendering of the report in a language other than English is made with that
    language's compiled catalogue, and the ``report_generated`` entry records the
    catalogue's sha256 beside the rendering. The bundle carries the catalogue as
    ``i18n/<lang>/report.mo``. Each recorded catalogue must be there and hash as
    recorded; every catalogue there must be one a rendering records; and a translated
    rendering must record one, or nothing says which translation produced it."""
    question = (
        "is the catalogue each translated rendering of the report was made with in the "
        "bundle, as the ledger records it?"
    )
    reports = [e for e in entries if e.get("entry_type") == "report_generated"]
    body = reports[-1].get("body") if reports else None
    recorded_list = (body or {}).get("renderings") if isinstance(body, dict) else None
    i18n_dir = bundle.root / "i18n"
    present: dict[str, Any] = {}
    if i18n_dir.is_dir():
        for path in sorted(i18n_dir.rglob("*")):
            if path.is_file():
                present[str(path.relative_to(bundle.root))] = path
    if not isinstance(recorded_list, list) or not recorded_list:
        if present:
            return CheckResult(
                "i18n_catalogues",
                question,
                FAIL,
                f"the bundle carries {', '.join(sorted(present))}, but the ledger records "
                "no translated rendering of the report that was made with it",
            )
        return CheckResult(
            "i18n_catalogues",
            question,
            PASS,
            "the report was rendered in English only: no catalogue to carry",
        )
    expected: dict[str, str] = {}
    problems: list[str] = []
    for item in recorded_list:
        if not isinstance(item, dict):
            raise TypeError("a rendering record is not an object")
        lang = str(item.get("language", ""))
        sha = item.get("catalogue_sha256")
        if lang.lower() in UNTRANSLATED_LANGUAGES:
            if sha is not None:
                problems.append(f"the {lang} rendering records a catalogue, but {lang} reads none")
            continue
        if not isinstance(sha, str) or not sha.startswith("sha256:"):
            problems.append(
                f"the {lang} rendering of {item.get('document')} records no catalogue_sha256: "
                "nothing says which translation produced it"
            )
            continue
        if not lang.isalpha() or not lang.islower() or not 2 <= len(lang) <= 3:
            problems.append(f"{lang!r} is not a language a catalogue is carried under")
            continue
        if expected.setdefault(lang, sha) != sha:
            problems.append(f"the {lang} renderings record two different catalogues")
    for lang, sha in sorted(expected.items()):
        name = f"i18n/{lang}/{CATALOGUE_FILE}"
        path = present.pop(name, None)
        if path is None:
            problems.append(f"{name} is not in the bundle, though the {lang} rendering records it")
            continue
        found = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if found != sha:
            problems.append(f"{name} hashes to {found[:19]}…; the ledger records {sha[:19]}…")
    for name in sorted(present):
        problems.append(f"{name} is in the bundle, but no rendering records it")
    if problems:
        return CheckResult("i18n_catalogues", question, FAIL, "; ".join(problems[:5]))
    if not expected:
        return CheckResult(
            "i18n_catalogues",
            question,
            PASS,
            "every rendering is in English (or its pseudo-locale): no catalogue to carry",
        )
    return CheckResult(
        "i18n_catalogues",
        question,
        PASS,
        f"{len(expected)} catalogue(s) ({', '.join(sorted(expected))}) in the bundle, each "
        "hashing as the report_generated entry records it",
    )


def check_personal_data(bundle: Bundle, manifest: dict[str, Any]) -> CheckResult:
    """Does the manifest say what personal data the bundle holds?

    Derived again from the files (:meth:`histor.ledger.bundle.Bundle.personal_data`) and
    compared with the manifest's ``personal_data``. A bundle_version 0.1 manifest has
    only ``contains_personal_data``, written as ``false`` whatever the bundle held:
    that is a warning, since the software said it, not whoever changed the bundle.
    """
    question = "does the manifest say what personal data the bundle holds?"
    found = bundle.personal_data()
    summary = _personal_data_summary(found)
    if manifest.get("bundle_version") == "0.1":
        claimed = manifest.get("contains_personal_data")
        if found["present"] and claimed is not True:
            return CheckResult(
                "personal_data",
                question,
                WARN,
                f"this bundle_version 0.1 manifest says contains_personal_data: {claimed!r}, "
                f"a constant in the software that wrote it; the bundle holds {summary}. "
                "It holds no test-subject data",
            )
        return CheckResult("personal_data", question, PASS, f"the bundle holds {summary}")
    if manifest.get("personal_data") != found:
        return CheckResult(
            "personal_data",
            question,
            FAIL,
            f"the manifest's personal_data is not what the bundle holds, which is {summary}",
        )
    return CheckResult(
        "personal_data",
        question,
        PASS,
        f"as the manifest says, the bundle holds {summary}, and no test-subject data "
        "(none of the files the export writes can carry it)",
    )


# --- orchestration ----------------------------------------------------------

# What malformed input raises in a check that reads it: a field missing or of the
# wrong type, a value out of range, a signature that does not parse. It fails the
# bundle; it never stops the verifier with a traceback.
MALFORMED = (
    KeyError,
    TypeError,
    ValueError,
    AttributeError,
    IndexError,
    OverflowError,
    UnicodeError,
    RecursionError,
    OSError,
    signing.VerificationError,
)


def _malformed(check_id: str, error: BaseException) -> CheckResult:
    return CheckResult(
        check_id,
        "is the bundle well formed where this check reads it?",
        FAIL,
        f"the bundle is malformed where {check_id} reads it ({type(error).__name__}: "
        f"{error}): an altered bundle, or one this verifier cannot read",
    )


def _runner(verdict: Verdict) -> Any:
    def run(check_id: str, check: Any, *args: Any) -> CheckResult:
        try:
            result = check(*args)
        except MALFORMED as error:
            result = _malformed(check_id, error)
        added: CheckResult = verdict.add(result)
        return added

    return run


def _current_plan(bundle: Bundle) -> dict[str, Any] | None:
    """``plan.json``, where the bundle also carries ``plans/``: the plan the manifest
    says the runs were judged against, which must be one of the versions."""
    if not (bundle.root / "plans").is_dir():
        return None  # plan.json is the one version, read as plans already
    plan: Any = bundle.read_json("plan.json")
    if not isinstance(plan, dict):
        raise TypeError("plan.json is not a plan object")
    return plan


def check_bundle_digest(bundle: Bundle, manifest: dict[str, Any]) -> CheckResult:
    question = "does the bundle match the digest in its own manifest?"
    recomputed = bundle.digest()
    if manifest.get("bundle_digest") != recomputed:
        return CheckResult(
            "bundle_digest",
            question,
            FAIL,
            f"manifest says {str(manifest.get('bundle_digest'))[:19]}…, "
            f"contents hash to {recomputed[:19]}…",
        )
    return CheckResult("bundle_digest", question, PASS, recomputed)


def check_bundle_files(bundle: Bundle) -> CheckResult | None:
    """None when every path in the bundle is a regular file or a directory; a failure
    naming the first that is not. A symbolic link could make the verifier hash or scan
    a file outside the bundle, and a FIFO or a device could hang it, so neither is
    followed or read: the bundle is refused whole, as ``ledger.bundle.unpack`` refuses
    such an archive."""
    found = bundle.special_files()
    if not found:
        return None
    return CheckResult(
        "bundle_files",
        "is every path in the bundle a regular file or a directory?",
        FAIL,
        f"the bundle holds {', '.join(found[:5])}: a bundle holds regular files only, and "
        "nothing in it was read",
    )


def check_bundle_version(manifest: dict[str, Any]) -> CheckResult:
    question = "is this a bundle format this verifier knows how to check?"
    version = manifest.get("bundle_version")
    if version not in SUPPORTED_BUNDLE_VERSIONS:
        return CheckResult(
            "bundle_version",
            question,
            FAIL,
            f"bundle_version {version!r} is not one this verifier understands (it reads "
            f"{', '.join(SUPPORTED_BUNDLE_VERSIONS)}): use a verifier that supports it, "
            "rather than one that would skip the checks it does not know about",
        )
    if version in LEGACY_BUNDLE_VERSIONS:
        return CheckResult(
            "bundle_version",
            question,
            WARN,
            f"LEGACY FORMAT, WEAKER GUARANTEES: bundle_version {version} predates "
            f"{BUNDLE_VERSION}, whose ledger records the keys that sign the runs' statements "
            "and the bundle's own format. This bundle is checked as it was written, and what "
            "those records would establish is not established: see signing_keys and "
            "bundle_format",
        )
    return CheckResult("bundle_version", question, PASS, f"bundle_version {version}")


# When each legacy format was superseded. A ledger a timestamp authority you hold
# stamped after that was written by software that exports a later format.
SUPERSEDED = {
    "0.1": datetime.datetime(2026, 9, 27, tzinfo=datetime.UTC),
    "0.2": datetime.datetime(2026, 9, 28, tzinfo=datetime.UTC),
}
# Ledger entries only a writer of bundle_version 0.3 or later records.
FORMAT_MARKERS = frozenset({"signing_key_registered"})


def check_bundle_format(
    manifest: dict[str, Any], entries: list[dict[str, Any]], anchors: Anchors
) -> CheckResult:
    """Is the manifest's bundle_version the one the ledger was written for?

    Nothing signs the manifest, and an older format is checked more leniently (a 0.1
    manifest's personal-data flag, for one, is a constant nobody compared with the
    files). So a bundle relabelled as older would pass checks it fails. The format is
    held to the ledger, which is chained and timestamped: the ``bundle_version`` its
    ``report_generated`` entry records, the entry types only a later writer records,
    and, with a timestamp authority root you hold, when the ledger was stamped.
    """
    from histor.crypto.timestamps import verify_rfc3161

    question = "is the bundle's format the one its ledger was written for?"
    claimed = str(manifest.get("bundle_version"))
    recorded = [
        e
        for e in entries
        if e["entry_type"] == "report_generated" and e["body"].get("bundle_version")
    ]
    if recorded and str(recorded[-1]["body"]["bundle_version"]) != claimed:
        return CheckResult(
            "bundle_format",
            question,
            FAIL,
            f"the ledger's report_generated (seq {recorded[-1]['seq']}) records bundle_version "
            f"{recorded[-1]['body']['bundle_version']}, but the manifest says {claimed}: the "
            "manifest, which nothing signs, was relabelled",
        )
    reports = [e for e in entries if e["entry_type"] == "report_generated"]
    if (
        claimed not in LEGACY_BUNDLE_VERSIONS
        and reports
        and not reports[-1]["body"].get("bundle_version")
    ):
        return CheckResult(
            "bundle_format",
            question,
            FAIL,
            f"the manifest says bundle_version {claimed}, whose writer records the format in "
            f"its report_generated entry, but the last one (seq {reports[-1]['seq']}) records "
            "none: the report is from another writer, or the entry was rewritten",
        )
    if claimed not in LEGACY_BUNDLE_VERSIONS:
        where = (
            f"as the ledger's report_generated (seq {recorded[-1]['seq']}) records"
            if recorded
            else "not yet recorded in the ledger, which holds no report"
        )
        return CheckResult("bundle_format", question, PASS, f"bundle_version {claimed}, {where}")
    later = sorted({e["entry_type"] for e in entries if e["entry_type"] in FORMAT_MARKERS})
    if later or recorded:
        return CheckResult(
            "bundle_format",
            question,
            FAIL,
            f"the manifest says bundle_version {claimed}, but the ledger holds "
            f"{later or ['a report recording its format']}, which only a writer of "
            f"{BUNDLE_VERSION} or later records: it was relabelled to a format checked more "
            "leniently",
        )
    if anchors.tsa_root and entries and entries[-1].get("timestamp"):
        try:
            stamped = _instant(
                verify_rfc3161(
                    base64.b64decode(entries[-1]["timestamp"]["token"]["der"]),
                    entries[-1]["entry_hash"],
                    list(anchors.tsa_root),
                )["time"]
            )
        except (signing.VerificationError, ValueError, KeyError, TypeError):
            stamped = None  # anchor_tsa_root says why
        if stamped is not None and stamped >= SUPERSEDED[claimed]:
            return CheckResult(
                "bundle_format",
                question,
                FAIL,
                f"the ledger's last entry was stamped at {_stamp(stamped)}, after bundle_version "
                f"{claimed} was superseded ({SUPERSEDED[claimed]:%Y-%m-%d}): a bundle exported "
                "then is not in that format, so this one was relabelled",
            )
    return CheckResult(
        "bundle_format",
        question,
        PASS,
        f"bundle_version {claimed}: nothing in the ledger was written by a later format's "
        "writer"
        + (
            ""
            if anchors.tsa_root
            else ", and without a TSA root you hold, when it was stamped proves nothing"
        ),
    )


def _report_dir(bundle: Bundle, entries: list[dict[str, Any]], given: Path | None) -> Path | None:
    """Where the report's renderings are: the directory given, or else the bundle's own
    parent when it holds every file the last ``report_generated`` entry records (the
    demo and ``histor run`` write them there). The files are checked against the hashes
    the ledger records, so where they came from does not matter to the verdict."""
    if given is not None:
        return given
    body: Any = next(
        (e["body"] for e in reversed(entries) if e["entry_type"] == "report_generated"), {}
    )
    recorded = body.get("renderings") if isinstance(body, dict) else None
    if not isinstance(recorded, list) or not recorded:
        return None
    parent = bundle.root.resolve().parent
    names = [str(i.get("file")) for i in recorded if isinstance(i, dict)]
    if names and all(
        Path(n).name == n and not n.startswith(".") and (parent / n).is_file() for n in names
    ):
        return parent
    return None


def verify_bundle(
    bundle: Bundle,
    anchors: Anchors | None = None,
    in_progress: bool = False,
    report_dir: Path | None = None,
) -> Verdict:
    """``anchors`` are what the verifier holds from outside the bundle; any it does not
    give are taken from the bundle, and the verdict says which. ``in_progress`` says the
    participation has not ended, so a ledger without its ending only warns.
    ``report_dir`` is where the report and its renderings were written, if the verifier
    holds them; without it, the bundle's parent directory is used when it holds them."""
    anchors = anchors or Anchors()
    external = anchors.external()
    verdict = Verdict(
        anchors={
            "external": external,
            "from_bundle": anchors.from_bundle(),
        }
    )

    refused = check_bundle_files(bundle)
    if refused is not None:
        verdict.add(refused)
        verdict.caveats.append("later checks were skipped: the bundle holds special files")
        return verdict

    try:
        manifest = bundle.read_manifest()
        if not isinstance(manifest, dict):
            raise TypeError("the manifest is not a JSON object")
        version_result = verdict.add(check_bundle_version(manifest))
    except (OSError, ValueError, TypeError) as error:
        version_result = verdict.add(
            CheckResult(
                "bundle_version",
                "is this a bundle format this verifier knows how to check?",
                FAIL,
                f"the manifest is unreadable: {error}",
            )
        )
    if version_result.outcome == FAIL:
        verdict.caveats.append("later checks were skipped: the bundle's format is unknown")
        return verdict

    try:
        entries = bundle.read_jsonl("ledger.jsonl")
        plans = bundle.plan_versions()
        public_keys = bundle.read_json("public-keys.json")
        if not isinstance(public_keys, dict) or not all(
            isinstance(v, str) for v in public_keys.values()
        ):
            raise ValueError("public-keys.json is not an object of key id to PEM")
        if not all(isinstance(p, dict) for p in plans.values()):
            raise ValueError("a plan version is not a plan object")
    except (OSError, ValueError, TypeError, AttributeError) as error:
        # A ledger that no longer parses has been altered, and says so by failing,
        # not by taking the verifier down with it.
        verdict.add(
            CheckResult(
                "hash_chain",
                "is the ledger hash chain intact, with no gaps?",
                FAIL,
                f"the ledger or plan in the bundle is unreadable: {error}",
            )
        )
        verdict.caveats.append("later checks were skipped: the ledger could not be read")
        return verdict

    # A flipped byte can leave valid JSON with a field renamed. That is an altered
    # ledger too, and the checks below would otherwise stop on the missing key.
    malformed = next(
        (
            position + 1
            for position, entry in enumerate(entries)
            if not isinstance(entry, dict)
            or not entry.keys() >= LEDGER_FIELDS
            or not isinstance(entry["body"], dict)
        ),
        None,
    )
    if malformed is not None:
        verdict.add(
            CheckResult(
                "hash_chain",
                "is the ledger hash chain intact, with no gaps?",
                FAIL,
                f"ledger line {malformed} is not a well-formed entry: it was altered",
            )
        )
        verdict.caveats.append("later checks were skipped: the ledger could not be read")
        return verdict

    run = _runner(verdict)
    run("bundle_format", check_bundle_format, manifest, entries, anchors)
    keys = SigningKeys()
    statements: list[dict[str, Any]] = []
    try:
        keys = resolve_signing_keys(entries, public_keys, anchors)
        signature_result, statements = check_signatures(bundle, entries, keys)
        if not all(
            isinstance(s, dict) and isinstance(s.get("predicate"), dict) for s in statements
        ):
            raise TypeError("an attestation's statement carries no predicate object")
    except MALFORMED as error:
        signature_result = _malformed("signatures", error)
    run("signing_keys", check_signing_keys, keys, entries, statements, bool(external))
    verdict.add(signature_result)
    if signature_result.outcome == FAIL:
        verdict.caveats.append("later checks were skipped: nothing here can be trusted")
        return verdict
    run("statement_types", check_statement_types, bundle, statements)

    run("hash_chain", check_hash_chain, entries)
    run("run_numbers", check_run_numbers, entries, statements)
    # plan.json is read inside the check, so a plan.json that does not parse fails
    # plan_versions and the other checks still run.
    run(
        "plan_versions",
        lambda: check_plan_versions(entries, plans, _current_plan(bundle)),
    )
    run(
        "plan_signatures",
        check_plan_signatures,
        entries,
        plans,
        anchors,
        public_keys,
        statements,
    )
    run("report_signature", check_report_signature, entries, plans, anchors)
    run("artifact_digests", check_artifact_digests, plans, statements)
    run("dataset_commitments", check_dataset_commitments, entries, statements, plans)
    run(
        "isolation",
        check_isolation,
        plans,
        statements,
        public_keys,
        entries,
        anchors.centre_keys,
        bool(external),
    )
    if tee_evidence_present(plans, statements, entries):
        run(
            "tee_attestation",
            check_tee_attestation,
            plans,
            statements,
            entries,
            public_keys,
            anchors.vendor_roots,
        )
    run("run_logs", check_run_logs, bundle, statements)
    run(
        "harness_statements",
        check_harness_statements,
        bundle,
        statements,
        keys,
        entries,
        bool(external),
    )
    run("thresholds", check_thresholds, statements)
    run("sample_sizes", check_sample_sizes, statements)
    run("deletion", check_deletion, entries)
    run("completeness", check_completeness, bundle, entries, bool(external), in_progress)
    run("timestamps", check_timestamps, entries, public_keys)
    run("tsa_revocation", check_tsa_revocation, entries, public_keys, anchors.tsa_root)
    run("personal_data", check_personal_data, bundle, manifest)
    run("i18n_catalogues", check_i18n_catalogues, bundle, entries)
    if any(e["entry_type"] == "report_generated" for e in entries):
        # A separate module that imports this one; loaded here to keep it that way.
        from histor.verifier.renderings import ID as RENDERINGS
        from histor.verifier.renderings import check_report_renderings

        run(
            RENDERINGS,
            check_report_renderings,
            entries,
            _plan_in_force(entries, plans),
            _report_dir(bundle, entries, report_dir),
        )
    # The notified body's own tests (Annex VII point 4.4), when the ledger has any.
    from histor.verifier import nb_tests

    if nb_tests.applies(entries, statements):
        run(nb_tests.ID, nb_tests.check_nb_tests, entries, statements, plans, anchors)
    if anchors.checkpoints:
        run(
            "anchor_checkpoints",
            check_anchor_checkpoints,
            anchors.checkpoints,
            entries,
            manifest,
            keys,
            public_keys,
            anchors.tsa_root,
        )
    needed = _situational_anchors(statements, entries, plans)
    verdict.anchors["from_bundle"] = anchors.from_bundle(needed)
    try:
        for result in check_anchors(anchors, manifest, entries, plans, statements, needed):
            verdict.add(result)
    except MALFORMED as error:
        verdict.add(_malformed("anchors", error))
    run("bundle_digest", check_bundle_digest, bundle, manifest)

    for warning in verdict.warnings:
        verdict.caveats.append(f"{warning.id}: {warning.detail}")
    return verdict
