"""What every check shares: the result and verdict types, and the helpers
more than one area of checks uses."""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass, field
from typing import Any

from histor.crypto import signing
from histor.crypto.canonical import canonical_json_ascii

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


def _raw_key(pem: Any) -> bytes | None:
    from cryptography.hazmat.primitives import serialization

    try:
        return signing.load_public(str(pem)).public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    except (ValueError, TypeError, AttributeError, UnicodeError):
        return None


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


# --- times, as the ledger and the tokens write them -----------------------


# How far the time an authority signed may lie from the entry's ``recorded_at``. The
# ledger writes ``recorded_at`` and then asks the authority for a token before the entry
# is stored (ledger.store.Ledger._append), so the two differ by the round trip and the
# two clocks' skew. Ten minutes allows a slow authority and a badly set clock; it does
# not allow an entry written, or a ledger rebuilt, at another time than it claims.
RECORDED_AT_TOLERANCE = datetime.timedelta(minutes=10)


def _instant(value: Any) -> datetime.datetime | None:
    """An ISO 8601 time, as the ledger and the tokens write it, or None."""
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=datetime.UTC)


def _stamp(value: datetime.datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


# --- a signed statement's digest ---------------------------------------------


def _canonical_digest(envelope: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_ascii(envelope)).hexdigest()
