"""Build the tampered copies of the sample evidence bundle.

Each copy changes one thing in ``examples/sample-participation/evidence-bundle/`` and
then rewrites the manifest's ``bundle_digest`` over the changed files, as an operator
covering their tracks would. Without that rewrite every copy would also fail
``bundle_digest``; with it, the check that catches the change is the one named in
``TAMPERS``.

Deterministic, so the committed copies can be checked against a fresh build. The one
copy that signs anything signs with a key derived from a fixed, published seed: it
plays an operator who made their own keys, and the point is that the verifier does
not take the bundle's word for whose keys they are.

    python examples/tampered/build.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from histor.crypto import signing
from histor.ledger.bundle import Bundle

HERE = Path(__file__).resolve().parent
GOOD = HERE.parent / "sample-participation" / "evidence-bundle"

Json = dict[str, Any]


def _read_lines(path: Path) -> list[Json]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write_lines(path: Path, rows: list[Json]) -> None:
    # The same serialisation the sandbox writes: one sorted-key JSON object per line.
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def _statement(envelope: Json) -> Json:
    statement: Json = json.loads(base64.b64decode(envelope["payload"]))
    return statement


def _envelope_digest(envelope: Json) -> str:
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def ledger_one_char_edit(bundle: Path) -> None:
    """The gate refused the test lab's attempt to swap the dataset, and recorded why.
    One character of that recorded reason is changed: "not permitted" becomes "now
    permitted"."""
    path = bundle / "ledger.jsonl"
    text = path.read_text(encoding="utf-8")
    if text.count("is not permitted") != 1:
        raise SystemExit("ledger-one-char-edit: expected exactly one refusal reason to edit")
    path.write_text(text.replace("is not permitted", "is now permitted"), encoding="utf-8")


def swapped_result(bundle: Path) -> None:
    """Run 1 failed. Its signed attestation gets run 2's passing results and outcome
    pasted in, and the original signature is left as it was."""
    path = bundle / "attestations.jsonl"
    envelopes = _read_lines(path)
    statements = [_statement(e) for e in envelopes]
    by_run = {s["predicate"]["run_number"]: i for i, s in enumerate(statements)}
    first, second = statements[by_run[1]], statements[by_run[2]]
    first["predicate"]["results"] = second["predicate"]["results"]
    first["predicate"]["outcome"] = second["predicate"]["outcome"]
    payload = json.dumps(first, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelopes[by_run[1]]["payload"] = base64.b64encode(payload).decode("ascii")
    _write_lines(path, envelopes)


def removed_timestamp(bundle: Path) -> None:
    """The timestamp is taken off the entry recording the refused dataset swap, as if
    that entry had been slipped into the ledger later without one."""
    entries = _read_lines(bundle / "ledger.jsonl")
    refused = [e for e in entries if e["entry_type"] == "gate_decision" and not e["body"]["allow"]]
    if not refused or "timestamp" not in refused[0]:
        raise SystemExit("removed-timestamp: no timestamped refusal to strip")
    del refused[0]["timestamp"]
    _write_lines(bundle / "ledger.jsonl", entries)


def plan_digest_mismatch(bundle: Path) -> None:
    """The first signed plan version is kept under its file name (its digest), but its
    per-group threshold for minors accepted as adults is loosened to 75%, so the failed
    run would have passed. The file no longer hashes to the digest it is filed under."""
    entries = _read_lines(bundle / "ledger.jsonl")
    first = next(e for e in entries if e["entry_type"] == "plan_signed")
    path = bundle / "plans" / (first["body"]["plan_digest"].removeprefix("sha256:") + ".json")
    plan = json.loads(path.read_text(encoding="utf-8"))
    test = next(t for t in plan["tests"] if "max_per_group" in t.get("thresholds", {}))
    test["thresholds"]["max_per_group"] = 0.75
    path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# The substitute keys' seeds. Published on purpose: these keys belong to "the operator"
# in this example, and anyone may sign with them. That is the point of the example.
SUBSTITUTE_SEED = b"histor tampered example: key substitution"


def key_substitution(bundle: Path) -> None:
    """The operator makes their own control-plane and harness keys, puts their public
    halves in public-keys.json, and re-signs run 1's harness statement and attestation
    with run 2's passing results. Every envelope in the bundle verifies against a key
    in the bundle; the ledger, with its timestamps, is left exactly as it was, and still
    records the failing run and the original keys."""
    keys = {
        key_id: signing.from_seed(
            key_id, hashlib.sha256(SUBSTITUTE_SEED + key_id.encode("ascii")).digest()
        )
        for key_id in ("control-plane", "harness")
    }
    attestations = _read_lines(bundle / "attestations.jsonl")
    statements = _read_lines(bundle / "harness-statements.jsonl")
    measured = {_envelope_digest(e): _statement(e) for e in statements}
    predicates = [_statement(a) for a in attestations]
    passing = next(p for p in predicates if p["predicate"]["run_number"] == 2)["predicate"]
    new_statements, new_attestations = [], []
    for attestation in predicates:
        predicate = attestation["predicate"]
        harness = measured[predicate["harness_statement_digest"]]
        if predicate["run_number"] == 1:
            harness["predicate"]["results"] = [
                r for r in passing["results"] if r["type"] != "decision_logging"
            ]
            harness["predicate"]["outcome"] = "pass"
            predicate["results"] = passing["results"]
            predicate["outcome"] = "pass"
        envelope = signing.sign_json(keys["harness"], harness)
        new_statements.append(envelope)
        predicate["harness_statement_digest"] = _envelope_digest(envelope)
        new_attestations.append(signing.sign_json(keys["control-plane"], attestation))
    _write_lines(bundle / "harness-statements.jsonl", new_statements)
    _write_lines(bundle / "attestations.jsonl", new_attestations)
    public = json.loads((bundle / "public-keys.json").read_text(encoding="utf-8"))
    for key_id, keypair in keys.items():
        public[key_id] = keypair.public_pem
    text = json.dumps(public, indent=2, sort_keys=True) + "\n"
    (bundle / "public-keys.json").write_text(text, encoding="utf-8")


@dataclass(frozen=True)
class Tamper:
    change: Callable[[Path], None]
    # The checks that must fail, any one of them: the verifier names the one that caught it.
    checks: tuple[str, ...]
    # Built only when the verifier this ships with rejects it (see the export tool).
    conditional: bool = False


TAMPERS: dict[str, Tamper] = {
    "ledger-one-char-edit": Tamper(ledger_one_char_edit, ("hash_chain",)),
    "swapped-result": Tamper(swapped_result, ("signatures",)),
    "removed-timestamp": Tamper(removed_timestamp, ("timestamps",)),
    "plan-digest-mismatch": Tamper(plan_digest_mismatch, ("plan_versions",)),
    "key-substitution": Tamper(key_substitution, ("signing_keys", "signatures"), True),
}


def build_one(name: str, good: Path, out: Path) -> Path:
    """``out/<name>/evidence-bundle``: a copy of ``good`` with one tamper applied."""
    bundle = out / name / "evidence-bundle"
    if bundle.exists():
        shutil.rmtree(bundle)
    shutil.copytree(good, bundle)
    TAMPERS[name].change(bundle)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["bundle_digest"] = Bundle(bundle).digest()
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    manifest_path.write_text(text, encoding="utf-8")
    return bundle


def build(out: Path = HERE, good: Path = GOOD, names: list[str] | None = None) -> None:
    for name in names if names is not None else [n for n in TAMPERS if (HERE / n).is_dir()]:
        build_one(name, good, out)


if __name__ == "__main__":
    build(Path(sys.argv[1]) if len(sys.argv) > 1 else HERE)
