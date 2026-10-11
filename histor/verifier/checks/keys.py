"""Signing keys, signatures, the statements' types, and the harness's own
signed statements: whose key each statement is checked under, and that it verifies."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

from histor.crypto import namespace, signing
from histor.ledger.bundle import (
    Bundle,
)
from histor.verifier.anchors import Anchors
from histor.verifier.checks._common import (
    FAIL,
    PASS,
    WARN,
    CheckResult,
    _canonical_digest,
    _raw_key,
)

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


# --- harness statements -----------------------------------------------------


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
