"""The checks against trust anchors the verifier was given from outside the
bundle."""

from __future__ import annotations

import base64
from typing import Any

from histor.crypto import signing
from histor.crypto.timestamps import parse as parse_timestamp
from histor.verifier.anchors import NAMES as ANCHOR_NAMES
from histor.verifier.anchors import Anchors
from histor.verifier.checks._common import (
    FAIL,
    PASS,
    RECORDED_AT_TOLERANCE,
    WARN,
    CheckResult,
    _instant,
)
from histor.verifier.checks.bundle import software_records
from histor.verifier.checks.isolation import _signer
from histor.verifier.checks.keys import SigningKeys
from histor.verifier.checks.tee import tee_evidence_present

# --- 11. external anchors ---------------------------------------------------
#
# Every other check measures the bundle against what the bundle itself carries: its
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
    when there is TEE evidence or a plan that asks for it; the histor releases, when
    the ledger records which histor wrote it."""
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
    if entries is not None and software_records(entries):
        needed.append("releases")
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
