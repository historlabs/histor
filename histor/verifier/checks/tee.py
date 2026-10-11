"""Hardware attestation of a key release, checked again offline."""

from __future__ import annotations

import datetime
from typing import Any

from histor.crypto import signing
from histor.crypto.timestamps import parse as parse_timestamp
from histor.crypto.timestamps import verify_token
from histor.verifier.checks._common import FAIL, PASS, WARN, CheckResult, _instant, _of_run

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
