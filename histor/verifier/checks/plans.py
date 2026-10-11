"""The plan: every version the ledger records is in the bundle, and each
was signed by the parties whose agreement it needs."""

from __future__ import annotations

import base64
from typing import Any

from histor.crypto import signing
from histor.crypto.canonical import canonical_json_ascii
from histor.plan import digest as plan_digest
from histor.verifier.anchors import Anchors
from histor.verifier.checks._common import FAIL, PASS, WARN, CheckResult, _of_run
from histor.verifier.checks._parties import (
    SIGNING_PARTIES,
    _login_time_problems,
    _party_problems,
    _principal,
)

# --- plan versions -----------------------------------------------------------


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


# --- 9. who signed the plan -----------------------------------------------


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
    payloads = [canonical_json_ascii({"plan_digest": d}) for d in signed_digests]
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


def _verifies(payload: bytes, key_id: str, sig: str, key: dict[str, str]) -> bool:
    envelope = {
        "payloadType": signing.PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
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
