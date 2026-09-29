"""Was every run the notified body initiated authorised as its plan says?

AI Act Annex VII point 4.4 lets the notified body carry out further tests. In the
sandbox such a run is marked ``initiated_by: notified_body`` in its ``run_started``
entry and in its attestation, with an ``authorisation`` naming what allowed it
(``histor/plan/nbtests.py``, ``spec/run-attestation.md`` section 5a). This check walks
that chain back through the ledger, from the bundle alone:

1. **The run.** Its ``run_started`` entry follows a ``gate_decision`` that allowed
   ``run_nb_test``, and says what the attestation says, initiated_by and
   authorisation alike.
2. **The proposal.** The entry the authorisation names is an ``nb_test_proposed``
   entry before the run, made by the notified body through the gate, with a
   justification, whose digest recomputes from its fields. The run tests that test and
   nothing else, and no decline came between them.
3. **The approvals, as the plan the run cites says.** Pre-authorised: the plan's
   ``notified_body_tests.allowed`` is true, the proposed test is within its limits, and
   every approver it names approved after the proposal and before the run, through
   the gate, with an IdP login bound to the proposal's digest by the person the plan
   names for that party. By amendment: the plan the run cites adopts the proposal, with
   the proposed test unchanged, and was put in force after the proposal and before the
   run (its signatures are ``plan_signatures``'s to check).
4. **The limits.** No more runs initiated by the notified body than the plan's
   ``notified_body_tests.max_runs``.

And the other way: a run not marked as the notified body's that reports a test its
plan does not list is a notified-body test run without its authorisation.

A separate module, run by :func:`histor.verifier.checks.verify_bundle` whenever the
ledger records a proposal or a run marked as the notified body's.
"""

from __future__ import annotations

from typing import Any

from histor.plan import nbtests
from histor.verifier.anchors import Anchors
from histor.verifier.checks import FAIL, PASS, WARN, CheckResult, _party_problems

ID = "nb_tests"
QUESTION = (
    "was every run the notified body initiated authorised as the plan it ran under says: "
    "its proposal, then the approvals or the amendment, then the run?"
)
NB_ENTRIES = frozenset({"nb_test_proposed", "nb_test_approved", "nb_test_declined"})


def applies(entries: list[dict[str, Any]], statements: list[dict[str, Any]]) -> bool:
    """Whether the bundle has anything this check reads."""
    return any(
        e["entry_type"] in NB_ENTRIES
        or (e["entry_type"] == "run_started" and "initiated_by" in e["body"])
        for e in entries
    ) or any("initiated_by" in s.get("predicate", {}) for s in statements)


def _decision(
    by_seq: dict[int, dict[str, Any]], seq: int, action: str, roles: set[str]
) -> str | None:
    """What is wrong with the gate decision that should precede the entry at ``seq``."""
    before = by_seq.get(seq - 1)
    body = before["body"] if before else {}
    if (
        before is None
        or before["entry_type"] != "gate_decision"
        or body.get("action") != action
        or body.get("allow") is not True
    ):
        return f"it does not follow a gate decision allowing {action}"
    if body.get("role") not in roles:
        return f"the gate decision allowing {action} was for the {body.get('role')}"
    return None


def _plan_at(
    entries: list[dict[str, Any]], plans: dict[str, dict[str, Any]], seq: int
) -> tuple[str | None, dict[str, Any] | None]:
    """The plan in force at ``seq``: the last version put in force before it."""
    digest = None
    for entry in entries:
        if entry["seq"] >= seq:
            break
        if entry["entry_type"] == "plan_signed":
            digest = str(entry["body"].get("plan_digest"))
    return digest, plans.get(digest) if digest else None


def _approval_problems(
    auth: dict[str, Any],
    proposal: dict[str, Any],
    started_seq: int,
    plan: dict[str, Any],
    by_seq: dict[int, dict[str, Any]],
    anchors: Anchors,
    weak: list[str],
) -> list[str]:
    from histor.identity import signature

    problems = []
    rules = nbtests.settings(plan)
    if rules.get("allowed") is not True:
        return ["the plan it ran under does not pre-authorise notified-body tests"]
    problems += [
        f"under the plan it ran under, {p}"
        for p in nbtests.spec_problems(plan, proposal["body"].get("test"))
    ]
    approvers = set(nbtests.approvers(plan))
    seen: set[str] = set()
    seqs = auth.get("approvals")
    if not isinstance(seqs, list):
        return [*problems, "its authorisation names no approvals"]
    for seq in seqs:
        entry = by_seq.get(seq) if isinstance(seq, int) else None
        if entry is None or entry["entry_type"] != "nb_test_approved":
            problems.append(f"ledger seq {seq} is not an approval")
            continue
        body = entry["body"]
        party = str(body.get("party"))
        where = f"the {party}'s approval (seq {seq})"
        if body.get("proposal_seq") != proposal["seq"] or body.get("proposal_digest") != (
            proposal["body"].get("proposal_digest")
        ):
            problems.append(f"{where} is of another proposal")
        if not proposal["seq"] < seq < started_seq:
            problems.append(f"{where} is not between the proposal and the run")
        if party not in approvers:
            problems.append(f"{where}: the plan does not name the {party} to approve")
        seen.add(party)
        decision = _decision(by_seq, seq, "approve_test", {party})
        if decision:
            problems.append(f"{where}: {decision}")
        problems += [f"{where}: {p}" for p in signature.verify(body)]
        found, loose = _party_problems(body, plan, anchors)
        problems += [f"{where}: {p}" for p in found]
        weak += [f"{where}: {w}" for w in loose]
        if signature.is_development(body):
            weak.append(f"{where} was made through the development IdP, and identifies nobody")
    missing = sorted(approvers - seen)
    if missing:
        problems.append(f"no approval by the {' and the '.join(missing)}, as the plan requires")
    return problems


def _amendment_problems(
    auth: dict[str, Any],
    proposal: dict[str, Any],
    started_seq: int,
    plan_digest: str | None,
    plan: dict[str, Any],
    by_seq: dict[int, dict[str, Any]],
) -> list[str]:
    problems = []
    test = proposal["body"].get("test") or {}
    adopted = nbtests.adopted(plan, proposal["seq"])
    if adopted is None:
        return [f"the plan it ran under does not adopt proposal {proposal['seq']}"]
    in_plan = next((t for t in plan.get("tests") or [] if t.get("id") == adopted), None)
    if in_plan != test:
        problems.append(f"the plan adopts test {adopted!r}, which is not the test proposed")
    signed = by_seq.get(auth.get("plan_signed_seq"))  # type: ignore[arg-type]
    if (
        signed is None
        or signed["entry_type"] != "plan_signed"
        or signed["body"].get("plan_digest") != plan_digest
        or auth.get("plan_digest") != plan_digest
    ):
        problems.append("its authorisation does not name the plan version it ran under")
    elif not proposal["seq"] < signed["seq"] < started_seq:
        problems.append("the amendment adopting it was not put in force between proposal and run")
    return problems


def check_nb_tests(
    entries: list[dict[str, Any]],
    statements: list[dict[str, Any]],
    plans: dict[str, dict[str, Any]],
    anchors: Anchors | None = None,
) -> CheckResult:
    anchors = anchors or Anchors()
    by_seq = {int(e["seq"]): e for e in entries}
    sandbox_id = str(entries[0]["sandbox_id"]) if entries else ""
    started: dict[int, dict[str, Any]] = {}
    for each in entries:
        if each["entry_type"] == "run_started" and "run_number" in each["body"]:
            started.setdefault(int(each["body"]["run_number"]), each)
    predicates = {int(s["predicate"]["run_number"]): s["predicate"] for s in statements}
    marked = sorted(
        {n for n, e in started.items() if "initiated_by" in e["body"]}
        | {n for n, p in predicates.items() if "initiated_by" in p}
    )
    problems: list[str] = []
    weak: list[str] = []
    nb_runs = 0
    for run in marked:
        entry, predicate = started.get(run), predicates.get(run)
        here = f"run {run}"
        if entry is None:
            problems.append(f"{here} is marked as the notified body's and was never started")
            continue
        body = entry["body"]
        if body.get("initiated_by") != nbtests.INITIATED_BY:
            problems.append(
                f"{here}: initiated_by {body.get('initiated_by')!r} is not the notified body"
            )
            continue
        if predicate is not None and (
            predicate.get("initiated_by") != body.get("initiated_by")
            or predicate.get("authorisation") != body.get("authorisation")
        ):
            problems.append(
                f"{here}: the attestation and the run_started entry say different things of who "
                "initiated it and what authorised it"
            )
        decision = _decision(by_seq, entry["seq"], "run_nb_test", {"notified_body", "regulator"})
        if decision:
            problems.append(f"{here}: {decision}")
        nb_runs += 1
        auth = body.get("authorisation")
        if not isinstance(auth, dict):
            problems.append(f"{here}: it names nothing that authorised it")
            continue
        proposal_entry = by_seq.get(auth.get("proposal_seq"))  # type: ignore[arg-type]
        if proposal_entry is None or proposal_entry["entry_type"] != "nb_test_proposed":
            problems.append(f"{here}: ledger seq {auth.get('proposal_seq')} is not a proposal")
            continue
        proposal = {"seq": proposal_entry["seq"], "body": proposal_entry["body"]}
        pbody = proposal_entry["body"]
        test = pbody.get("test") if isinstance(pbody.get("test"), dict) else {}
        if proposal["seq"] >= entry["seq"]:
            problems.append(f"{here}: its proposal comes after it")
        decision = _decision(by_seq, proposal["seq"], "propose_test", {"notified_body"})
        if decision:
            problems.append(f"{here}: its proposal: {decision}")
        if not str(pbody.get("justification") or "").strip():
            problems.append(f"{here}: its proposal gives no justification")
        digest = nbtests.digest_of(pbody, sandbox_id)
        if digest != pbody.get("proposal_digest") or digest != auth.get("proposal_digest"):
            problems.append(f"{here}: its proposal's digest does not recompute")
        if body.get("test_ids") != [test.get("id")]:
            problems.append(
                f"{here}: it ran {body.get('test_ids')}, not the proposed test {test.get('id')!r}"
            )
        if predicate is not None:
            reported = {r.get("test_id") for r in predicate.get("results") or []}
            if reported - {test.get("id")}:
                problems.append(
                    f"{here}: it reports {sorted(map(str, reported - {test.get('id')}))}, "
                    "which the proposal does not"
                )
        declined = [
            e["seq"]
            for e in entries
            if e["entry_type"] == "nb_test_declined"
            and e["body"].get("proposal_seq") == proposal["seq"]
            and e["seq"] < entry["seq"]
        ]
        if declined:
            problems.append(f"{here}: its proposal was declined (seq {declined[0]}) before it")
        if predicate is not None:
            plan_digest: str | None = str(predicate.get("plan_digest"))
            plan = plans.get(str(plan_digest))
        else:
            plan_digest, plan = _plan_at(entries, plans, entry["seq"])
        if plan is None:
            problems.append(f"{here}: the plan it ran under is not in the bundle")
            continue
        route = auth.get("route")
        if route == nbtests.PRE_AUTHORISED:
            found = _approval_problems(auth, proposal, entry["seq"], plan, by_seq, anchors, weak)
        elif route == nbtests.AMENDMENT:
            found = _amendment_problems(auth, proposal, entry["seq"], plan_digest, plan, by_seq)
        else:
            found = [f"route {route!r} is neither pre_authorised nor amendment"]
        problems += [f"{here}: {p}" for p in found]
        limit = nbtests.max_runs(plan)
        if limit is not None and nb_runs > limit:
            problems.append(f"{here} is the notified body's run {nb_runs}; the plan allows {limit}")

    # A run not marked as the notified body's that reports a proposed test the plan it
    # cites does not list: the test ran without the chain above.
    proposed = {
        str((e["body"].get("test") or {}).get("id"))
        for e in entries
        if e["entry_type"] == "nb_test_proposed"
    }
    for run, predicate in sorted(predicates.items()):
        if run in marked:
            continue
        listed = {
            t.get("id")
            for t in (plans.get(str(predicate.get("plan_digest"))) or {}).get("tests") or []
        }
        stray = sorted(
            str(r.get("test_id"))
            for r in predicate.get("results") or []
            if r.get("test_id") in proposed and r.get("test_id") not in listed
        )
        if stray:
            problems.append(
                f"run {run} reports the notified body's proposed test {', '.join(stray)}, which "
                "the plan it cites does not list, and it is not marked as the notified body's run"
            )

    if problems:
        return CheckResult(ID, QUESTION, FAIL, "; ".join(problems))
    proposals = sum(1 for e in entries if e["entry_type"] == "nb_test_proposed")
    said = (
        f"{nb_runs} run(s) initiated by the notified body, each authorised by its proposal "
        f"and the approvals or amendment its plan requires; {proposals} proposal(s) in all"
        if nb_runs
        else f"{proposals} notified-body proposal(s), and no run initiated by the notified body"
    )
    if weak:
        return CheckResult(ID, QUESTION, WARN, f"{said}; but {'; '.join(weak)}")
    return CheckResult(ID, QUESTION, PASS, said)
