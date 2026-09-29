"""Tests the notified body carries out itself: what the plan allows, and how to read it.

AI Act Annex VII, point 4.4: the notified body may carry out further tests. In the
sandbox, a notified body's test is a test like any other (one of the harness's built-in
types, against a committed dataset, under the gate) and the plan stays the single
source of authority for it. The plan's optional ``notified_body_tests`` field says
which of two routes a proposal takes:

* **Pre-authorised** (``allowed: true``). The plan already agrees, within its limits
  (``test_types``, ``datasets``, ``max_runs``), that the notified body may test. Each
  approver the plan names (the regulator, and the provider when the plan says so)
  approves a proposal by a fresh login at their own identity provider bound to the
  proposal's digest, as a plan is signed. No amendment: the plan the parties signed
  already covers it.
* **By amendment** (no field, or ``allowed: false``). The regulator and the provider
  put a new version of the plan in force that carries the proposed test, unchanged,
  in ``tests`` and names the proposal under ``notified_body_tests.adopted``. The
  amendment is signed by both parties like the original.

This module is the plan's side: the rules a proposal is held to, and the digest that
approvals bind to. The gate (``histor.gate``) and the verifier
(``histor.verifier.nb_tests``) both read it; neither trusts the other's record of it.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema import exceptions as js_exceptions

# The legal basis a proposal records, whatever its justification says.
LEGAL_BASIS = "AI Act Annex VII, point 4.4"

# Who initiated a run, as the run_started entry and the attestation say it.
INITIATED_BY = "notified_body"

# The harness's built-in test types, from the plan schema's enum.
BUILT_IN_TYPES = (
    "accuracy_by_group",
    "rate_by_group",
    "robustness",
    "determinism",
    "decision_logging",
    "adversarial_robustness",
    "fail_safe",
)

PRE_AUTHORISED = "pre_authorised"
AMENDMENT = "amendment"

JUSTIFICATION_LIMIT = 4000


def settings(plan: dict[str, Any]) -> dict[str, Any]:
    """The plan's ``notified_body_tests``, or an empty mapping."""
    value = plan.get("notified_body_tests")
    return value if isinstance(value, dict) else {}


def pre_authorised(plan: dict[str, Any]) -> bool:
    return settings(plan).get("allowed") is True


def route(plan: dict[str, Any]) -> str:
    """How a proposal made under this plan is approved."""
    return PRE_AUTHORISED if pre_authorised(plan) else AMENDMENT


def approvers(plan: dict[str, Any]) -> list[str]:
    """Who approves under the pre-authorisation; under an amendment, both parties sign."""
    if not pre_authorised(plan):
        return ["provider", "regulator"]
    return sorted({str(a) for a in settings(plan).get("approvers") or ["regulator"]})


def max_runs(plan: dict[str, Any]) -> int | None:
    value = settings(plan).get("max_runs")
    return int(value) if isinstance(value, int) and not isinstance(value, bool) else None


def adopted(plan: dict[str, Any], proposal_seq: int) -> str | None:
    """The id of the test this plan version adopts for a proposal, if it does."""
    for item in settings(plan).get("adopted") or []:
        if isinstance(item, dict) and item.get("proposal") == proposal_seq:
            return str(item.get("test_id"))
    return None


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def proposal_digest(
    sandbox_id: str, plan_digest: str, test: Any, justification: str, proposed_by: str
) -> str:
    """What an approval binds to: the test as proposed, why, by whom, under which plan.

    Recomputed by the verifier from the ``nb_test_proposed`` entry, so an approval
    cannot be moved to a test other than the one it was given for."""
    material = {
        "type": "sandbox-nb-test-proposal/v1",
        "sandbox_id": sandbox_id,
        "plan_digest": plan_digest,
        "test": test,
        "justification": justification,
        "proposed_by": proposed_by,
    }
    return "sha256:" + hashlib.sha256(canonical(material)).hexdigest()


def digest_of(body: dict[str, Any], sandbox_id: str) -> str:
    """The digest of a recorded proposal, from the fields that make it up."""
    return proposal_digest(
        sandbox_id,
        str(body.get("plan_digest")),
        body.get("test"),
        str(body.get("justification", "")),
        str(body.get("proposed_by", "")),
    )


def _test_validator() -> Draft202012Validator:
    from histor.plan import load_schema

    schema = load_schema()
    return Draft202012Validator(
        {"$ref": "#/$defs/test", "$defs": schema["$defs"]},
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def with_test(plan: dict[str, Any], test: dict[str, Any]) -> dict[str, Any]:
    """The plan the harness is given for a pre-authorised test: the plan in force, and
    the proposed test beside its own. The run still cites the plan in force."""
    out = copy.deepcopy(plan)
    if not any(t.get("id") == test.get("id") for t in out.get("tests") or []):
        out["tests"] = [*(out.get("tests") or []), copy.deepcopy(test)]
    return out


def spec_problems(plan: dict[str, Any], test: Any) -> list[str]:
    """Why a proposed test is not one this plan lets the notified body run; empty if it is.

    A built-in type the plan admits, parameters within the schema's ranges for that
    type, a dataset the plan declares (and admits for notified-body tests), and the
    cross-checks the plan's own tests are held to. Its id must be new."""
    if not isinstance(test, dict):
        return ["a proposed test is an object, as a test in the plan is"]
    problems = []
    for error in sorted(_test_validator().iter_errors(test), key=js_exceptions.relevance):
        where = "/".join(str(p) for p in error.absolute_path) or "(test)"
        problems.append(f"the proposed test's {where}: {error.message}")
    if problems:
        return problems
    rules = settings(plan)
    kind = test.get("type")
    allowed_types = rules.get("test_types") or list(BUILT_IN_TYPES)
    if kind not in allowed_types:
        problems.append(
            f"test type {kind!r} is not one the plan admits for notified-body tests "
            f"({', '.join(allowed_types)})"
        )
    if any(t.get("id") == test.get("id") for t in plan.get("tests") or []):
        problems.append(
            f"the plan already has a test {test.get('id')!r}; a proposal takes a new id"
        )
    dataset_id = test.get("dataset")
    if dataset_id is not None:
        declared = {d.get("id") for d in plan.get("datasets") or []}
        if dataset_id not in declared:
            problems.append(
                f"dataset {dataset_id!r} is not declared in the plan; new data is an amendment, "
                "committed through the test lab"
            )
        elif rules.get("datasets") and dataset_id not in rules["datasets"]:
            problems.append(
                f"dataset {dataset_id!r} is not one the plan admits for notified-body tests "
                f"({', '.join(rules['datasets'])})"
            )
    if not problems:
        from histor.plan import check_coherence, check_references

        combined = with_test(plan, test)
        index = len(combined["tests"]) - 1
        where = f"tests/{index} ("
        problems += [
            p.replace(where, "the proposed test (", 1)
            for p in check_references(combined) + check_coherence(combined)
            if p.startswith(where)
        ]
    return problems


def coherence_problems(plan: dict[str, Any]) -> list[str]:
    """What the plan loader checks of ``notified_body_tests`` beyond its schema."""
    rules = settings(plan)
    if not rules:
        return []
    problems = []
    declared = {d.get("id") for d in plan.get("datasets") or [] if isinstance(d, dict)}
    for dataset_id in rules.get("datasets") or []:
        if dataset_id not in declared:
            problems.append(
                f"notified_body_tests: admits dataset {dataset_id!r}, which the plan does not "
                "declare"
            )
    tests = {t.get("id") for t in plan.get("tests") or [] if isinstance(t, dict)}
    seen: set[Any] = set()
    for item in rules.get("adopted") or []:
        if item.get("proposal") in seen:
            problems.append(
                f"notified_body_tests: proposal {item.get('proposal')} is adopted twice"
            )
        seen.add(item.get("proposal"))
        if item.get("test_id") not in tests:
            problems.append(
                f"notified_body_tests: adopts proposal {item.get('proposal')} as test "
                f"{item.get('test_id')!r}, which the plan does not declare"
            )
    limit = (plan.get("limits") or {}).get("max_runs")
    if (
        isinstance(rules.get("max_runs"), int)
        and isinstance(limit, int)
        and rules["max_runs"] > limit
    ):
        problems.append(
            f"notified_body_tests: max_runs {rules['max_runs']} is more than the plan's "
            f"limits.max_runs {limit}"
        )
    return problems


def adopt(plan: dict[str, Any], proposal_seq: int, test: dict[str, Any]) -> dict[str, Any]:
    """The amendment that approves a proposal on the amendment route: the plan with the
    proposed test, unchanged, and the proposal adopted. Unsigned: both parties sign it
    as any amendment, and the gate puts it in force."""
    out = with_test(plan, test)
    out.pop("signatures", None)
    rules = dict(settings(out)) or {"allowed": False}
    rules["adopted"] = [
        *(rules.get("adopted") or []),
        {"proposal": int(proposal_seq), "test_id": str(test["id"])},
    ]
    out["notified_body_tests"] = rules
    return out
