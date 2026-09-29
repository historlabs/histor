"""Loading, validating and digesting a sandbox plan.

The plan is the root of the evidence chain. Its digest appears in every run
attestation, so two things matter more than convenience:

* **One canonical form.** The digest is taken over a canonical JSON serialisation,
  not over the YAML bytes. Reformatting a plan, reordering its keys or rewriting its
  comments must not change what the attestation commits to; changing a threshold
  must.
* **Schema validation is not optional.** A plan that does not validate cannot be
  signed, committed or run against. The gate calls this before anything else.

Cross-references that JSON Schema cannot express — a test naming a dataset that the
plan does not declare, a test requesting a group the dataset does not carry — are
checked here in :func:`check_references`, and are as fatal as a schema error.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema import exceptions as js_exceptions

from histor.crypto.resources import resource

# Resolved when a plan is validated, not at import: an out-of-tree consumer vendors
# this module to read bundles and carries no schema.
SCHEMA = "spec/plan.schema.json"


class PlanError(ValueError):
    """A plan is not usable. Carries every problem found, not just the first."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        joined = "\n".join(f"  - {p}" for p in problems)
        super().__init__(f"{len(problems)} problem(s) in plan:\n{joined}")


@dataclass(frozen=True)
class Plan:
    """A validated plan, its canonical bytes, and the digest taken over them."""

    data: dict[str, Any]
    canonical: bytes
    digest: str

    @property
    def sandbox_id(self) -> str:
        return str(self.data["sandbox_id"])

    @property
    def is_signed(self) -> bool:
        """Both parties, per Art. 57(5). One signature is not agreement."""
        signatures = self.data.get("signatures") or {}
        return bool(signatures.get("provider")) and bool(signatures.get("regulator"))

    def dataset(self, dataset_id: str) -> dict[str, Any]:
        for dataset in self.data["datasets"]:
            if dataset["id"] == dataset_id:
                return dict(dataset)
        raise KeyError(dataset_id)

    def test(self, test_id: str) -> dict[str, Any]:
        for test in self.data["tests"]:
            if test["id"] == test_id:
                return dict(test)
        raise KeyError(test_id)


def load_schema() -> dict[str, Any]:
    with resource(SCHEMA).open(encoding="utf-8") as handle:
        schema: dict[str, Any] = json.load(handle)
    return schema


def canonicalise(data: dict[str, Any]) -> bytes:
    """Serialise a plan to the exact bytes its digest is taken over.

    Sorted keys, no insignificant whitespace, UTF-8 without escaping. This is the
    only place the on-disk format and the committed identity are allowed to differ.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def digest(data: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonicalise(data)).hexdigest()


def unsigned_digest(data: dict[str, Any]) -> str:
    """The digest the parties sign with their keys: the plan without ``signatures``,
    which cannot cover themselves. The plan's own digest, which the ledger records and
    every run cites, covers the signatures too."""
    return digest({key: value for key, value in data.items() if key != "signatures"})


def _schema_problems(data: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(
        load_schema(), format_checker=Draft202012Validator.FORMAT_CHECKER
    )
    problems = []
    for error in sorted(validator.iter_errors(data), key=js_exceptions.relevance):
        location = "/".join(str(part) for part in error.absolute_path) or "(root)"
        problems.append(f"{location}: {error.message}")
    return problems


def check_references(data: dict[str, Any]) -> list[str]:
    """Cross-references JSON Schema cannot reach.

    A test naming a dataset that does not exist, or disaggregating by a group the
    dataset does not carry, would otherwise validate cleanly and then fail at run
    time — after the plan had been signed.
    """
    problems: list[str] = []

    datasets = {d["id"]: d for d in data.get("datasets", []) if isinstance(d, dict)}
    seen_datasets: set[object] = set()
    for dataset in data.get("datasets", []):
        dataset_id = dataset.get("id") if isinstance(dataset, dict) else None
        if dataset_id in seen_datasets:
            problems.append(f"datasets: duplicate dataset id {dataset_id!r}")
        seen_datasets.add(dataset_id)

    seen_tests: set[object] = set()
    for index, test in enumerate(data.get("tests", [])):
        if not isinstance(test, dict):
            continue
        test_id = test.get("id")
        where = f"tests/{index} ({test_id})"
        if test_id in seen_tests:
            problems.append(f"{where}: duplicate test id {test_id!r}")
        seen_tests.add(test_id)

        dataset_id = test.get("dataset")
        if dataset_id is None:
            continue
        dataset = datasets.get(dataset_id)
        if dataset is None:
            problems.append(
                f"{where}: names dataset {dataset_id!r}, which the plan does not declare"
            )
            continue

        declared = set(dataset.get("groups") or [])
        for group in test.get("groups", []):
            if group not in declared:
                problems.append(
                    f"{where}: disaggregates by group {group!r}, "
                    f"which dataset {dataset_id!r} does not carry"
                )

    goals = (data.get("objectives") or {}).get("goals") or []
    for index, goal in enumerate(goals):
        for test_id in goal.get("evidenced_by", []):
            if test_id not in seen_tests:
                problems.append(
                    f"objectives/goals/{index} ({goal.get('id')}): evidenced by test "
                    f"{test_id!r}, which the plan does not declare"
                )

    seen_indicators: set[object] = set()
    for index, indicator in enumerate(data.get("process_indicators") or []):
        indicator_id = indicator.get("id")
        if indicator_id in seen_indicators:
            problems.append(
                f"process_indicators/{index}: duplicate process indicator id {indicator_id!r}"
            )
        seen_indicators.add(indicator_id)

    # Both optional: the check applies once the plan says what is in scope.
    in_scope = {r.get("reference") for r in data.get("requirements_in_scope") or []}
    for index, challenge in enumerate(data.get("regulatory_challenges") or []):
        reference = challenge.get("reference")
        if in_scope and reference is not None and reference not in in_scope:
            problems.append(
                f"regulatory_challenges/{index}: concerns {reference!r}, which "
                "requirements_in_scope does not list"
            )

    # The run_started entry names an agreement by id, so an id has to mean one document.
    seen_agreements: set[object] = set()
    for index, agreement in enumerate(data.get("agreements") or []):
        agreement_id = agreement.get("id") if isinstance(agreement, dict) else None
        if agreement_id in seen_agreements:
            problems.append(f"agreements/{index}: duplicate agreement id {agreement_id!r}")
        seen_agreements.add(agreement_id)

    for pointer in (data.get("confidentiality") or {}).get("confidential", []):
        if not _resolves(data, pointer):
            problems.append(f"confidentiality: {pointer!r} does not resolve in this plan")

    return problems


def _resolves(data: Any, pointer: str) -> bool:
    """Whether an RFC 6901 pointer names something in ``data``."""
    node = data
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list) and token.isdigit() and int(token) < len(node):
            node = node[int(token)]
        else:
            return False
    return True


def check_coherence(data: dict[str, Any]) -> list[str]:
    """Statements a plan can make that are individually valid and jointly wrong."""
    problems: list[str] = []

    timeframe = data.get("timeframe") or {}
    start, end = timeframe.get("start"), timeframe.get("end")
    if isinstance(start, str) and isinstance(end, str):
        try:
            if datetime.fromisoformat(start) >= datetime.fromisoformat(end):
                problems.append("timeframe: start is not before end")
        except ValueError:  # malformed dates are the schema's problem, not ours
            pass

    for index, dataset in enumerate(data.get("datasets", [])):
        if not isinstance(dataset, dict):
            continue
        where = f"datasets/{index} ({dataset.get('id')})"
        special = dataset.get("special_category") or {}
        retention = dataset.get("retention") or {}
        if special.get("contains_special_category") and not retention:
            problems.append(
                f"{where}: declares special-category data but no retention block; "
                "Art. 4 bis(1)(e) requires an erasure trigger"
            )
        if (
            special.get("contains_special_category")
            and special.get("anonymised") is False
            and not special.get("anonymisation_impact_note")
        ):
            problems.append(
                f"{where}: special-category data is not anonymised and no "
                "anonymisation_impact_note explains why"
            )

    for index, test in enumerate(data.get("tests", [])):
        if not isinstance(test, dict):
            continue
        where = f"tests/{index} ({test.get('id')})"
        thresholds = test.get("thresholds") or {}
        gap = thresholds.get("max_gap_between_groups")
        if gap is not None and len(test.get("groups", [])) < 2:
            problems.append(
                f"{where}: sets max_gap_between_groups but disaggregates by fewer than two groups"
            )
        if gap is not None and not test.get("statistics", {}).get("min_items_per_group"):
            problems.append(
                f"{where}: sets max_gap_between_groups without min_items_per_group; "
                "a between-group gap over an unstated sample size is not evidence"
            )
        if test.get("type") == "adversarial_robustness":
            problems.extend(_attack_budget_problems(where, test, data.get("limits") or {}))

    personal = data.get("personal_data")
    if isinstance(personal, dict):
        special = [
            d.get("id")
            for d in data.get("datasets", [])
            if isinstance(d, dict)
            and (d.get("special_category") or {}).get("contains_special_category")
        ]
        if special and personal.get("processed") is False:
            problems.append(
                "personal_data: says no personal data is processed, but datasets "
                f"{', '.join(map(str, special))} declare special-category data"
            )
        if personal.get("dpa_involvement") == "required" and not (data.get("roles") or {}).get(
            "dpa"
        ):
            problems.append("personal_data: DPA involvement is required but roles.dpa names nobody")
        if personal.get("processed") and not personal.get("legal_basis"):
            problems.append(
                "personal_data: personal data is processed but no legal_basis is given; "
                "outside Art. 59 the AI Act supplies none"
            )

    # Annex VII point 4.4: the tests the notified body may carry out itself.
    from histor.plan import nbtests

    problems.extend(nbtests.coherence_problems(data))
    return problems


# What a run needs from the centre, weakest first. A centre's personal_data_accepted
# must be at least what the plan's data needs.
_PERSONAL_DATA_LEVELS = ("none", "personal", "special_category")
_ACCEPTS = {
    "none": "accepts no personal data",
    "personal": "accepts personal data but not special-category data",
    "special_category": "accepts special-category personal data",
}

DEFAULT_LEASE_SECONDS = 300


def _data_of(plan: Plan | dict[str, Any]) -> dict[str, Any]:
    return plan.data if isinstance(plan, Plan) else plan


def centre(plan: Plan | dict[str, Any]) -> dict[str, Any] | None:
    """The plan's ``execution.centre`` block, or ``None`` if it declares no centre."""
    execution = _data_of(plan).get("execution")
    block = execution.get("centre") if isinstance(execution, dict) else None
    return dict(block) if isinstance(block, dict) else None


def lease_seconds(plan: Plan | dict[str, Any]) -> int:
    """How long a run at a centre may go on without a fresh lease.

    ``execution.centre.lease_seconds`` if the plan sets it, otherwise 300. The courier
    renews every third of this, and the length goes into the ``job_submitted`` entry.
    """
    block = centre(plan) or {}
    return int(block.get("lease_seconds", DEFAULT_LEASE_SECONDS))


def check_centre(data: dict[str, Any]) -> list[str]:
    """The plan's data must be allowed at the centre it runs at.

    What the data needs is read from what the plan already declares: special-category
    data if any dataset says ``contains_special_category``, personal data if
    ``personal_data.processed`` is true, and none otherwise. A plan that leaves
    ``personal_data`` out and declares no special-category dataset is taken at its
    word. The centre's ``personal_data_accepted`` must be at least that. Without an
    ``execution.centre`` block there is nothing to check.
    """
    block = centre(data)
    if block is None:
        return []
    name = block.get("name")
    accepted = block.get("personal_data_accepted")
    if accepted not in _PERSONAL_DATA_LEVELS:  # the schema's problem, not ours
        return []

    special = [
        str(d.get("id"))
        for d in data.get("datasets", [])
        if isinstance(d, dict)
        and (d.get("special_category") or {}).get("contains_special_category")
    ]
    personal = (data.get("personal_data") or {}).get("processed") is True
    rank = _PERSONAL_DATA_LEVELS.index(accepted)
    where = f"execution/centre ({name})"

    if special and rank < _PERSONAL_DATA_LEVELS.index("special_category"):
        return [
            f"{where}: datasets {', '.join(special)} declare special-category personal "
            f"data (GDPR Art. 9), but {name} {_ACCEPTS[accepted]}. Run with synthetic "
            "data there, or at a centre that accepts special-category data"
        ]
    if personal and rank < _PERSONAL_DATA_LEVELS.index("personal"):
        return [
            f"{where}: personal_data says personal data is processed, but {name} "
            f"{_ACCEPTS[accepted]}"
        ]
    return []


def attack_query_budget(test: dict[str, Any]) -> int:
    """The most calls an adversarial robustness test can make: a clean call and every
    attack's budget per item, plus decoys, at most one extra per round from rounding.

    The same arithmetic as ``histor.harness.adversarial.planned_queries``, restated here so
    the plan loader does not import the harness; a test holds the two together.
    """
    rounds = 1 + sum(int(a.get("queries_per_item", 0)) for a in test.get("attacks", []))
    decoys = float(test.get("decoy_fraction", 0.0))
    return math.ceil(int(test.get("max_items", 0)) * rounds * (1 + decoys)) + rounds


def _attack_budget_problems(where: str, test: dict[str, Any], limits: dict[str, Any]) -> list[str]:
    """A budget the relay's rate limit cannot deliver within the run's time limit
    would be cut short by rejections, and the attack success rate reported would be
    a lower bound nobody planned for."""
    rate = limits.get("max_requests_per_minute")
    minutes = limits.get("max_run_duration_minutes")
    if not rate or not minutes:
        return []
    budget = attack_query_budget(test)
    capacity = int(rate) * int(minutes)
    if budget > capacity:
        return [
            f"{where}: plans up to {budget} calls, more than the {capacity} the plan's rate "
            f"limit ({rate}/min) allows in its maximum run duration ({minutes} min)"
        ]
    return []


# Draft implementing act (December 2025), Art. 5(2): what a sandbox plan specifies
# "at least". Each element is paired with the plan fields that carry it.
ARTICLE_5_2 = (
    ("(a) applicant and AI system", ("participant",)),
    ("(b) timeline with an end date", ("timeframe",)),
    ("(c) objectives and scope of activities", ("objectives",)),
    ("(d) requirements and obligations in scope", ("requirements_in_scope",)),
    ("(e) personal data and DPA involvement", ("personal_data",)),
    ("(f) risk safeguards and serious-incident procedure", ("risk_management",)),
)


def article_5_gaps(data: dict[str, Any]) -> list[str]:
    """The Art. 5(2) elements this plan does not declare.

    Not fatal: the fields are optional in plan version 0.1 so that plans signed
    before they existed stay valid. `histor plan validate` prints these, and the
    written proof says what the plan left out. Point (g), a real-world testing plan,
    is not listed: this system does not test in real-world conditions.
    """
    return [label for label, fields in ARTICLE_5_2 if not all(data.get(f) for f in fields)]


# EUSAiR Union Sandbox Framework, Annex XI (sandbox plan template), known only from
# its slide summary (EUSAiR Session 1, slides 43-44): each section, with the plan
# fields that carry it. The Supplement on real-world testing is not listed; this
# system does not test in real-world conditions.
ANNEX_XI = (
    ("Project information", ("participant",)),
    ("Objectives & goals", ("objectives.goals",)),
    ("AI system description", ("participant.intended_purpose",)),
    ("Sandbox activities", ("objectives.activities", "objectives.cooperation")),
    ("Development constraints", ("development_constraints",)),
    ("Conditions", ("limits", "roles", "risk_management.safeguards")),
    ("Timeframe", ("timeframe", "timeframe.milestones")),
    (
        "Methodology",
        ("tests", "methodology.regulatory_flexibilities", "methodology.information_exchange"),
    ),
    ("Performance metrics", ("process_indicators",)),
    (
        "Requirements",
        (
            "requirements_in_scope",
            "regulatory_challenges",
            "risk_management",
            "complaints_procedure",
        ),
    ),
)


def _field(data: dict[str, Any], path: str) -> Any:
    node: Any = data
    for part in path.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    return node


def annex_xi_gaps(data: dict[str, Any]) -> list[str]:
    """The Annex XI sections this plan leaves partly or wholly empty, with the fields.

    Informational, like :func:`article_5_gaps`: Annex XI is a template, not law.
    """
    gaps = []
    for section, fields in ANNEX_XI:
        missing = [f for f in fields if not _field(data, f)]
        if missing:
            gaps.append(f"{section} ({', '.join(missing)})")
    return gaps


def narrow(data: dict[str, Any], test_ids: set[str], dataset_ids: set[str]) -> dict[str, Any]:
    """A copy of ``data`` keeping only these tests and datasets, and its references.

    The demo scripts derive a participation's plan from the example by dropping the
    tests and datasets it does not run. Goals then name tests that are gone, and a
    confidentiality pointer such as ``/datasets/1/processors`` would silently come
    to name a *different* dataset, so a value marked confidential would lose its
    marking. Pointers are renumbered here, and dropped with their target.
    """
    narrowed = copy.deepcopy(data)
    kept: dict[str, dict[int, int]] = {}
    for key, ids in (("tests", test_ids), ("datasets", dataset_ids)):
        old = narrowed.get(key, [])
        indices = [i for i, item in enumerate(old) if item.get("id") in ids]
        kept[key] = {old_index: new for new, old_index in enumerate(indices)}
        narrowed[key] = [old[i] for i in indices]

    # A goal whose every test is dropped is not pursued here; kept with no tests it
    # would read as one the authority assesses by hand.
    objectives = narrowed.get("objectives")
    if isinstance(objectives, dict):
        goals = []
        for goal in objectives.get("goals") or []:
            evidence = goal.get("evidenced_by")
            if evidence:
                goal["evidenced_by"] = [t for t in evidence if t in test_ids]
                if not goal["evidenced_by"]:
                    continue
            goals.append(goal)
        if goals:
            objectives["goals"] = goals
        else:
            del narrowed["objectives"]

    confidentiality = narrowed.get("confidentiality")
    if isinstance(confidentiality, dict):
        pointers = []
        for pointer in confidentiality.get("confidential", []):
            parts = pointer.split("/")
            if len(parts) > 2 and parts[1] in kept and parts[2].isdigit():
                new = kept[parts[1]].get(int(parts[2]))
                if new is None:
                    continue
                parts[2] = str(new)
            pointers.append("/".join(parts))
        confidentiality["confidential"] = pointers
    return narrowed


def validate(data: dict[str, Any]) -> None:
    """Raise :class:`PlanError` listing every problem, or return cleanly."""
    problems = _schema_problems(data)
    if not problems:
        # Only worth checking references once the shape is known to be right.
        problems = check_references(data) + check_coherence(data) + check_centre(data)
    if problems:
        raise PlanError(problems)


def load(path: Path | str) -> Plan:
    """Read, validate and digest a plan file."""
    path = Path(path)
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise PlanError([f"{path}: expected a YAML mapping at the top level"])
    validate(data)
    return Plan(data=data, canonical=canonicalise(data), digest=digest(data))
