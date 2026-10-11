"""What each run cites and reports: the artifacts and datasets it used, its
logs, and the outcomes and sample sizes its numbers support."""

from __future__ import annotations

from typing import Any

from histor.ledger.bundle import (
    RUN_LOGS,
    Bundle,
    sha256_text,
)
from histor.verifier.checks._common import FAIL, PASS, WARN, CheckResult

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


def check_sample_sizes(
    statements: list[dict[str, Any]], plans: dict[str, dict[str, Any]] | None = None
) -> CheckResult:
    """A check on the evidence's strength, not its integrity. A pass on a group of
    four items is arithmetically correct and evidentially worthless, and the verifier is the last
    place anyone looks before relying on the number. So is a group the parties never
    agreed on, or an agreed group with no items: where the plan a run cites names a
    dimension's values (``group_values``), the groups scored are held to them."""
    question = "were any thresholds passed on samples too small to mean anything?"
    thin, stray, empty = [], [], []
    for statement in statements:
        predicate = statement["predicate"]
        run = predicate["run_number"]
        plan = (plans or {}).get(str(predicate.get("plan_digest"))) or {}
        named_values = plan.get("group_values")
        values: dict[str, Any] = named_values if isinstance(named_values, dict) else {}
        for result in predicate["results"]:
            scored: dict[str, set[str]] = {}
            for metric, attributes in (result.get("by_group") or {}).items():
                for attribute, groups in attributes.items():
                    scored.setdefault(attribute, set()).update(groups)
                    for value, measurement in groups.items():
                        if measurement.get("insufficient_sample"):
                            thin.append(
                                f"run {run} {result['test_id']} {metric} "
                                f"{attribute}={value} (n={measurement['n']})"
                            )
            for attribute, seen in sorted(scored.items()):
                named = values.get(attribute) or []
                if not named:
                    continue
                where = f"run {run} {result['test_id']}"
                stray += [f"{where} {attribute}={v}" for v in sorted(seen - set(named))]
                empty += [f"{where} {attribute}={v}" for v in named if v not in seen]
    said = []
    if thin:
        said.append(
            f"{len(thin)} group(s) fell below the plan's minimum and were not scored: "
            + ", ".join(thin[:5])
        )
    if stray:
        said.append(
            f"{len(stray)} group(s) scored that the plan's group values do not name: "
            + ", ".join(stray[:5])
        )
    if empty:
        said.append(
            f"{len(empty)} group value(s) the plan names had no items: " + ", ".join(empty[:5])
        )
    if said:
        return CheckResult("sample_sizes", question, WARN, "; ".join(said))
    return CheckResult("sample_sizes", question, PASS, "every scored group met the plan's minimum")


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
