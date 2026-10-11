""":func:`verify_bundle`: runs every check, in the registry's order
(spec/check-registry.md), and turns a malformed bundle into a failure, never a
traceback."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from histor.crypto import signing
from histor.ledger.bundle import (
    Bundle,
)
from histor.verifier.anchors import Anchors
from histor.verifier.checks._common import FAIL, LEDGER_FIELDS, CheckResult, Verdict
from histor.verifier.checks.anchors import (
    _situational_anchors,
    check_anchor_checkpoints,
    check_anchors,
)
from histor.verifier.checks.bundle import (
    check_bundle_digest,
    check_bundle_files,
    check_bundle_format,
    check_bundle_version,
    check_personal_data,
    check_software_release,
    software_records,
)
from histor.verifier.checks.isolation import check_isolation
from histor.verifier.checks.keys import (
    SigningKeys,
    check_harness_statements,
    check_signatures,
    check_signing_keys,
    check_statement_types,
    resolve_signing_keys,
)
from histor.verifier.checks.ledger import (
    check_completeness,
    check_deletion,
    check_hash_chain,
    check_run_numbers,
    check_timestamps,
    check_tsa_revocation,
)
from histor.verifier.checks.plans import check_plan_signatures, check_plan_versions
from histor.verifier.checks.reports import (
    _plan_in_force,
    check_i18n_catalogues,
    check_report_signature,
)
from histor.verifier.checks.runs import (
    check_artifact_digests,
    check_dataset_commitments,
    check_run_logs,
    check_sample_sizes,
    check_thresholds,
)
from histor.verifier.checks.tee import check_tee_attestation, tee_evidence_present

# --- orchestration ----------------------------------------------------------

# What malformed input raises in a check that reads it: a field missing or of the
# wrong type, a value out of range, a signature that does not parse. It fails the
# bundle; it never stops the verifier with a traceback.
MALFORMED = (
    KeyError,
    TypeError,
    ValueError,
    AttributeError,
    IndexError,
    OverflowError,
    UnicodeError,
    RecursionError,
    OSError,
    signing.VerificationError,
)


def _malformed(check_id: str, error: BaseException) -> CheckResult:
    return CheckResult(
        check_id,
        "is the bundle well formed where this check reads it?",
        FAIL,
        f"the bundle is malformed where {check_id} reads it ({type(error).__name__}: "
        f"{error}): an altered bundle, or one this verifier cannot read",
    )


def _runner(verdict: Verdict) -> Any:
    def run(check_id: str, check: Any, *args: Any) -> CheckResult:
        try:
            result = check(*args)
        except MALFORMED as error:
            result = _malformed(check_id, error)
        added: CheckResult = verdict.add(result)
        return added

    return run


def _current_plan(bundle: Bundle) -> dict[str, Any] | None:
    """``plan.json``, where the bundle also carries ``plans/``: the plan the manifest
    says the runs were judged against, which must be one of the versions."""
    if not (bundle.root / "plans").is_dir():
        return None  # plan.json is the one version, read as plans already
    plan: Any = bundle.read_json("plan.json")
    if not isinstance(plan, dict):
        raise TypeError("plan.json is not a plan object")
    return plan


def _report_dir(bundle: Bundle, entries: list[dict[str, Any]], given: Path | None) -> Path | None:
    """Where the report's renderings are: the directory given, or else the bundle's own
    parent when it holds every file the last ``report_generated`` entry records (the
    demo and ``histor run`` write them there). The files are checked against the hashes
    the ledger records, so where they came from does not matter to the verdict."""
    if given is not None:
        return given
    body: Any = next(
        (e["body"] for e in reversed(entries) if e["entry_type"] == "report_generated"), {}
    )
    recorded = body.get("renderings") if isinstance(body, dict) else None
    if not isinstance(recorded, list) or not recorded:
        return None
    parent = bundle.root.resolve().parent
    names = [str(i.get("file")) for i in recorded if isinstance(i, dict)]
    if names and all(
        Path(n).name == n and not n.startswith(".") and (parent / n).is_file() for n in names
    ):
        return parent
    return None


def verify_bundle(
    bundle: Bundle,
    anchors: Anchors | None = None,
    in_progress: bool = False,
    report_dir: Path | None = None,
    before_report: bool = False,
) -> Verdict:
    """``anchors`` are what the verifier holds from outside the bundle; any it does not
    give are taken from the bundle, and the verdict says which. ``in_progress`` says the
    participation has not ended, so a ledger without its ending only warns.
    ``report_dir`` is where the report and its renderings were written, if the verifier
    holds them; without it, the bundle's parent directory is used when it holds them.
    ``before_report`` says this verdict is for the exit report about to be written,
    which quotes it: the report and its signature cannot be in the ledger yet."""
    anchors = anchors or Anchors()
    external = anchors.external()
    verdict = Verdict(
        anchors={
            "external": external,
            "from_bundle": anchors.from_bundle(),
        }
    )

    refused = check_bundle_files(bundle)
    if refused is not None:
        verdict.add(refused)
        verdict.caveats.append("later checks were skipped: the bundle holds special files")
        return verdict

    try:
        manifest = bundle.read_manifest()
        if not isinstance(manifest, dict):
            raise TypeError("the manifest is not a JSON object")
        version_result = verdict.add(check_bundle_version(manifest))
    except (OSError, ValueError, TypeError) as error:
        version_result = verdict.add(
            CheckResult(
                "bundle_version",
                "is this a bundle format this verifier knows how to check?",
                FAIL,
                f"the manifest is unreadable: {error}",
            )
        )
    if version_result.outcome == FAIL:
        verdict.caveats.append("later checks were skipped: the bundle's format is unknown")
        return verdict

    try:
        entries = bundle.read_jsonl("ledger.jsonl")
        plans = bundle.plan_versions()
        public_keys = bundle.read_json("public-keys.json")
        if not isinstance(public_keys, dict) or not all(
            isinstance(v, str) for v in public_keys.values()
        ):
            raise ValueError("public-keys.json is not an object of key id to PEM")
        if not all(isinstance(p, dict) for p in plans.values()):
            raise ValueError("a plan version is not a plan object")
    except (OSError, ValueError, TypeError, AttributeError) as error:
        # A ledger that no longer parses has been altered, and says so by failing,
        # not by taking the verifier down with it.
        verdict.add(
            CheckResult(
                "hash_chain",
                "is the ledger hash chain intact, with no gaps?",
                FAIL,
                f"the ledger or plan in the bundle is unreadable: {error}",
            )
        )
        verdict.caveats.append("later checks were skipped: the ledger could not be read")
        return verdict

    # A flipped byte can leave valid JSON with a field renamed. That is an altered
    # ledger too, and the checks below would otherwise stop on the missing key.
    malformed = next(
        (
            position + 1
            for position, entry in enumerate(entries)
            if not isinstance(entry, dict)
            or not entry.keys() >= LEDGER_FIELDS
            or not isinstance(entry["body"], dict)
        ),
        None,
    )
    if malformed is not None:
        verdict.add(
            CheckResult(
                "hash_chain",
                "is the ledger hash chain intact, with no gaps?",
                FAIL,
                f"ledger line {malformed} is not a well-formed entry: it was altered",
            )
        )
        verdict.caveats.append("later checks were skipped: the ledger could not be read")
        return verdict

    run = _runner(verdict)
    run("bundle_format", check_bundle_format, manifest, entries, anchors)
    keys = SigningKeys()
    statements: list[dict[str, Any]] = []
    try:
        keys = resolve_signing_keys(entries, public_keys, anchors)
        signature_result, statements = check_signatures(bundle, entries, keys)
        if not all(
            isinstance(s, dict) and isinstance(s.get("predicate"), dict) for s in statements
        ):
            raise TypeError("an attestation's statement carries no predicate object")
    except MALFORMED as error:
        signature_result = _malformed("signatures", error)
    run("signing_keys", check_signing_keys, keys, entries, statements, bool(external))
    verdict.add(signature_result)
    if signature_result.outcome == FAIL:
        verdict.caveats.append("later checks were skipped: nothing here can be trusted")
        return verdict
    run("statement_types", check_statement_types, bundle, statements)

    run("hash_chain", check_hash_chain, entries)
    run("run_numbers", check_run_numbers, entries, statements)
    # plan.json is read inside the check, so a plan.json that does not parse fails
    # plan_versions and the other checks still run.
    run(
        "plan_versions",
        lambda: check_plan_versions(entries, plans, _current_plan(bundle)),
    )
    run(
        "plan_signatures",
        check_plan_signatures,
        entries,
        plans,
        anchors,
        public_keys,
        statements,
    )
    run("report_signature", check_report_signature, entries, plans, anchors)
    run("artifact_digests", check_artifact_digests, plans, statements)
    run("dataset_commitments", check_dataset_commitments, entries, statements, plans)
    run(
        "isolation",
        check_isolation,
        plans,
        statements,
        public_keys,
        entries,
        anchors.centre_keys,
        bool(external),
    )
    if tee_evidence_present(plans, statements, entries):
        run(
            "tee_attestation",
            check_tee_attestation,
            plans,
            statements,
            entries,
            public_keys,
            anchors.vendor_roots,
        )
    run("run_logs", check_run_logs, bundle, statements)
    run(
        "harness_statements",
        check_harness_statements,
        bundle,
        statements,
        keys,
        entries,
        bool(external),
    )
    run("thresholds", check_thresholds, statements)
    run("sample_sizes", check_sample_sizes, statements, plans)
    run("deletion", check_deletion, entries)
    run(
        "completeness",
        check_completeness,
        bundle,
        entries,
        bool(external),
        in_progress,
        before_report,
    )
    run("timestamps", check_timestamps, entries, public_keys)
    run("tsa_revocation", check_tsa_revocation, entries, public_keys, anchors.tsa_root)
    run("personal_data", check_personal_data, bundle, manifest)
    run("i18n_catalogues", check_i18n_catalogues, bundle, entries)
    if software_records(entries):
        run("software_release", check_software_release, entries, anchors.releases)
    if any(e["entry_type"] == "report_generated" for e in entries):
        # A separate module that imports this one; loaded here to keep it that way.
        from histor.verifier.renderings import ID as RENDERINGS
        from histor.verifier.renderings import check_report_renderings

        run(
            RENDERINGS,
            check_report_renderings,
            entries,
            _plan_in_force(entries, plans),
            _report_dir(bundle, entries, report_dir),
        )
    # The notified body's own tests (Annex VII point 4.4), when the ledger has any.
    from histor.verifier import nb_tests

    if nb_tests.applies(entries, statements):
        run(nb_tests.ID, nb_tests.check_nb_tests, entries, statements, plans, anchors)
    if anchors.checkpoints:
        run(
            "anchor_checkpoints",
            check_anchor_checkpoints,
            anchors.checkpoints,
            entries,
            manifest,
            keys,
            public_keys,
            anchors.tsa_root,
        )
    needed = _situational_anchors(statements, entries, plans)
    verdict.anchors["from_bundle"] = anchors.from_bundle(needed)
    try:
        for result in check_anchors(anchors, manifest, entries, plans, statements, needed):
            verdict.add(result)
    except MALFORMED as error:
        verdict.add(_malformed("anchors", error))
    run("bundle_digest", check_bundle_digest, bundle, manifest)

    for warning in verdict.warnings:
        verdict.caveats.append(f"{warning.id}: {warning.detail}")
    return verdict
