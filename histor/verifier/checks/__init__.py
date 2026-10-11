"""The checks, plus what they refuse to assume.

Input is an evidence bundle; output is a verdict. No network, no data, no trust in
the operator who produced the bundle.

Two design rules run through all of it:

* **Recompute, never re-read.** Where the bundle states a conclusion — a threshold
  held, a run passed, a chain is intact — the verifier derives it again from the
  underlying numbers and compares. A verifier that reads ``"outcome": "pass"`` and
  reports a pass is a formatting tool.
* **Say what was not checked.** A bundle can be internally perfect and still prove
  very little: development timestamps prove no time, ``local_process`` isolation
  proves no isolation. Those are reported as prominently as failures, because a
  green tick on a bundle that establishes nothing is the worst output this tool
  could produce.

The checks live in one module per area. This package re-exports their public names,
and the few private helpers other modules use, so ``from histor.verifier.checks
import ...`` reads as it did when the checks were one file:

* ``_common``: the result and verdict types, and the helpers several areas share (a
  time as the ledger writes it, a statement's digest, a run's records, a raw key).
* ``keys``: ``signing_keys``, ``signatures``, ``statement_types``,
  ``harness_statements``.
* ``ledger``: ``hash_chain``, ``run_numbers``, ``deletion``, ``completeness``,
  ``timestamps``, ``tsa_revocation``.
* ``runs``: ``artifact_digests``, ``dataset_commitments``, ``run_logs``,
  ``thresholds``, ``sample_sizes``.
* ``isolation``: ``isolation``, with an HPC centre's claims, conversions, releases
  and undertaking.
* ``tee``: ``tee_attestation``.
* ``_parties``: whose login a party's signature is, shared by ``plan_signatures``,
  ``report_signature`` and ``nb_tests``.
* ``plans``: ``plan_versions``, ``plan_signatures``.
* ``reports``: ``report_signature``, ``i18n_catalogues``.
* ``anchors``: the ``anchor_*`` checks and ``anchors``.
* ``bundle``: ``bundle_files``, ``bundle_version``, ``bundle_format``,
  ``personal_data``, ``software_release``, ``bundle_digest``.
* ``verify``: :func:`verify_bundle`, which runs them in the order
  spec/check-registry.md gives.

``report_renderings`` and ``nb_tests`` are modules of their own beside this package
(:mod:`histor.verifier.renderings`, :mod:`histor.verifier.nb_tests`).
"""

from __future__ import annotations

from histor.verifier.checks._common import (
    FAIL,
    LEDGER_FIELDS,
    PASS,
    RECORDED_AT_TOLERANCE,
    WARN,
    CheckResult,
    Verdict,
    _canonical_digest,
)
from histor.verifier.checks._parties import LOGIN_BEFORE_RECORDING, SIGNING_PARTIES, _party_problems
from histor.verifier.checks.anchors import (
    _situational_anchors,
    check_anchor_checkpoints,
    check_anchor_harness_digest,
    check_anchor_idp_keys,
    check_anchor_ledger_head,
    check_anchor_plan_digest,
    check_anchor_policy_digest,
    check_anchor_sandbox_id,
    check_anchor_tsa_root,
    check_anchors,
)
from histor.verifier.checks.bundle import (
    FORMAT_MARKERS,
    SUPERSEDED,
    check_bundle_digest,
    check_bundle_files,
    check_bundle_format,
    check_bundle_version,
    check_personal_data,
    check_software_release,
    software_records,
)
from histor.verifier.checks.isolation import (
    ISOLATION_BY_BACKEND,
    PINNED_COMPONENTS,
    SIGNERS,
    check_isolation,
)
from histor.verifier.checks.keys import (
    DRIVER_TYPE,
    KEY_ENTRIES,
    KEY_ROLES,
    RELAY_COUNTED,
    SigningKeys,
    check_harness_statements,
    check_signatures,
    check_signing_keys,
    check_statement_types,
    resolve_signing_keys,
    signer_of,
)
from histor.verifier.checks.ledger import (
    ORDER_TOLERANCE,
    check_completeness,
    check_deletion,
    check_hash_chain,
    check_run_numbers,
    check_timestamps,
    check_tsa_revocation,
    signed_time_problem,
)
from histor.verifier.checks.plans import check_plan_signatures, check_plan_versions
from histor.verifier.checks.reports import (
    UNTRANSLATED_LANGUAGES,
    check_i18n_catalogues,
    check_report_signature,
)
from histor.verifier.checks.runs import (
    COMPARISONS,
    check_artifact_digests,
    check_dataset_commitments,
    check_run_logs,
    check_sample_sizes,
    check_thresholds,
    recompute_observed,
)
from histor.verifier.checks.tee import check_tee_attestation, tee_evidence_present
from histor.verifier.checks.verify import MALFORMED, _report_dir, verify_bundle

__all__ = [
    "COMPARISONS",
    "DRIVER_TYPE",
    "FAIL",
    "FORMAT_MARKERS",
    "ISOLATION_BY_BACKEND",
    "KEY_ENTRIES",
    "KEY_ROLES",
    "LEDGER_FIELDS",
    "LOGIN_BEFORE_RECORDING",
    "MALFORMED",
    "ORDER_TOLERANCE",
    "PASS",
    "PINNED_COMPONENTS",
    "RECORDED_AT_TOLERANCE",
    "RELAY_COUNTED",
    "SIGNERS",
    "SIGNING_PARTIES",
    "SUPERSEDED",
    "UNTRANSLATED_LANGUAGES",
    "WARN",
    "CheckResult",
    "SigningKeys",
    "Verdict",
    "_canonical_digest",
    "_party_problems",
    "_report_dir",
    "_situational_anchors",
    "check_anchor_checkpoints",
    "check_anchor_harness_digest",
    "check_anchor_idp_keys",
    "check_anchor_ledger_head",
    "check_anchor_plan_digest",
    "check_anchor_policy_digest",
    "check_anchor_sandbox_id",
    "check_anchor_tsa_root",
    "check_anchors",
    "check_artifact_digests",
    "check_bundle_digest",
    "check_bundle_files",
    "check_bundle_format",
    "check_bundle_version",
    "check_completeness",
    "check_dataset_commitments",
    "check_deletion",
    "check_harness_statements",
    "check_hash_chain",
    "check_i18n_catalogues",
    "check_isolation",
    "check_personal_data",
    "check_plan_signatures",
    "check_plan_versions",
    "check_report_signature",
    "check_run_logs",
    "check_run_numbers",
    "check_sample_sizes",
    "check_signatures",
    "check_signing_keys",
    "check_software_release",
    "check_statement_types",
    "check_tee_attestation",
    "check_thresholds",
    "check_timestamps",
    "check_tsa_revocation",
    "recompute_observed",
    "resolve_signing_keys",
    "signed_time_problem",
    "signer_of",
    "software_records",
    "tee_evidence_present",
    "verify_bundle",
]
