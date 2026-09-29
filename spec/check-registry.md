# Verifier check registry

Status: normative. The stable ids of the checks a Histor verifier emits for an
evidence bundle of format 0.3 (and legacy 0.1 and 0.2), what each means, which
requirements of [`evidence-bundle.md`](evidence-bundle.md) it enforces, and when it
fails or warns. The same content, for programs, is in
[`check-registry.json`](check-registry.json). The key words MUST, SHOULD and MAY are
to be interpreted as in BCP 14 (RFC 2119, RFC 8174) when in all capitals.

## Stability

A check id MUST NOT be renamed, removed while the bundle formats it checks are
still read, or reused with another meaning (B-11). A new check takes a new id. The
registry version changes when a check is added, and the conformance suite's expected
results name checks by these ids.

## Outcomes

Each result is `pass`, `fail` or `warn`. A bundle is verified exactly when no result
is `fail`. A warning never changes the exit code, and the verifier prints every
warning in full under "What this bundle does NOT establish".

**Anchored.** Several checks fail where they would otherwise warn when the verifier
was given *any* external anchor (`--anchors`, an `--expect-*` option, `--tsa-root`,
`--idp-keys`, `--signing-key`, `--control-plane-keys`, `--expect-head`,
`--checkpoint`, `--centre-keys`, `--vendor-roots`): the person asked for the
bundle to be held to something outside it. The registry marks these "fail instead of
warn when any anchor is given". `--in-progress` turns the missing ending of a
participation back into a warning for `completeness` (and only for it).

**Malformed input.** A check that cannot read a field it needs (missing, wrong type,
a token that does not parse) fails under its own id with the detail "the bundle is
malformed where <id> reads it". It never ends the verifier. If the verifier as a
whole cannot proceed, the command line emits the single result `malformed`.

## Order and short-circuits

Results are emitted in the order of the table. Some failures stop the run, and the
checks after them are not emitted:

1. `bundle_files` fails: nothing else runs, and nothing in the bundle is read.
2. `bundle_version` fails (unknown version or unreadable manifest): nothing else
   runs; the exit code is 2.
3. The ledger, a plan or `public-keys.json` cannot be read, or a ledger line is not an
   entry: `hash_chain` fails at that point and nothing else runs.
4. `signatures` fails: `statement_types` and every check after it is skipped.

The `anchor_*` checks are emitted only for the anchors given: `anchor_checkpoints`
after `report_renderings` and `nb_tests`, then `anchor_plan_digest`, `anchor_sandbox_id`,
`anchor_tsa_root`, `anchor_idp_keys`, `anchor_policy_digest`, `anchor_harness_digest`
and `anchor_ledger_head`, then `anchors`. The anchors `signing_keys`, `audience` and
`centre_keys` have no check of their own; they act inside `signing_keys`,
`signatures`, `harness_statements`, `plan_signatures`, `report_signature` and
`isolation`; `vendor_roots` has none either, and acts inside `tee_attestation`, which is
emitted only when a plan pins a `tee_policy` or the bundle holds TEE evidence.
`report_renderings` is emitted only when the ledger records a report, and
`nb_tests` only when it records a notified body's proposal or a run it initiated.

A test in the engine's suite (`tests/test_check_registry.py`, published with the
engine) holds this registry to the reference verifier: the ids here are exactly the ids its source can emit, the order and
"Enforces" columns match `check-registry.json`, and "Enforces" is what the coverage
table of `evidence-bundle.md` (section 19.1) names.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Verified: no check failed. Warnings may be present. |
| 1 | At least one check failed, including an anchor mismatch and malformed input. |
| 2 | No verdict: the directory has no `manifest.json`, the `bundle_version` is unknown or the manifest unreadable, an anchor cannot be read (missing, malformed, empty, or an unknown name in an anchors file), or the command line is invalid. |

## Output

With `--json` the verifier prints one object:

```json
{
  "verified": true,
  "counts": {"pass": 24, "fail": 0, "warn": 2},
  "results": [{"id": "hash_chain", "question": "…", "outcome": "pass", "detail": "…"}],
  "caveats": ["…"],
  "anchors": {"external": ["plan_digest"], "from_bundle": ["sandbox_id", "…"]}
}
```

The `id` and `outcome` of each result are normative; `question`, `detail` and
`caveats` are for people and MAY change between releases.

## Checks

"Enforces" lists the requirements whose *Check* names this check.

<!-- TABLE -->

| # | Check id | Meaning | Enforces | Fails when | Warns when | Anchors |
|---|---|---|---|---|---|---|
| 1 | `bundle_files` | Every path in the bundle is a regular file or a directory. Emitted only when it fails. | B-12 | a path is a symbolic link, FIFO, socket or device; nothing else is read and no other check runs | never | no effect |
| 2 | `bundle_version` | The manifest states a bundle_version this verifier reads. | B-3, B-4, B-5, B-19 | the manifest is unreadable or not an object, or the version is unknown; no other check runs and the CLI exits 2 | the version is legacy (0.1, 0.2) | no effect |
| 3 | `bundle_format` | The manifest's bundle_version is the one the ledger was written for. | B-21, B-22, B-141, B-146 | report_generated records another version; a legacy version with a signing_key_registered entry or a report_generated recording a version; with TSA roots, a legacy version whose ledger was stamped after that version was superseded; a current version whose last report_generated records no bundle_version | never | TSA roots enable the superseded-date rule |
| 4 | `signing_keys` | Each statement signer's keys come from an anchor or the ledger, and every copy of a key agrees. | B-34, B-35, B-36, B-90, B-91, B-92, B-93, B-147 | a recorded key is not Ed25519; two different keys under one key id; a copy differs from the chosen key; a signer in use has no key; the control-plane key was recorded after the first attestation | a signer in use has a key from public-keys.json alone (KEYS NOT ANCHORED) | fail instead of warn when any anchor is given; signing_keys anchors take precedence over the ledger |
| 5 | `signatures` | Each attestation is the envelope its run_attestation entry recorded, and verifies under the control plane's key. When it fails, every later check is skipped. | B-14, B-16, B-41, B-84, B-86, B-87, B-88, B-90, B-94, B-95 | attestations unreadable or absent; count differs from the ledger's run_attestation entries; an envelope differs by canonical digest; it does not verify under a control-plane key; its run number differs | never | control-plane anchors are the only keys used when given |
| 6 | `statement_types` | Every signed statement is of a type this verifier knows. | B-6, B-7, B-8, B-16 | an attestation or harness statement has an unknown predicateType; harness-statements.jsonl is unreadable | a statement uses the legacy namespace https://sandbox-mvp.dev/ | no effect |
| 7 | `hash_chain` | The ledger chain is intact: seq, prev_hash and entry_hash. Also emitted early, as a failure, when the ledger cannot be read. | B-14, B-16, B-17, B-26, B-27, B-28, B-29, B-30 | the ledger, plan or public-keys.json is unreadable or malformed (later checks are skipped); the ledger is empty; seq, prev_hash or entry_hash is wrong | never | no effect |
| 8 | `run_numbers` | Every run was started once, numbered without gaps, and ended in the ledger. | B-37, B-38, B-39, B-40, B-41 | no runs attested; a run started twice; numbers not contiguous from 1; attested twice or without a start; a run started and not ended (other than the last before exit); the ledger's attested runs differ from the bundle's | the last run has not ended and the participation has not exited | no effect |
| 9 | `plan_versions` | Every plan version the ledger records as signed is carried, hashes to its name, and plan.json is the one in force. | B-14, B-33, B-58, B-59, B-60 | a plan file does not hash to its name; no plan_signed entry; a signed version is missing; plan.json is not the version last put in force; plan.json is unreadable (the other checks still run) | never | no effect |
| 10 | `plan_signatures` | Every plan version put in force was signed by the people the plan names for each party. | B-63, B-64, B-65, B-66, B-67, B-68, B-70, B-71, B-72, B-73, B-74, B-75, B-76, B-77, B-78, B-81, B-82, B-163, B-164 | an IdP token does not verify, bind the digest, match the record, or is stale; the signer is not named in the plan's roles for the party; one principal signed for both parties; an amendment lacks the IdP signatures the original had (or method idp, or IdP keys given); recorded key signatures do not verify; a run cites a plan not in force before it started; with an audience anchor, aud or azp does not match; with a plan member naming an audience, aud or azp does not match it; under any anchor, a signer named by email only without a pinned issuer and a verified email | no IdP signatures at all (signed with sandbox keys); development IdP; a party matched by email alone | --idp-keys makes IdP signatures required; --expect-audience enables the aud check; any anchor turns an unpinned or unverified email-only signer into a failure |
| 11 | `report_signature` | The last exit report was signed by the regulator the plan in force names. | B-70, B-71, B-72, B-73, B-74, B-75, B-77, B-79, B-80, B-81, B-82, B-148, B-149, B-150, B-151, B-163, B-164 | a report signature with no report; a token that does not verify or is stale; signed by another party; signer not in roles.regulator; with an audience anchor, aud or azp does not match; its ledger_head is not in the ledger, not before the signature, or before the report it signs; the nonce does not commit to the head it records; under any anchor, an unpinned or unverified email-only signer | no report; the last report is unsigned (a draft); development IdP; email-only match; a signature that commits to no ledger head | --expect-audience enables the aud check; a missing signature fails completeness, not this check; any anchor turns an unpinned or unverified email-only signer into a failure |
| 12 | `artifact_digests` | Each run's model, harness and relay images match the pins of the plan version it cites. | B-62, B-69 | the cited plan is not carried; a subject is missing or differs from the pin | never | no effect |
| 13 | `dataset_commitments` | Every dataset a run used was committed, at that digest, before the run started, at the commitment the plan it cites pins. | B-115, B-116, B-117, B-119, B-165 | not committed; committed at another digest; committed after the run's first run_started; the plan the run cites lists datasets and does not admit this one, or pins another commitment | never | no effect |
| 14 | `isolation` | Isolation evidence is present and matches the plan and the backend. | B-120, B-121, B-122, B-123, B-124, B-125, B-126, B-127, B-128, B-129, B-130, B-131, B-132, B-157, B-158, B-159 | unknown backend or arm; backend and arm disagree; cilium policy digest differs or no drop log; hpc_centre signature, key, conversion, key release, weights release or undertaking problems; with --centre-keys, centre evidence not signed under a key given for that centre, or the bundle recording another key for it; an HPC key recorded after what it signs; under any anchor, a centre key only the bundle names or an operator key only in public-keys.json | any local_process run; any sound hpc_centre run (never passes); a refused key release (incident); a centre key only the bundle names, without anchors | --centre-keys are the only keys centre evidence verifies under; any anchor turns a bundle-only HPC key into a failure |
| 15 | `tee_attestation` | Each run's keys were released to a trusted execution environment whose hardware attestation report meets the plan's tee_policy and binds the key they were sealed to. Emitted only when a plan pins a tee_policy or the bundle holds TEE evidence. | B-173, B-174, B-175, B-176, B-177, B-178, B-179, B-180, B-181 | the plan a run cites pins a tee_policy and its key_released records no TEE evidence (a run refused its keys that ended halted is exempt); the evidence is malformed, its report or collateral does not hash to its digest, or its typed fields differ from the report; the chain does not verify to a root the policy lists for the platform, or with --vendor-roots to one given; a mock root under sev-snp or tdx; at the time the entry's timestamp signs, a certificate not valid, a required revocation list missing or not current, a chain certificate revoked, or the TCB information not current; the report's signature does not verify; the platform, measurement or init_data_digest is not the policy's, the TCB is below min_tcb, or debug is on; report_data does not bind the key the ledger says the keys were sealed to, for this run of the plan it cites; the run's isolation_evidence.tee or the provider's receipt names another report, or a run names a report no key_released records | platform mock, always (MOCK PLATFORM: NOT HARDWARE EVIDENCE); sev-snp or tdx while this implementation has been tested on synthetic structures only (UNVERIFIED IMPLEMENTATION); evidence under a plan with no tee_policy | --vendor-roots: the chain must also end at a root given |
| 16 | `run_logs` | Carried run logs hash to the digests their attestations carry. | B-133, B-134 | a log does not match its digest | a log whose digest is claimed is not carried | no effect |
| 17 | `harness_statements` | Each harness statement is ledger-recorded, signed by the harness (or scorer), and agrees with its attestation. | B-89, B-90, B-96, B-97, B-98, B-99, B-100, B-101, B-102, B-103, B-104, B-105 | a statement not recorded in the ledger; a cited statement missing; wrong key; fields or results differ; halted harness vs attestation; log coverage mismatch; driver/scorer disagreement | a run cites no harness statement | fail instead of warn when any anchor is given |
| 18 | `thresholds` | Every stated outcome follows from the numbers reported with it. | B-109, B-110, B-111, B-112 | held does not follow; outcome inconsistent; pass with a failing test; recomputed observed values or Wilson intervals disagree | never | no effect |
| 19 | `sample_sizes` | Whether any group was too small to be scored. | B-113 | never | any insufficient_sample group | no effect |
| 20 | `deletion` | Keys were destroyed after an exit the gate allowed. | B-43, B-44 | keys destroyed with no allowed exit; allowed exit without destruction; destruction before exit (a refused exit is not an exit) | no exit yet | no effect |
| 21 | `completeness` | The ledger ends as an ended participation does, and no file changed after the report. | B-23, B-24, B-42, B-45 | the last report's bundle_digest is not D(k) (always); a missing exit, destruction, report or regulator signature, when any anchor is given and not --in-progress | a missing ending without anchors, or with --in-progress | fail instead of warn when any anchor is given |
| 22 | `timestamps` | Every entry is stamped over its hash by a token that verifies, at the time it states, in chain order, near recorded_at. | B-32, B-46, B-47, B-48, B-49, B-50, B-51, B-52, B-53, B-54, B-55, B-56, B-57 | no entry or not every entry stamped; digest differs from entry_hash; token does not verify or chain; stated time is not the signed time; more than 10 minutes from recorded_at; more than 5 seconds backwards; a development token's signed digest is not the entry's hash | development tokens only, or a mix of kinds | no effect (anchor_tsa_root is separate) |
| 23 | `tsa_revocation` | The timestamp authority's certificate had not been revoked when it stamped, from the CA's answer kept beside each RFC 3161 token. | B-160, B-161, B-162 | revocation evidence present is not an OCSP response or CRL signed by the signer certificate's issuer (or a delegated responder), is about another certificate, is not current at genTime, or shows the certificate revoked by then | an RFC 3161 token carries no revocation evidence; the ledger holds no RFC 3161 token (development timestamps only) | with --tsa-root, the chain the evidence is checked against ends at the given roots |
| 24 | `personal_data` | The manifest says what personal data the bundle holds. | B-19, B-135, B-137 | 0.2 or later: personal_data differs from the derived object | 0.1: contains_personal_data is not true while personal data is present | no effect |
| 25 | `i18n_catalogues` | Each catalogue a translated rendering of the report was made with is in the bundle, as the ledger records it. Passes with nothing to check for a report in English only. | B-166, B-167, B-168, B-169 | a recorded catalogue is missing from i18n/<lang>/report.mo or hashes otherwise; a translated rendering records no catalogue_sha256; English or en-XA records one; two catalogues for one language; a catalogue no rendering records | never | no effect |
| 26 | `report_renderings` | The exit report is rendered in every language the plan names, the authentic one being the report the ledger committed to, each rendering named by hash in it. Emitted only when the ledger records a report. Implemented in histor/verifier/renderings.py. | B-170, B-171, B-172 | the plan names languages and the report entry records no renderings, or other languages; a language lacks a document; no single authentic pair; the authentic report or written proof is not the one the entry records; given the files, one hashes otherwise or the authentic report does not name another by hash | the renderings are recorded but their files were not available (--report-dir, or the bundle's parent directory) | no effect |
| 27 | `nb_tests` | Every run the notified body initiated was authorised as the plan it ran under says: its proposal, then the approvals or the amendment, then the run. Emitted only when the ledger records a notified-body proposal, approval or decline, or a run or attestation carries initiated_by. Implemented in histor/verifier/nb_tests.py. | B-183, B-184, B-185, B-186, B-187, B-188, B-189, B-190 | the run_started entry and the attestation disagree on initiated_by or authorisation; the run or its proposal does not follow the gate decision that allowed it; the proposal is missing, later than the run, unjustified, declined before the run, or its digest does not recompute; the run tests anything but the proposed test; pre-authorised: the plan it cites does not allow notified-body tests or admit the test, or an approver it names did not approve between proposal and run, or an approval's IdP token does not verify, bind the proposal's digest or name the person the plan names; by amendment: the plan it cites does not adopt the proposal unchanged, or was not put in force between proposal and run; more notified-body runs than notified_body_tests.max_runs; a run not marked as the notified body's reports a proposed test its plan does not list | an approval was made through the development IdP, or matches the plan's party by email only | any anchor turns an unpinned or unverified email-only approver into a failure, as for plan_signatures |
| 28 | `anchor_checkpoints` | The ledger extends every head checkpoint you were given. | B-153, B-154, B-155, B-156 | a checkpoint's control-plane signature or timestamp does not verify, or its timestamp is over something else or at another time; it names another sandbox; the ledger holds no entry at its seq with its head_hash; that entry was recorded after the checkpoint was made | a checkpoint carries a development timestamp | emitted only with --checkpoint; stands in for ledger_head in the anchors check |
| 29 | `anchor_plan_digest` | Every plan the bundle names is one whose digest you gave. | B-59, B-106 | a plan file does not hash to its name; a plan version, signing or run names another digest; no plan | never | emitted only with --expect-plan-digest |
| 30 | `anchor_sandbox_id` | The manifest, ledger, plans and runs name the sandbox id you gave. | B-25 | any of them names another | never | emitted only with --expect-sandbox-id |
| 31 | `anchor_tsa_root` | Every timestamp chains to a TSA root you gave. | B-49, B-53, B-54, B-140 | no entry stamped; a dev token; a token that does not chain to the given roots | never | emitted only with --tsa-root |
| 32 | `anchor_idp_keys` | Every plan and report signature was made with a key in the JWKS you gave. | B-83 | no IdP signature at all; a signature's JWK thumbprint is not in the set | never | emitted only with --idp-keys |
| 33 | `anchor_policy_digest` | Every plan version and run records the network policy digest you gave. | B-107 | a plan or run records another; no plan | never | emitted only with --expect-policy-digest |
| 34 | `anchor_harness_digest` | Every plan version and run records the harness image digest you gave. | B-108 | a plan or run records another; no plan | never | emitted only with --expect-harness-digest |
| 35 | `anchor_ledger_head` | The ledger holds the head you hold. | B-152 | the ledger ends before the head's seq (entries were cut from its end), or its entry there hashes otherwise (it was rewritten from that point) | never | emitted only with --expect-head |
| 36 | `anchors` | Which anchors were given from outside the bundle. | B-139 | never (a malformed-input failure only) | any anchor came from the bundle (ledger_head and checkpoints count as one; centre_keys only when a centre signed evidence; vendor_roots only when there is TEE evidence or a tee_policy) | passes when all are given |
| 37 | `bundle_digest` | No file changed after the manifest was written. Emitted last. | B-19, B-20 | manifest.bundle_digest is not D | never | no effect |
| 38 | `malformed` | The CLI's last resort: the bundle could not be read at all. Emitted by the CLI, not by verify_bundle. Every check reads what it needs inside itself, so the reference implementation reaches it only for input none of them foresaw. | B-144 | verify_bundle raised; this is then the only result | never | no effect |

<!-- /TABLE -->
