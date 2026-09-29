# Threat model

What can go wrong in a sandbox participation, what Histor does about each threat,
what evidence that leaves in the bundle, and where the control is tested. The rule
behind the table: every control listed as built has a test that exercises it, because
a control without a test is a claim. The tests and `make` targets named here live in
the engine's test suite, which is published with the engine. This repository's
`tests/` covers only the package it ships.

The second half of this page lists the risks that are not solved. They are written
down rather than mitigated, so that nobody reads more into a verified bundle than it
carries.

## Threats and controls

| Threat | Control | Evidence it leaves | Where it is tested |
|---|---|---|---|
| The provider swaps the model after it passes | The model's digest is pinned in the signed plan; the gate refuses a mismatch | Gate denial entries; the digest in every attestation | `tests/test_gate.py::TestDenyPaths::test_wrong_model_digest` |
| The provider picks friendlier data | Commitments precede runs; the held-out set belongs to the test lab | `dataset_committed` entries ordered before `run_started` | `test_substituted_dataset`, `test_dataset_committed_by_the_wrong_role`, verifier `check_dataset_commitments` |
| The provider runs many times and reports the best | Monotonic run numbers, `max_runs`, contiguity checked | A gap in the run numbers | `test_over_max_runs`, `TestRunNumbers::test_a_missing_run_is_caught` |
| The model reads the test data store | No route from segment A to segment C; the relay is the only path | Cilium drops; the policy digest in the attestation | `test_segment_a_has_no_route_to_segment_c`; live: `make kind-isolation` (`connect_model_directly`, `resolve_model_name`) |
| The model sends data to the internet | Default-deny egress including DNS; the model has no egress rule at all | Cilium drops | `test_the_model_has_no_egress_rule_anywhere`; live: `make kind-isolation`, where `mock-evil` tries DNS, a segment A pod and the internet, and each attempt must appear as a Hubble drop |
| The model keeps images for later | Read-only root, memory-backed tmpfs, namespace deleted at teardown | Teardown evidence | `test_the_model_pod_is_locked_down`; live: `make kind-isolation` (`mock-evil`'s write is refused by the read-only root) |
| The model signals out through live telemetry: how fast it answers, how often the relay refuses it, where its refused packets were headed | Counts, the current test and the live drop feed go only to the roles that read results whole; the provider and the others see the run's phase | None needed: nothing reaches the provider to record | `tests/test_dashboard.py::TestRoleBoundaries::test_the_provider_cannot_watch_what_the_model_can_modulate` |
| The model hides data in its responses | Strict schema validation at the relay, which rejects rather than trims | A relay rejection in the hash log | `tests/test_relay_and_keys.py::TestResponseValidation` |
| The model infers groups or labels | Labels never leave segment A; shuffling, decoys, repeats | The harness configuration in the attestation | `test_no_label_or_id_reaches_the_model` |
| The ledger is rewritten | A hash chain, append-only enforced by the database, external timestamps | The verifier's chain check | `TestTampering`, `TestLedgerAppendOnly` |
| Unpinned files reach the harness in a sealed set | `seal` packs only the manifest and the files it lists; opening refuses any other member; the commitment refuses manifest paths that are absolute, use `..` or resolve outside the set | Refusal before the run; nothing to record | `tests/test_sealed_archive.py::test_seal_packs_only_the_manifest_and_what_it_lists`, `test_open_refuses_a_member_the_manifest_does_not_list`, `tests/test_dataset_commitment.py::test_a_path_outside_the_dataset_is_refused_under_every_scheme` |
| A crafted sealed set writes outside the harness's memory volume (tar-slip) | Every member is read into memory and checked first: regular files only (no symlinks, hard links, devices, FIFOs or directories), relative names with no `..`, no name twice; written into an empty directory with `O_EXCL` and `O_NOFOLLOW` | Refusal before the run | `tests/test_sealed_archive.py::test_open_refuses_tar_slip`, `test_open_refuses_a_member_twice` |
| The sealed set reveals who sealed it and when | Every member is packed with uid/gid 0, no user or group names, a fixed time and mode, and no time in the gzip header | None needed: the plaintext is the same whoever seals it | `tests/test_sealed_archive.py::test_sealing_is_deterministic_and_carries_no_owner_or_time` |
| The operator tampers with the harness | The harness digest is pinned; the key broker refuses a mismatched image | The attestation's digest; a refused key release | `test_a_different_harness_image_gets_nothing` |
| The operator changes a result after the run | The harness signs its measurements in segment A with a per-participation key released only to the pinned harness; the attestation cites the statement | The `harness_statements` verifier check; coverage recomputed from signed request ids | `TestHarnessStatements`, `test_a_signing_key_is_provisioned_released_and_destroyed_like_a_data_key` |
| The data is not deleted | Crypto-shredding; a signed `keys_destroyed` event | The verifier's deletion check | `TestKeyBroker`, `TestDeletion` |
| Numbers are reported that the run does not support | The verifier recomputes every threshold from the reported measurements | A recomputation mismatch | `TestThresholdRecomputation` |
| A pass is claimed on a group too small to mean anything | A minimum n per group in the plan; groups below it are not scored | `insufficient_sample` in the attestation; the verifier warns | `test_group_test_requires_min_items_per_group`, `check_sample_sizes` |
| Evidence from an unisolated run is passed off as sandbox evidence | The `local_process` isolation arm; the verifier refuses to treat it as evidence | A warning and a caveat in every verifier run | `test_local_process_isolation_warns_loudly` |
| Test data is sent to a hosted model without saying so | `hosted-vlm` runs on the local backend only, on synthetic data only; the backend records `model_egress` | The verifier and the report state where the data went | `test_attestation_says_where_the_data_went` |
| A participant's IdP administrator grants themselves the regulator role | Each IdP is capped at the roles it may vouch for; the plan names who holds each role | Login refused; no session | `tests/test_identity.py::TestTrust::test_roles_are_capped_at_what_the_idp_may_vouch_for`, `test_the_plan_decides_the_role_not_the_idp` |
| A user from another tenant signs in through a multi-tenant issuer | `require` pins `tid` or `hd` in the trust file | Login refused | `test_entra_uses_oid_and_the_tenant_pin` |
| The operator moves a party's signature to different plan terms | The signing login's nonce is derived from the plan digest, inside the IdP's signature | The verifier's `plan_signatures` fails | `TestPlanSignature::test_it_cannot_be_moved_to_other_terms`, `test_a_tampered_signature_fails_the_verifier` |
| Someone opens the test data unnoticed | `view_test_data` is a gate action; processors are named per dataset | Allow and deny entries in the ledger, in the DPA's view | `TestTheTestData` |
| A cross-site form acts with a signed-in person's cookie | A CSRF token on every form; `SameSite=Lax` | A 403, nothing recorded | `test_a_form_without_its_token_is_refused` |
| A provider pastes an API key into the console | Only credential references are accepted; the key is refused before the gate | Nothing recorded; the message says to rotate the key | `test_a_credential_itself_is_refused_before_it_reaches_the_gate` |
| The operator re-signs the bundle's attestations or harness statements with keys it ships in `public-keys.json` | Each must be the envelope the timestamped ledger recorded with its run; keys come from the ledger (`signing_key_registered`, recorded before the runs) or from `--signing-key` or `--control-plane-keys`; a key only `public-keys.json` holds fails under any anchor | `signatures`, `signing_keys`, `harness_statements` fail | `tests/test_verifier_adversarial.py::TestF1AttestationsBoundToTheLedger`, `TestRotatedControlPlaneKeys` |
| The operator rebuilds the ledger later and has a real authority stamp it afresh | The token's signed `genTime` must equal the stated time, lie within 10 minutes of `recorded_at`, and not go backwards along the chain; IdP logins are held to the same clock | `timestamps` fails | `TestF2TheAuthoritysTimeCounts` |
| The operator records one person's IdP login as another party's signature, or a login to another application | The token's issuer and subject or email must be someone the signed plan names for that party; the two parties must be different people; `--expect-audience` pins `aud` | `plan_signatures`, `report_signature` fail | `TestF3SignaturesBoundToParties` |
| The operator puts an amendment in force without both parties' signatures | Every plan version carries what the first did, whatever its `method` field says, and every run cites a version signed before it | `plan_signatures` fails | `TestF4AmendmentsSignedAsTheOriginal` |
| The operator cuts the ledger short, or changes files after the report | An ended participation must end with exit, deletion, a report and the regulator's signature; the report's `bundle_digest` is recomputed | `completeness` fails under any anchor | `TestF5Truncation` |
| The operator cuts the ledger after the regulator's signature, hands over a truncated bundle as "in progress", or rewrites entries before the signature and has them stamped again at their times | The report signature's nonce commits to the ledger head at signing; the verifier checks a head (`--expect-head`) or signed, stamped head checkpoints (`--checkpoint`) the regulator holds | `report_signature`, `anchor_ledger_head`, `anchor_checkpoints` fail | `tests/test_verifier_residual_risks.py::TestTheReportSignatureCommitsToTheHead`, `TestTheHeadYouHold`, `TestHeadCheckpoints` |
| The operator records its own key as the HPC centre's and signs the isolation evidence as the centre | The centre's key reaches the recipient from the centre (`--centre-keys`), and the ledger's `hpc_centre_key` must match it; a centre key only the bundle names fails under any anchor; keys must be recorded before what they sign | `isolation` fails | `tests/test_verifier_residual_risks.py::TestCentreKeys` |
| A timestamp authority certificate that was already revoked stamps the ledger | The stamping code fetches the certificate's OCSP or CRL status and refuses a revoked certificate; the status is kept with each token and checked offline against the token's chain | `tsa_revocation` fails (warns when absent) | `tests/test_verifier_residual_risks.py::TestTsaRevocation` |
| A login at an IdP that asserts another person's email is recorded as a party's signature | A signer the plan names by email only fails under any anchor unless the plan pins the issuer and the token has `email_verified: true`; the plan schema asks for `{issuer, subject}` | `plan_signatures`, `report_signature` fail | `tests/test_verifier_residual_risks.py::TestEmailOnlyParties` |
| The operator commits a dataset other than the one the plan pins, puts a plan in force mid-run, records a refused exit before destroying keys, or drops the format from a current report entry | The ledger's commitment must be the plan's pin; the cited plan must be in force before `run_started`; only an allowed exit counts; a 0.3 report entry must record its format | `dataset_commitments`, `plan_signatures`, `deletion`, `bundle_format` fail | `tests/test_verifier_residual_risks.py::TestFoundWritingTheSpec` |
| The operator hides a run, or runs twice under one number | Every `run_started` is unique, contiguous and ended by an attestation or a halt | `run_numbers` fails | `TestF6RunsStartedAndNotReported` |
| The operator relabels a bundle as an older, more leniently checked format | The format is recorded in the ledger (`report_generated.bundle_version`); a legacy claim over a later writer's entries, or stamped after that format was superseded, fails | `bundle_format` fails | `TestF8FormatDowngrade` |
| A certificate issued for anything else under a pinned TSA root stamps tokens | Issuers must be CAs allowed to sign certificates, within their path length and valid at `genTime`; the signer carries only the critical time-stamping usage | `timestamps`, `anchor_tsa_root` fail | `TestF9TimestampChain` |
| A bundle holds a link or a FIFO, or malformed JSON | The bundle is refused before it is read; a check that cannot read its input fails | `bundle_files` or the check fails; never a traceback | `TestLows` |

## Residual risks, stated rather than mitigated

These are real and unsolved. Writing them down is the mitigation available today.

**The model can still signal a little to the provider.** A few bits per run reach the
provider through what it may see: the run's phase and how long it took, the model's
pod or job state, restarts and exit code, and the aggregate outcome per test.
`max_runs` caps the total. The decision log is free text the model wrote, and it goes
into the bundle, which only the regulator and the notified body can fetch. A bundle
handed on to a provider must leave it out.

**The control plane vouches for the harness; hardware does not.** The key broker
releases a data key when the gate says the harness image digest matches and its
signature verifies. An operator who can run modified code inside the control plane can
mint a token for it. The planned answer is to condition key release on a
confidential-VM measurement instead. Phase P0 of that exists: typed TEE evidence
(`histor/crypto/tee/`), a plan's `artifacts.tee_policy`, a key broker and a provider's
releaser that release only on a report bound to the key they seal to, and the
verifier's `tee_attestation`, which checks every recorded report again offline. **The
residual risk is unchanged until phase P1.** Only the mock platform runs today. A mock
report is software that anyone holding the mock root's key can produce, so the
verifier warns on it every time; no confidential VM is in use; and the key broker that
checks the report is still the operator's software, so an operator who modifies it can
still release a key. P1 runs the harness in a confidential VM and moves custody of the
dataset key to a releaser the data owner runs. The roadmap and the key broker are
published with the engine.

**Development timestamps anchor nothing.** `DevAuthority` signs with the operator's
own key. An operator who can rebuild the ledger can reissue every timestamp with it.
The verifier reports this as a caveat on every bundle that carries them. RFC 3161
against a real authority is a deployment step, not a code change.

**The model can detect the test environment.** A system that behaves differently when
it believes it is being watched will pass a sandbox and fail in the field. The pinned
digest is what makes this checkable afterwards: the same digest has to be running in
production, and that is a post-market check, not a sandbox one. The report says so, so
that it reaches whoever does that check. The adversarial robustness test sharpens the
problem: its query-based attacks send near-identical variants of one image, and
interleaving them among decoys does not make them unlinkable to a model that keeps
in-memory state for the run and compares what it is shown. Such a model can answer
near-duplicates conservatively and report a lower attack success rate than an attacker
would get in the field. See `spec/run-attestation.md` §2a.

**Pixel-level side channels in the fixture.** `mock-good` reads an apparent
demographic band out of the image, which is the point of the fixture. A real model
could also key on something nobody put there on purpose. The sandbox measures outcomes,
not mechanisms, and a disparity is a disparity whatever produced it. But the harness
cannot say *why* a model failed, and the report should not imply otherwise.

**A single relay is a single point of trust.** Both sides trust it. That is why it is
the smallest component, standard library only, with its controls testable without
standing up a network. It is still the place where a compromise would be worth most.

**The drop log is what Hubble still held.** Each Cilium agent keeps recent flows in a
bounded ring buffer, 4,095 per node by default. The backend collects at the end of the
run, so a long or noisy run can lose its earliest drops, and the digest then covers a
shorter log than the run produced. The count is in the attestation, and a count at the
buffer size is a sign. Streaming the drops to storage during the run, or raising
`hubble.eventBufferCapacity`, closes this for real runs.

**Without gVisor the model has one boundary, not two.** Where the host cannot run
gVisor (the engine's kind notes say which hosts cannot), the model runs under the
node's default runtime: network policy, read-only root, no capabilities, no token,
but the host kernel. The backend reports which runtime the model had
(`container_runtime`), meant for the attestation's `hardware.container_runtime`, so
that it shows in the evidence instead of being assumed away. No in-cluster run writes
an attestation yet; until one does, the isolation check's `summary.json` is where it
is recorded.

**The control plane's key is the operator's.** The ledger binds each attestation to
the time its run ended, and the verifier checks it under the key recorded before the
runs. It cannot stop the operator signing a false attestation at the time and
recording it. What covers the numbers is the harness's statement, signed with a key the
operator does not hold outside the pinned harness. On the local backend, the demo's,
the operator holds that key too. Without a TSA root you hold, the key registrations
are the operator's word, as is the rest of the ledger.

**The end of the ledger is anchored only by a head someone else holds.** The
regulator's report signature commits to the ledger head when they signed, and the
verifier checks a bundle against a head (`--expect-head`) or head checkpoints
(`--checkpoint`) the recipient holds. What was written after the last head held
outside the operator is still the operator's word: a bundle checked with neither, or
with `--in-progress` and no recent checkpoint, may be a truncated one. Checkpoints are
only as frequent as the operator runs the engine's checkpoint command, and only as
independent as the regulator's keeping of them. The operator could issue two
checkpoints for one seq to two recipients, which only a shared public log (Sigstore
Rekor, not built) would show.

**The timestamp tolerances are windows.** An entry may be stamped up to 10 minutes
from its `recorded_at`, and up to 5 seconds before the entry preceding it. Within
those windows an operator writing entries at the time can order or date them as it
likes. The token's ESSCertID is not checked. The authority certificate's revocation
status is checked only where the stamping code could fetch it (an OCSP responder or a
CRL the certificate names): a token without it warns, and an operator can leave it
out. The status is the CA's answer on the day. A compromise the CA learns of later and
backdates shows only in a CRL or OCSP answer fetched later, which the bundle does not
hold.

**A party named by email.** A plan that names a signer by email only fails under any
anchor unless it pins the IdP and the token says the email was verified; then, and
always without anchors, it warns. What remains is the IdP's word that the address is
the person's today: an address can be reassigned, a subject cannot. Naming each signer
as `{issuer, subject}` in the plan removes this. Without `--expect-audience`, or an
`audience` for the signer in the plan, the audience of each login is not checked.

**Legacy bundles.** A 0.1 or 0.2 bundle's statement keys come from
`public-keys.json`, and its format can be relabelled to the other legacy version
undetectably unless its ledger was stamped by an authority whose root the verifier
holds. Plans signed with keys the sandbox holds (the demo's) are checked against the
parties' keys in `public-keys.json`, which only anchors can vouch for. Without
`--centre-keys`, a centre's key comes from the operator's ledger record or
`public-keys.json`; the verifier warns, and fails under any anchor, but a recipient
who gives no anchor at all reads the centre's word on the operator's say-so.

**Gate denial before effect, but not atomically.** The gate writes its decision to the
ledger and then acts. A crash between the two leaves a recorded intent with no effect,
which is the safe direction, but a reader should know the record can lead reality by
one step.
