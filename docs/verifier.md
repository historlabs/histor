# Verifying an evidence bundle

This guide is for the staff of a notified body or a market surveillance authority who
have been handed the evidence bundle of a sandbox participation and have to decide
what it proves. `histor verify` runs on your own machine, with no network, no access
to the test data, and no need to trust the operator who produced the bundle.

One idea runs through the whole guide. A bundle carries the values it is checked
against: the plan, the public keys, the timestamp authority's root certificate, the
keys each identity provider signed with. Checked against those alone, a bundle shows
that it agrees with itself and nothing more. An operator who rebuilt it from scratch
could replace every one of those values consistently, and the rebuilt bundle would
verify. So you bring the values you can obtain **independently of the operator**
(section 4). The verifier then fails the bundle where it does not match them and
tells you about every value you did not bring.

## 1. Install

You need Python 3.12 or later. From a checkout of the repository, at the commit or
release you have reviewed:

```sh
git clone https://github.com/historlabs/histor && cd histor
python3 -m venv .venv && . .venv/bin/activate
pip install .
histor verify --version
# histor verify 0.1.0 (bundle_version 0.1, 0.2, 0.3)
```

You can also install a released wheel, after checking it against its signature and
provenance; the release page says how. A plain install is the core only: the verifier
and the plan validator, with five dependencies (asn1crypto, cryptography, jsonschema,
pyyaml, rfc3339-validator) and nothing that runs a participation.

To satisfy yourself that the check makes no network calls, run it without a network:
in a container started with `--network none`, or on a machine unplugged after the
install.

When you cite a verdict, quote the `--version` line with it. A bundle's
`manifest.json` states its `bundle_version`. The verifier refuses any version it does
not list, with exit code 2, rather than check the bundle as if it were a format it
knows. Otherwise a check the verifier did not know to run would pass unnoticed. A
newer bundle needs a newer verifier.

## 2. Commands

```sh
# Check the bundle against itself only. The verdict warns that every anchor came
# from the bundle.
histor verify evidence-bundle

# Check it against anchors you hold.
histor verify evidence-bundle \
  --expect-sandbox-id sbx-2026-014 \
  --expect-plan-digest sha256:4f1c…   --expect-plan-digest sha256:9b07… \
  --tsa-root freetsa-root.pem \
  --idp-keys regulator-idp-jwks.json \
  --expect-policy-digest sha256:9a0e… \
  --expect-harness-digest sha256:77b2…

# The same anchors, kept in one file per participation.
histor verify evidence-bundle --anchors sbx-2026-014.anchors.yaml

# Machine-readable output, for a case file.
histor verify evidence-bundle --anchors sbx-2026-014.anchors.yaml --json

# A participation that has not ended. The missing exit, deletion and signed report
# warn instead of failing. The head checkpoints you were given show whether the
# ledger was cut short.
histor verify evidence-bundle --anchors sbx-2026-014.anchors.yaml --in-progress \
  --checkpoint head-2026-10-01.json --checkpoint head-2026-10-15.json

# The ledger head the regulator saw when they signed the exit report.
histor verify evidence-bundle --anchors sbx-2026-014.anchors.yaml \
  --expect-head 57:sha256:3c9e…

# A report rendered in several languages: each rendering is hashed against the
# ledger. Without --report-dir, the bundle's parent directory is used when it holds
# the renderings.
histor verify evidence-bundle --report-dir ./reports

# Keys released on hardware attestation reports: hold the vendors' roots yourself.
histor verify evidence-bundle --vendor-roots amd-ark-milan.pem --vendor-roots intel-sgx-root.pem
```

An anchors file holds any of the same values. Relative paths resolve against the
file's own directory. A misspelt key makes the verifier refuse the whole file rather
than ignore the key, because an ignored key would fall back silently to the bundle's
own value:

```yaml
sandbox_id: sbx-2026-014
plan_digest:                     # every version you signed, if the plan was amended
  - sha256:4f1c…
  - sha256:9b07…
tsa_root: [freetsa-root.pem]     # PEM certificates
idp_keys: regulator-idp-jwks.json
policy_digest: sha256:9a0e…
harness_digest: sha256:77b2…
signing_keys:                    # Ed25519 public keys, PEM, by the key id that signs
  control-plane: control-plane.pem
control_plane_keys: cp.jwks      # or every version of the control plane's key
audience: [histor-console]       # the console's client id at each party's IdP
ledger_head: "57:sha256:3c9e…"   # a ledger head you hold, <seq>:sha256:<hex>
checkpoints: [head-2026-10-01.json, head-2026-10-15.json]  # head checkpoints you kept
centre_keys: centres.jwks        # each HPC centre's signing key, from the centre
vendor_roots: [amd-ark-milan.pem] # TEE vendors' root certificates, from the vendors
```

A flag on the command line replaces the file's value for the same anchor.
`--tsa-root` and `--expect-plan-digest` can be repeated. A digest may be written as
`sha256:<hex>` or as bare hex.

With `--json`, the output records which anchors you gave and which were read from the
bundle:

```json
"anchors": {"external": ["plan_digest", "sandbox_id", "idp_keys"],
            "from_bundle": ["tsa_root", "policy_digest", "harness_digest"]}
```

## 3. What each check proves, and what it does not

Every check recomputes its result from the underlying data. None of them trusts a
conclusion the bundle states about itself. A warning does not change the exit code.
Warnings are printed last and in full, under "What this bundle does NOT establish".
Read them as closely as you would read a failure.

| Check | What a pass proves | What it does not prove |
|---|---|---|
| `bundle_files` | Appears only when it fails: a path in the bundle is a symbolic link, a FIFO or a device. Nothing in the bundle is read then, because a link could make the verifier hash a file outside the bundle and a FIFO could hang it. | — |
| `bundle_version` | The verifier knows this bundle format. A legacy format (0.1, 0.2) warns that its guarantees are weaker. | Anything about the contents. |
| `bundle_format` | The manifest's `bundle_version` is the one the ledger was written for: the one its `report_generated` entry records, and for a legacy version, no entry that only a later writer records (`signing_key_registered`). With `--tsa-root`, a legacy bundle whose ledger was stamped after that format was superseded (0.1 on 2026-09-27, 0.2 on 2026-09-28) fails. A current-format bundle whose last `report_generated` entry records no `bundle_version` fails. | That a legacy bundle stamped with development timestamps, or read without a TSA root, was not relabelled. |
| `signing_keys` | Each statement signer's public key (the control plane's, the harness's, the scorer's) came from your `--signing-key` or from the ledger, where it was recorded before the runs, and every other copy of it in the bundle is the same key (`spec/run-attestation.md` §1c). | That the operator did not sign a false attestation with its own key at the time. A key read from `public-keys.json` alone warns `KEYS NOT ANCHORED` and fails once you give any anchor. |
| `signatures` | Each attestation in `attestations.jsonl` is, by digest, the envelope the ledger's `run_attestation` entry recorded for its run, one for one, and verifies under the control plane's key and no other. | That the control plane attested truthfully. The harness's statement covers the measurements. |
| `statement_types` | Every run attestation and harness or driver statement is of a type this verifier knows, under `https://historlabs.eu/`. A bundle from before the rename uses `https://sandbox-mvp.dev/` and warns. | Anything about the statements' contents. |
| `hash_chain` | The ledger has not been edited, reordered or truncated in the middle since it was written. | That the operator did not rebuild the whole chain. Timestamps and anchors cover that. |
| `run_numbers` | Every run the gate started (`run_started`) was started once, the numbers have no gaps, and each run ended in the ledger with an attestation or a halt. Every attestation belongs to a run the gate started, once. A run started and never ended fails, except the last run of a participation that has not exited, which warns. | That no run happened outside the sandbox. |
| `plan_versions` | Every plan version the ledger records as signed is in the bundle, and each plan file hashes to the digest it is filed under. The digest is recomputed from the file every time, with or without `--expect-plan-digest`. `plan.json`, which the manifest calls the plan the runs were judged against, is the version last put in force. | That it is the plan *you* signed. That is `anchor_plan_digest`. |
| `plan_signatures` | Each identity-provider token verifies against its recorded key, its nonce commits to the plan digest, and its signer is the party the entry says: the token's `iss` with its `sub` or `email` matches someone the signed plan names under `roles` for that party (`provider` or `regulator`), and the two parties are different people. With `--expect-audience`, each login was to that application. Every plan version put in force, amendments included, carries the signatures the first one did, whatever its `method` field says: both parties' IdP signatures recorded before it, if the original had them or you gave `--idp-keys`; otherwise the `signatures` it records must verify under each party's key over that plan. Every run cites a plan version signed before the run started. Where the plan names a signer with an `audience`, their login must have been to it. | That the recorded key was the IdP's; that is `anchor_idp_keys`. A warning here means the sandbox's own keys or the development IdP signed, or that the plan names a party by email only rather than by issuer and subject. A plan should name each signer as `{issuer: <iss URL>, subject: <sub>}`. A signer named by email alone fails once you give any anchor, unless the plan pins the IdP (`{issuer, email}`) and the token carries `email_verified: true`. A bare email is an address any IdP whose key you accept could assert; an unverified one is an address nobody checked. The same holds for `report_signature`. |
| `report_signature` | The regulator's token commits to the exit report's SHA-256, and its signer is someone the plan in force names as the regulator, bound as for `plan_signatures`. A signature made from 2026-09-28 onwards also commits, in the token's nonce, to the ledger head when the regulator signed (`ledger_head`: the last entry's seq and hash). The ledger must hold that entry, before the signature and not before the report. Through the chain, that fixes every entry up to it, the `report_generated` entry and its bundle digest included, so a ledger rewritten before that point fails even if every entry was stamped again at its own time. A signature without a head warns. | The report's contents: hash your copy and compare it with `report_generated`. Anything written after the signature. |
| `artifact_digests` | Each run's model, harness and relay images match the pins of the plan version the run cites. | That the images do what their documentation says. |
| `dataset_commitments` | Each dataset was committed before the run that used it, at the digest it was used at, and that commitment is the one the cited plan pins for the dataset (`datasets[].commitment`). A dataset the plan does not admit fails. | Anything about the data itself, which you never see. |
| `isolation` | The isolation evidence exists and matches the plan's network policy. For a run at an HPC centre, the signature over the job record and node configuration, and each image conversion, verifies under the signer's key recorded in the ledger before it (`hpc_centre_key`, `hpc_operator_key`), or, for a centre, under the key you gave with `--centre-keys`, which the ledger's record must then match. A centre's key that only the bundle names (the ledger's record, which the operator writes, or `public-keys.json`), or an operator's key found only in `public-keys.json`, warns, and fails once you give any anchor. | For a local run: any isolation at all (it warns). For a centre run: anything beyond the centre's signed word. |
| `tee_attestation` | Appears only when a plan pins `artifacts.tee_policy` or the bundle holds TEE evidence. Each run's `key_released` holds the hardware attestation report its keys were released on, with the collateral captured then. The report is checked again offline with the code the key broker and the provider's releaser ran: its certificate chain to a root the plan's policy lists (and to one you gave with `--vendor-roots`), every certificate valid, a current revocation list from each issuer that must issue one and nothing revoked, all as of the time the release was stamped; the report's signature; the policy's launch measurement, launch configuration (`init_data_digest`) and minimum TCB; debug off; and its `report_data`, which must bind the key the ledger says the keys were sealed to, for this run of the plan it cites. A run under a `tee_policy` with no such evidence fails. The mock platform always warns (`MOCK PLATFORM: NOT HARDWARE EVIDENCE`). SEV-SNP and TDX evidence warns too, because this verifier's checks for them have been tested on synthetic structures only. | That the measured code is free of flaws, or anything about side channels, physical attacks or availability. Hardware attestation shows which code the key went to, not what that code does. |
| `run_logs` | The logs in the bundle hash to the digests the signed attestations carry. | That the logs are complete beyond what the harness recorded. |
| `harness_statements` | Every statement in `harness-statements.jsonl` is one the ledger recorded with a run's attestation, the harness signed what it measured under the harness key (the scorer's under `scorer`), and the attestation agrees with it. A run whose attestation cites no harness statement warns, and fails once you give any anchor: its numbers then rest on the operator's control plane alone. | That the harness measured correctly. That depends on the harness image, which is pinned. |
| `thresholds` | Every pass or fail follows from the numbers reported with it. | That the thresholds were the right ones. That was decided when the plan was agreed. |
| `sample_sizes` | Warns when any threshold was passed on a group too small to support a conclusion. | — |
| `deletion` | The ledger records that the keys were destroyed after an exit the gate allowed. A refused request to exit is not an exit. | That no copy of the data was made before exit. |
| `completeness` | The ledger ends the way an ended participation's does: the regulator's exit, the keys' destruction after it, an exit report after that, and the regulator's signature over the last report. The last `report_generated` entry's `bundle_digest` is recomputed over every file as it is now and the ledger up to the entry before, and must match, so no file changed after the report. A missing ending warns, and fails once you give any anchor, unless you pass `--in-progress`. | That nothing happened after the last entry. A ledger cut after the report's signature, or a bundle checked with `--in-progress`, cannot be told from one that ended there unless you hold a later head; `anchor_ledger_head` and `anchor_checkpoints` check that. |
| `timestamps` | Every ledger entry carries a timestamp; every timestamp covers its entry's hash (for a development token, the digest inside what it signs, not only the one beside it) and chains to a pinned root; and the time each token *signs* (RFC 3161 `genTime`) is the one stated beside it, lies within 10 minutes of the entry's `recorded_at`, and does not go backwards along the chain by more than 5 seconds. The pass names the span the ledger was stamped over. The rules are spelt out below. | That the root is a real authority's; that is `anchor_tsa_root`. Development timestamps anchor nothing and warn. |
| `tsa_revocation` | The timestamp authority's certificate had not been revoked when it stamped. Beside each RFC 3161 token the stamping code keeps the CA's answer as fetched at the time: an OCSP response from the responder the certificate names, or else its CRL. It is checked offline: signed by the signer certificate's issuer in the token's chain (under your `--tsa-root` when given) or by a responder that issuer delegated to; about that certificate; current at the stamped time (produced no more than 10 minutes after it, not expired before it, and with no next update, no more than a day before it); and not saying revoked before then. Evidence that fails any of these fails. A token without it warns, as does a ledger with only development timestamps, which carry none. | That the CA's own records are true. That the certificate was not revoked later for a compromise reaching back before the token; a CRL or OCSP answer says revoked from when. |
| `i18n_catalogues` | Each catalogue that a translated rendering of the report was made with is in the bundle as `i18n/<lang>/report.mo` and hashes to the `catalogue_sha256` the last `report_generated` entry records for that language. A rendering in a language other than English (or the `en-XA` pseudo-locale) that records no catalogue fails; so does a catalogue that no rendering records, or two catalogues for one language. A report in English only passes with nothing to check. | That the translation is right. A catalogue is what the rendering was made with, not a legal review of it. |
| `report_renderings` | Runs whenever the ledger records a report. The last `report_generated` entry records a rendering of the exit report and the written proof in every language the plan in force names, with one authentic pair, the authentic report being the one the ledger committed to. Given the directory the reports were written to (`--report-dir`, or by default the bundle's parent when it holds every recorded file), each file hashes as recorded and the authentic report names every other rendering by hash, so the regulator's one signature covers them all. Without the files it warns. A plan that names no languages passes with one English report. | That a convenience translation says what the authentic report says. |
| `nb_tests` | Runs whenever the ledger records a notified body's proposed test (AI Act Annex VII point 4.4). Every run marked `initiated_by: notified_body`, in its `run_started` entry and its attestation alike, has its chain: the notified body's proposal through the gate, with a justification and a digest that recomputes; then, as the cited plan says, an approval by each approver it names, with an IdP login bound to the proposal's digest, or an amendment that adopts the test unchanged, put in force between proposal and run; then the run, of that test only, within `notified_body_tests.max_runs`. A run not so marked that reports a proposed test its plan does not list fails. Approvals through the development IdP, or matched by email only, warn. | That the test was a good one to run. The plan's approvers judged that, and the verifier checks that they did. |
| `personal_data` | The manifest's `personal_data` is what the files hold: the staff identifiers (emails, IdP subject ids) and the raw IdP ID tokens, counted, with the files they are in. | That there is no test-subject data. That rests on what the export writes, which is stated, not found. A 0.1 bundle's `contains_personal_data: false` warns when the bundle names anyone. |
| `anchor_*` | The bundle matches an anchor you gave from outside it (section 4). | Anything about an anchor you did not give. |
| `anchors` | Warns with the list of anchors that came from the bundle itself. Passes if you gave them all. | — |
| `bundle_digest` | No file changed after the manifest was written. | That the manifest itself is original. The signed report embeds this digest. |

### The two timestamp rules

**Every entry must be stamped, or the check fails.** A timestamp token is issued over
its entry's hash. The entry's hash does not cover the token, so deleting a token
leaves the hash chain intact, and nothing in a single entry shows that it was ever
stamped. The rule therefore applies to the whole ledger: it is stamped from its first
entry to its last. If any entry has no timestamp, `timestamps` fails and names the
first such entry. A ledger with no timestamps at all fails too, because nothing
anchors it to a clock. The ledger enforces the same rule when it is written: once its
first entry is stamped it refuses an unstamped one, and the other way round. Every
engine command that appends to a participation's ledger therefore takes the same
`--tsa` as the command that started it.

**The signed time is the one that counts.** The `timestamp` field stored beside each
token is written by whoever assembled the bundle. The time an RFC 3161 authority
signs, `genTime`, is not. An operator who rebuilt the ledger months later could have a
real authority stamp every entry again, and the tokens would verify and chain to your
root, but they would carry the rebuild's time. So `timestamps` reads the signed time
and fails when:

- the stated `timestamp` differs from it;
- it is more than **10 minutes** from the entry's `recorded_at`. The ledger writes
  `recorded_at` and then asks the authority, so the two differ by one round trip plus
  the skew between the clocks; ten minutes allows for a slow authority and a badly set
  clock;
- it is earlier than the previous entry's signed time by more than **5 seconds**. Two
  authorities may disagree by a second or so; one authority only moves forward.

The identity-provider logins behind plan and report signatures are held to the same
clock. A token's `iat` more than 10 minutes after the `recorded_at` of the entry that
records it, or more than an hour before it, fails `plan_signatures` or
`report_signature`, so an old login cannot be replayed into a rebuilt ledger. With
development timestamps the same rules apply to the operator's own clock, and anchor
nothing.

### The anchor checks

| Anchor | Check | Fails when |
|---|---|---|
| `--expect-plan-digest` | `anchor_plan_digest` | A plan version in the bundle, a signing in the ledger, or a run cites a digest you did not give, or a plan file does not hash to the digest it is filed under. |
| `--expect-sandbox-id` | `anchor_sandbox_id` | The manifest, any ledger entry, any plan or any run names another sandbox. |
| `--tsa-root` | `anchor_tsa_root` | Any ledger timestamp does not chain to a root you gave, the operator's own development timestamps included. The bundle's pinned root is ignored. A chain is accepted only when every issuer in it, the root included, is a CA (`basicConstraints CA:TRUE`) allowed to sign certificates (`keyCertSign`, when it states a key usage), within its path length and valid at the stamped time, and the signer's certificate is not a CA's and has time stamping as its only extended key usage, marked critical (RFC 3161 §2.3). So the holder of an ordinary certificate under a root that also issues others cannot stamp tokens that chain to it. Revocation evidence kept with the tokens is checked against the chain to your root (`tsa_revocation`). |
| `--idp-keys` | `anchor_idp_keys` | Any plan or report signature was made with a key that is not in your key set (compared by RFC 7638 thumbprint), or no signature was made through an IdP at all. |
| `--expect-audience` | `plan_signatures`, `report_signature` | A plan or report signature's ID token was not issued to one of these client ids (`aud`, and `azp` when there are several audiences): a login to some other application recorded as a signature. A plan can also name the client id per signer (`audience` under `roles`), which is checked without this flag. |
| `--expect-policy-digest` | `anchor_policy_digest` | Any plan version pins another network policy, or any run records one. A run at an HPC centre records no policy digest, so for those runs only the plan's pin is checked. |
| `--expect-harness-digest` | `anchor_harness_digest` | Any plan version pins another harness image, or any run attests another one. |
| `--signing-key ID=PEM` | `signing_keys` | The key you gave for `control-plane`, `harness` or `scorer` (or a version of one, such as `control-plane@v2`) is not the one the ledger recorded, or the one `public-keys.json` carries, under that key id. Once given, your keys are the only ones that signer's statements are checked under. |
| `--control-plane-keys FILE` | `signing_keys`, `signatures` | As `--signing-key`, for every version of the control plane's key at once: a JWKS of Ed25519 keys whose `kid` names each version, or a JSON object of key id to PEM. An attestation signed under a key id you did not give fails. |
| `--expect-head SEQ:HASH` | `anchor_ledger_head` | The ledger holds no entry at that seq (it ends before it, so entries were cut from its end), or the entry there hashes to something else (the ledger was rewritten from that point). A ledger that extends the head passes and says by how many entries. |
| `--centre-keys FILE` | `isolation` | Evidence or an image conversion a centre signed does not verify under a key you gave for that centre (a JWKS whose `kid` is the centre's name, a JSON object of name to PEM, or one PEM for any centre, `hpc-centre`), or the ledger's `hpc_centre_key` records another key for it: the operator's key passed off as the centre's. |
| `--vendor-roots PEM` | `tee_attestation` | A recorded attestation report's certificate chain does not end at one of the root certificates you gave (repeatable; a file may hold several; each must be self-signed). Without it, the roots are the ones the plan's `tee_policy` lists by fingerprint, which both parties signed but which you did not obtain yourself. |
| `--checkpoint FILE` | `anchor_checkpoints` | A head checkpoint's signature does not verify under the control plane's key (from your `--signing-key`, else the ledger), its timestamp does not verify (under your `--tsa-root` when given) or does not cover what it signs, it names another sandbox, or the ledger does not hold its head recorded no later than the checkpoint was made. A checkpoint stamped by the development authority warns: the operator could have made it at any time. |

## 4. Getting anchors independently of the operator

An anchor protects you only if the operator could not have chosen it. Get each one
yourself, from the party it belongs to, and never from the bundle or from a message
the operator passes on.

- **Plan digest.** The digest of every plan version the regulator and the provider
  signed. Each party sees it when they sign in the console, and it is bound into their
  IdP token. The regulator can recompute it from the plan file it holds: `histor plan
  validate plan.yaml` prints `plan_digest=…`. If the plan was amended, give every
  version.
- **Sandbox id.** From the regulator's admission decision for the participation.
- **TSA root.** From the timestamp authority's own publication, not from the
  operator's repository. FreeTSA, for example, publishes its root at
  `https://freetsa.org/files/cacert.pem`. Check its fingerprint through a second
  channel. The `timestamps` check prints the start of the root's SHA-256 for each
  authority it saw.
- **IdP keys.** The signing IdP's key set, fetched by its own organisation from the
  `jwks_uri` in the IdP's OpenID discovery document. Identity providers rotate their
  keys, so keep the set that was in force when the plan and the report were signed.
  `--idp-keys` takes one JWKS; merge the sets if the parties used different IdPs. A
  merged set, or an IdP that signs for many organisations (Entra ID, Google), accepts
  a key, not a person. Which person signed for which party comes from the plan's
  `roles`, which both parties signed, matched against the token's issuer and subject.
- **Audience.** The client id the console is registered under at each party's IdP,
  from that IdP's administrator. With it, a login to any other application cannot be
  recorded as a signature.
- **Network policy digest and harness image digest.** Both are pinned in the signed
  plan, so a correct plan digest already covers them. Give them separately when you
  hold them independently of any single plan. A notified body that has reviewed one
  harness release and its network policy can check every bundle against that release.
- **Signing keys.** The control plane's attestation key, and on the local backend the
  harness's, are recorded in the ledger before the first run
  (`signing_key_registered`), so a timestamped ledger already fixes them. Give them
  with `--signing-key` when you received the public key yourself when the
  participation opened, for example in the operator's letter to the regulator.
- **HPC centre keys.** When a centre signs its runs' isolation evidence, ask the
  centre itself for the public half of its signing key, through a channel the sandbox
  operator does not run, and give it with `--centre-keys`. Without it, the centre's
  key is whatever the operator recorded in the ledger as the centre's, and the
  centre's word is then only as good as the operator's.
- **TEE vendor roots.** When a participation's keys are released on hardware
  attestation, get the vendors' root certificates from the vendors: AMD's ARK for the
  processor generation, from AMD's Key Distribution Service (`kdsintf.amd.com`), and
  Intel's SGX root CA, from Intel's Provisioning Certification Service. Compare their
  SHA-256 fingerprints with the ones the plan's `tee_policy` lists, and give them with
  `--vendor-roots`. The mock platform's root, which the engine's demo uses, is not a
  vendor's root; it proves only that the flow runs.
- **Ledger head.** Nothing inside a bundle says where its ledger should end. When the
  regulator signs the exit report, the engine's console shows the ledger head as it
  then stands (`<seq>:sha256:<hex>`). The regulator keeps it in its own records and
  passes it to the notified body with the report. During the participation the
  operator can publish **head checkpoints**: the engine's checkpoint command,
  published with the engine, signs the head with the control plane's key and has the
  timestamp authority stamp it. Run on a schedule, each file goes to the regulator, who
  keeps it where the operator cannot reach. `--checkpoint` checks that the bundle
  extends every one. No transparency log is needed; the regulator's records are the
  log. Publishing the checkpoints to a public log such as Sigstore Rekor would let
  anyone see that no two heads were issued for one seq. That is a later option, not
  built.

If you cannot get an anchor independently, leave it out. The verifier will warn you
that it came from the bundle. Taking a value out of the bundle and passing it back in
does not make it an independent anchor.

## 5. Exit codes

| Code | Meaning |
|---|---|
| 0 | Verified: no check failed. Warnings may still be printed, so read them. |
| 1 | At least one check failed, an anchor mismatch included. Input a check cannot read (a missing field, a wrong type, a token that does not parse) fails that check as malformed and the other checks still run; a `plan.json` that does not parse fails `plan_versions`. The run never ends in a traceback. |
| 2 | Nothing was verified: the directory is not a bundle, its `bundle_version` is unknown, an anchor could not be read (a missing file, a PEM that is not a certificate, a malformed digest, an unknown key in the anchors file, an anchor given empty), or the command line was invalid. |

An anchor the verifier cannot read ends the run with code 2. The verifier never falls
back to the bundle's own value in its place.
