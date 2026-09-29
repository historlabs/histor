# Run attestation v0.1

What the sandbox says about a run, in a form someone can check without the data.

## 1. Envelope

An **in-toto Statement v1** in a DSSE envelope, signed by the **control plane**,
which completes it. What the harness measured is signed separately, by the harness,
and cited from here (§1a).

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "model-image",   "digest": {"sha256": "..."}},
    {"name": "harness-image", "digest": {"sha256": "..."}},
    {"name": "relay-image",   "digest": {"sha256": "..."}},
    {"name": "dataset:lab-heldout-v1", "digest": {"sha256": "..."}}
  ],
  "predicateType": "https://historlabs.eu/run/v0.1",
  "predicate": { }
}
```

Subjects are the model image digest, the harness image digest, the relay image
digest, and each dataset commitment used in the run. Naming the datasets as subjects
is what binds a result to the data it came from without disclosing any of it.

The predicate is validated against [`predicate.schema.json`](predicate.schema.json).

### Namespace

Every type and schema URI this project defines is under **`https://historlabs.eu/`**,
with the path unchanged from the working-title namespace it replaced:

| What | URI |
|---|---|
| Run attestation (this document) | `https://historlabs.eu/run/v0.1` |
| The harness's statement (§1a) | `https://historlabs.eu/harness-measurement/v0.1` |
| The driver's statement (§1b) | `https://historlabs.eu/driver-observation/v0.1` |
| Written proof | `https://historlabs.eu/written-proof/v0.1` |
| JSON Schemas | `https://historlabs.eu/spec/<name>.schema.json` |

They are stable identifiers signed into attestations, not live endpoints. The code
takes them from one place, [`histor/crypto/namespace.py`](../histor/crypto/namespace.py). A new
version of a type changes the last path segment (`v0.2`), never the host.

**Legacy namespace.** Before the project was named Histor (2026-09-27), the same
paths were under `https://sandbox-mvp.dev/`. Bundles made then carry those URIs in
signed statements, and evidence is not rewritten, so the verifier reads them as the
same types and its `statement_types` check warns that the bundle uses the legacy
namespace. A statement of any other type fails that check. Nothing new is written
under the legacy namespace.

## 1a. The harness's statement

The harness runs in segment A and can see neither the model's decision log nor the
network's drops, so the attestation is completed by the control plane. What the
harness measured, it signs itself, where it measured it:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "dataset:lab-heldout-v1", "digest": {"sha256": "..."}}],
  "predicateType": "https://historlabs.eu/harness-measurement/v0.1",
  "predicate": {
    "sandbox_id": "...", "plan_digest": "sha256:...", "run_number": 1,
    "started_at": "...", "ended_at": "...", "relay_log_digest": "sha256:...",
    "results": [ ... ], "outcome": "pass", "request_ids": [ ... ]
  }
}
```

It is signed with a key the key broker provisions for the participation
(`signing/<sandbox>/harness`), releases only to the pinned harness image, as it
releases data keys, and destroys at exit. The attestation cites it as
`harness_statement_digest`: the sha256 of the envelope's canonical JSON. The bundle
carries it in `harness-statements.jsonl`, the ledger in the `run_attestation` entry,
and the public key in a `harness_key_provisioned` entry and in `public-keys.json`
under `harness`.

The verifier requires the statement to verify under the `harness` key and no other,
every result it signed to appear unchanged in the attestation, and any other result
to be decision logging. It recomputes decision-logging coverage from the signed
request ids and the model's log. An operator who changed a number after the run would
have to forge the harness's signature to hide it.

## 1b. At an HPC centre: the driver's statement and the scorer's

A run at a centre keeps the labels in the control plane: its scoring is kept off
the centre. Segment A is split: the **driver** in the job sends a
prepared work package of images and records the answers; the **scorer** in the
control plane scores them against the labels. Each signs what it did.

The driver signs, with the harness key released to the job:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "work-package", "digest": {"sha256": "..."}}],
  "predicateType": "https://historlabs.eu/driver-observation/v0.1",
  "predicate": {
    "sandbox_id": "...", "plan_digest": "sha256:...", "run_number": 1,
    "started_at": "...", "ended_at": "...",
    "work_digest": "sha256:...", "responses_digest": "sha256:...",
    "relay_log_digest": "sha256:...", "request_ids": [ ... ],
    "segments": {"s1": {"kind": "stream", "complete": true, "answered": 157,
                        "relay_records": 157, "relay_rejections": 0}},
    "outcome": "completed"
  }
}
```

The scorer signs the measurement statement of §1a with its own key, `scorer`
(`signing/<sandbox>/scorer`, recorded as `scorer_key_provisioned` and in
`public-keys.json` under `scorer`). Its predicate adds `driver_statement_digest`,
`responses_digest`, `work_digest` and `segments`, which maps each test id to the
segments its result was computed from. The attestation cites the scorer's statement as
`harness_statement_digest` and the driver's as `driver_statement_digest`. Both
statements are in `harness-statements.jsonl`, and the ledger's `run_attestation`
entry carries both.

For a run that cites a driver statement, the verifier requires:

- the driver's statement verifies under `harness` and is of the driver's type, and the
  scorer's verifies under `scorer`;
- both name the run, the plan and the relay log the attestation names, and the
  scorer's names the driver's statement, its `responses_digest` and its
  `work_digest`;
- the request ids are the driver's, and decision-logging coverage is recomputed from
  them;
- each result's segments were completed by the driver; an `adversarial_robustness`
  or `fail_safe` result's `queries_sent` equals the relay's records for its segments;
  no other result counts more items than the driver saw answered;
- every result in the attestation is one the scorer signed, as in §1a.

The verifier has no labels, so it cannot score the responses again. Anyone who holds
the labels can, from the responses the digests pin, and must get the same numbers.
Runs without `driver_statement_digest` (Kubernetes, local, and HPC runs from before
2026-09-27) are checked as in §1a.

## 1c. Binding to the ledger, and where the keys come from

Every file in a bundle is written by whoever assembled it, and the operator who runs
the sandbox is one of the parties the verifier does not trust. So the signed files
are only evidence as far as the ledger, which is chained and timestamped as it is
written, binds them:

- **Statements.** Each envelope in `attestations.jsonl` must be the `envelope` of a
  `run_attestation` entry, one for one and in ledger order, compared by the sha256 of
  its canonical JSON (sorted keys, no whitespace). Each envelope in
  `harness-statements.jsonl` must be the `harness_statement` or `driver_statement` of
  a `run_attestation` entry. A file entry the ledger did not record fails
  `signatures` or `harness_statements`.
- **Keys.** Each statement is verified under one key id and no other: the attestation
  under `control-plane`, the harness's statement and the driver's under `harness`, the
  scorer's under `scorer`. The public key for each comes, in this order, from:
  1. the verifier's own anchor (`--signing-key control-plane=cp.pem`, or
     `signing_keys:` in an anchors file; every version of a rotated control-plane key
     with `--control-plane-keys`);
  2. the ledger: a `signing_key_registered` entry
     (`{"key_id": "control-plane", "public_key": "<PEM>", "signs": "attestations"}`),
     or, for the harness and the scorer, the key broker's `harness_key_provisioned` and
     `scorer_key_provisioned` entries. The control plane's key is recorded before the
     first run's attestation; the demo scripts and the cluster record it right after
     the plan is signed, and on the local backend the harness's too;
  3. `public-keys.json`, only when neither of the above holds a key for that signer.

  A key that is rotated (the control plane's in Vault transit) has a key id per
  version, `control-plane@v1`, `control-plane@v2`, and each signature names the one it
  was made with. Every version is registered, and a signature verifies under the key
  its key id names among the signer's keys from the first source that holds any, or
  not at all. Where two sources hold a key under the same key id, they must be the same
  key, or `signing_keys` fails. A key from `public-keys.json` alone warns (`KEYS NOT
  ANCHORED`), and fails when any anchor is given: a key the bundle names for itself
  vouches for whatever its assembler signed with it.

What the binding does not do: the control plane's key is the operator's own, so the
operator can still sign a false attestation *at the time of the run* and record it in
the ledger. What stops that is the harness's statement, signed with a key the
operator does not hold outside the pinned harness (§1a), and the timestamps, which fix
when each entry was written (`docs/verifier.md`, `timestamps`).

## 2. The load-bearing idea

The attestation exists so that someone with **no access to the data, the model, or the
platform** can decide whether the stated outcome follows from what was run. Every
field is there because the verifier needs it to make that decision:

| Field | The question it answers |
|---|---|
| `plan_digest` | Which rules was this run judged against? |
| `run_number` | Is this every run, or the flattering subset? |
| subjects | Is this the model and data that were committed, or a substitute? |
| `inference_params` | Could the result be reproduced, and was the system asked deterministically? |
| `harness_config` | Could the model have inferred the dataset boundaries? |
| `isolation_evidence` | Was the model actually unable to reach the data or the network? |
| `relay_log_digest`, `model_stdout_digest` | Do the logs behind these numbers still exist, unaltered? |
| `results[].metrics[].n`, `ci_*` | Is the number large enough and tight enough to mean anything? |
| `thresholds_evaluated` | Does the stated pass follow from the stated numbers? |

The last two are the reason `measurement` is an object rather than a float. A verifier
handed `{"false_adult_rate": 0.004}` can check it against a `0.01` threshold and learn
nothing about whether the run was informative. Handed
`{"value": 0.004, "n": 12, "insufficient_sample": true}` it can say what actually
happened: the threshold was not meaningfully tested.

## 2a. Adversarial robustness and fail-safe results

Two test types measure how the system behaves when the input is hostile or wrong
rather than merely degraded. Both are black-box: the model sits behind the relay, so
every input is a call through the relay, logged, counted and decision-logged like any
other, and `relay_log_digest` covers them.

- **`adversarial_robustness`.** `metrics.attack_success_rate` is a Wilson rate over the
  true minors the system refused on the clean image; an item counts if any planned
  attack turned it into `is_adult: true` within its query budget.
  `metrics.clean_false_adult_rate` reports the minors already served before any
  attack. `by_group.attack_success_rate.attack` holds one rate per planned attack,
  and the other attributes under it are the plan's demographic groups.
  `metrics.queries_sent` states the calls made (decoys included) against the plan's
  budget, and `metrics.queries_rejected` the calls the relay refused, which are
  counted as failed attempts, so a rate with rejections is a lower bound.
- **`fail_safe`.** `metrics.approval_rate` is a Wilson rate over the generated
  out-of-scope inputs answered `is_adult: true`; `metrics.mean_confidence` is the
  mean confidence reported for them; `by_group.approval_rate.input_kind` has one rate
  per kind. A relay rejection counts as not approved, and stays in `n`.

For both, `method_digest` is the digest over the code that generated the inputs, as
the plan fixes only their parameters. The verifier recomputes every `observed` value
for these types from the reported measurements, checks that each rate is a count over
its `n` with its own Wilson interval, and that the conditions and groups add up to
the headline rate (for attacks, the union lies between the largest single attack and
their sum). A threshold these types do not define fails the bundle.

**What the model can see.** A query-based attack sends variants of one image several
times. The harness sends attack queries breadth-first, one per item per round, each
round shuffled among in-scope decoys, so no two variants of one item are adjacent and
no item id or label is ever sent. That does not make the variants unlinkable: they
are within a few intensity levels of each other, and a model that keeps state in
memory during the run (nothing in the isolation rules prevents that) could match
them and answer near-duplicates conservatively. The measured attack success rate is
then an underestimate. Out-of-scope inputs are conspicuous by nature, and the decoys
only stop them arriving as one block. Both are instances of the residual risk that
the model detects the test.

**What these results are not.** Not a penetration test of the system under test:
nothing here probes the provider's infrastructure, authentication, supply chain or
deployment, and a pass says nothing about them. Not a bound on a stronger attacker:
one with more queries, the weights, or gradients may do better.

## 3. Isolation evidence is a tagged union

Two arms, `cilium` and `hpc_centre`, with different trust models:

- **`cilium`** — the platform enforced isolation and we can prove what it enforced.
  The `network_policy_digest` must equal the plan's pin; the `drop_log_digest` covers
  the Hubble drop events captured during the run. Blocked attempts are evidence, so
  the drop log matters as much when it is empty as when it is full. The optional
  `image_signatures` says whether the sandbox itself checked each image's cosign
  signature before launch, and against which policy (`policy_digest`):
  `verified`, `partially_verified`, or `not_verified_by_sandbox` when no policy was
  configured. A failed check is never recorded, because the launch is refused.
- **`hpc_centre`** — no user-controlled network policy exists, so someone vouches for
  exclusive node allocation and node configuration by signing the job record and the
  node configuration. `signed_by` says who:
  - `sandbox_operator` (the default): the courier, which reaches the centre only
    through the project's login, signs what it observed with the `sandbox-operator`
    key, whose public half is in the ledger as `hpc_operator_key`. This is the sandbox
    operator vouching for its own run. It shows that the operator committed to these
    records at the time, and that is all: an operator willing to lie could have signed
    something else.
  - `centre`: the centre signs with its own key, recorded as `hpc_centre_key`. A third
    party that runs the machine is better placed to know, and has less reason to
    shade the answer, than the operator. The operator writes that ledger entry, so
    the centre's word is only anchored by the key the centre gives the recipient
    directly (`histor verify --centre-keys`); without it the verifier warns, and fails
    under any anchor.

  Either key is recorded (`{"centre", "key_id", "public_key"}`) when the participation
  opens at the centre, before any conversion or run; a signature checked under a key
  the ledger recorded only after it fails.

  The signature is in `signature`, base64 of a DSSE envelope over the arm without its
  signature fields, so `signed_by` is itself signed. An arm without `signed_by` was
  made before it existed: it is read as the centre's, with the signature in
  `centre_signature`, which `signed_by: centre` also still accepts.

  The `image_converted` ledger entries, which join each OCI pin to the SIF that ran,
  carry `signed_by` and `signature` by the same rule. For a run under either signer
  the ledger must also hold a `key_released` entry for the run: the key broker
  released the data keys to one job's public key only after that job's measured SIF
  digests matched the conversions, every probe from the model's namespace was
  blocked, and that namespace held only loopback. A
  `key_release_refused` entry is an incident, and the verifier reports it.

These are **not equivalent**, and the verifier must not present them as if they were.
Under `cilium` the claim rests on a policy we can hash. Under `hpc_centre` it rests on
someone's word: the centre's, a third party's, or weaker still, the sandbox
operator's own. Verifier output states which one it checked, and who signed.

The MVP produces only `cilium`. The verifier handles both from the start, because a
format that gains an arm later gains a version skew problem later.

## 4. Ledger placement

Every attestation is written to the evidence ledger as a `run_attestation` entry,
carrying `prev_hash` and an external RFC 3161 timestamp like every other entry. The
attestation proves what a run did; the chain proves nothing was removed afterwards.
Neither is sufficient alone.

**The head.** The chain proves nothing was removed from the middle, but a ledger cut
after any entry is still an intact chain. Two records fix where it had got to, both
optional and additive in `bundle_version` 0.3:

- The regulator's `report_signature` entry carries `ledger_head: {"seq": n,
  "entry_hash": "sha256:…"}`, the last entry when they signed, and the ID token's nonce
  commits to it: `nonce = "sbx-report." + b64url(sha256("sandbox-report-signature/v2\n"
  + "<seq>:<entry_hash>" + "\n" + report_sha256 + "\n" + salt))`. Through the chain that
  is every entry before, the `report_generated` entry and its `bundle_digest`
  included. A signature without `ledger_head` keeps the v1 nonce and is read as before.
- A **head checkpoint** (the engine's `histor ledger checkpoint`), a file kept outside the bundle by
  the regulator: `{"checkpoint": S, "envelope": DSSE(S), "timestamp": T}`, where `S` is
  `{"type": "https://historlabs.eu/ledger-head-checkpoint/v1", "sandbox_id", "seq",
  "head_hash", "time"}`, the envelope is signed by the control plane's attestation
  key, and `T` is a ledger timestamp token (RFC 3161, or development) over the sha256
  of `S`'s canonical JSON. The verifier's `--checkpoint` requires the bundle's ledger
  to hold entry `seq` with hash `head_hash`, recorded no later than `time`.

**Revocation.** An RFC 3161 token in the ledger may carry, beside its `der`, the
authority certificate's revocation status as its CA gave it when the token was
stamped: `token.revocation = {"kind": "ocsp" | "crl", "url": "<where it came from>",
"der": "<base64 OCSP response or CRL>"}`. It is optional and outside the entry's hash,
as the token is. The verifier (`tsa_revocation`) checks it offline against the
token's own certificate chain.

A head the recipient holds (`--expect-head <seq>:sha256:<hex>`) is checked the same
way. What comes after the last head someone outside the operator holds remains the
operator's word.

## 4a. The evidence bundle and its manifest

Attestations travel to a verifier in an evidence bundle (`histor/ledger/bundle.py`): the
ledger as JSON lines, the attestations, the harness statements, every plan version,
the policies, the public keys and each run's logs. Its `manifest.json` names each file,
the `bundle_version`, the `bundle_digest` over every other file, and, from
`bundle_version` 0.2, what personal data the bundle holds:

```json
"personal_data": {
  "present": true,
  "categories": {
    "staff_identifiers": {"description": "…", "count": 7,
                          "files": ["ledger.jsonl", "plan.json", "plans/"]},
    "idp_id_tokens":     {"description": "…", "count": 1, "files": ["ledger.jsonl"]}
  },
  "test_subject_data": false,
  "test_subject_data_basis": "none, by construction of the export: …"
}
```

The categories are found in the files, not declared: `staff_identifiers` counts the
distinct email addresses anywhere in the bundle, signed payloads decoded, plus the
IdP subject of each IdP-bound signature; `idp_id_tokens` counts the ledger entries
carrying a raw ID token. A category that is absent is left out, and `present` is
false only when none is there. `test_subject_data` is stated, not found: no file the
export writes carries an image, a ground-truth label or age, a group label of an item
or an item id, and results are aggregates by group. The verifier derives the
description again and fails a manifest that differs (`personal_data`).

`bundle_version` 0.1 manifests carried `"contains_personal_data": false` instead, as a
constant, whatever the bundle held. The verifier still reads them, and warns when the
bundle holds personal data the flag denies.

## 5. Outcomes

`pass`, `fail`, or `halted`. `halted` requires `halt_reason` — a run stopped
mid-execution under Art. 59(1)(c) is evidence too, and an attestation that records the
stop without the reason is a gap in the record rather than a tidy absence.

A `pass` with any `test_result.outcome` of `fail` is a malformed attestation. The
verifier checks this rather than trusting the top-level field.

## 5a. Runs the notified body initiated

AI Act Annex VII point 4.4 lets the notified body carry out further tests. A run it
initiated carries two more predicate fields, both copied from the gate's
`run_started` entry, and never present on an ordinary run:

```json
"initiated_by": "notified_body",
"authorisation": {
  "proposal_seq": 41,
  "proposal_digest": "sha256:…",
  "route": "pre_authorised",
  "approvals": [43]
}
```

`route` is `pre_authorised` when the plan's `notified_body_tests.allowed` is true, and
`approvals` names the `nb_test_approved` entries, one per approver the plan names; or
`amendment`, with `plan_digest` and `plan_signed_seq` naming the plan version that
adopted the proposal (`notified_body_tests.adopted`). The run's plan digest is the plan
in force; a pre-authorised test is not in its `tests`, and is the test the proposal
entry records. Additive in `v0.1`: a verifier that does not know the fields reads the
run as before, and `histor verify` walks the chain in the ledger (`nb_tests`,
`spec/evidence-bundle.md` section 27).

## 6. Versioning

`v0.1`. Breaking changes take a new predicate type URL; the verifier keeps handling
old ones, because evidence outlives the code that made it. Attestations are never
rewritten — a correction is a new entry that references the old one, never an edit.
