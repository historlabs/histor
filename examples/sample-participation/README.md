# The sample participation: what a regulator receives

This folder is the output of one complete sandbox participation, simulated end to
end. It is what a competent authority, a data protection authority or a notified body
would be handed when a participation ends: the evidence bundle, the verifier's
verdicts on it, the exit report and the written proof.

Two things to know before reading further.

**It proves nothing about isolation.** Every component ran as an ordinary process on
one computer. The verifier says so in capitals, and so do the exit report and every
run's attestation. What the sample does show is the shape and the integrity of the
evidence: every signature, hash and recomputed number in it can be checked by you,
offline, without trusting us or whoever ran it.

**Everything in it is synthetic.** The test images were generated from a fixed seed
and are not included. Every person is an address on a reserved `.example` domain,
which can belong to nobody. In a real participation those identities would be
personal data, so the bundle's manifest says what it holds under `personal_data`, and
the verifier's `personal_data` check derives the same description from the files.

## What happened

A provider submits a point-of-sale age estimator under
[`../age-estimation.plan.yaml`](../age-estimation.plan.yaml). The plan runs 150
synthetic images, with each test's minimum group size lowered to 15 so a run takes
seconds; the lowering is part of the signed plan.

1. The regulator and the provider sign the plan. Its digest pins everything that
   follows.
2. The provider commits its model. The test lab commits a held-out dataset the
   provider never sees.
3. Run 1 fails. The model is biased against one skin-tone band, which the harness found
   from the model's answers alone.
4. The provider tries to swap the dataset. The gate refuses and records the refusal.
5. The provider fixes the model. The plan is amended and signed again, and run 2
   passes.
6. Exit. The data keys are destroyed, the written proof and the exit report are
   generated, and the regulator signs the report.

## The files

| File | What it is |
|---|---|
| [`evidence-bundle/`](evidence-bundle/) | The whole record of the participation, which the verifier checks. |
| `evidence-bundle/manifest.json` | What is in the bundle, and the digest over all of it. |
| `evidence-bundle/ledger.jsonl` | Every event in order, 27 entries, each carrying the hash of the one before it and a timestamp. |
| `evidence-bundle/attestations.jsonl` | One signed statement per run: which model, which data, which plan, the results, the isolation evidence. |
| `evidence-bundle/harness-statements.jsonl` | What the test harness measured, signed with the harness's own key. |
| `evidence-bundle/plan.json`, `plans/` | The plan the runs were judged against, and every signed version of it. |
| `evidence-bundle/policies/` | The network policy files the plan pins. On this host they were not applied. |
| `evidence-bundle/public-keys.json` | The public halves of every key that signed something in the bundle. |
| `evidence-bundle/runs/<n>/` | Each run's relay log and the model's own decision log. Their digests are in the attestations. |
| [`anchors.yaml`](anchors.yaml), [`anchors/`](anchors/) | The trust anchors a regulator would hold from outside the bundle: the sandbox id, the digest of each signed plan version, and the public keys that sign the attestations and the harness's measurements. |
| [`verify-anchored.txt`](verify-anchored.txt), [`verify-anchored.json`](verify-anchored.json) | The verdict of `histor verify --anchors anchors.yaml`, as text and as JSON. |
| [`verify.txt`](verify.txt), [`verify.json`](verify.json) | The verdict with the bundle checked against itself alone. |
| [`exit-report.md`](exit-report.md) | The exit report, generated from the ledger. Its hash is in the ledger and the regulator's signature covers it. |
| [`written-proof.md`](written-proof.md), [`written-proof.json`](written-proof.json) | The written proof of the activities in the sandbox (AI Act Art. 57(7)). Both hashes are in the ledger. |

## Check it yourself

```sh
pip install .
histor verify --anchors examples/sample-participation/anchors.yaml \
  examples/sample-participation/evidence-bundle
```

The output matches [`verify-anchored.txt`](verify-anchored.txt) and ends
`VERIFIED — 21 checks passed, 7 warning(s)`. Add `--json` to compare with
[`verify-anchored.json`](verify-anchored.json). Leave out `--anchors` and the output
matches [`verify.txt`](verify.txt), ending `VERIFIED — 19 checks passed, 7
warning(s)`: the same checks, with the anchors read from the bundle itself, which the
verdict warns about.

The anchors here were taken from the sample's own ledger, because its parties are
synthetic. In a real participation you get each one from its owner, never from the
operator: the sandbox id from the admission decision, the plan digests from the plan
versions you signed, the signing keys from the sandbox's published key register.

Then change one character, say a `"fail"` to a `"pass"` in
`evidence-bundle/ledger.jsonl`, and run the verifier again. It fails.
[`../tampered/`](../tampered/) holds copies altered in more careful ways and says which
check catches each.

## What the seven warnings mean

"Verified" means that nothing in the bundle changed after it was produced and that
every stated outcome follows from the numbers reported with it. The warnings stop that
from being read as more than it is:

- no isolation was enforced;
- the plan and the report were signed with development keys and a development
  identity provider, which identify nobody;
- the timestamps came from a development authority, not from a third party, and so
  carry no revocation evidence to check;
- every anchor was read from the bundle itself, unless you passed `--anchors`;
- one group in each run was too small for the plan's minimum and was not judged.

[`../../docs/verifier.md`](../../docs/verifier.md) explains each check and how to bring
anchors from outside the bundle.
