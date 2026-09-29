# Tampered bundles

Five copies of [`../sample-participation/evidence-bundle`](../sample-participation/evidence-bundle),
each altered in one way. `histor verify` must reject every one with exit code 1 and
name the check that caught it.

In each copy the manifest's `bundle_digest` was recomputed over the altered files, as
an operator covering their tracks would do. Without that step every copy would also
fail `bundle_digest`. With it, the check that fails is the one that detects the
alteration itself.

| Copy | What was changed | Check that fails |
|---|---|---|
| `ledger-one-char-edit/` | The gate refused the test lab's attempt to swap the dataset and recorded why. One character of that reason is changed: "not permitted" becomes "now permitted". | `hash_chain` |
| `swapped-result/` | Run 1 failed. Its signed attestation gets run 2's passing results and outcome pasted in, with the original signature left in place. | `signatures` |
| `removed-timestamp/` | The timestamp is removed from the entry that records the refused dataset swap, as if that entry had been slipped into the ledger later. | `timestamps` |
| `plan-digest-mismatch/` | The first signed plan version keeps its file name (its digest), but its threshold for minors accepted as adults is loosened to 75%, so the failed run would have passed. The file no longer hashes to the digest it is filed under. | `plan_versions` |
| `key-substitution/` | The operator makes its own control-plane and harness keys, puts their public halves in `public-keys.json`, and re-signs run 1's harness statement and attestation with run 2's passing results. Every envelope in the bundle verifies against a key in the bundle. The ledger, with its timestamps, is untouched and still records the failing run and the original keys. | `signing_keys` or `signatures` |

Every copy exits 1 with the sample's anchors and without them.

Run one the way a regulator would:

```sh
histor verify --anchors examples/sample-participation/anchors.yaml \
  examples/tampered/swapped-result/evidence-bundle
```

## Rebuilding the copies

[`build.py`](build.py) makes the five copies from the sample. It is deterministic, and
a test checks that the committed copies are what it builds. Only `key-substitution`
signs anything, with keys derived from a seed published in the script; they stand for
an operator's own keys.

```sh
python examples/tampered/build.py
```

Rebuild them whenever the sample is regenerated.
