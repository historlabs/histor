# Histor: evidence formats and an offline verifier

When an AI system is tested in a regulatory sandbox under Article 57 of the EU AI Act,
someone has to be able to check the result afterwards. Histor defines what that
record looks like and ships the tool that checks it.

A sandbox participation produces an **evidence bundle**: what was tested, under which
signed plan, with which numbers, and what each party did along the way. A regulator, a
data protection authority or a notified body runs `histor verify` on that bundle on
their own machine. The verifier needs no network and never sees the test data. It
recomputes every hash, signature, timestamp and pass/fail decision from the
underlying files. It takes no conclusion on the bundle's own say-so, and it ends every
run with a list of what the bundle does not establish, even when every check passes.

## What this release contains

Version 0.1.0 is the first public release. It holds the formats and the verifier only.

| Path | Contents |
|---|---|
| [`spec/`](spec/) | The evidence formats: the [run attestation](spec/run-attestation.md), the [inference profile](spec/inference-profile.md) that run logs follow, the [dataset commitment](spec/dataset-commitment.md), the [check registry](spec/check-registry.md), and JSON Schemas for the plan, the attestation predicate, the written proof and the model card. |
| [`histor/`](histor/) | `histor verify` and `histor plan validate`, with exactly the library code those two commands import. |
| [`examples/sample-participation/`](examples/sample-participation/) | One complete, synthetic participation: the bundle, the trust anchors a regulator would hold for it, the verifier's verdicts, the exit report and the written proof. |
| [`examples/tampered/`](examples/tampered/) | Five altered copies of that bundle. The verifier must reject each one, and the README says which check catches it. |
| [`examples/age-estimation.plan.yaml`](examples/age-estimation.plan.yaml) | The plan the sample ran under, before signing. |
| [`docs/verifier.md`](docs/verifier.md) | How to verify a bundle, what each check proves and does not prove, and where to get trust anchors that the operator could not have chosen. |
| [`docs/threat-model.md`](docs/threat-model.md) | The threats to a participation, the control for each, and the risks that are stated rather than solved. |
| [`tests/`](tests/) | The tests CI runs. |

The rest of Histor is the engine that produces bundles: the test harness, the relay
between harness and model, the gate that enforces the signed plan, the supervisor
console, and the Kubernetes and HPC backends that keep the model away from the data
and the network. It will be published under the same licence when the first pilot is
agreed. Until then, this repository is enough to read the formats, run the verifier,
and see how it treats altered evidence.

## Try it in two minutes

You need Python 3.12 or later. From a checkout of this repository:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install .
histor verify --anchors examples/sample-participation/anchors.yaml \
  examples/sample-participation/evidence-bundle
```

The run ends with `VERIFIED — 21 checks passed, 7 warning(s)` and then the list of
what the sample does not establish. Exit code 0 means no check failed. The seven
warnings are expected: the sample was produced on one computer with no isolation and
with development keys, and the [sample's README](examples/sample-participation/README.md)
explains each warning.

Now check a copy that an operator has tampered with:

```sh
histor verify --anchors examples/sample-participation/anchors.yaml \
  examples/tampered/key-substitution/evidence-bundle
```

This exits with code 1 and names the check that failed. In this copy the operator
re-signed a failing run as a pass with keys of its own; the signatures no longer
verify under the keys the ledger recorded and you hold.
[`examples/tampered/README.md`](examples/tampered/README.md) lists all five copies.

Three more commands you will use:

- `histor verify --json` writes the verdict as JSON, for a case file.
- `histor verify --version` prints the line to quote beside any verdict.
- `histor plan validate PLAN` checks a plan against the schema and prints the digest
  both parties sign.

## Why the anchors matter

A bundle carries the values it is checked against: the plan digests, the public keys,
the timestamp authority's root certificate, the identity providers' keys. Checked
against those alone, a bundle only proves that it agrees with itself. An operator who
rebuilt the bundle from scratch could replace every one of those values consistently.

So you bring the values you can get from their owners, and the verifier checks the
bundle against them:

```sh
histor verify evidence-bundle \
  --expect-sandbox-id <the id in the admission decision> \
  --expect-plan-digest sha256:<each plan version you signed> \
  --signing-key control-plane=<the sandbox's published key>.pem \
  --tsa-root <the timestamp authority's root, from the authority>.pem \
  --idp-keys <your identity provider's key set>.json
```

The same values can live in one YAML file per participation, passed with
`--anchors`, as the sample's [`anchors.yaml`](examples/sample-participation/anchors.yaml)
does. Every anchor you give is checked and fails on a mismatch. Every anchor you leave
out is read from the bundle, and the verdict tells you so. Section 4 of
[`docs/verifier.md`](docs/verifier.md) says where each anchor comes from.

## What the package includes

`histor verify` needs parts of the wider system: the ledger's hash chain and bundle
reader, Ed25519 and DSSE signing, the timestamp and plan-digest code, and the
identity code that checks plan and report signatures. This release ships exactly the
modules the two commands import, found by running them. Some of those modules contain
functions only the engine calls. `histor --help` lists only the commands this package
can run.

## Licence and contact

[European Union Public Licence v. 1.2](LICENSE) (EUPL-1.2).

- Security issues: [`SECURITY.md`](SECURITY.md).
- Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Everything else: [hello@historlabs.eu](mailto:hello@historlabs.eu) and
  [historlabs.eu](https://historlabs.eu).
