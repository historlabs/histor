# Security policy

This repository holds Histor's evidence formats and the offline verifier a regulator
uses to check a sandbox participation without trusting the provider or the operator.
So the verifier's own honesty is the asset. A flaw that lets a forged, altered or
incomplete bundle pass, or that makes the verifier report a check it did not make, is
a vulnerability even if nothing else is exposed.

## How to report one

Report it privately, in one of two ways. Both reach the same people.

- Email [security@historlabs.eu](mailto:security@historlabs.eu).
- Use GitHub's private vulnerability reporting: **Security**, then **Report a
  vulnerability**, at
  [github.com/historlabs/histor/security/advisories/new](https://github.com/historlabs/histor/security/advisories/new).

Do not open a public issue or pull request for it.

Tell us what an attacker can do, which part is affected (an evidence format, a verifier
check, the plan loader), the version or commit you tested, and how to reproduce it.
The most useful thing you can send is a bundle, ledger or plan that demonstrates the
problem. The sample participation and its tampered copies in [`examples/`](examples/)
are a good starting point. Never send real personal data; every reproduction works on
the synthetic sample.

## What happens next

| Step | Target |
|---|---|
| We acknowledge your report | within 5 working days |
| We tell you whether it is confirmed, and how severe | within 10 working days |
| A fix or a mitigation for a confirmed high or critical issue | within 30 days |

We keep you informed while we work, agree a disclosure date with you, and credit you
in the advisory unless you prefer not to be named. These are targets set by a small
team, not a contractual promise.

## Where fixes are announced

Every confirmed vulnerability gets a GitHub Security Advisory at
[github.com/historlabs/histor/security/advisories](https://github.com/historlabs/histor/security/advisories),
with a CVE where one is assigned, the affected and fixed versions, and what a host
should do. The release that fixes it says so in its release notes, with a link to the
advisory. Watch the repository's releases or its advisories to be told.

## Supported versions

The latest minor release is supported: the newest `X.Y`, at its latest patch. A
security fix is published as the next patch of that release, and a host stays
supported by taking it. When a new minor release comes out, the previous one leaves
support, and later fixes land in the new one. Until the first release is tagged, the
supported version is the `main` branch.

| Version | Security fixes |
|---|---|
| Latest minor release, latest patch | Yes, free of charge |
| Earlier minor releases | No: upgrade to the latest minor |
| `main`, before the first release | Yes |

Security fixes are free for the whole support period. Wherever possible they are
published apart from feature changes, so that taking a fix never means taking anything
else. That matches what the EU Cyber Resilience Act (Regulation (EU) 2024/2847, Annex
I, Part II) asks of a manufacturer's vulnerability handling, and this policy is
written to stay consistent with it.

## Scope

In scope: everything in this repository. The formats and schemas in [`spec/`](spec/),
the verifier and the code it runs in [`histor/`](histor/), and the sample
participation with its tampered copies in [`examples/`](examples/).

Out of scope: the parts of the sample that are untrusted on purpose, when used as
documented. The sample was produced with no isolation, and its bundle says so. Its
development keys, development identity provider and development timestamp authority
vouch for nobody, and the verifier says so. A way to make the verifier stop saying so
is in scope.

## Known residual risks

Some risks are known, written down and not yet mitigated: what a model can still
signal to its provider, a control plane that vouches for the harness in place of
hardware, development timestamps, a model that detects the test environment, and the
relay as a single point of trust. They are listed with their reasoning under
"Residual risks, stated rather than mitigated" in
[`docs/threat-model.md`](docs/threat-model.md). A report that one of them can be
exploited in a way that document does not describe is welcome.
