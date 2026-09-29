"""Hardware attestation evidence for key release: the typed evidence, the binding,
the platforms' report formats and one verification routine shared by every party
that checks it.

`docs/roadmap-hardware-attestation.md`, phase P0. A run inside a trusted execution
environment (TEE) makes a fresh X25519 key pair and asks the hardware for a report
whose ``report_data`` binds that public key, a nonce the key broker issued, the plan
digest and the run number (:func:`evidence.binding_report_data`). Whoever releases a
key checks the report with :func:`verify.verify_evidence` before sealing anything to
that key: the key broker, the provider's releaser, and later, offline, the verifier.
The same code in all three places, so the three cannot disagree about what a good
report is.

Platforms:

* ``mock`` (:mod:`.mock`): a clearly labelled JSON report signed under a test root
  that Histor generates. It proves nothing about hardware. It exists so the whole flow
  runs in CI, and it is accepted only where a plan's ``tee_policy`` names the mock
  root explicitly. The verifier always warns on it.
* ``sev-snp`` (:mod:`.snp`): the AMD SEV-SNP attestation report, ECDSA P-384 signed
  by the chip's VCEK, chained ARK -> ASK -> VCEK.
* ``tdx`` (:mod:`.tdx`): the Intel TDX v4 quote, ECDSA P-256, chained through the
  quoting enclave's report to the PCK certificate and Intel's root.

The ``sev-snp`` and ``tdx`` parsers and chain checks are an **unverified
implementation**: they follow the vendors' published layouts and are tested on
synthetic structures built to those layouts, not yet on reports from real hardware.
"""

from __future__ import annotations

from histor.crypto.tee.evidence import (
    HARDWARE_PLATFORMS,
    PLATFORMS,
    Collateral,
    TeeBinding,
    TeeError,
    TeeEvidence,
    binding_report_data,
    check_binding,
)

__all__ = [
    "HARDWARE_PLATFORMS",
    "PLATFORMS",
    "Collateral",
    "TeeBinding",
    "TeeError",
    "TeeEvidence",
    "binding_report_data",
    "check_binding",
]
