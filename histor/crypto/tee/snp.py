"""AMD SEV-SNP attestation reports. **Unverified implementation.**

The layout is the ``ATTESTATION_REPORT`` structure of AMD's SEV Secure Nested Paging
Firmware ABI Specification (publication 56860), versions 2 and later, as the
``SNP_GUEST_REQUEST`` ``MSG_REPORT_REQ`` returns it: 0x4A0 bytes, of which bytes
0x000-0x29F are signed with ECDSA P-384 and SHA-384 by the chip's Versioned Chip
Endorsement Key (VCEK). The signature's ``r`` and ``s`` are 72-byte little-endian
integers at 0x2A0 and 0x2E8.

The VCEK certificate is issued by the AMD SEV Key (ASK), itself issued by the AMD Root
Key (ARK); both of those are RSA-4096 keys signing with RSASSA-PSS and SHA-384. The
ARK signs a revocation list of ASKs. AMD's Key Distribution Service publishes all
three certificates and the list. The VCEK's extensions name the chip
(``hwID``, 1.3.6.1.4.1.3704.1.4) and the TCB it was derived for (the SPL extensions
under 1.3.6.1.4.1.3704.1.3), which must be the report's ``CHIP_ID`` and
``REPORTED_TCB``.

What this module has been tested on: synthetic reports built to that layout, under a
synthetic ARK, ASK and VCEK (``tests/test_tee_platforms.py``). It has not yet been run
against a report from real hardware; see ``docs/roadmap-hardware-attestation.md``.
The TCB layout read here is Milan's and Genoa's; Turin's differs and is not read.
"""

from __future__ import annotations

from cryptography import x509

from histor.crypto.tee.evidence import TeeError
from histor.crypto.tee.report import (
    SHA384,
    ParsedReport,
    Platform,
    der_integer,
    der_value,
    ecdsa_verify,
)

REPORT_SIZE = 0x4A0
SIGNED_END = 0x2A0
SIGNATURE_ALGO_ECDSA_P384_SHA384 = 1
POLICY_DEBUG_BIT = 19

# Offsets into the report.
VERSION = 0x00
POLICY = 0x08
SIGNATURE_ALGO = 0x34
REPORT_DATA = (0x50, 0x90)
MEASUREMENT = (0x90, 0xC0)
HOST_DATA = (0xC0, 0xE0)
REPORTED_TCB = (0x180, 0x188)
CHIP_ID = (0x1A0, 0x1E0)
SIG_R = (0x2A0, 0x2E8)
SIG_S = (0x2E8, 0x330)

# The VCEK's extensions (AMD's "Versioned Chip Endorsement Key (VCEK) Certificate and
# KDS Interface Specification", publication 57230).
OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1"
OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2"
OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3"
OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8"
OID_HW_ID = "1.3.6.1.4.1.3704.1.4"
SPL_OIDS = {
    "bootloader": OID_BL_SPL,
    "tee": OID_TEE_SPL,
    "snp": OID_SNP_SPL,
    "microcode": OID_UCODE_SPL,
}


def decode_tcb(value: bytes) -> dict[str, int]:
    """A Milan or Genoa ``TCB_VERSION``: byte 0 the boot loader's SPL, 1 the PSP OS's
    (``tee``), 6 the SNP firmware's, 7 the microcode's."""
    return {"bootloader": value[0], "tee": value[1], "snp": value[6], "microcode": value[7]}


def encode_tcb(tcb: dict[str, int]) -> bytes:
    out = bytearray(8)
    out[0], out[1], out[6], out[7] = tcb["bootloader"], tcb["tee"], tcb["snp"], tcb["microcode"]
    return bytes(out)


def _slice(report: bytes, span: tuple[int, int]) -> bytes:
    return report[span[0] : span[1]]


def parse(report: bytes) -> ParsedReport:
    if len(report) != REPORT_SIZE:
        raise TeeError(
            f"an SEV-SNP report is {REPORT_SIZE} bytes; this is {len(report)}: not an SEV-SNP "
            "attestation report"
        )
    version = int.from_bytes(report[VERSION : VERSION + 4], "little")
    if version < 2:
        raise TeeError(f"SEV-SNP report version {version} is not one this reads (2 and later)")
    algo = int.from_bytes(report[SIGNATURE_ALGO : SIGNATURE_ALGO + 4], "little")
    if algo != SIGNATURE_ALGO_ECDSA_P384_SHA384:
        raise TeeError(f"SEV-SNP signature algorithm {algo} is not ECDSA P-384 with SHA-384")
    policy = int.from_bytes(report[POLICY : POLICY + 8], "little")
    return ParsedReport(
        platform="sev-snp",
        measurement=_slice(report, MEASUREMENT).hex(),
        init_data_digest=_slice(report, HOST_DATA).hex(),
        tcb=decode_tcb(_slice(report, REPORTED_TCB)),
        report_data=_slice(report, REPORT_DATA).hex(),
        debug=bool(policy >> POLICY_DEBUG_BIT & 1),
    )


def _extension(certificate: x509.Certificate, oid: str) -> bytes | None:
    try:
        value = certificate.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid)).value
    except x509.ExtensionNotFound:
        return None
    return value.value if isinstance(value, x509.UnrecognizedExtension) else None


def signature_problems(report: bytes, leaf: x509.Certificate) -> list[str]:
    """The report's signature under the VCEK, and the VCEK's chip and TCB against the
    report's."""
    problems = []
    r = int.from_bytes(_slice(report, SIG_R), "little")
    s = int.from_bytes(_slice(report, SIG_S), "little")
    from cryptography.hazmat.primitives.asymmetric import ec

    problem = ecdsa_verify(leaf.public_key(), ec.SECP384R1, r, s, report[:SIGNED_END], SHA384())
    if problem:
        problems.append(f"the SEV-SNP report's signature under the VCEK: {problem}")
    hw_id = _extension(leaf, OID_HW_ID)
    if hw_id is None:
        problems.append("the VCEK certificate names no chip (hwID)")
    else:
        try:
            chip = der_value(hw_id, 0x04)
        except ValueError:
            chip = hw_id  # some encoders put the raw bytes in the extension
        if chip != _slice(report, CHIP_ID):
            problems.append("the VCEK certificate is for another chip than the report's CHIP_ID")
    reported = decode_tcb(_slice(report, REPORTED_TCB))
    for component, oid in SPL_OIDS.items():
        raw = _extension(leaf, oid)
        try:
            spl = der_integer(raw) if raw is not None else None
        except ValueError:
            spl = None
        if spl != reported[component]:
            problems.append(
                f"the VCEK was derived for {component} SPL {spl}, the report's REPORTED_TCB "
                f"says {reported[component]}"
            )
    return problems


PLATFORM = Platform(
    name="sev-snp",
    parse=parse,
    signature_problems=signature_problems,
    # The ARK's list of revoked ASKs. The VCEK is not revoked by list: a VCEK is derived
    # for a TCB, and an old TCB is refused by the policy's minimum.
    required_crl_issuers=(-1,),
)
