"""Intel TDX quotes, version 4. **Unverified implementation.**

The layout is the TD quote of Intel's "TDX DCAP Quoting Library API" (quote format
version 4, attestation key type 2, ECDSA-256-with-P-256, TEE type 0x81):

* a 48-byte header;
* the 584-byte TD quote body: ``TEE_TCB_SVN`` (16), ``MRSEAM`` (48), ``MRSIGNERSEAM``
  (48), ``SEAMATTRIBUTES`` (8), ``TDATTRIBUTES`` (8), ``XFAM`` (8), ``MRTD`` (48),
  ``MRCONFIGID`` (48), ``MROWNER`` (48), ``MROWNERCONFIG`` (48), ``RTMR0``-``RTMR3``
  (4 x 48) and ``REPORTDATA`` (64);
* the signature data's length (4, little-endian), then the ECDSA signature over the
  header and body (r and s, 32 bytes each, big-endian), the attestation public key
  (x and y, 32 bytes each), and certification data of type 6: the quoting enclave's
  384-byte SGX report, its signature by the PCK key, the QE authentication data, and
  nested certification data of type 5, the PCK certificate chain in PEM.

Three signatures make the chain: Intel's root and the PCK platform or processor CA
issue the PCK certificate; the PCK key signs the quoting enclave's report, whose
``REPORTDATA`` holds ``sha256(attestation key || QE authentication data)``; the
attestation key signs the quote. ``TDATTRIBUTES`` bit 0 is ``DEBUG``.

Not implemented yet: the signature of Intel's TCB information and QE identity, and
matching the TCB against its levels. The TCB information's validity dates are checked;
the policy's minimum is compared with ``TEE_TCB_SVN`` byte by byte.

What this module has been tested on: synthetic quotes built to that layout, under a
synthetic root and PCK chain (``tests/test_tee_platforms.py``). It has not yet been run
against a quote from real hardware; see ``docs/roadmap-hardware-attestation.md``.
"""

from __future__ import annotations

import hashlib
import re

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from histor.crypto.tee.evidence import TeeError
from histor.crypto.tee.report import SHA256, ParsedReport, Platform, ecdsa_verify

HEADER_SIZE = 48
BODY_SIZE = 584
SIGNED_END = HEADER_SIZE + BODY_SIZE
QUOTE_VERSION = 4
ATTESTATION_KEY_ECDSA_P256 = 2
TEE_TYPE_TDX = 0x81
QE_REPORT_SIZE = 384
CERT_QE_REPORT = 6
CERT_PCK_CHAIN = 5

# Offsets into the body.
TEE_TCB_SVN = (0, 16)
TD_ATTRIBUTES = (120, 128)
MRTD = (136, 184)
MRCONFIGID = (184, 232)
REPORTDATA = (520, 584)
# Offset of REPORTDATA in an SGX report body.
QE_REPORTDATA = (320, 384)

_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


class _Quote:
    def __init__(self, quote: bytes) -> None:
        if len(quote) < SIGNED_END + 4:
            raise TeeError(f"a TDX quote is at least {SIGNED_END + 4} bytes; this is {len(quote)}")
        version = int.from_bytes(quote[0:2], "little")
        key_type = int.from_bytes(quote[2:4], "little")
        tee_type = int.from_bytes(quote[4:8], "little")
        if (version, key_type, tee_type) != (
            QUOTE_VERSION,
            ATTESTATION_KEY_ECDSA_P256,
            TEE_TYPE_TDX,
        ):
            raise TeeError(
                f"quote version {version}, key type {key_type}, TEE type {tee_type:#x} is not a "
                "TDX v4 ECDSA-P256 quote"
            )
        self.body = quote[HEADER_SIZE:SIGNED_END]
        length = int.from_bytes(quote[SIGNED_END : SIGNED_END + 4], "little")
        data = quote[SIGNED_END + 4 :]
        if len(data) != length or length < 64 + 64 + 6 + QE_REPORT_SIZE + 64 + 2:
            raise TeeError("the TDX quote's signature data is truncated")
        self.signed = quote[:SIGNED_END]
        self.signature = data[0:64]
        self.attestation_key = data[64:128]
        cert_type = int.from_bytes(data[128:130], "little")
        cert_size = int.from_bytes(data[130:134], "little")
        cert = data[134 : 134 + cert_size]
        if cert_type != CERT_QE_REPORT or len(cert) != cert_size:
            raise TeeError("the TDX quote's certification data is not a QE report (type 6)")
        self.qe_report = cert[:QE_REPORT_SIZE]
        self.qe_signature = cert[QE_REPORT_SIZE : QE_REPORT_SIZE + 64]
        rest = cert[QE_REPORT_SIZE + 64 :]
        auth_size = int.from_bytes(rest[0:2], "little")
        self.qe_auth = rest[2 : 2 + auth_size]
        inner = rest[2 + auth_size :]
        if len(inner) < 6:
            raise TeeError("the TDX quote carries no PCK certificate chain")
        inner_type = int.from_bytes(inner[0:2], "little")
        inner_size = int.from_bytes(inner[2:6], "little")
        if inner_type != CERT_PCK_CHAIN or len(inner) < 6 + inner_size:
            raise TeeError("the TDX quote's nested certification data is not a PCK chain (type 5)")
        self.pck_chain = inner[6 : 6 + inner_size]

    def field(self, span: tuple[int, int]) -> bytes:
        return self.body[span[0] : span[1]]


def parse(report: bytes) -> ParsedReport:
    quote = _Quote(report)
    return ParsedReport(
        platform="tdx",
        measurement=quote.field(MRTD).hex(),
        init_data_digest=quote.field(MRCONFIGID).hex(),
        tcb={"tee_tcb_svn": quote.field(TEE_TCB_SVN).hex()},
        report_data=quote.field(REPORTDATA).hex(),
        debug=bool(quote.field(TD_ATTRIBUTES)[0] & 1),
    )


def embedded_chain(report: bytes) -> list[str]:
    """The PCK certificate chain the quote carries, PEM, leaf first."""
    return [m.decode("ascii") for m in _PEM.findall(_Quote(report).pck_chain)]


def signature_problems(report: bytes, leaf: x509.Certificate) -> list[str]:
    """The quoting enclave's report under the PCK key, its binding of the attestation
    key, and the quote's signature under the attestation key."""
    quote = _Quote(report)
    problems = []
    problem = ecdsa_verify(
        leaf.public_key(),
        ec.SECP256R1,
        int.from_bytes(quote.qe_signature[:32], "big"),
        int.from_bytes(quote.qe_signature[32:], "big"),
        quote.qe_report,
        SHA256(),
    )
    if problem:
        problems.append(f"the quoting enclave's report under the PCK key: {problem}")
    bound = hashlib.sha256(quote.attestation_key + quote.qe_auth).digest() + bytes(32)
    if quote.qe_report[QE_REPORTDATA[0] : QE_REPORTDATA[1]] != bound:
        problems.append("the quoting enclave's report does not bind the quote's attestation key")
    try:
        attestation_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b"\x04" + quote.attestation_key
        )
    except ValueError:
        return [*problems, "the quote's attestation key is not a P-256 point"]
    problem = ecdsa_verify(
        attestation_key,
        ec.SECP256R1,
        int.from_bytes(quote.signature[:32], "big"),
        int.from_bytes(quote.signature[32:], "big"),
        quote.signed,
        SHA256(),
    )
    if problem:
        problems.append(f"the quote's signature under its attestation key: {problem}")
    return problems


PLATFORM = Platform(
    name="tdx",
    parse=parse,
    signature_problems=signature_problems,
    # The PCK CA's list of revoked PCK certificates, and the root's list of revoked CAs.
    required_crl_issuers=(1, -1),
    embedded_chain=embedded_chain,
)
