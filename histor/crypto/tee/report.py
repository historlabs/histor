"""What every platform's parser returns, and the little DER and ECDSA helpers they share."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


@dataclass(frozen=True)
class ParsedReport:
    """The fields of a report the policy is checked against, read from its bytes."""

    platform: str
    measurement: str
    init_data_digest: str
    tcb: dict[str, Any]
    report_data: str
    debug: bool


@dataclass(frozen=True)
class Platform:
    """One platform's report format.

    ``parse`` reads a report (raising :class:`histor.crypto.tee.evidence.TeeError`);
    ``signature_problems`` checks the report's signature under the chain's leaf
    certificate and anything else the leaf must agree with; ``required_crl_issuers``
    are the positions in the chain (0 is the leaf, -1 the root) whose revocation list
    the collateral must carry; ``embedded_chain`` returns a chain the report itself
    carries (TDX), which must be the collateral's."""

    name: str
    parse: Callable[[bytes], ParsedReport]
    signature_problems: Callable[[bytes, x509.Certificate], list[str]]
    required_crl_issuers: tuple[int, ...]
    embedded_chain: Callable[[bytes], list[str]] | None = None


def ecdsa_verify(
    public_key: Any, curve: type[ec.EllipticCurve], r: int, s: int, data: bytes, algorithm: Any
) -> str | None:
    """None when (r, s) is a valid ECDSA signature over ``data`` under ``public_key``
    on ``curve``; otherwise why not."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, curve
    ):
        return f"the signing key is not an ECDSA {curve.name} key"
    try:
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(algorithm))
    except InvalidSignature:
        return "the signature does not verify"
    return None


SHA256 = hashes.SHA256
SHA384 = hashes.SHA384


def der_value(data: bytes, tag: int) -> bytes:
    """The content of one DER TLV of ``tag`` at the start of ``data``."""
    if len(data) < 2 or data[0] != tag:
        raise ValueError(f"expected DER tag {tag:#x}")
    length = data[1]
    offset = 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or len(data) < 2 + count:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[2 : 2 + count], "big")
        offset = 2 + count
    if len(data) < offset + length:
        raise ValueError("truncated DER value")
    return data[offset : offset + length]


def der_integer(data: bytes) -> int:
    return int.from_bytes(der_value(data, 0x02), "big", signed=True)
