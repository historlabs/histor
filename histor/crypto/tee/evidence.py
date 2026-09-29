"""The typed TEE evidence, its collateral, and the binding of a report to a release.

``TeeEvidence`` replaces the untyped ``RequesterAttestation.hardware_quote``. It
carries the raw report exactly as the platform produced it (``report``, base64), and
beside it the fields a reader wants to see without parsing a binary structure. The
report is authoritative: :func:`histor.crypto.tee.verify.verify_evidence` parses it
again and refuses evidence whose typed fields say something the report does not.

**The collateral** is everything needed to check the report offline, captured when
the key was released: the certificate chain up to the vendor's root, the revocation
lists, the vendor's TCB information and any OCSP responses (for GPU evidence). It is
kept whole in the ledger, so the verifier can re-check the report years later with
no network, at the time the release was stamped.

**The binding.** A report's 64-byte ``report_data`` is chosen by the software that
asks for the report, and the hardware signs it. Histor sets it to::

    sha256(release_public_key || broker_nonce || plan_digest || run_number) || 0^32

with fixed-width fields, so the concatenation is unambiguous: the 32 raw bytes of the
X25519 public key the key is sealed to, the 32 raw bytes of the nonce the key broker
issued for the run, the 32 raw bytes of the plan's SHA-256 digest, and the run number
as an unsigned 64-bit big-endian integer; the SHA-256 fills the first half of the
field and the second half is zero. A report bound this way names the one key the
release may be sealed to, for one run of one plan: a key substituted after the report
was made no longer matches it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

PLATFORMS = ("sev-snp", "tdx", "mock")
HARDWARE_PLATFORMS = ("sev-snp", "tdx")

REPORT_DATA_BYTES = 64
_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_HEX = re.compile(r"^[0-9a-f]*$")


class TeeError(ValueError):
    """TEE evidence, collateral or a binding that is malformed."""


def canonical(value: Any) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _hex(value: Any, what: str, length: int | None = None) -> str:
    text = str(value)
    if not _HEX.match(text) or len(text) % 2:
        raise TeeError(f"{what} is not lowercase hex")
    if length is not None and len(text) != 2 * length:
        raise TeeError(f"{what} is {len(text) // 2} bytes, not {length}")
    return text


def _strings(value: Any, what: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise TeeError(f"{what} is not a list of strings")
    return tuple(value)


@dataclass(frozen=True)
class Collateral:
    """What checking a report needs, captured at release time.

    ``certificates`` are PEM, leaf first and the vendor's root last. ``crls`` are PEM
    revocation lists issued by certificates in that chain. ``tcb_info`` is the
    vendor's TCB information as the raw JSON text it was received as (its signature,
    where it has one, covers the exact bytes). ``ocsp`` holds base64 DER OCSP
    responses, for GPU evidence. ``captured_at`` is when it was fetched (RFC 3339).
    """

    certificates: tuple[str, ...]
    crls: tuple[str, ...] = ()
    tcb_info: str | None = None
    ocsp: tuple[str, ...] = ()
    captured_at: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "certificates": list(self.certificates),
            "crls": list(self.crls),
            "tcb_info": self.tcb_info,
            "ocsp": list(self.ocsp),
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_json(cls, value: Any) -> Collateral:
        if not isinstance(value, dict):
            raise TeeError("the collateral is not an object")
        tcb_info = value.get("tcb_info")
        if tcb_info is not None and not isinstance(tcb_info, str):
            raise TeeError("the collateral's tcb_info is not the raw JSON text")
        certificates = _strings(value.get("certificates"), "the collateral's certificates")
        if not certificates:
            raise TeeError("the collateral holds no certificate chain")
        return cls(
            certificates=certificates,
            crls=_strings(value.get("crls", []), "the collateral's crls"),
            tcb_info=tcb_info,
            ocsp=_strings(value.get("ocsp", []), "the collateral's ocsp"),
            captured_at=str(value.get("captured_at", "")),
        )

    def digest(self) -> str:
        """``sha256:`` over the canonical JSON of :meth:`to_json`."""
        return sha256_digest(canonical(self.to_json()))


@dataclass(frozen=True)
class TeeEvidence:
    """One attestation report, typed, with the collateral to check it offline.

    ``measurement`` is the launch measurement (SEV-SNP ``MEASUREMENT``, TDX ``MRTD``),
    ``init_data_digest`` the launch configuration the harness digest is pinned in
    (SEV-SNP ``HOST_DATA``, TDX ``MRCONFIGID``), ``tcb`` the platform's TCB level by
    component, ``report_data`` the 64 bytes the binding sets, all in lowercase hex.
    ``gpu`` is a list of GPU evidence objects, carried and not yet verified (phase P2).
    """

    platform: str
    report: str
    report_digest: str
    measurement: str
    init_data_digest: str
    tcb: dict[str, Any]
    report_data: str
    debug: bool
    collateral: Collateral
    collateral_digest: str
    gpu: tuple[dict[str, Any], ...] | None = field(default=None)

    @property
    def report_bytes(self) -> bytes:
        try:
            return base64.b64decode(self.report, validate=True)
        except (binascii.Error, ValueError) as error:
            raise TeeError(f"the report is not base64: {error}") from None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "platform": self.platform,
            "report": self.report,
            "report_digest": self.report_digest,
            "measurement": self.measurement,
            "init_data_digest": self.init_data_digest,
            "tcb": dict(self.tcb),
            "report_data": self.report_data,
            "debug": self.debug,
            "collateral": self.collateral.to_json(),
            "collateral_digest": self.collateral_digest,
        }
        if self.gpu is not None:
            out["gpu"] = [dict(g) for g in self.gpu]
        return out

    def summary(self) -> dict[str, Any]:
        """The ``isolation_evidence.tee`` object of a run predicate: what identifies
        the report and what it attests, without the report and collateral themselves,
        which the ledger holds."""
        out: dict[str, Any] = {
            "platform": self.platform,
            "report_digest": self.report_digest,
            "measurement": self.measurement,
            "init_data_digest": self.init_data_digest,
            "tcb": dict(self.tcb),
            "collateral_digest": self.collateral_digest,
        }
        if self.gpu is not None:
            out["gpu"] = [dict(g) for g in self.gpu]
        return out

    @classmethod
    def from_json(cls, value: Any) -> TeeEvidence:
        if not isinstance(value, dict):
            raise TeeError("the TEE evidence is not an object")
        try:
            platform = str(value["platform"])
            if platform not in PLATFORMS:
                raise TeeError(f"platform {platform!r} is not one of {list(PLATFORMS)}")
            tcb = value["tcb"]
            if not isinstance(tcb, dict):
                raise TeeError("tcb is not an object")
            debug = value["debug"]
            if not isinstance(debug, bool):
                raise TeeError("debug is not a boolean")
            gpu = value.get("gpu")
            if gpu is not None and not (
                isinstance(gpu, list) and all(isinstance(g, dict) for g in gpu)
            ):
                raise TeeError("gpu is not a list of objects")
            for name in ("report_digest", "collateral_digest"):
                if not _DIGEST.match(str(value[name])):
                    raise TeeError(f"{name} is not sha256:<hex>")
            evidence = cls(
                platform=platform,
                report=str(value["report"]),
                report_digest=str(value["report_digest"]),
                measurement=_hex(value["measurement"], "measurement"),
                init_data_digest=_hex(value["init_data_digest"], "init_data_digest"),
                tcb=dict(tcb),
                report_data=_hex(value["report_data"], "report_data", REPORT_DATA_BYTES),
                debug=debug,
                collateral=Collateral.from_json(value["collateral"]),
                collateral_digest=str(value["collateral_digest"]),
                gpu=tuple(gpu) if gpu is not None else None,
            )
        except KeyError as error:
            raise TeeError(f"the TEE evidence lacks {error}") from None
        evidence.report_bytes  # noqa: B018 - decodes, or raises TeeError
        return evidence


@dataclass(frozen=True)
class TeeBinding:
    """What a report's ``report_data`` binds: the public key a release is sealed to,
    the broker's nonce, the plan digest and the run number. Recorded beside the
    evidence in ``key_released`` so the verifier can recompute the binding."""

    release_public_key: str  # base64 of the raw 32-byte X25519 public key
    broker_nonce: str  # hex of 32 bytes
    plan_digest: str
    run_number: int

    def to_json(self) -> dict[str, Any]:
        return {
            "release_public_key": self.release_public_key,
            "broker_nonce": self.broker_nonce,
            "plan_digest": self.plan_digest,
            "run_number": self.run_number,
        }

    @classmethod
    def from_json(cls, value: Any) -> TeeBinding:
        if not isinstance(value, dict):
            raise TeeError("the TEE binding is not an object")
        try:
            return cls(
                release_public_key=str(value["release_public_key"]),
                broker_nonce=_hex(value["broker_nonce"], "broker_nonce", 32),
                plan_digest=str(value["plan_digest"]),
                run_number=int(value["run_number"]),
            )
        except KeyError as error:
            raise TeeError(f"the TEE binding lacks {error}") from None

    @property
    def public_key_bytes(self) -> bytes:
        try:
            raw = base64.b64decode(self.release_public_key, validate=True)
        except (binascii.Error, ValueError) as error:
            raise TeeError(f"release_public_key is not base64: {error}") from None
        if len(raw) != 32:
            raise TeeError(f"release_public_key is {len(raw)} bytes, not 32")
        return raw

    @property
    def public_key_digest(self) -> str:
        """``sha256:`` over the raw key, as ``key_released`` records the job's key."""
        return sha256_digest(self.public_key_bytes)

    def report_data(self) -> bytes:
        return binding_report_data(
            self.public_key_bytes,
            bytes.fromhex(self.broker_nonce),
            self.plan_digest,
            self.run_number,
        )


def binding_report_data(
    release_public_key: bytes, broker_nonce: bytes, plan_digest: str, run_number: int
) -> bytes:
    """The 64 bytes a report's ``report_data`` must hold for this release."""
    if len(release_public_key) != 32:
        raise TeeError("the release public key is not 32 bytes")
    if len(broker_nonce) != 32:
        raise TeeError("the broker nonce is not 32 bytes")
    match = _DIGEST.match(str(plan_digest))
    if match is None:
        raise TeeError(f"plan digest {plan_digest!r} is not sha256:<hex>")
    if not 0 <= int(run_number) < 2**63:
        raise TeeError(f"run number {run_number} is out of range")
    message = (
        release_public_key
        + broker_nonce
        + bytes.fromhex(match.group(1))
        + int(run_number).to_bytes(8, "big")
    )
    return hashlib.sha256(message).digest() + bytes(32)


def check_binding(evidence: TeeEvidence, binding: TeeBinding) -> str | None:
    """None when the evidence's ``report_data`` is the binding's; otherwise why not.

    Only the typed field is compared here; :func:`histor.crypto.tee.verify.verify_evidence`
    holds the typed field to the signed report."""
    try:
        expected = binding.report_data().hex()
    except (TeeError, ValueError) as error:
        return f"the binding cannot be computed: {error}"
    if evidence.report_data != expected:
        return (
            f"the report binds report_data {evidence.report_data[:16]}…, but the release to "
            f"key {binding.public_key_digest[:19]}… for run {binding.run_number} of plan "
            f"{binding.plan_digest[:19]}… needs {expected[:16]}…: the report was made for "
            "another key, nonce, plan or run"
        )
    return None
