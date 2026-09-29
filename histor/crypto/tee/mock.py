"""The mock platform: software-made reports under a test root. **Not hardware evidence.**

It exists so the whole attested-release flow (binding, release, ledger, offline
verification) runs in CI and in ``histor run demo --tee mock``, with no TEE. A mock
report is a JSON object whose ``format`` is ``histor-mock-tee-report-v1`` and whose
``notice`` says, in words, that it is not hardware evidence. It is signed with ECDSA
P-384 by an attestation key whose certificate a mock root issues; the root's common
name says it is a mock and not a vendor's root.

Nothing about it is secret or trusted. Whoever holds the mock root's private key,
which is written to disk beside the demo's other development keys, can make a report
saying anything. So:

* the mock root is accepted only where a plan's ``tee_policy`` lists it by
  fingerprint under platform ``mock``, and never under ``sev-snp`` or ``tdx``
  (:func:`histor.crypto.tee.verify.verify_evidence` refuses a root whose name marks it
  as a mock under a hardware platform);
* a mock report does not parse as an SEV-SNP report or a TDX quote, so it cannot be
  passed off as one;
* the verifier warns on every mock report, valid or not: "mock platform: not hardware
  evidence".
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from histor.crypto.tee.evidence import (
    Collateral,
    TeeError,
    TeeEvidence,
    canonical,
    sha256_digest,
)
from histor.crypto.tee.report import SHA384, ParsedReport, Platform, ecdsa_verify

FORMAT = "histor-mock-tee-report-v1"
TCB_INFO_FORMAT = "histor-mock-tcb-info-v1"
NOTICE = (
    "MOCK TEE REPORT: made in software by Histor for tests and the demo. It is not "
    "hardware evidence and proves nothing about where or on what it was made."
)
# The marker a mock certificate's common name starts with. The verifier refuses a
# root carrying it under a hardware platform.
MARKER = "Histor MOCK TEE"
ROOT_NAME = f"{MARKER} root (not a vendor root, not hardware)"
ATTESTER_NAME = f"{MARKER} attestation key (not hardware)"

ROOT_FILE = "mock-tee-root.pem"
ROOT_KEY_FILE = "mock-tee-root.key.pem"
ATTESTER_FILE = "mock-tee-attester.pem"
ATTESTER_KEY_FILE = "mock-tee-attester.key.pem"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(microsecond=0)


def _stamp(value: datetime.datetime) -> str:
    return value.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Histor (mock, for tests)"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def fingerprint(certificate_pem: str) -> str:
    """``sha256:`` over a certificate's DER, as ``tee_policy.vendor_roots`` names a root."""
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    return sha256_digest(certificate.public_bytes(serialization.Encoding.DER))


@dataclass
class MockRoot:
    """The mock root and the attestation key it certifies."""

    root_key: ec.EllipticCurvePrivateKey
    root: x509.Certificate
    attester_key: ec.EllipticCurvePrivateKey
    attester: x509.Certificate

    @classmethod
    def generate(
        cls,
        not_before: datetime.datetime | None = None,
        attester_days: int = 365,
    ) -> MockRoot:
        start = (not_before or _now()) - datetime.timedelta(days=1)
        root_key = ec.generate_private_key(ec.SECP384R1())
        root = (
            x509.CertificateBuilder()
            .subject_name(_name(ROOT_NAME))
            .issuer_name(_name(ROOT_NAME))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(start + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(root_key, hashes.SHA384())
        )
        attester_key = ec.generate_private_key(ec.SECP384R1())
        attester = (
            x509.CertificateBuilder()
            .subject_name(_name(ATTESTER_NAME))
            .issuer_name(root.subject)
            .public_key(attester_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(start + datetime.timedelta(days=attester_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(root_key, hashes.SHA384())
        )
        return cls(root_key, root, attester_key, attester)

    @property
    def root_pem(self) -> str:
        return _pem(self.root)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.root_pem)

    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / ROOT_FILE).write_text(self.root_pem, encoding="ascii")
        (directory / ATTESTER_FILE).write_text(_pem(self.attester), encoding="ascii")
        for name, key in ((ROOT_KEY_FILE, self.root_key), (ATTESTER_KEY_FILE, self.attester_key)):
            path = directory / name
            path.write_bytes(_key_pem(key))
            path.chmod(0o600)

    @classmethod
    def load(cls, directory: Path) -> MockRoot:
        def key(name: str) -> ec.EllipticCurvePrivateKey:
            loaded = serialization.load_pem_private_key((directory / name).read_bytes(), None)
            if not isinstance(loaded, ec.EllipticCurvePrivateKey):
                raise TeeError(f"{directory / name} is not an EC private key")
            return loaded

        def cert(name: str) -> x509.Certificate:
            return x509.load_pem_x509_certificate((directory / name).read_bytes())

        return cls(key(ROOT_KEY_FILE), cert(ROOT_FILE), key(ATTESTER_KEY_FILE), cert(ATTESTER_FILE))

    @classmethod
    def ensure(cls, directory: Path) -> MockRoot:
        """The mock root in ``directory``, made there the first time."""
        if (directory / ROOT_KEY_FILE).exists():
            return cls.load(directory)
        root = cls.generate()
        root.save(directory)
        return root

    def crl(
        self,
        last_update: datetime.datetime,
        next_update: datetime.datetime,
        revoked: tuple[int, ...] = (),
    ) -> str:
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.root.subject)
            .last_update(last_update)
            .next_update(next_update)
        )
        for serial in revoked:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(last_update)
                .build()
            )
        crl = builder.sign(self.root_key, hashes.SHA384())
        return crl.public_bytes(serialization.Encoding.PEM).decode("ascii")


def tcb_info(
    issue_date: datetime.datetime, next_update: datetime.datetime, tcb: dict[str, Any]
) -> str:
    """The mock's TCB information, as raw JSON text: when it was issued, when it must be
    replaced, and the TCB it describes as current."""
    return json.dumps(
        {
            "format": TCB_INFO_FORMAT,
            "notice": NOTICE,
            "issue_date": _stamp(issue_date),
            "next_update": _stamp(next_update),
            "tcb": tcb,
        },
        sort_keys=True,
    )


def make_report(
    key: ec.EllipticCurvePrivateKey,
    measurement: str,
    init_data_digest: str,
    tcb: dict[str, Any],
    report_data: bytes,
    debug: bool = False,
) -> bytes:
    body = {
        "format": FORMAT,
        "notice": NOTICE,
        "measurement": measurement,
        "init_data_digest": init_data_digest,
        "tcb": tcb,
        "debug": debug,
        "report_data": report_data.hex(),
    }
    signature = key.sign(canonical(body), ec.ECDSA(hashes.SHA384()))
    return canonical({"body": body, "signature": base64.b64encode(signature).decode("ascii")})


def _read(report: bytes) -> tuple[dict[str, Any], bytes]:
    try:
        data = json.loads(report)
        body = data["body"]
        signature = base64.b64decode(str(data["signature"]), validate=True)
    except (ValueError, KeyError, TypeError, binascii.Error) as error:
        raise TeeError(f"not a mock TEE report: {error}") from None
    if not isinstance(body, dict) or body.get("format") != FORMAT:
        raise TeeError(f"not a {FORMAT}")
    if canonical(data) != report:
        raise TeeError("the mock report is not in canonical form")
    return body, signature


def parse(report: bytes) -> ParsedReport:
    body, _ = _read(report)
    try:
        tcb = body["tcb"]
        debug = body["debug"]
        if not isinstance(tcb, dict) or not isinstance(debug, bool):
            raise TypeError("tcb or debug has the wrong type")
        return ParsedReport(
            platform="mock",
            measurement=str(body["measurement"]),
            init_data_digest=str(body["init_data_digest"]),
            tcb=dict(tcb),
            report_data=str(body["report_data"]),
            debug=debug,
        )
    except (KeyError, TypeError) as error:
        raise TeeError(f"the mock report is malformed: {error}") from None


def signature_problems(report: bytes, leaf: x509.Certificate) -> list[str]:
    body, signature = _read(report)
    try:
        r, s = decode_dss_signature(signature)
    except ValueError:
        return ["the mock report's signature is not a DER ECDSA signature"]
    problem = ecdsa_verify(leaf.public_key(), ec.SECP384R1, r, s, canonical(body), SHA384())
    return [f"the mock report's signature under its attestation key: {problem}"] if problem else []


PLATFORM = Platform(
    name="mock", parse=parse, signature_problems=signature_problems, required_crl_issuers=(-1,)
)


@dataclass
class MockAttester:
    """Makes mock evidence for one launch configuration, as a harness inside a TEE
    would ask the hardware for a report."""

    root: MockRoot
    measurement: str
    init_data_digest: str
    tcb: dict[str, Any] = field(default_factory=lambda: {"version": 1})
    debug: bool = False
    crl_days: int = 7
    tcb_info_days: int = 30

    def attest(self, report_data: bytes, at: datetime.datetime | None = None) -> TeeEvidence:
        now = at or _now()
        report = make_report(
            self.root.attester_key,
            self.measurement,
            self.init_data_digest,
            self.tcb,
            report_data,
            self.debug,
        )
        start = now - datetime.timedelta(hours=1)
        collateral = Collateral(
            certificates=(_pem(self.root.attester), self.root.root_pem),
            crls=(self.root.crl(start, now + datetime.timedelta(days=self.crl_days)),),
            tcb_info=tcb_info(start, now + datetime.timedelta(days=self.tcb_info_days), self.tcb),
            ocsp=(),
            captured_at=_stamp(now),
        )
        return TeeEvidence(
            platform="mock",
            report=base64.b64encode(report).decode("ascii"),
            report_digest=sha256_digest(report),
            measurement=self.measurement,
            init_data_digest=self.init_data_digest,
            tcb=dict(self.tcb),
            report_data=report_data.hex(),
            debug=self.debug,
            collateral=collateral,
            collateral_digest=collateral.digest(),
        )


def launch_measurement(harness_image_digest: str) -> str:
    """The mock's stand-in for a launch measurement of a harness image: SHA-384 of a
    labelled string, 48 bytes like SEV-SNP's ``MEASUREMENT`` and TDX's ``MRTD``."""
    return hashlib.sha384(f"histor-mock-launch:{harness_image_digest}".encode()).hexdigest()


def init_data_digest(harness_image_digest: str) -> str:
    """The mock's stand-in for the launch configuration that pins the harness image:
    SHA-256 of ``{"harness_image_digest": ...}`` in canonical JSON, 32 bytes like
    SEV-SNP's ``HOST_DATA``."""
    return hashlib.sha256(canonical({"harness_image_digest": harness_image_digest})).hexdigest()


def policy_for(
    root: MockRoot, harness_image_digest: str, min_tcb: dict[str, Any] | None = None
) -> dict[str, Any]:
    """A plan's ``artifacts.tee_policy`` that accepts this mock root, and only it, for
    the harness image given."""
    return {
        "platforms": ["mock"],
        "measurements": [launch_measurement(harness_image_digest)],
        "init_data_digest": init_data_digest(harness_image_digest),
        "min_tcb": dict(min_tcb or {"version": 1}),
        "vendor_roots": [
            {"platform": "mock", "sha256": root.fingerprint, "name": ROOT_NAME},
        ],
    }
