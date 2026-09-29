"""Checking TEE evidence: one routine for the key broker, the provider's releaser and
the offline verifier.

:func:`verify_evidence` answers, for one :class:`TeeEvidence` at one instant: is the
report the one its digest names, and do its typed fields say what its bytes say; does
its certificate chain run, signature by signature, to a vendor root the policy names
(and, when the caller holds roots of its own, to one of those); were the chain, the
revocation lists and the TCB information valid at that instant, and nothing in the
chain revoked; does the report's signature verify under the chain's leaf; and does it
meet the policy: an accepted platform and launch measurement, the pinned launch
configuration, at least the minimum TCB, and debug off. Given a :class:`TeeBinding`,
it also checks that the report binds the release.

It returns the problems it found, all of them, rather than stopping at the first, so
a refusal or a verdict can say everything that was wrong.

The policy is a plan's ``artifacts.tee_policy`` (``spec/plan.schema.json``).
"""

from __future__ import annotations

import datetime
import itertools
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from histor.crypto.tee import mock, snp, tdx
from histor.crypto.tee.evidence import (
    HARDWARE_PLATFORMS,
    PLATFORMS,
    TeeBinding,
    TeeError,
    TeeEvidence,
    check_binding,
    sha256_digest,
)
from histor.crypto.tee.report import ParsedReport, Platform

PLATFORM_FORMATS: dict[str, Platform] = {
    "mock": mock.PLATFORM,
    "sev-snp": snp.PLATFORM,
    "tdx": tdx.PLATFORM,
}
# Platforms whose verification has been run only on synthetic structures, never on
# evidence from real hardware. The verifier says so for each of them.
UNVERIFIED_IMPLEMENTATIONS = frozenset({"sev-snp", "tdx"})
# How much later than the instant it is checked at collateral may say it was captured.
CAPTURE_TOLERANCE = datetime.timedelta(minutes=10)


@dataclass
class Verification:
    platform: str
    problems: list[str] = field(default_factory=list)
    root_sha256: str | None = None
    parsed: ParsedReport | None = None

    @property
    def ok(self) -> bool:
        return not self.problems


def _instant(value: Any) -> datetime.datetime | None:
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.UTC)


def _stamp(value: datetime.datetime) -> str:
    return value.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _common_name(name: x509.Name) -> str:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(values[0].value) if values else name.rfc4514_string()


def _der_sha256(certificate: x509.Certificate) -> str:
    return sha256_digest(certificate.public_bytes(serialization.Encoding.DER))


def root_fingerprints(roots_pem: Sequence[str]) -> set[str]:
    """``sha256:`` over each root certificate's DER."""
    return {_der_sha256(x509.load_pem_x509_certificate(pem.encode("ascii"))) for pem in roots_pem}


def policy_roots(policy: Mapping[str, Any] | None, platform: str) -> set[str]:
    """The root fingerprints a policy accepts for a platform."""
    roots = (policy or {}).get("vendor_roots") or []
    return {
        str(r.get("sha256"))
        for r in roots
        if isinstance(r, dict) and str(r.get("platform")) == platform
    }


def tcb_problems(actual: Mapping[str, Any], minimum: Mapping[str, Any]) -> list[str]:
    """Each component of ``minimum`` the reported TCB is below, or does not report. An
    integer is compared as a number; a hex string (TDX's ``tee_tcb_svn``) byte by byte."""
    problems = []
    for component, least in sorted(minimum.items()):
        value = actual.get(component)
        if value is None:
            problems.append(f"the report states no TCB component {component!r}")
        elif isinstance(least, int) and isinstance(value, int):
            if value < least:
                problems.append(f"TCB {component} is {value}, below the policy's minimum {least}")
        elif isinstance(least, str) and isinstance(value, str) and len(least) == len(value):
            try:
                below = any(
                    a < b for a, b in zip(bytes.fromhex(value), bytes.fromhex(least), strict=True)
                )
            except ValueError:
                below = True
            if below:
                problems.append(
                    f"TCB {component} is {value}, below the policy's minimum {least} in at least "
                    "one component"
                )
        else:
            problems.append(f"TCB {component} {value!r} cannot be compared with {least!r}")
    return problems


def _chain_problems(
    platform: Platform,
    evidence: TeeEvidence,
    report: bytes,
    at: datetime.datetime,
    accepted: set[str] | None,
    anchored: set[str] | None,
    verification: Verification,
) -> list[str]:
    problems: list[str] = []
    try:
        chain = [
            x509.load_pem_x509_certificate(pem.encode("ascii"))
            for pem in evidence.collateral.certificates
        ]
    except ValueError as error:
        return [f"a certificate in the collateral does not parse: {error}"]
    if platform.embedded_chain is not None:
        try:
            embedded = [
                x509.load_pem_x509_certificate(pem.encode("ascii"))
                for pem in platform.embedded_chain(report)
            ]
        except (TeeError, ValueError) as error:
            return [f"the report's own certificate chain does not parse: {error}"]
        if [_der_sha256(c) for c in embedded] != [_der_sha256(c) for c in chain]:
            problems.append("the collateral's chain is not the one the report carries")
    for child, issuer in itertools.pairwise(chain):
        try:
            child.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm) as error:
            problems.append(
                f"{_common_name(child.subject)!r} is not signed by "
                f"{_common_name(issuer.subject)!r}: {error or type(error).__name__}"
            )
    root = chain[-1]
    try:
        root.verify_directly_issued_by(root)
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        problems.append(f"the chain ends at {_common_name(root.subject)!r}, which is not a root")
    fingerprint = _der_sha256(root)
    verification.root_sha256 = fingerprint
    if mock.MARKER in _common_name(root.subject) and evidence.platform in HARDWARE_PLATFORMS:
        problems.append(
            f"the chain ends at a mock root ({_common_name(root.subject)!r}) but the evidence "
            f"claims platform {evidence.platform}: mock evidence presented as hardware"
        )
    if accepted is not None and fingerprint not in accepted:
        problems.append(
            f"the chain ends at root {fingerprint[:23]}… ({_common_name(root.subject)!r}), "
            f"which the policy does not list for platform {evidence.platform}"
        )
    if anchored is not None and fingerprint not in anchored:
        problems.append(
            f"the chain ends at root {fingerprint[:23]}…, which is not one of the vendor roots "
            "you gave"
        )
    for certificate in chain:
        if not certificate.not_valid_before_utc <= at <= certificate.not_valid_after_utc:
            problems.append(
                f"certificate {_common_name(certificate.subject)!r} was not valid at "
                f"{_stamp(at)} (valid {_stamp(certificate.not_valid_before_utc)} to "
                f"{_stamp(certificate.not_valid_after_utc)})"
            )

    # Revocation lists.
    try:
        crls = [x509.load_pem_x509_crl(pem.encode("ascii")) for pem in evidence.collateral.crls]
    except ValueError as error:
        return [*problems, f"a revocation list in the collateral does not parse: {error}"]
    current: dict[int, x509.CertificateRevocationList] = {}
    for crl in crls:
        issuer_at = next(
            (
                i
                for i, c in enumerate(chain)
                if c.subject == crl.issuer and crl.is_signature_valid(c.public_key())  # type: ignore[arg-type]
            ),
            None,
        )
        if issuer_at is None:
            problems.append(
                f"a revocation list from {_common_name(crl.issuer)!r} is not signed by any "
                "certificate in the chain"
            )
            continue
        following = crl.next_update_utc
        if not (crl.last_update_utc <= at and (following is None or at <= following)):
            problems.append(
                f"the revocation list from {_common_name(crl.issuer)!r} was not current at "
                f"{_stamp(at)} (issued {_stamp(crl.last_update_utc)}, next update "
                f"{_stamp(following) if following else 'none'})"
            )
        current[issuer_at] = crl
        for certificate in chain:
            if certificate.issuer != crl.issuer or certificate.subject == certificate.issuer:
                continue
            revoked = crl.get_revoked_certificate_by_serial_number(certificate.serial_number)
            if revoked is not None and revoked.revocation_date_utc <= at:
                problems.append(
                    f"certificate {_common_name(certificate.subject)!r} was revoked at "
                    f"{_stamp(revoked.revocation_date_utc)}"
                )
    for position in platform.required_crl_issuers:
        index = position % len(chain)
        if index not in current:
            problems.append(
                f"the collateral carries no revocation list from "
                f"{_common_name(chain[index].subject)!r}, so revocation is not shown"
            )
    problems += platform.signature_problems(report, chain[0])
    return problems


def _tcb_info_problems(text: str | None, at: datetime.datetime) -> list[str]:
    if text is None:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return ["the collateral's TCB information is not JSON"]
    body = data.get("tcbInfo", data) if isinstance(data, dict) else {}
    issued = _instant(body.get("issueDate", body.get("issue_date")))
    following = _instant(body.get("nextUpdate", body.get("next_update")))
    if issued is None or following is None:
        return ["the collateral's TCB information states no issue date and next update"]
    if not issued <= at <= following:
        return [
            f"the TCB information was not current at {_stamp(at)} (issued {_stamp(issued)}, "
            f"next update {_stamp(following)})"
        ]
    return []


def verify_evidence(
    evidence: TeeEvidence,
    policy: Mapping[str, Any] | None,
    at: datetime.datetime,
    *,
    binding: TeeBinding | None = None,
    anchored_roots: Sequence[str] = (),
) -> Verification:
    """Every problem with ``evidence`` at instant ``at`` under ``policy``.

    ``policy`` None checks the report and its chain but no pin; the caller decides
    what that means. ``anchored_roots`` are PEM root certificates the caller holds
    itself (the verifier's ``--vendor-roots``); given, the chain must end at one.
    """
    verification = Verification(platform=evidence.platform)
    problems = verification.problems
    platform = PLATFORM_FORMATS.get(evidence.platform)
    if platform is None or evidence.platform not in PLATFORMS:
        problems.append(f"platform {evidence.platform!r} is not one of {list(PLATFORMS)}")
        return verification
    try:
        report = evidence.report_bytes
    except TeeError as error:
        problems.append(str(error))
        return verification
    if sha256_digest(report) != evidence.report_digest:
        problems.append(
            f"the report hashes to {sha256_digest(report)[:19]}…, not its report_digest "
            f"{evidence.report_digest[:19]}…"
        )
    if evidence.collateral.digest() != evidence.collateral_digest:
        problems.append("the collateral does not hash to its collateral_digest")
    try:
        parsed = platform.parse(report)
    except TeeError as error:
        problems.append(f"the report is not a {evidence.platform} report: {error}")
        return verification
    verification.parsed = parsed
    for name in ("measurement", "init_data_digest", "tcb", "report_data", "debug"):
        if getattr(parsed, name) != getattr(evidence, name):
            problems.append(
                f"the evidence says {name} {getattr(evidence, name)!r}, the signed report says "
                f"{getattr(parsed, name)!r}"
            )

    accepted = policy_roots(policy, evidence.platform) if policy is not None else None
    try:
        anchored = root_fingerprints(anchored_roots) if anchored_roots else None
    except ValueError as error:
        problems.append(f"a vendor root you gave does not parse: {error}")
        anchored = set()
    if accepted is None and anchored is None:
        problems.append("no vendor root to check the chain against: no policy and no roots given")
    problems += _chain_problems(platform, evidence, report, at, accepted, anchored, verification)
    problems += _tcb_info_problems(evidence.collateral.tcb_info, at)
    captured = _instant(evidence.collateral.captured_at)
    if captured is None:
        problems.append("the collateral does not say when it was captured")
    elif captured > at + CAPTURE_TOLERANCE:
        problems.append(
            f"the collateral was captured at {_stamp(captured)}, after the release it is "
            f"evidence for ({_stamp(at)})"
        )

    if parsed.debug:
        problems.append(
            "the TEE was launched with debug enabled: its memory is readable by the host"
        )
    if policy is not None:
        platforms = [str(p) for p in policy.get("platforms") or []]
        if evidence.platform not in platforms:
            problems.append(
                f"platform {evidence.platform} is not one the policy accepts ({platforms})"
            )
        measurements = [str(m) for m in policy.get("measurements") or []]
        if parsed.measurement not in measurements:
            problems.append(
                f"launch measurement {parsed.measurement[:16]}… is not one the policy accepts"
            )
        if parsed.init_data_digest != str(policy.get("init_data_digest")):
            problems.append(
                f"launch configuration {parsed.init_data_digest[:16]}… is not the pinned "
                f"init_data_digest {str(policy.get('init_data_digest'))[:16]}…"
            )
        minimum = policy.get("min_tcb") or {}
        if isinstance(minimum, Mapping):
            problems += tcb_problems(parsed.tcb, minimum)
    if binding is not None:
        problem = check_binding(evidence, binding)
        if problem:
            problems.append(problem)
    return verification
