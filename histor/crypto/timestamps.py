"""External timestamps.

The ledger's hash chain proves nothing was removed from the middle. It does not prove
when anything happened, and an operator who controls the ledger can rebuild the whole
chain with different contents. An external timestamp is what stops that: a third party
attests that a given entry hash existed at a given time, so a rebuilt chain would have
to forge the third party's signature too.

The external authority speaks RFC 3161. This module defines the interface and ships two
implementations:

``Rfc3161Authority``
    The real thing, against a timestamp authority over HTTPS. Needs network at
    stamping time (never at verification time, which is the point). The authority's
    root certificate is pinned by the operator and carried in the bundle; the
    verifier checks every token's signature and chain against it, offline.

``DevAuthority``
    A local signer, for development and CI. It is **not** an external timestamp — it
    is the same operator signing their own clock — and it says so in every token it
    produces, so a verifier can and does report it as such.

Verification never needs the network in either case: the token and the authority's
public key travel in the evidence bundle.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from histor.crypto import signing
from histor.crypto.resources import resource


@dataclass(frozen=True)
class TimestampToken:
    authority: str
    kind: str  # rfc3161 | dev
    timestamp: str
    digest: str
    token: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "kind": self.kind,
            "timestamp": self.timestamp,
            "digest": self.digest,
            "token": self.token,
        }

    @property
    def is_external(self) -> bool:
        """Whether a third party vouched for this time.

        The verifier reports on this explicitly. A bundle timestamped by the operator
        that produced it has a hash chain and nothing anchoring it to a clock.
        """
        return self.kind == "rfc3161"


class TimestampAuthority(Protocol):
    name: str

    def stamp(self, digest: str) -> TimestampToken: ...

    def public_keys(self) -> dict[str, str]: ...


class DevAuthority:
    """A local signer standing in for a timestamp authority.

    Every token it issues carries ``"external": false`` and a warning string, because
    the failure mode to design against is a demo bundle being mistaken for a real one.
    """

    def __init__(self, keypair: signing.KeyPair, name: str = "dev-local") -> None:
        self.keypair = keypair
        self.name = name

    def stamp(self, digest: str) -> TimestampToken:
        now = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        payload = {
            "digest": digest,
            "timestamp": now,
            "authority": self.name,
            "external": False,
            "warning": (
                "Signed by the sandbox operator's own key, not by a third-party "
                "timestamp authority. This anchors nothing: an operator who can "
                "rebuild the ledger can reissue these. Not valid as evidence."
            ),
        }
        return TimestampToken(
            authority=self.name,
            kind="dev",
            timestamp=now,
            digest=digest,
            token=signing.sign_json(self.keypair, payload),
        )

    def public_keys(self) -> dict[str, str]:
        return {self.keypair.key_id: self.keypair.public_pem}


# The key id a development token is signed under (sandbox/devkeys.py).
DEV_KEY_ID = "timestamp-authority"


class Rfc3161Error(signing.VerificationError):
    """An RFC 3161 token or response that does not check out."""


# The prefix under which a timestamp authority's pinned root sits among the bundle's
# public keys, so a verifier holding only the bundle knows which roots to trust.
TSA_ROOT_PREFIX = "tsa-root:"


class Rfc3161Authority:
    """An RFC 3161 timestamp authority over HTTPS.

    Each ledger entry's hash is sent as the message imprint, with a fresh nonce and a
    request for the authority's certificate. The response is checked before the entry
    is written — the right imprint, the right nonce, a signature that verifies up to
    the pinned root — so a ledger never holds a token its own verifier would reject.

    ``root_pem`` is the authority's root certificate, pinned by the operator (for
    FreeTSA, ``infra/timestamps/freetsa-cacert.pem``). It travels in the bundle's
    public keys under ``tsa-root:<name>``; verification needs nothing else and no
    network.
    """

    def __init__(
        self, url: str, root_pem: str, name: str | None = None, timeout: float = 20.0
    ) -> None:
        self.url = url
        self.root_pem = root_pem
        self.name = name or url
        self.timeout = timeout
        # Where the signer's revocation status comes from; replaced in tests.
        self.fetch_revocation: Callable[[list[bytes], float], dict[str, Any] | None] = (
            fetch_revocation
        )
        self._revocations: dict[bytes, dict[str, Any]] = {}

    def stamp(self, digest: str) -> TimestampToken:
        import base64
        import os
        import urllib.request

        from asn1crypto import algos, core, tsp

        imprint = bytes.fromhex(digest.removeprefix("sha256:"))
        nonce = int.from_bytes(os.urandom(8), "big")
        request = tsp.TimeStampReq(
            {
                "version": "v1",
                "message_imprint": tsp.MessageImprint(
                    {
                        "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                        "hashed_message": imprint,
                    }
                ),
                "nonce": core.Integer(nonce),
                "cert_req": True,
            }
        )
        http = urllib.request.Request(
            self.url,
            data=request.dump(),
            headers={"Content-Type": "application/timestamp-query"},
            method="POST",
        )
        with urllib.request.urlopen(http, timeout=self.timeout) as response:
            raw = response.read()
        reply = tsp.TimeStampResp.load(raw)
        status = reply["status"]["status"].native
        if status not in {"granted", "granted_with_mods"}:
            raise Rfc3161Error(f"{self.name} refused the request: {status}")
        token_der = reply["time_stamp_token"].dump()
        attested = verify_rfc3161(token_der, digest, [self.root_pem])
        if attested["nonce"] != nonce:
            raise Rfc3161Error(f"{self.name} answered with another request's nonce")
        token: dict[str, Any] = {
            "url": self.url,
            "der": base64.b64encode(token_der).decode("ascii"),
        }
        revocation = self._revocation(attested)
        if revocation is not None:
            token["revocation"] = revocation
        return TimestampToken(
            authority=self.name,
            kind="rfc3161",
            timestamp=attested["time"],
            digest=digest,
            token=token,
        )

    def _revocation(self, attested: dict[str, Any]) -> dict[str, Any] | None:
        """The signer certificate's revocation status as the authority's CA gave it at
        stamping time, fetched once and reused while it is current. A certificate
        revoked by then refuses the token; none to be had records nothing, and the
        verifier says so."""
        chain: list[bytes] = attested["chain_der"]
        at = _instant(attested["time"])
        cached = self._revocations.get(chain[0])
        if cached is not None and at is not None and revocation_problem(cached, chain, at) is None:
            return cached
        evidence = self.fetch_revocation(chain, self.timeout)
        if evidence is None:
            return None
        if at is not None:
            problem = revocation_problem(evidence, chain, at)
            if problem is not None:
                raise Rfc3161Error(f"{self.name}: {problem}")
        self._revocations[chain[0]] = evidence
        return evidence

    def public_keys(self) -> dict[str, str]:
        return {TSA_ROOT_PREFIX + self.name: self.root_pem}


def verify_rfc3161(token_der: bytes, digest: str, roots_pem: list[str]) -> dict[str, Any]:
    """Verify an RFC 3161 TimeStampToken offline, and return what it attests.

    Checks, in order: it is CMS SignedData over a TSTInfo; the TSTInfo's imprint is
    ``digest``; the signed attributes carry the TSTInfo's hash; the signer's
    certificate signed those attributes, is valid at the stamped time and is marked
    for time stamping; and the certificate chain ends at one of ``roots_pem``.
    """
    import hashlib

    from asn1crypto import cms, tsp
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID

    try:
        content = cms.ContentInfo.load(token_der)
        if content["content_type"].native != "signed_data":
            raise Rfc3161Error("the token is not CMS signed data")
        signed = content["content"]
        encap = signed["encap_content_info"]
        if encap["content_type"].native != "tst_info":
            raise Rfc3161Error("the token does not carry timestamp info")
        tst_der = encap["content"].parsed.dump()
        tst = tsp.TSTInfo.load(tst_der)
    except (ValueError, TypeError, KeyError) as error:
        raise Rfc3161Error(f"the token does not parse: {error}") from error

    imprint = tst["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].native != "sha256":
        raise Rfc3161Error("the imprint is not SHA-256")
    if imprint["hashed_message"].native.hex() != digest.removeprefix("sha256:"):
        raise Rfc3161Error("the token was issued over another digest")

    if len(signed["signer_infos"]) != 1:
        raise Rfc3161Error("the token does not have exactly one signer")
    (signer_info,) = signed["signer_infos"]
    algorithm = signer_info["digest_algorithm"]["algorithm"].native
    hash_algorithms: dict[str, hashes.HashAlgorithm] = {
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }
    if algorithm not in hash_algorithms:
        raise Rfc3161Error(f"unsupported digest algorithm {algorithm}")
    attributes = {a["type"].native: a["values"][0] for a in signer_info["signed_attrs"]}
    if attributes.get("content_type") is None or attributes["content_type"].native != "tst_info":
        raise Rfc3161Error("the signed attributes do not name timestamp info")
    expected = hashlib.new(algorithm, tst_der).digest()
    if attributes.get("message_digest") is None or attributes["message_digest"].native != expected:
        raise Rfc3161Error("the signature covers other timestamp info than the token carries")

    certificates = [
        x509.load_der_x509_certificate(c.chosen.dump()) for c in signed["certificates"] or []
    ]
    sid = signer_info["sid"]
    signer: x509.Certificate | None = None
    for certificate in certificates:
        if sid.name == "issuer_and_serial_number":
            if certificate.serial_number == sid.chosen["serial_number"].native:
                signer = certificate
        else:
            try:
                ski = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            except x509.ExtensionNotFound:
                continue
            if ski.value.digest == sid.chosen.native:
                signer = certificate
    if signer is None:
        raise Rfc3161Error("the token does not include the certificate that signed it")

    # The signed attributes are signed as a DER SET, not as the [0]-tagged field.
    signed_attrs = bytearray(signer_info["signed_attrs"].dump())
    signed_attrs[0] = 0x31
    signature = signer_info["signature"].native
    public = signer.public_key()
    try:
        if isinstance(public, rsa.RSAPublicKey):
            public.verify(
                signature, bytes(signed_attrs), padding.PKCS1v15(), hash_algorithms[algorithm]
            )
        elif isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(signature, bytes(signed_attrs), ec.ECDSA(hash_algorithms[algorithm]))
        else:
            raise Rfc3161Error("unsupported signing key type")
    except InvalidSignature as error:
        raise Rfc3161Error("the authority's signature does not verify") from error

    gen_time = tst["gen_time"].native
    if not signer.not_valid_before_utc <= gen_time <= signer.not_valid_after_utc:
        raise Rfc3161Error("the signing certificate was not valid at the stamped time")
    # RFC 3161 §2.3: the signer's certificate carries one extended key usage,
    # timeStamping, marked critical. A certificate issued for anything else, under a
    # root that also issues those, is not a timestamp authority's.
    try:
        extension = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound as error:
        raise Rfc3161Error("the signing certificate is not marked for time stamping") from error
    if ExtendedKeyUsageOID.TIME_STAMPING not in extension.value:
        raise Rfc3161Error("the signing certificate is not marked for time stamping")
    if not extension.critical or len(list(extension.value)) != 1:
        raise Rfc3161Error(
            "the signing certificate's time-stamping usage is not its only usage, marked "
            "critical (RFC 3161 §2.3)"
        )
    if _is_ca(signer):
        raise Rfc3161Error("the signing certificate is a CA's, not a timestamp authority's")

    roots = [x509.load_pem_x509_certificate(pem.encode("ascii")) for pem in roots_pem]
    pool = certificates + roots
    chain = [signer]
    refused = ""
    while True:
        current = chain[-1]
        anchor = next((r for r in roots if r == current), None)
        if anchor is not None:
            break
        # By name first, then by signature: two certificates can share a name, and
        # only the one whose key signed this certificate is its issuer. And an issuer
        # must be a CA that may sign certificates, valid when the token was stamped,
        # with no more CAs below it than its path length allows (RFC 5280 §4.2.1.9).
        issuer = None
        for candidate in pool:
            if candidate.subject != current.issuer or candidate in chain:
                continue
            try:
                current.verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature):
                continue
            problem = _issuer_problem(candidate, len(chain) - 1, gen_time)
            if problem:
                refused = problem
                continue
            issuer = candidate
            break
        if issuer is None:
            raise Rfc3161Error(refused or "the certificate chain does not reach a pinned root")
        chain.append(issuer)
        if len(chain) > 8:
            raise Rfc3161Error("the certificate chain is too long")

    nonce = tst["nonce"].native
    from cryptography.hazmat.primitives import serialization

    return {
        "time": gen_time.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "digest": digest,
        "nonce": nonce,
        "authority": signer.subject.rfc4514_string(),
        "root_sha256": chain[-1].fingerprint(hashes.SHA256()).hex(),
        # The signer's certificate first, the pinned root last: what revocation
        # evidence is checked against (check_revocation).
        "chain_der": [c.public_bytes(serialization.Encoding.DER) for c in chain],
    }


def _is_ca(certificate: Any) -> bool:
    from cryptography import x509

    try:
        return bool(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _issuer_problem(certificate: Any, below: int, gen_time: datetime) -> str:
    """Why ``certificate`` cannot have issued the one below it, or "". ``below`` counts
    the CA certificates already between it and the timestamp authority's own."""
    from cryptography import x509

    name = certificate.subject.rfc4514_string()
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return f"{name} issued a certificate in the chain but is not a CA (no basicConstraints)"
    if not constraints.ca:
        return f"{name} issued a certificate in the chain but is not a CA (CA:FALSE)"
    if constraints.path_length is not None and below > constraints.path_length:
        return f"{name} allows {constraints.path_length} CA(s) below it; the chain has {below}"
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.key_cert_sign:
        return f"{name} issued a certificate in the chain but may not sign certificates"
    if not certificate.not_valid_before_utc <= gen_time <= certificate.not_valid_after_utc:
        return f"{name} was not valid at the stamped time"
    return ""


# --- revocation of the authority's certificate ----------------------------------------
#
# A token signed by a certificate its CA had revoked is not the authority's word. The
# status is fetched when the token is stamped, from the CA's OCSP responder or its
# CRL (the signer certificate's authorityInfoAccess and cRLDistributionPoints), and
# kept beside the token as ``token["revocation"] = {"kind": "ocsp" | "crl", "url",
# "der": <base64>}``. The verifier checks it offline against the token's own chain.

# How current the evidence must be at the stamped time: produced no later than this
# after it, and, where it states no next update, no earlier than REVOCATION_MAX_AGE.
REVOCATION_SKEW = timedelta(minutes=10)
REVOCATION_MAX_AGE = timedelta(hours=24)


def _instant(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _urls(certificate: Any) -> tuple[list[str], list[str]]:
    """The OCSP responders and CRL locations a certificate names."""
    from cryptography import x509
    from cryptography.x509.oid import AuthorityInformationAccessOID

    ocsp_urls: list[str] = []
    crl_urls: list[str] = []
    try:
        access = certificate.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value
        ocsp_urls = [
            d.access_location.value
            for d in access
            if d.access_method == AuthorityInformationAccessOID.OCSP
            and isinstance(d.access_location, x509.UniformResourceIdentifier)
        ]
    except x509.ExtensionNotFound:
        pass
    try:
        points = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        crl_urls = [
            name.value
            for point in points
            for name in point.full_name or []
            if isinstance(name, x509.UniformResourceIdentifier)
        ]
    except x509.ExtensionNotFound:
        pass
    return ocsp_urls, crl_urls


def fetch_revocation(chain_der: list[bytes], timeout: float = 20.0) -> dict[str, Any] | None:
    """The signer certificate's revocation status, from its CA's OCSP responder, else
    its CRL; None when it names neither or neither answers. Stamping never fails for
    want of it: the verifier says the token carries none."""
    import base64
    import urllib.request

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import ocsp

    if len(chain_der) < 2:
        return None
    signer = x509.load_der_x509_certificate(chain_der[0])
    issuer = x509.load_der_x509_certificate(chain_der[1])
    ocsp_urls, crl_urls = _urls(signer)
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(signer, issuer, hashes.SHA1())
        .build()
        .public_bytes(serialization.Encoding.DER)
    )
    for url in ocsp_urls:
        try:
            http = urllib.request.Request(
                url,
                data=request,
                headers={"Content-Type": "application/ocsp-request"},
                method="POST",
            )
            with urllib.request.urlopen(http, timeout=timeout) as response:
                der = response.read()
            if ocsp.load_der_ocsp_response(der).response_status != (
                ocsp.OCSPResponseStatus.SUCCESSFUL
            ):
                continue
        except (OSError, ValueError):
            continue
        return {"kind": "ocsp", "url": url, "der": base64.b64encode(der).decode("ascii")}
    for url in crl_urls:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                der = response.read()
            x509.load_der_x509_crl(der)
        except (OSError, ValueError):
            continue
        return {"kind": "crl", "url": url, "der": base64.b64encode(der).decode("ascii")}
    return None


def _current(this: datetime, following: datetime | None, at: datetime) -> str | None:
    if this > at + REVOCATION_SKEW:
        return f"it was produced at {this.isoformat()}, after the token was stamped ({at})"
    if following is not None and following < at - REVOCATION_SKEW:
        return f"it expired at {following.isoformat()}, before the token was stamped ({at})"
    if following is None and this < at - REVOCATION_MAX_AGE:
        return f"it was produced at {this.isoformat()}, over a day before the token ({at})"
    return None


def _signed_by(public: Any, signature: bytes, data: bytes, algorithm: Any) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    try:
        if isinstance(public, rsa.RSAPublicKey):
            public.verify(signature, data, padding.PKCS1v15(), algorithm)
        elif isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(signature, data, ec.ECDSA(algorithm))
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def revocation_problem(evidence: Any, chain_der: list[bytes], at: datetime) -> str | None:
    """What is wrong with a token's revocation evidence, or None when it shows the
    signer certificate was not revoked at ``at`` (the stamped time). Offline: the
    evidence must be signed by the signer's issuer in ``chain_der`` (or, for OCSP, by a
    responder that issuer delegated to), be about the signer, and be current at ``at``."""
    import base64

    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.x509 import ocsp
    from cryptography.x509.oid import ExtendedKeyUsageOID

    if not isinstance(evidence, dict) or evidence.get("kind") not in {"ocsp", "crl"}:
        return "the revocation evidence is not an OCSP response or a CRL"
    if len(chain_der) < 2:
        return "the token's certificate chain has no issuer to check revocation against"
    signer = x509.load_der_x509_certificate(chain_der[0])
    issuer = x509.load_der_x509_certificate(chain_der[1])
    try:
        der = base64.b64decode(str(evidence.get("der")), validate=True)
    except ValueError:
        return "the revocation evidence is not base64"
    if evidence["kind"] == "crl":
        try:
            crl = x509.load_der_x509_crl(der)
        except ValueError:
            return "the CRL does not parse"
        if crl.issuer != issuer.subject or not crl.is_signature_valid(
            issuer.public_key()  # type: ignore[arg-type]
        ):
            return "the CRL is not signed by the certificate's issuer"
        stale = _current(crl.last_update_utc, crl.next_update_utc, at)
        if stale:
            return f"the CRL is not current: {stale}"
        revoked = crl.get_revoked_certificate_by_serial_number(signer.serial_number)
        if revoked is not None and revoked.revocation_date_utc <= at:
            return (
                f"the CRL lists the authority's certificate as revoked on "
                f"{revoked.revocation_date_utc.isoformat()}, before the token was stamped"
            )
        return None
    try:
        response = ocsp.load_der_ocsp_response(der)
    except ValueError:
        return "the OCSP response does not parse"
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return f"the OCSP responder answered {response.response_status.name}"
    responder = None
    for candidate in [issuer, *response.certificates]:
        if (
            response.responder_name is not None and candidate.subject != response.responder_name
        ) or (
            response.responder_key_hash is not None
            and x509.SubjectKeyIdentifier.from_public_key(candidate.public_key()).digest
            != response.responder_key_hash
        ):
            continue
        if candidate != issuer:
            # A delegated responder: issued by the issuer, for OCSP signing only.
            try:
                candidate.verify_directly_issued_by(issuer)
                usage = candidate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            except (ValueError, TypeError, x509.ExtensionNotFound, InvalidSignature):
                continue
            if ExtendedKeyUsageOID.OCSP_SIGNING not in usage.value:
                continue
        responder = candidate
        break
    if responder is None or not _signed_by(
        responder.public_key(),
        response.signature,
        response.tbs_response_bytes,
        response.signature_hash_algorithm,
    ):
        return "the OCSP response is not signed by the certificate's issuer or its responder"
    single = next((r for r in response.responses if r.serial_number == signer.serial_number), None)
    if single is None:
        return "the OCSP response is about another certificate"
    stale = _current(single.this_update_utc, single.next_update_utc, at)
    if stale:
        return f"the OCSP response is not current: {stale}"
    if single.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        when = single.revocation_time_utc
        if when is None or when <= at:
            return "the OCSP responder says the authority's certificate was revoked"
    elif single.certificate_status != ocsp.OCSPCertStatus.GOOD:
        return "the OCSP responder does not know the authority's certificate"
    return None


def verify_token(token: dict[str, Any], public_keys: dict[str, str]) -> dict[str, Any]:
    """Check a timestamp token and return what it attests."""
    kind = token.get("kind")
    if kind == "dev":
        # The development authority's key and no other: a token signed by any key
        # the bundle lists would otherwise pass as one.
        key = {DEV_KEY_ID: public_keys[DEV_KEY_ID]} if DEV_KEY_ID in public_keys else {}
        return signing.verify_json(token["token"], key)
    if kind == "rfc3161":
        import base64

        roots = [pem for key, pem in public_keys.items() if key.startswith(TSA_ROOT_PREFIX)]
        if not roots:
            raise Rfc3161Error("the bundle pins no timestamp authority root to verify against")
        return verify_rfc3161(base64.b64decode(token["token"]["der"]), token["digest"], roots)
    raise signing.VerificationError(f"unknown timestamp kind {kind!r}")


# Timestamp authorities the repository pins a root for: name -> (URL, root certificate,
# relative to the repository root; a wheel carries a copy, see histor/crypto/resources.py).
KNOWN_AUTHORITIES = {
    "freetsa": ("https://freetsa.org/tsr", "infra/timestamps/freetsa-cacert.pem"),
}


def authority_from(spec: str, dev_key: signing.KeyPair | None) -> TimestampAuthority:
    """``dev``, a name in ``KNOWN_AUTHORITIES``, or ``<url>|<root.pem>``.

    Never falls back: an authority that cannot be reached is an error, because a
    bundle's timestamps have to be what was asked for.
    """
    if spec == "dev":
        if dev_key is None:
            raise ValueError("--tsa dev: no development timestamp key to stamp with")
        return DevAuthority(dev_key)
    if spec in KNOWN_AUTHORITIES:
        url, root = KNOWN_AUTHORITIES[spec]
        return Rfc3161Authority(url, resource(root).read_text(encoding="ascii"), name=spec)
    url, _, root_path = spec.partition("|")
    if not url.startswith("https://") or not root_path:
        raise ValueError(
            f"--tsa {spec!r}: expected dev, {', '.join(KNOWN_AUTHORITIES)}, or url|root.pem"
        )
    return Rfc3161Authority(url, Path(root_path).read_text(encoding="ascii"))


def authority_for(spec: str | None, keys_dir: Path) -> TimestampAuthority | None:
    """The authority a command that appends to an existing ledger names with ``--tsa``,
    or None without one. The development key is read from ``keys_dir``, never made:
    a new key would stamp tokens nothing else in the ledger chains to."""
    if not spec:
        return None
    dev_key = signing.load("timestamp-authority", keys_dir) if spec == "dev" else None
    return authority_from(spec, dev_key)


def parse(payload: dict[str, Any]) -> TimestampToken:
    return TimestampToken(
        authority=payload["authority"],
        kind=payload["kind"],
        timestamp=payload["timestamp"],
        digest=payload["digest"],
        token=payload["token"],
    )
