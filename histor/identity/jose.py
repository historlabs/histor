"""JWS compact tokens, verified against JSON Web Keys.

Just enough of RFC 7515/7517/7518/8037 to verify the ID tokens and access tokens an
OpenID Provider issues, and to mint the development IdP's own. Standard library plus
``cryptography``, which the project already depends on for DSSE.

The algorithms are the ones the identity providers a sandbox will meet actually sign
with. Keycloak, Microsoft Entra ID, Okta, Google and the Commission's EU Login sign ID
tokens with RS256 by default; Keycloak and Okta can be set to ES256 or PS256; EdDSA is
the development IdP's. ``none`` and the HMAC family are refused outright: ``none``
because it is no signature, HMAC because a shared secret means the console could mint
the same token it is verifying.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "ES256", "ES384", "EdDSA"})


class JoseError(Exception):
    """A token that is malformed, unsigned, or signed by a key that did not verify it."""


def b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise JoseError(f"not base64url: {error}") from error


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class Token:
    """A parsed, not yet verified, compact JWS."""

    header: dict[str, Any]
    claims: dict[str, Any]
    signing_input: bytes
    signature: bytes
    raw: str

    @property
    def alg(self) -> str:
        return str(self.header.get("alg", ""))

    @property
    def kid(self) -> str | None:
        kid = self.header.get("kid")
        return str(kid) if kid is not None else None


def parse(raw: str) -> Token:
    parts = raw.strip().split(".")
    if len(parts) != 3:
        raise JoseError("not a compact JWS: expected three dot-separated parts")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
    except ValueError as error:
        raise JoseError(f"header or claims are not JSON: {error}") from error
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JoseError("header and claims must be JSON objects")
    return Token(
        header=header,
        claims=claims,
        signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
        signature=b64url_decode(parts[2]),
        raw=raw.strip(),
    )


def _int(value: str) -> int:
    return int.from_bytes(b64url_decode(value), "big")


def public_key(jwk: dict[str, Any]) -> Any:
    """A ``cryptography`` public key from a JWK. Private members are ignored."""
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
        if kty == "EC":
            curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}.get(str(jwk.get("crv")))
            if curve is None:
                raise JoseError(f"unsupported EC curve {jwk.get('crv')!r}")
            return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), curve).public_key()
        if kty == "OKP" and jwk.get("crv") == "Ed25519":
            return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))
    except KeyError as error:
        raise JoseError(f"JWK is missing {error}") from error
    raise JoseError(f"unsupported key type {kty!r}")


def verify(token: Token, jwk: dict[str, Any]) -> None:
    """Raise unless ``token`` is signed by ``jwk`` under an allowed algorithm.

    A header that marks any parameter critical (``crit``, RFC 7515 §4.1.11) is refused:
    this code understands no extension, and a critical one it ignored would change what
    the signature means without anyone noticing."""
    if "crit" in token.header:
        raise JoseError(
            f"the token marks {token.header['crit']!r} critical, which is not understood"
        )
    alg = token.alg
    if alg not in ALGORITHMS:
        raise JoseError(f"algorithm {alg!r} is not accepted")
    if jwk.get("alg") and jwk["alg"] != alg:
        # A key published for one algorithm must not verify under another: the
        # classic confusion attack is an RSA public key accepted as an HMAC secret.
        raise JoseError(f"key {jwk.get('kid')!r} is for {jwk['alg']}, token says {alg}")
    key = public_key(jwk)
    data, sig = token.signing_input, token.signature
    try:
        if alg.startswith("RS") and isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, data, padding.PKCS1v15(), _hash(alg))
        elif alg.startswith("PS") and isinstance(key, rsa.RSAPublicKey):
            hash_ = _hash(alg)
            key.verify(sig, data, padding.PSS(padding.MGF1(hash_), hash_.digest_size), hash_)
        elif alg.startswith("ES") and isinstance(key, ec.EllipticCurvePublicKey):
            size = len(sig) // 2
            der = encode_dss_signature(
                int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big")
            )
            key.verify(der, data, ec.ECDSA(_hash(alg)))
        elif alg == "EdDSA" and isinstance(key, Ed25519PublicKey):
            key.verify(sig, data)
        else:
            raise JoseError(f"key type {jwk.get('kty')!r} cannot verify {alg}")
    except InvalidSignature as error:
        raise JoseError("signature did not verify") from error


def check_audience(claims: dict[str, Any], expected: Collection[str]) -> None:
    """Raise unless the token was issued to one of the ``expected`` audiences: ``aud``
    names one of them, and a token with several audiences names it as ``azp`` too."""
    aud = claims.get("aud")
    values = (
        [aud]
        if isinstance(aud, str)
        else [str(a) for a in aud or []]
        if isinstance(aud, list)
        else []
    )
    if not any(value in expected for value in values):
        raise JoseError(f"the token is for {values}, not for {sorted(expected)}")
    if len(values) > 1 and claims.get("azp") not in expected:
        raise JoseError("the token has several audiences and was not issued to yours (azp)")


def _hash(alg: str) -> hashes.HashAlgorithm:
    return {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}[alg[-3:]]


def select_key(token: Token, jwks: list[dict[str, Any]]) -> dict[str, Any]:
    """The key a token names, from a key set.

    By ``kid`` when the token carries one. Without a ``kid``, only a key set of one
    signing key is unambiguous; trying each key in turn would make any key the IdP
    ever published a valid signer, including ones rotated out for cause.
    """
    signing = [k for k in jwks if k.get("use", "sig") == "sig"]
    if token.kid is not None:
        for key in signing:
            if key.get("kid") == token.kid:
                return key
        raise JoseError(f"no key with kid {token.kid!r} in the issuer's key set")
    if len(signing) == 1:
        return signing[0]
    raise JoseError("token names no kid and the issuer publishes more than one key")


def thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 JWK thumbprint, SHA-256."""
    members = {
        "RSA": ("e", "kty", "n"),
        "EC": ("crv", "kty", "x", "y"),
        "OKP": ("crv", "kty", "x"),
    }.get(str(jwk.get("kty")))
    if members is None:
        raise JoseError(f"unsupported key type {jwk.get('kty')!r}")
    canonical = json.dumps({m: jwk[m] for m in members}, separators=(",", ":"), sort_keys=True)
    return b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


# --------------------------------------------------------------- the dev IdP's side


def ed25519_jwk(key: Ed25519PublicKey, kid: str) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization

    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url_encode(raw),
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
    }


def sign_eddsa(private: Ed25519PrivateKey, kid: str, claims: dict[str, Any]) -> str:
    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    head = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    body = b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signature = private.sign(f"{head}.{body}".encode("ascii"))
    return f"{head}.{body}.{b64url_encode(signature)}"
