"""Signing and verification.

DSSE envelopes (the format in-toto attestations travel in, and the format cosign
produces) over Ed25519, with keys held locally. A keyless sigstore flow would sign
the same envelopes; what changes is where the key lives and who vouches for it.

Two properties matter more than the algorithm choice:

* **The payload is signed as bytes, under PAE.** DSSE's pre-authentication encoding
  binds the payload type into the signature, so a payload cannot be re-interpreted as
  a different type by an attacker who keeps the signature.
* **Verification needs no network and no registry.** The public keys travel in the
  evidence bundle. A notified body checks a bundle on a laptop with the wifi off, and
  that is the point of the whole design.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PAYLOAD_TYPE = "application/vnd.in-toto+json"
# Between a key's name and its version in a key id: ``control-plane@v2``.
VERSION_SEPARATOR = "@v"


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding.

    Length-prefixed rather than delimiter-joined, so no payload can be crafted that
    parses as a different (type, payload) pair with the same signature input.
    """
    return b"DSSEv1 %d %s %d %s" % (
        len(payload_type),
        payload_type.encode("utf-8"),
        len(payload),
        payload,
    )


@dataclass(frozen=True)
class KeyPair:
    key_id: str
    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @property
    def public_pem(self) -> str:
        return self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")


def generate(key_id: str) -> KeyPair:
    private = Ed25519PrivateKey.generate()
    return KeyPair(key_id=key_id, private=private, public=private.public_key())


def from_seed(key_id: str, seed: bytes) -> KeyPair:
    """A key pair from 32 bytes of key material, as the key broker holds it.

    Lets a signing key be provisioned, released and destroyed exactly like a data
    key: the broker stores the seed, and whoever redeems it can sign.
    """
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return KeyPair(key_id=key_id, private=private, public=private.public_key())


def save(keypair: KeyPair, directory: Path) -> tuple[Path, Path]:
    """Write a keypair to disk for development.

    Unencrypted, because these are dev keys in a gitignored directory and pretending
    otherwise would be worse than saying so. Production key custody is the key
    broker's job and, in version 2, hardware attestation's.
    """
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / f"{keypair.key_id}.ed25519"
    public_path = directory / f"{keypair.key_id}.pub.pem"
    private_path.write_bytes(
        keypair.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_text(keypair.public_pem, encoding="ascii")
    return private_path, public_path


def load(key_id: str, directory: Path) -> KeyPair:
    private_bytes = (directory / f"{key_id}.ed25519").read_bytes()
    private = serialization.load_pem_private_key(private_bytes, password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise TypeError(f"{key_id} is not an Ed25519 private key")
    return KeyPair(key_id=key_id, private=private, public=private.public_key())


def load_public(pem: str) -> Ed25519PublicKey:
    public = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(public, Ed25519PublicKey):
        raise TypeError("not an Ed25519 public key")
    return public


def sign(keypair: KeyPair, payload: bytes, payload_type: str = PAYLOAD_TYPE) -> dict[str, Any]:
    """Produce a DSSE envelope."""
    signature = keypair.private.sign(pae(payload_type, payload))
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {"keyid": keypair.key_id, "sig": base64.b64encode(signature).decode("ascii")}
        ],
    }


def sign_json(keypair: KeyPair, payload: dict[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sign(keypair, canonical)


class VerificationError(Exception):
    """A signature did not verify, or no key was offered that could."""


def verify(envelope: dict[str, Any], public_keys: dict[str, str]) -> bytes:
    """Check a DSSE envelope against a set of public keys, returning the payload.

    Raises rather than returning False: a caller that forgets to check a boolean gets
    a passing verifier, and this is the function the whole evidence chain rests on.
    """
    try:
        payload_type = envelope["payloadType"]
        payload = base64.b64decode(envelope["payload"])
        signatures = envelope["signatures"]
    except (KeyError, TypeError, ValueError) as error:
        raise VerificationError(f"malformed DSSE envelope: {error}") from error

    if not signatures:
        raise VerificationError("envelope carries no signatures")

    signed = pae(payload_type, payload)
    for entry in signatures:
        key_id = entry.get("keyid")
        pem = public_keys.get(key_id)
        if pem is None and isinstance(key_id, str) and VERSION_SEPARATOR in key_id:
            # ``control-plane@v2`` is version 2 of the control plane's key
            # (histor/sandbox/vaultsign.py). A verifier holding only ``control-plane``
            # tries that key: the signature must still verify under it, so the key id
            # is only a hint of which key to try, never a reason to accept.
            pem = public_keys.get(key_id.rsplit(VERSION_SEPARATOR, 1)[0])
        if pem is None:
            continue
        try:
            load_public(pem).verify(base64.b64decode(entry["sig"]), signed)
        except (InvalidSignature, ValueError, TypeError) as error:
            raise VerificationError(f"signature by {key_id!r} did not verify: {error}") from error
        return payload

    offered = sorted(str(e.get("keyid")) for e in signatures)
    raise VerificationError(
        f"no public key supplied for any of the signing keys {offered}; "
        f"bundle carries keys {sorted(public_keys)}"
    )


def verify_json(envelope: dict[str, Any], public_keys: dict[str, str]) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(verify(envelope, public_keys))
    return payload
