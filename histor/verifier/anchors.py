"""Trust anchors a verifier holds from outside the bundle.

A bundle carries everything needed to check it, including what it is checked
*against*: the plan digest, the timestamp authority's root, the identity providers'
keys, the network policy and harness digests. Checked against only those, a bundle
proves that it agrees with itself. An operator who rebuilt one could swap every
anchor consistently, re-sign with keys of their own, and it would still verify.

So a notified body or regulator can bring its own. Each anchor is something they can
obtain out of band, from the party it belongs to and never from the operator: the digest
of the plan they signed, the sandbox id they were given, the root the timestamp
authority publishes, the key set their own IdP publishes, the network policy digest and
the harness image digest the plan pinned when they signed it. Given one, the verifier
pins the bundle to it, and fails on any mismatch. Not given one, it says the anchor came
from the bundle itself.

One file can hold all of them, so a notified body keeps one per participation::

    # anchors.yaml: paths are relative to this file
    sandbox_id: sbx-2026-014
    plan_digest:                  # every signed version you hold
      - sha256:4f1c…
    tsa_root: [freetsa-root.pem]  # PEM files
    idp_keys: authority-jwks.json # a JWKS
    policy_digest: sha256:9a0e…
    harness_digest: sha256:77b2…
    signing_keys:                 # PEM public keys, by the key id that signs
      control-plane: control-plane.pem
      harness: harness.pem
    control_plane_keys: cp.jwks   # or every version of the control plane's key
    audience: [histor-console]    # the console's client id at each party's IdP
    ledger_head: "57:sha256:3c9e…" # a head you hold: the one shown when the report was signed
    checkpoints: [head-2026-10-01.json]  # head checkpoints you were given and kept
    centre_keys: centres.jwks     # each HPC centre's key, by its name, from the centre
    vendor_roots: [amd-ark-milan.pem]  # TEE vendors' root certificates, from the vendors
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Any

import yaml

# The anchors, in the order they are reported, and how each is named to a reader.
NAMES = {
    "plan_digest": "the plan digest",
    "sandbox_id": "the sandbox id",
    "tsa_root": "the timestamp authority's root",
    "idp_keys": "the identity providers' keys",
    "policy_digest": "the network policy digest",
    "harness_digest": "the harness image digest",
    "signing_keys": "the statement signing keys",
    "audience": "the audience the parties' IdP logins were for",
    "ledger_head": "the ledger head",
    "checkpoints": "the ledger head checkpoints",
    "centre_keys": "the HPC centres' keys",
    "vendor_roots": "the TEE vendors' root certificates",
}
# Anchors that only a bundle with that kind of evidence is checked against, and which
# the verdict names as missing only then: the centres' keys, for evidence a centre
# signed; the TEE vendors' roots, for hardware attestation evidence.
SITUATIONAL = ("centre_keys", "vendor_roots")
# Anchors that stand in for one another when the verdict lists those not given: a
# head you hold anchors the end of the ledger, whether as a head or a checkpoint.
_ALTERNATIVES = {"checkpoints": "ledger_head"}

_HEAD = re.compile(r"^(\d+):(sha256:[0-9a-f]{64})$")

# The key ids whose public key can be given as an anchor: who signs the run
# attestations, the harness's measurements (and a driver's observations), and the
# measurements when scoring is kept off a centre (spec/run-attestation.md §1a-§1c).
SIGNING_KEY_IDS = ("control-plane", "harness", "scorer")

_DIGEST = re.compile(r"^(sha256:)?([0-9a-f]{64})$")


class AnchorError(ValueError):
    """An anchor that cannot be read. Never a reason to fall back to the bundle's."""


@dataclass(frozen=True)
class Anchors:
    """What the verifier was given from outside the bundle. Empty means not given."""

    plan_digest: tuple[str, ...] = ()
    sandbox_id: str | None = None
    tsa_root: tuple[str, ...] = ()  # PEM certificates
    idp_keys: tuple[dict[str, Any], ...] = ()  # JWKs
    policy_digest: str | None = None
    harness_digest: str | None = None
    # (key id, PEM public key). A key id is a signer's (control-plane, harness,
    # scorer), or one version of it (control-plane@v2) when the key is rotated.
    signing_keys: tuple[tuple[str, str], ...] = ()
    audience: tuple[str, ...] = ()  # the console's OIDC client ids at the parties' IdPs
    # (seq, entry hash) of a head the recipient holds: the ledger must hold that entry.
    ledger_head: tuple[int, str] | None = None
    checkpoints: tuple[dict[str, Any], ...] = ()  # histor.ledger.checkpoint files
    # (key id, PEM): an HPC centre's Ed25519 key, by the centre's name, or hpc-centre.
    centre_keys: tuple[tuple[str, str], ...] = ()
    # PEM root certificates a TEE report's chain may end at: AMD's ARK, Intel's SGX
    # root, or, for the mock platform, the mock root.
    vendor_roots: tuple[str, ...] = ()

    def external(self) -> list[str]:
        """The anchors given, by name."""
        return [name for name in NAMES if getattr(self, name)]

    def from_bundle(self, needed: tuple[str, ...] = ()) -> list[str]:
        """The anchors not given, by name, one name for anchors that stand in for one
        another: what the verdict says was read from the bundle. A situational anchor
        is named only when ``needed``."""
        given = set(self.external())
        given |= {_ALTERNATIVES[name] for name in given if name in _ALTERNATIVES}
        return [
            name
            for name in NAMES
            if name not in given
            and name not in _ALTERNATIVES
            and (name not in SITUATIONAL or name in needed)
        ]

    def merged(self, other: Anchors) -> Anchors:
        """These anchors, with each one ``other`` gives taking the place of this one's."""
        given = {f.name: getattr(other, f.name) for f in fields(other) if getattr(other, f.name)}
        return replace(self, **given)


def digest(value: Any, what: str) -> str:
    """A sha256 digest as ``sha256:<hex>``, from that or bare hex."""
    match = _DIGEST.match(str(value).strip().lower())
    if match is None:
        raise AnchorError(f"{what}: {value!r} is not a sha256 digest")
    return "sha256:" + match.group(2)


def head(value: Any, what: str = "ledger_head") -> tuple[int, str]:
    """A ledger head as ``<seq>:sha256:<hex>``, the form the console shows the regulator
    when they sign the report and ``histor ledger export`` prints."""
    match = _HEAD.match(str(value).strip().lower())
    if match is None:
        raise AnchorError(f"{what}: {value!r} is not <seq>:sha256:<hex>")
    return int(match.group(1)), match.group(2)


def read_checkpoint(path: Path) -> dict[str, Any]:
    """A head checkpoint file (``histor ledger checkpoint``), read but not yet checked:
    the check, ``checkpoints``, needs the bundle's keys."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AnchorError(f"checkpoint {path}: {error}") from error
    if not isinstance(data, dict) or not {"envelope", "timestamp"} <= set(data):
        raise AnchorError(f"checkpoint {path}: not a ledger head checkpoint")
    return {**data, "file": path.name}


def read_vendor_roots(path: Path) -> tuple[str, ...]:
    """TEE vendor root certificates: every PEM certificate in the file, each one
    self-signed. A file with none, or a certificate that is not a root, is refused."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

    try:
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise AnchorError(f"vendor roots {path}: {error}") from error
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\s*", text, re.S)
    if not blocks:
        raise AnchorError(f"vendor roots {path}: no PEM certificate")
    for block in blocks:
        try:
            certificate = x509.load_pem_x509_certificate(block.encode("ascii"))
            certificate.verify_directly_issued_by(certificate)
        except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm) as error:
            raise AnchorError(
                f"vendor roots {path}: a certificate is not a self-signed root: {error}"
            ) from error
    return tuple(blocks)


def read_pem(path: Path) -> str:
    try:
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise AnchorError(f"TSA root {path}: {error}") from error
    from cryptography import x509

    try:
        x509.load_pem_x509_certificate(text.encode("ascii"))
    except ValueError as error:
        raise AnchorError(f"TSA root {path}: not a PEM certificate") from error
    return text


_KEY_ID = re.compile(r"^(control-plane|harness|scorer)(@[A-Za-z0-9._-]+)?$")


def _checked_key(key_id: str, pem: str, where: str) -> tuple[str, str]:
    if not _KEY_ID.match(key_id):
        raise AnchorError(
            f"{where}: key id {key_id!r} is not one of {list(SIGNING_KEY_IDS)}, or a version "
            "of one (control-plane@v2)"
        )
    from histor.crypto import signing

    try:
        signing.load_public(pem)
    except (ValueError, TypeError) as error:
        raise AnchorError(f"{where}: {key_id} is not an Ed25519 public key") from error
    return key_id, pem


def read_signing_key(key_id: str, path: Path) -> tuple[str, str]:
    """A statement signing key: an Ed25519 public key in PEM, for a known key id."""
    try:
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise AnchorError(f"signing key {key_id} {path}: {error}") from error
    return _checked_key(key_id, text, f"signing key {path}")


def read_key_set(path: Path, signer: str = "control-plane") -> tuple[tuple[str, str], ...]:
    """Every version of one signer's key, by key id: a JWKS of Ed25519 keys (``kid``
    naming each version), or a JSON object of key id to PEM. A key id of another
    signer is refused."""
    pairs = _key_pairs(path, f"{signer} keys", signer)
    checked = tuple(_checked_key(k, pem, f"{signer} keys {path}") for k, pem in pairs)
    others = sorted(k for k, _ in checked if k.split("@", 1)[0] != signer)
    if others:
        raise AnchorError(f"{signer} keys {path}: {others} are not {signer}'s")
    return checked


def read_centre_keys(path: Path) -> tuple[tuple[str, str], ...]:
    """The HPC centres' keys, as each centre gave them: a JWKS of Ed25519 keys whose
    ``kid`` is the centre's name (as the plan's ``execution.centre`` and the evidence
    name it), a JSON object of that name to PEM, or one PEM public key, which is taken
    as ``hpc-centre``: any centre's."""
    from histor.crypto import signing

    text = ""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise AnchorError(f"centre keys {path}: {error}") from error
    if text.lstrip().startswith("-----BEGIN"):
        pairs = [("hpc-centre", text)]
    else:
        pairs = _key_pairs(path, "centre keys", "hpc-centre")
    for key_id, pem in pairs:
        try:
            signing.load_public(pem)
        except (ValueError, TypeError) as error:
            raise AnchorError(
                f"centre keys {path}: {key_id} is not an Ed25519 public key"
            ) from error
    return tuple(pairs)


def _key_pairs(path: Path, what: str, default_kid: str) -> list[tuple[str, str]]:
    """(key id, PEM) from a JWKS of Ed25519 keys, or a JSON object of key id to PEM."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AnchorError(f"{what} {path}: {error}") from error
    pairs: list[tuple[str, str]] = []
    if isinstance(data, dict) and isinstance(data.get("keys"), list):
        from histor.identity import jose

        for jwk in data["keys"]:
            if not (
                isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519"
            ):
                raise AnchorError(f"{what} {path}: every key must be an Ed25519 JWK")
            try:
                raw = jose.b64url_decode(str(jwk["x"]))
                pem = (
                    Ed25519PublicKey.from_public_bytes(raw)
                    .public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    .decode("ascii")
                )
            except (KeyError, ValueError) as error:
                raise AnchorError(f"{what} {path}: a key is not usable: {error}") from error
            pairs.append((str(jwk.get("kid") or default_kid), pem))
    elif isinstance(data, dict) and data:
        pairs = [(str(k), str(v)) for k, v in data.items()]
    else:
        raise AnchorError(f"{what} {path}: not a JWKS or an object of key id to PEM")
    return pairs


def read_jwks(path: Path) -> tuple[dict[str, Any], ...]:
    """A JWKS (``{"keys": [...]}``), a list of JWKs, or one JWK."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AnchorError(f"IdP keys {path}: {error}") from error
    keys = data.get("keys", [data]) if isinstance(data, dict) else data
    if not isinstance(keys, list) or not keys or not all(isinstance(k, dict) for k in keys):
        raise AnchorError(f"IdP keys {path}: not a JWKS")
    from histor.identity import jose

    for key in keys:
        try:
            jose.thumbprint(key)
        except (KeyError, jose.JoseError) as error:
            raise AnchorError(f"IdP keys {path}: a key is not usable: {error}") from error
    return tuple(keys)


def _listed(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else [value]


def load(path: Path) -> Anchors:
    """An anchors file. Any key it does not know is refused, since a misspelt anchor
    would otherwise be dropped in silence and the bundle's used in its place."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise AnchorError(f"{path}: {error}") from error
    if not isinstance(data, dict):
        raise AnchorError(f"{path}: expected a mapping of anchors")
    # control_plane_keys is read into signing_keys: every version of that one key.
    unknown = sorted(set(data) - set(NAMES) - {"control_plane_keys"})
    if unknown:
        raise AnchorError(f"{path}: unknown anchor(s) {unknown}; known: {list(NAMES)}")
    # An empty value would read as "not given" and fall back to the bundle's, which is
    # the one thing an anchor is for never doing.
    empty = sorted(k for k, v in data.items() if v is None or not str(v).strip() or v in ([], {}))
    if empty:
        raise AnchorError(f"{path}: anchor(s) {empty} are empty; leave out an anchor you lack")
    base = path.parent

    def resolve(name: Any) -> Path:
        candidate = Path(str(name)).expanduser()
        return candidate if candidate.is_absolute() else base / candidate

    keys = data.get("signing_keys") or {}
    if not isinstance(keys, dict):
        raise AnchorError(f"{path}: signing_keys is a mapping of key id to a PEM file")
    signing_keys = tuple(read_signing_key(str(k), resolve(v)) for k, v in keys.items())
    if data.get("control_plane_keys"):
        signing_keys += read_key_set(resolve(data["control_plane_keys"]))
    return Anchors(
        vendor_roots=tuple(
            pem
            for p in _listed(data.get("vendor_roots") or [])
            for pem in read_vendor_roots(resolve(p))
        ),
        centre_keys=read_centre_keys(resolve(data["centre_keys"]))
        if data.get("centre_keys")
        else (),
        ledger_head=head(data["ledger_head"]) if data.get("ledger_head") else None,
        checkpoints=tuple(
            read_checkpoint(resolve(p)) for p in _listed(data.get("checkpoints") or [])
        ),
        audience=tuple(str(a) for a in _listed(data.get("audience") or [])),
        signing_keys=signing_keys,
        plan_digest=tuple(digest(d, "plan_digest") for d in _listed(data.get("plan_digest") or [])),
        sandbox_id=str(data["sandbox_id"]) if data.get("sandbox_id") else None,
        tsa_root=tuple(read_pem(resolve(p)) for p in _listed(data.get("tsa_root") or [])),
        idp_keys=read_jwks(resolve(data["idp_keys"])) if data.get("idp_keys") else (),
        policy_digest=(
            digest(data["policy_digest"], "policy_digest") if data.get("policy_digest") else None
        ),
        harness_digest=(
            digest(data["harness_digest"], "harness_digest") if data.get("harness_digest") else None
        ),
    )
