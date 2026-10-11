"""Keys sealed to the job: the key-release request, and the sealed response.

The release request and the release response, for a run at an HPC centre. There, the
harness makes an X25519 key pair in its own memory and writes a request carrying the
public half and the measurements the job took before any key existed there. The
broker checks the request (:meth:`histor.sandbox.keybroker.KeyBroker.release_to_job`) and
seals the run's keys to that public key. The courier carries the sealed blob and
nothing that opens it, and the private key never leaves the harness process.

**The sealed box is HPKE (RFC 9180)**, base mode, suite DHKEM(X25519, HKDF-SHA256) /
HKDF-SHA256 / ChaCha20-Poly1305, with ``info = b"sbx-key-release-v1"`` and the request
digest as associated data. The associated data is what makes a response open only for
the request it answers: a response carried to a different request, even one from the
same job key, fails to open.

**Why the HPKE here is our own few lines rather than the library's.**
``cryptography.hazmat.primitives.hpke`` (cryptography 50) offers only single-shot
``Suite.encrypt(plaintext, public_key, info)`` and ``Suite.decrypt``, with no
associated data, and the contract needs it. So :func:`_seal` and :func:`_open`
implement RFC 9180 §4.1 (DHKEM), §5.1 (key schedule, base mode) and §5.2 (one message
at sequence number 0) from the library's X25519, HKDF and ChaCha20-Poly1305
primitives. With empty associated data they produce and accept exactly what the
library's ``Suite`` does, and ``tests/test_job_release.py`` checks that both ways, so
the day the library grows an ``aad`` argument the two can be swapped without a format
change. The wire format is the library's: the 32-byte encapsulated key, then the
ciphertext.

The request digest is ``sha256:`` over the request's canonical JSON, CJ-A
(:func:`histor.crypto.canonical.canonical_json_ascii`), the form the harness's
statement digests use. That module imports nothing from ``histor``, so the key
broker still does not import the harness.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from histor.crypto.canonical import canonical_json_ascii

REQUEST_FORMAT = "sbx-release-request-v1"
RESPONSE_FORMAT = "sbx-release-v1"
INFO = b"sbx-key-release-v1"

# RFC 9180 identifiers for the suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
# ChaCha20-Poly1305.
_KEM_ID = 0x0020
_KDF_ID = 0x0001
_AEAD_ID = 0x0003
_MODE_BASE = b"\x00"
_N_ENC = 32
_N_SECRET = 32
_N_KEY = 32
_N_NONCE = 12
_KEM_SUITE = b"KEM" + _KEM_ID.to_bytes(2, "big")
_HPKE_SUITE = (
    b"HPKE" + _KEM_ID.to_bytes(2, "big") + _KDF_ID.to_bytes(2, "big") + _AEAD_ID.to_bytes(2, "big")
)


class ReleaseError(Exception):
    """A release request or response is malformed, or a response does not open."""


# --- RFC 9180, base mode, one message -------------------------------------------


def _extract(salt: bytes, ikm: bytes) -> bytes:
    mac = hmac.HMAC(salt or b"\0" * 32, hashes.SHA256())
    mac.update(ikm)
    return mac.finalize()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(hashes.SHA256(), length, info).derive(prk)


def _labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def _labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return _expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, length)


def _raw(public: X25519PublicKey) -> bytes:
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _shared_secret(dh: bytes, enc: bytes, recipient: bytes) -> bytes:
    prk = _labeled_extract(_KEM_SUITE, b"", b"eae_prk", dh)
    return _labeled_expand(_KEM_SUITE, prk, b"shared_secret", enc + recipient, _N_SECRET)


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(_HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(_HPKE_SUITE, b"", b"info_hash", info)
    context = _MODE_BASE + psk_id_hash + info_hash
    secret = _labeled_extract(_HPKE_SUITE, shared_secret, b"secret", b"")
    key = _labeled_expand(_HPKE_SUITE, secret, b"key", context, _N_KEY)
    base_nonce = _labeled_expand(_HPKE_SUITE, secret, b"base_nonce", context, _N_NONCE)
    return key, base_nonce


def _seal(recipient: X25519PublicKey, info: bytes, aad: bytes, plaintext: bytes) -> bytes:
    ephemeral = X25519PrivateKey.generate()
    enc = _raw(ephemeral.public_key())
    shared = _shared_secret(ephemeral.exchange(recipient), enc, _raw(recipient))
    key, nonce = _key_schedule(shared, info)
    return enc + ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def _open(private: X25519PrivateKey, info: bytes, aad: bytes, blob: bytes) -> bytes:
    if len(blob) < _N_ENC + 16:
        raise ReleaseError("the release response is too short to be a sealed box")
    enc, ciphertext = blob[:_N_ENC], blob[_N_ENC:]
    try:
        dh = private.exchange(X25519PublicKey.from_public_bytes(enc))
    except ValueError as error:
        raise ReleaseError(f"the release response's encapsulated key is invalid: {error}") from None
    shared = _shared_secret(dh, enc, _raw(private.public_key()))
    key, nonce = _key_schedule(shared, info)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise ReleaseError(
            "the release response does not open: it was altered, sealed to another job "
            "key, or answers another request"
        ) from None


def seal_to(recipient: bytes, info: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """A sealed box to a raw X25519 public key: the construction above, for another
    ``info`` (the provider's weights key, :mod:`histor.crypto.weights`)."""
    return _seal(X25519PublicKey.from_public_bytes(recipient), info, aad, plaintext)


# --- the job's key pair ---------------------------------------------------------


class JobKey:
    """The job's X25519 key pair. The private half lives in this object and nowhere
    else: there is no method that returns it, and it is never written to a file. It is
    gone when the process ends."""

    def __init__(self) -> None:
        self._private = X25519PrivateKey.generate()

    @property
    def public_bytes(self) -> bytes:
        return _raw(self._private.public_key())

    @property
    def public_b64(self) -> str:
        return base64.b64encode(self.public_bytes).decode("ascii")

    def open(self, blob: bytes, aad: bytes, info: bytes = INFO) -> bytes:
        return _open(self._private, info, aad, blob)


# --- the request ----------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_request(
    *,
    run_id: str,
    sandbox_id: str,
    run_number: int,
    plan_digest: str,
    slurm_job_id: str,
    token: str,
    job_public_key: str,
    sif: dict[str, str],
    probe: list[dict[str, Any]],
    netns_links: list[str],
    requested_at: str | None = None,
) -> dict[str, Any]:
    """An ``sbx-release-request-v1``. ``job_public_key`` is :attr:`JobKey.public_b64`."""
    return {
        "format": REQUEST_FORMAT,
        "run_id": run_id,
        "sandbox_id": sandbox_id,
        "run_number": int(run_number),
        "plan_digest": plan_digest,
        "slurm_job_id": str(slurm_job_id),
        "token": token,
        "job_public_key": job_public_key,
        "measurements": {"sif": dict(sif), "probe": list(probe), "netns_links": list(netns_links)},
        "requested_at": requested_at or _now(),
    }


# How the plan's centre keeps the model off the network (``execution.centre.
# network_isolation``): a network namespace holding loopback alone, or, on nodes that
# make no network namespaces, the job's syscall filter (``sandbox-net confine``).
NAMESPACE = "namespace"
SYSCALL_FILTER = "syscall_filter"
# What the probe records when the syscall filter refused an attempt: the kernel's
# EPERM, not an unreachable network or a timeout.
FILTER_REFUSAL = "blocked: Operation not permitted"


def network_isolation(plan: dict[str, Any]) -> str:
    """The plan's ``execution.centre.network_isolation``; ``namespace`` when unset."""
    centre = (plan.get("execution") or {}).get("centre") or {}
    return str(centre.get("network_isolation") or NAMESPACE)


def isolation_problems(measurements: dict[str, Any], isolation: str = NAMESPACE) -> list[str]:
    """What is wrong with the job's measurements of the model's network, under the
    isolation the plan declares; none when keys may go to the job.

    Every attempt of the probe must have been blocked. Under ``namespace`` the model's
    namespace must hold loopback alone. Under ``syscall_filter`` the model shares the
    node's interfaces, so they are recorded but not required to be loopback; instead
    every connection the probe tried must have been refused by the filter itself, which
    shows the probe ran under it. The key broker, the provider's releaser and the
    verifier all apply this, so they cannot disagree."""
    if isolation not in (NAMESPACE, SYSCALL_FILTER):
        return [f"the plan names network isolation {isolation!r}, which nothing here checks"]
    probe = measurements.get("probe")
    if not isinstance(probe, list) or not probe:
        return ["the probe recorded no attempts"]
    reached = [
        str(attempt.get("target", "?")) if isinstance(attempt, dict) else str(attempt)
        for attempt in probe
        if not (isinstance(attempt, dict) and str(attempt.get("result", "")).startswith("blocked"))
    ]
    if reached:
        return [f"the probe was not blocked for {', '.join(reached)}"]
    if isolation == SYSCALL_FILTER:
        unfiltered = [
            str(attempt.get("target"))
            for attempt in probe
            if str(attempt.get("target", "")).rpartition(":")[2].isdigit()
            and attempt.get("result") != FILTER_REFUSAL
        ]
        if unfiltered:
            return [
                "the syscall filter did not refuse the probe's connections to "
                f"{', '.join(unfiltered)}, so the probe did not run under it"
            ]
        return []
    links = measurements.get("netns_links")
    if links != ["lo"]:
        return [f"the model's namespace has interfaces {links}, not loopback alone"]
    return []


def request_digest(request: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_ascii(request)).hexdigest()


def job_public_key_bytes(request: dict[str, Any]) -> bytes:
    """The request's ``job_public_key``, decoded and checked to be an X25519 key."""
    try:
        raw = base64.b64decode(str(request["job_public_key"]), validate=True)
    except (KeyError, binascii.Error) as error:
        raise ReleaseError(f"the request's job_public_key is not base64: {error}") from None
    if len(raw) != 32:
        raise ReleaseError(f"the request's job_public_key is {len(raw)} bytes, not 32")
    return raw


def public_key_digest(request: dict[str, Any]) -> str:
    """``sha256:`` over the raw 32 bytes of the job's public key, for the ledger."""
    return "sha256:" + hashlib.sha256(job_public_key_bytes(request)).hexdigest()


def check_request_shape(request: dict[str, Any]) -> None:
    """Refuse a request that is not an ``sbx-release-request-v1`` with every field."""
    if not isinstance(request, dict) or request.get("format") != REQUEST_FORMAT:
        raise ReleaseError(f"not an {REQUEST_FORMAT} request")
    missing = [
        name
        for name in (
            "run_id",
            "sandbox_id",
            "run_number",
            "plan_digest",
            "slurm_job_id",
            "token",
            "job_public_key",
            "measurements",
            "requested_at",
        )
        if name not in request
    ]
    if missing:
        raise ReleaseError(f"the release request lacks {', '.join(missing)}")
    measurements = request["measurements"]
    if not isinstance(measurements, dict) or not all(
        isinstance(measurements.get(name), kind)
        for name, kind in (("sif", dict), ("probe", list), ("netns_links", list))
    ):
        raise ReleaseError("the release request's measurements need sif, probe and netns_links")
    job_public_key_bytes(request)


# --- the response ---------------------------------------------------------------


def _b64(data: bytes, what: str) -> str:
    if len(data) != 32:
        raise ReleaseError(f"{what} is {len(data)} bytes, not 32")
    return base64.b64encode(data).decode("ascii")


def seal_response(
    request: dict[str, Any], data_keys: dict[str, bytes], harness_signing_seed: bytes
) -> bytes:
    """Seal the run's keys to the request's ``job_public_key``, bound to its digest."""
    check_request_shape(request)
    digest = request_digest(request)
    plaintext = canonical_json_ascii(
        {
            "format": RESPONSE_FORMAT,
            "request_digest": digest,
            "data_keys": {
                dataset_id: _b64(key, f"the data key for {dataset_id}")
                for dataset_id, key in data_keys.items()
            },
            "harness_signing_seed": _b64(harness_signing_seed, "the harness signing seed"),
        }
    )
    recipient = X25519PublicKey.from_public_bytes(job_public_key_bytes(request))
    return _seal(recipient, INFO, digest.encode("utf-8"), plaintext)


def open_response(job_key: JobKey, request: dict[str, Any], blob: bytes) -> dict[str, Any]:
    """Open a response in memory: ``{"data_keys": {id: bytes}, "harness_signing_seed":
    bytes}``. Raises :class:`ReleaseError` if the request was not made with this job
    key, or the blob was altered or answers another request."""
    if request.get("job_public_key") != job_key.public_b64:
        raise ReleaseError("the request names another job key than this process holds")
    digest = request_digest(request)
    plaintext = job_key.open(blob, digest.encode("utf-8"))
    try:
        payload = json.loads(plaintext)
        if payload["format"] != RESPONSE_FORMAT:
            raise ReleaseError(f"the release response is not {RESPONSE_FORMAT}")
        if payload["request_digest"] != digest:
            raise ReleaseError("the release response names another request")
        data_keys = {k: base64.b64decode(v) for k, v in payload["data_keys"].items()}
        seed = base64.b64decode(payload["harness_signing_seed"])
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise ReleaseError(f"the release response is malformed: {error}") from None
    return {"data_keys": data_keys, "harness_signing_seed": seed}
