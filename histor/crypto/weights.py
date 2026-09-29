"""Provider-encrypted model weights: the file, the weights key sealed to the job, and
the messages between the control plane and the provider's releaser.

This module holds the formats, the pin in the plan and the provider's receipt: what
the verifier reads. Encrypting and decrypting the file, sealing and opening the
weights key, and the control plane's order run beside the jobs and are in
:mod:`histor.sandbox.weights_runtime`.

The weights are released per run by the provider. The provider ships a runtime
image with no weights and a weights file encrypted under a key it keeps. The plan
pins the file's ciphertext and plaintext digests, with the provider's signature over
them. For each run, the provider's
releaser (:mod:`histor.sandbox.releaser`) seals the weights key to the job's public key, the
same key the key broker sealed the data keys to, and the job opens it in memory and
decrypts the weights into node memory for the model. Only ciphertext and sealed blobs
pass through the control plane, the courier and the centre's storage.

**The file, ``sbx-weights-v1``.** One line of canonical JSON (the header), a newline,
then the plaintext in chunks of ``chunk_size`` bytes, each sealed with
ChaCha20-Poly1305 under the 32-byte weights key. The nonce is ``nonce_prefix`` (7
bytes, random per file), the chunk's index (4 bytes, big-endian) and a flag byte that
is 1 on the last chunk only; the associated data is the SHA-256 of the header line.
This is the STREAM construction (Hoang, Reyhanitabar, Rogaway and Vizár, 2015): a
chunk cannot be reordered, dropped or taken from another file, and a truncated file
fails because its last chunk does not carry the flag. Chunks keep memory flat for
weights of many gigabytes. The header carries the plaintext digest, so it is bound
into every chunk, and the job checks it against the plan's pin after decrypting.

**The weights-key response.** The sealed box of :mod:`histor.crypto.release`, to the
request's ``job_public_key``, with the request digest as associated data and ``info =
b"sbx-weights-release-v1"``. The ``info`` differs from the data-key response's, so a
response for one cannot be opened as the other even though both answer one request
under one key.

**The order, the receipt and the refusal** are DSSE envelopes (:mod:`histor.crypto.signing`).
The control plane signs the order with its ``control-plane`` key, and the provider's
releaser signs its receipt or refusal with ``provider-releaser``, whose public key the
plan pins.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from histor.crypto import release, signing

FORMAT = "sbx-weights-v1"
KEY_RESPONSE_FORMAT = "sbx-weights-release-v1"
INFO = b"sbx-weights-release-v1"
ORDER_FORMAT = "sbx-weights-order-v1"
ANSWER_FORMAT = "sbx-weights-answer-v1"
RECEIPT_FORMAT = "sbx-weights-receipt-v1"
REFUSAL_FORMAT = "sbx-weights-refusal-v1"
RELEASER_KEY_ID = "provider-releaser"
CONTROL_PLANE_KEY_ID = "control-plane"
CHUNK_SIZE = 1 << 20
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
# What the provider's signature over the pin covers.
MANIFEST_FIELDS = ("format", "name", "ciphertext_digest", "plaintext_digest")


class WeightsError(Exception):
    """A weights file, pin, response, order or receipt is malformed or does not open."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path) -> str:
    """``sha256:`` over a file's bytes, read in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def check_name(name: str) -> str:
    """A weights file's name: one path component, no dot first, so it cannot leave
    the directory it is written to."""
    if not isinstance(name, str) or not _NAME.match(name):
        raise WeightsError(f"not a weights file name: {name!r}")
    return name


# --- the pin in the plan ------------------------------------------------------------


def pin_of(plan: dict[str, Any]) -> dict[str, Any] | None:
    """The plan's ``artifacts.model_weights``, or ``None`` when the weights are in the
    image."""
    pin = (plan.get("artifacts") or {}).get("model_weights")
    return pin if isinstance(pin, dict) else None


# What the job needs of the pin to decrypt and check the weights. A job at a centre
# gets no plan (the scoring happens off the centre), so ``run.json``
# carries these fields and nothing else of the pin.
JOB_PIN_FIELDS = ("name", "ciphertext_digest", "plaintext_digest")


def job_pin(pin: dict[str, Any]) -> dict[str, str]:
    """The part of the plan's pin the job needs: the file name and both digests."""
    check_name(str(pin.get("name", "")))
    return {name: str(pin[name]) for name in JOB_PIN_FIELDS}


def _manifest(fields: dict[str, Any]) -> dict[str, Any]:
    return {name: fields[name] for name in MANIFEST_FIELDS}


def make_pin(encrypted: dict[str, Any], releaser: signing.KeyPair) -> dict[str, Any]:
    """``artifacts.model_weights`` for what :func:`encrypt` returned, signed by the
    provider's releaser key, whose public half it carries."""
    fields = {
        "format": FORMAT,
        "name": encrypted["name"],
        "ciphertext_digest": encrypted["ciphertext_digest"],
        "plaintext_digest": encrypted["plaintext_digest"],
    }
    envelope = signing.sign_json(releaser, _manifest(fields))
    return {
        **fields,
        "releaser_public_key": releaser.public_pem,
        "provider_signature": base64.b64encode(_canonical(envelope)).decode("ascii"),
    }


def _envelope(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        decoded = json.loads(base64.b64decode(str(value), validate=True))
    except (ValueError, binascii.Error) as error:
        raise WeightsError(f"not a DSSE envelope: {error}") from None
    if not isinstance(decoded, dict):
        raise WeightsError("not a DSSE envelope")
    return decoded


def check_pin(pin: dict[str, Any]) -> None:
    """Refuse a pin that is incomplete, or whose provider signature does not verify
    under its releaser key or covers other digests."""
    missing = [
        name
        for name in (*MANIFEST_FIELDS, "releaser_public_key", "provider_signature")
        if not pin.get(name)
    ]
    if missing:
        raise WeightsError(f"the weights pin lacks {', '.join(missing)}")
    if pin["format"] != FORMAT:
        raise WeightsError(f"the weights pin is not {FORMAT}")
    try:
        signed = signing.verify_json(
            _envelope(pin["provider_signature"]),
            {RELEASER_KEY_ID: str(pin["releaser_public_key"])},
        )
    except (signing.VerificationError, ValueError, TypeError) as error:
        raise WeightsError(f"the provider's signature over the weights pin: {error}") from None
    if signed != _manifest(pin):
        raise WeightsError("the provider signed other weights than the pin names")


# --- the receipt, from the provider's releaser, for the ledger ----------------------

RECEIPT_FIELDS = (
    "run_number",
    "slurm_job_id",
    "request_digest",
    "job_public_key_digest",
    "ciphertext_digest",
    "plaintext_digest",
)


def check_receipt(
    envelope: dict[str, Any], blob: bytes, pin: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any]:
    """Check the provider's receipt for a sealed weights key and return the body of the
    ``weights_key_released`` ledger entry. The receipt must be signed by the pinned
    releaser key, answer this request, name this job key and the pinned file, and
    describe this blob."""
    try:
        receipt = signing.verify_json(envelope, {RELEASER_KEY_ID: str(pin["releaser_public_key"])})
    except (signing.VerificationError, ValueError, TypeError, KeyError) as error:
        raise WeightsError(f"the provider's receipt does not verify: {error}") from None
    expected = {
        "run_number": int(request["run_number"]),
        "slurm_job_id": str(request["slurm_job_id"]),
        "request_digest": release.request_digest(request),
        "job_public_key_digest": release.public_key_digest(request),
        "ciphertext_digest": pin.get("ciphertext_digest"),
        "plaintext_digest": pin.get("plaintext_digest"),
    }
    if receipt.get("format") != RECEIPT_FORMAT:
        raise WeightsError(f"the provider's receipt is not {RECEIPT_FORMAT}")
    wrong = [name for name, value in expected.items() if receipt.get(name) != value]
    if wrong:
        raise WeightsError(f"the provider's receipt differs from the request in {wrong}")
    if receipt.get("response_digest") != "sha256:" + hashlib.sha256(blob).hexdigest():
        raise WeightsError("the provider's receipt describes another sealed key")
    return {
        **expected,
        "runs_released": receipt.get("runs_released"),
        "max_runs": receipt.get("max_runs"),
        "receipt": envelope,
        # The TEE report the provider's releaser checked, when the plan asks for one.
        **({"tee": receipt["tee"]} if "tee" in receipt else {}),
    }
