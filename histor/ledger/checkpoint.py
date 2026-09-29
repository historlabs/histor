"""Ledger head checkpoints: the head, signed and stamped, for someone else to keep.

The hash chain shows that nothing was removed from the middle of the ledger, and the
timestamps that it was not rebuilt later. Neither says where it ends: a ledger cut
after any entry is an intact, stamped ledger. The end is anchored only by a head
someone outside the operator holds.

A checkpoint is that head, published: the control plane signs
``{sandbox_id, seq, head_hash, time}`` with its attestation key, a timestamp authority
stamps the statement's digest, and the file goes to the regulator (and whoever else
should keep it), who stores it where the operator cannot edit it. `histor verify
--checkpoint FILE` then checks that a bundle's ledger holds that entry, at that seq
with that hash: a bundle cut short before it, or rewritten from before it, fails.

Run it periodically (``histor ledger checkpoint`` from cron, or a CronJob beside the
console) and after each act that matters, the regulator's signature over the exit
report above all. It needs no transparency log: the regulator's own records are the
log. A public log (Sigstore Rekor) would let anyone check that no two checkpoints for
one seq exist, and is a later option (``docs/threat-model.md``).

The file::

    {"checkpoint": {"type": ..., "sandbox_id": ..., "seq": ..., "head_hash": ..., "time": ...},
     "envelope": <DSSE over the same object, by the control plane>,
     "timestamp": <a ledger timestamp token over sha256 of the object's canonical JSON>}

``checkpoint`` is a readable copy; what counts is the envelope's payload.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any

from histor.crypto import signing
from histor.crypto.timestamps import TimestampAuthority, verify_token

CHECKPOINT_TYPE = "https://historlabs.eu/ledger-head-checkpoint/v1"
# How far the authority's time may lie from the time the checkpoint states: as for
# a ledger entry's recorded_at (histor.verifier.checks.RECORDED_AT_TOLERANCE).
TIME_TOLERANCE = datetime.timedelta(minutes=10)


class CheckpointError(ValueError):
    """A checkpoint that cannot be read, or does not verify."""


UNREADABLE = (KeyError, TypeError, ValueError, NotImplementedError, signing.VerificationError)


def statement(sandbox_id: str, head: dict[str, Any], time: str) -> dict[str, Any]:
    return {
        "type": CHECKPOINT_TYPE,
        "sandbox_id": sandbox_id,
        "seq": int(head["seq"]),
        "head_hash": str(head["entry_hash"]),
        "time": time,
    }


def digest(value: dict[str, Any]) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def make(
    sandbox_id: str,
    head: dict[str, Any],
    key: signing.KeyPair,
    authority: TimestampAuthority,
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    """A checkpoint of ``head`` (``{"seq", "entry_hash"}``, as ``Ledger.head_entry``)."""
    when = (now or datetime.datetime.now(datetime.UTC)).isoformat(timespec="milliseconds")
    body = statement(sandbox_id, head, when.replace("+00:00", "Z"))
    return {
        "checkpoint": body,
        "envelope": signing.sign_json(key, body),
        "timestamp": authority.stamp(digest(body)).to_json(),
    }


def _instant(value: Any) -> datetime.datetime | None:
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=datetime.UTC)


def verify(
    checkpoint: Any, control_plane_keys: dict[str, str], timestamp_keys: dict[str, str]
) -> tuple[dict[str, Any], str]:
    """The statement a checkpoint signs, and the kind of timestamp over it (``rfc3161``
    or ``dev``); raises :class:`CheckpointError` when it does not verify.

    ``control_plane_keys`` are the keys the control plane's statements are checked
    under (by key id); ``timestamp_keys`` the TSA roots (``tsa-root:<name>``) and the
    development authority's key, as a bundle's public keys carry them.
    """
    if not isinstance(checkpoint, dict):
        raise CheckpointError("not a checkpoint object")
    try:
        body = signing.verify_json(checkpoint["envelope"], control_plane_keys)
    except (KeyError, TypeError, ValueError, signing.VerificationError) as error:
        raise CheckpointError(f"the control plane's signature does not verify: {error}") from error
    if not isinstance(body, dict) or body.get("type") != CHECKPOINT_TYPE:
        raise CheckpointError(f"it signs something other than a {CHECKPOINT_TYPE}")
    if not isinstance(body.get("seq"), int) or not str(body.get("head_hash", "")).startswith(
        "sha256:"
    ):
        raise CheckpointError("it names no head: an integer seq and a sha256 head_hash")
    token = checkpoint.get("timestamp")
    if not isinstance(token, dict) or token.get("digest") != digest(body):
        raise CheckpointError("its timestamp is over something other than what it signs")
    try:
        attested = verify_token(token, timestamp_keys)
    except UNREADABLE as error:
        raise CheckpointError(f"its timestamp does not verify: {error}") from error
    kind = str(token.get("kind"))
    if attested.get("digest") != token["digest"]:
        raise CheckpointError("its timestamp's signed digest is not the one it states")
    signed = _instant(attested.get("time") if kind == "rfc3161" else attested.get("timestamp"))
    stated = _instant(body.get("time"))
    if signed is None or stated is None:
        raise CheckpointError("its times do not parse")
    if abs(signed - stated) > TIME_TOLERANCE:
        raise CheckpointError(
            f"it says it was made at {body.get('time')}, but the authority stamped it at "
            f"{signed.isoformat()}"
        )
    return body, kind
