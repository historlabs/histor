"""The two canonical JSON forms digests and signatures are taken over.

`spec/evidence-bundle.md` section 1 defines exactly two, and every digest the
specifications name says which one it uses. Both are Python's ``json.dumps`` with
``sort_keys=True`` and ``separators=(",", ":")``; they differ only in how non-ASCII
text is written:

``CJ-A`` (:func:`canonical_json_ascii`)
    every non-ASCII character escaped as ``\\uXXXX``. Ledger entry hashes, DSSE
    payloads (:func:`histor.crypto.signing.sign_json`), envelope and harness-statement
    digests, plan-signature payloads, head checkpoints, TEE collateral, key-release
    requests and everything else that is not listed under CJ-U.
``CJ-U`` (:func:`canonical_json_utf8`)
    non-ASCII written as itself, then UTF-8. Plan digests, notified-body test proposal
    digests, the model card digest and the licence report digest.

The same value can give different bytes under the two forms (``"é"`` is
``"\\u00e9"`` in CJ-A and the two bytes ``c3 a9`` in CJ-U), so each caller must use
the form its specification names: choosing the other changes the digest of any value
holding non-ASCII text, and an artefact made before the change no longer verifies.
That is why there are two functions and no flag. ``tests/test_canonical.py`` pins
both.

This module is the only place either form is defined. It imports nothing from
``histor``, so the key broker, the verifier and the harness can all use it without
importing one another. The dataset commitment's v2 form is a third, separate
serialisation (CJ-U with numbers rewritten in one canonical form,
`spec/dataset-commitment.md`), and stays in :mod:`histor.crypto.commitment`.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json_ascii(value: Any) -> bytes:
    """CJ-A: sorted keys, no whitespace, every non-ASCII character escaped.

    The form of the ledger hash chain (B-30) and of every signed or digested
    statement except those :func:`canonical_json_utf8` lists. Its bytes are ASCII.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def canonical_json_utf8(value: Any) -> bytes:
    """CJ-U: sorted keys, no whitespace, non-ASCII written as itself, as UTF-8.

    The form of the plan digest (`spec/evidence-bundle.md` section 7), the notified
    body's test proposal digest, the model card digest and the licence report digest.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
