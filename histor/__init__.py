"""Histor: the trust layer for EU AI Act Article 57 regulatory sandboxes.

One package. The core, which a plain ``pip install histor`` gives, verifies an
evidence bundle and validates a plan (:mod:`histor.verifier`, :mod:`histor.ledger`,
:mod:`histor.identity`); the engine, ``histor[engine]``, runs participations. The
command is ``histor`` (:mod:`histor.cli`).
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
