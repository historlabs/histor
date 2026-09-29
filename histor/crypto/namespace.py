"""The URIs that name Histor's statement types and schemas.

They are identifiers, signed into every attestation, not endpoints. The namespace is
``https://historlabs.eu/``, and the path after it is unchanged from the working-title
namespace ``https://sandbox-mvp.dev/`` it replaces (spec/run-attestation.md, "Namespace").
Everything written from now on uses the new one; the verifier still reads the old one,
with a warning, because evidence is not rewritten.
"""

from __future__ import annotations

NAMESPACE = "https://historlabs.eu/"
LEGACY_NAMESPACE = "https://sandbox-mvp.dev/"

# The control plane's statement about a run (attestations.jsonl).
RUN_TYPE = NAMESPACE + "run/v0.1"
# What the harness measured, signed by the harness (harness-statements.jsonl).
MEASUREMENT_TYPE = NAMESPACE + "harness-measurement/v0.1"
# What the driver observed at a centre whose scoring was kept off it.
DRIVER_TYPE = NAMESPACE + "driver-observation/v0.1"
# The written proof's schema.
WRITTEN_PROOF_SCHEMA = NAMESPACE + "written-proof/v0.1"


def legacy(uri: str) -> str:
    """The working-title form of ``uri``, which bundles made before the rename carry."""
    return LEGACY_NAMESPACE + uri.removeprefix(NAMESPACE)


def is_type(value: object, uri: str) -> bool:
    """Whether ``value`` names ``uri``, in the current namespace or the legacy one."""
    return value in (uri, legacy(uri))


def is_legacy(value: object) -> bool:
    return isinstance(value, str) and value.startswith(LEGACY_NAMESPACE)
