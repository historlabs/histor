"""Files the code reads at run time that live outside the Python packages.

The plan and predicate schemas (``spec/``), the network policies whose digest a plan
pins (``infra/policies``), the Kubernetes manifests (``infra/k8s``) and the pinned
timestamp-authority roots (``infra/timestamps``) sit at the top of the repository,
beside the packages rather than in them. In a checkout, and in an editable install,
they are read from there. A wheel carries a copy of each under ``histor/_data``
(``[tool.hatch.build.targets.wheel.force-include]`` in ``pyproject.toml``), because
an installed package has no repository beside it.

One lookup for both layouts, so a schema is never read from one place in tests and
another in production: the packaged copy when it exists, the checkout otherwise.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def resource(relative: str) -> Path:
    """The path to ``relative`` (for example ``"spec/plan.schema.json"``).

    Raises :class:`FileNotFoundError` naming both places looked, rather than handing
    back a path that does not exist and failing later with less to go on.
    """
    packaged = Path(str(files("histor").joinpath("_data", *relative.split("/"))))
    if packaged.exists():
        return packaged
    checkout = REPO_ROOT / relative
    if checkout.exists():
        return checkout
    raise FileNotFoundError(
        f"{relative}: neither in the installed package ({packaged}) nor in a checkout ({checkout})"
    )
