"""Histor: the trust layer for EU AI Act Article 57 regulatory sandboxes.

One package. The core, which a plain ``pip install histor`` gives, verifies an
evidence bundle and validates a plan (:mod:`histor.verifier`, :mod:`histor.ledger`,
:mod:`histor.identity`); the engine, ``histor[engine]``, runs participations. The
command is ``histor`` (:mod:`histor.cli`).

Which histor this is lives here too, since every image copies this file. A version
alone does not say which code ran: every commit between two releases calls itself by
the earlier release's version. So what histor records about itself (:func:`software`,
in the ledger's ``report_generated`` entry and in a verification's record) is the
version and the commit, and the verifier checks the pair against the releases a reader
holds (``releases`` in an anchors file). The commit comes from, in order:

1. ``COMMIT`` below, which ``git archive`` fills in (``export-subst`` in
   .gitattributes): the console and runner are deployed from an archive, with no
   ``.git`` beside them;
2. ``HISTOR_SOURCE_COMMIT`` in the environment, for an image built some other way;
3. ``git`` in the checkout this file sits in, which also says whether the checkout has
   uncommitted changes.

None of these is proof. It is what the operator's software says about itself, and
the verifier reports it as that.
"""

from __future__ import annotations

from typing import Any

__all__ = ["__version__", "software", "software_label"]

__version__ = "0.1.1"

# Filled in by `git archive`; left as is in a checkout or an installed wheel.
COMMIT = "$Format:%H$"


def _is_sha(value: str) -> bool:
    return len(value) == 40 and all(c in "0123456789abcdef" for c in value)


def _git(*args: str) -> str | None:
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    if not (root / ".git").exists():
        return None  # an installed copy: a repository around it is not its source
    try:
        done = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, timeout=5, check=True
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout


def _commit() -> tuple[str | None, bool]:
    """The commit this code was built from, or None, and whether the checkout it runs
    from has uncommitted changes to tracked files (only a checkout can say)."""
    import os

    if _is_sha(COMMIT):
        return COMMIT, False
    given = os.environ.get("HISTOR_SOURCE_COMMIT", "").strip().lower()
    if _is_sha(given):
        return given, False
    head = (_git("rev-parse", "HEAD") or "").strip()
    if not _is_sha(head):
        return None, False
    status = _git("status", "--porcelain", "--untracked-files=no")
    return head, bool(status and status.strip())


def software() -> dict[str, Any]:
    """What histor records about itself: name, version, and the commit when known."""
    sha, dirty = _commit()
    record: dict[str, Any] = {"name": "histor", "version": __version__}
    if sha:
        record["commit"] = sha
    if dirty:
        record["dirty"] = True
    return record


def software_label(record: dict[str, Any] | None = None) -> str:
    """One line for a person: ``histor 0.2.0 (commit 1a2b3c4d5e6f, uncommitted changes)``."""
    record = software() if record is None else record
    parts = []
    if record.get("commit"):
        parts.append(f"commit {str(record['commit'])[:12]}")
    if record.get("dirty"):
        parts.append("uncommitted changes")
    suffix = f" ({', '.join(parts)})" if parts else ""
    return f"{record.get('name', 'histor')} {record.get('version', 'unknown')}{suffix}"
