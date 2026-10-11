"""The bundle as a set of files: what it may hold, its format and version,
the personal data its manifest declares, and its own digest."""

from __future__ import annotations

import base64
import datetime
from typing import Any

from histor.crypto import signing
from histor.ledger.bundle import (
    BUNDLE_VERSION,
    LEGACY_BUNDLE_VERSIONS,
    SUPPORTED_BUNDLE_VERSIONS,
    Bundle,
)
from histor.verifier.anchors import Anchors
from histor.verifier.checks._common import FAIL, PASS, WARN, CheckResult, _instant, _stamp

# --- personal data ------------------------------------------------------------


def _personal_data_summary(found: dict[str, Any]) -> str:
    categories = found["categories"]
    held = [
        f"{name.replace('_', ' ')} ({entry['count']}, in {', '.join(entry['files'])})"
        for name, entry in categories.items()
    ]
    return ("personal data: " + "; ".join(held)) if held else "no personal data"


def check_personal_data(bundle: Bundle, manifest: dict[str, Any]) -> CheckResult:
    """Does the manifest say what personal data the bundle holds?

    Derived again from the files (:meth:`histor.ledger.bundle.Bundle.personal_data`) and
    compared with the manifest's ``personal_data``. A bundle_version 0.1 manifest has
    only ``contains_personal_data``, written as ``false`` whatever the bundle held:
    that is a warning, since the software said it, not whoever changed the bundle.
    """
    question = "does the manifest say what personal data the bundle holds?"
    found = bundle.personal_data()
    summary = _personal_data_summary(found)
    if manifest.get("bundle_version") == "0.1":
        claimed = manifest.get("contains_personal_data")
        if found["present"] and claimed is not True:
            return CheckResult(
                "personal_data",
                question,
                WARN,
                f"this bundle_version 0.1 manifest says contains_personal_data: {claimed!r}, "
                f"a constant in the software that wrote it; the bundle holds {summary}. "
                "It holds no test-subject data",
            )
        return CheckResult("personal_data", question, PASS, f"the bundle holds {summary}")
    if manifest.get("personal_data") != found:
        return CheckResult(
            "personal_data",
            question,
            FAIL,
            f"the manifest's personal_data is not what the bundle holds, which is {summary}",
        )
    return CheckResult(
        "personal_data",
        question,
        PASS,
        f"as the manifest says, the bundle holds {summary}, and no test-subject data "
        "(none of the files the export writes can carry it)",
    )


# --- bundle files, version, format and digest ---------------------------------


def check_bundle_digest(bundle: Bundle, manifest: dict[str, Any]) -> CheckResult:
    question = "does the bundle match the digest in its own manifest?"
    recomputed = bundle.digest()
    if manifest.get("bundle_digest") != recomputed:
        return CheckResult(
            "bundle_digest",
            question,
            FAIL,
            f"manifest says {str(manifest.get('bundle_digest'))[:19]}…, "
            f"contents hash to {recomputed[:19]}…",
        )
    return CheckResult("bundle_digest", question, PASS, recomputed)


def check_bundle_files(bundle: Bundle) -> CheckResult | None:
    """None when every path in the bundle is a regular file or a directory; a failure
    naming the first that is not. A symbolic link could make the verifier hash or scan
    a file outside the bundle, and a FIFO or a device could hang it, so neither is
    followed or read: the bundle is refused whole, as ``ledger.bundle.unpack`` refuses
    such an archive."""
    found = bundle.special_files()
    if not found:
        return None
    return CheckResult(
        "bundle_files",
        "is every path in the bundle a regular file or a directory?",
        FAIL,
        f"the bundle holds {', '.join(found[:5])}: a bundle holds regular files only, and "
        "nothing in it was read",
    )


def check_bundle_version(manifest: dict[str, Any]) -> CheckResult:
    question = "is this a bundle format this verifier knows how to check?"
    version = manifest.get("bundle_version")
    if version not in SUPPORTED_BUNDLE_VERSIONS:
        return CheckResult(
            "bundle_version",
            question,
            FAIL,
            f"bundle_version {version!r} is not one this verifier understands (it reads "
            f"{', '.join(SUPPORTED_BUNDLE_VERSIONS)}): use a verifier that supports it, "
            "rather than one that would skip the checks it does not know about",
        )
    if version in LEGACY_BUNDLE_VERSIONS:
        return CheckResult(
            "bundle_version",
            question,
            WARN,
            f"LEGACY FORMAT, WEAKER GUARANTEES: bundle_version {version} predates "
            f"{BUNDLE_VERSION}, whose ledger records the keys that sign the runs' statements "
            "and the bundle's own format. This bundle is checked as it was written, and what "
            "those records would establish is not established: see signing_keys and "
            "bundle_format",
        )
    return CheckResult("bundle_version", question, PASS, f"bundle_version {version}")


# When each legacy format was superseded. A ledger a timestamp authority you hold
# stamped after that was written by software that exports a later format.
SUPERSEDED = {
    "0.1": datetime.datetime(2026, 9, 27, tzinfo=datetime.UTC),
    "0.2": datetime.datetime(2026, 9, 28, tzinfo=datetime.UTC),
}


# Ledger entries only a writer of bundle_version 0.3 or later records.
FORMAT_MARKERS = frozenset({"signing_key_registered"})


def check_bundle_format(
    manifest: dict[str, Any], entries: list[dict[str, Any]], anchors: Anchors
) -> CheckResult:
    """Is the manifest's bundle_version the one the ledger was written for?

    Nothing signs the manifest, and an older format is checked more leniently (a 0.1
    manifest's personal-data flag, for one, is a constant nobody compared with the
    files). So a bundle relabelled as older would pass checks it fails. The format is
    held to the ledger, which is chained and timestamped: the ``bundle_version`` its
    ``report_generated`` entry records, the entry types only a later writer records,
    and, with a timestamp authority root you hold, when the ledger was stamped.
    """
    from histor.crypto.timestamps import verify_rfc3161

    question = "is the bundle's format the one its ledger was written for?"
    claimed = str(manifest.get("bundle_version"))
    recorded = [
        e
        for e in entries
        if e["entry_type"] == "report_generated" and e["body"].get("bundle_version")
    ]
    if recorded and str(recorded[-1]["body"]["bundle_version"]) != claimed:
        return CheckResult(
            "bundle_format",
            question,
            FAIL,
            f"the ledger's report_generated (seq {recorded[-1]['seq']}) records bundle_version "
            f"{recorded[-1]['body']['bundle_version']}, but the manifest says {claimed}: the "
            "manifest, which nothing signs, was relabelled",
        )
    reports = [e for e in entries if e["entry_type"] == "report_generated"]
    if (
        claimed not in LEGACY_BUNDLE_VERSIONS
        and reports
        and not reports[-1]["body"].get("bundle_version")
    ):
        return CheckResult(
            "bundle_format",
            question,
            FAIL,
            f"the manifest says bundle_version {claimed}, whose writer records the format in "
            f"its report_generated entry, but the last one (seq {reports[-1]['seq']}) records "
            "none: the report is from another writer, or the entry was rewritten",
        )
    if claimed not in LEGACY_BUNDLE_VERSIONS:
        where = (
            f"as the ledger's report_generated (seq {recorded[-1]['seq']}) records"
            if recorded
            else "not yet recorded in the ledger, which holds no report"
        )
        return CheckResult("bundle_format", question, PASS, f"bundle_version {claimed}, {where}")
    later = sorted({e["entry_type"] for e in entries if e["entry_type"] in FORMAT_MARKERS})
    if later or recorded:
        return CheckResult(
            "bundle_format",
            question,
            FAIL,
            f"the manifest says bundle_version {claimed}, but the ledger holds "
            f"{later or ['a report recording its format']}, which only a writer of "
            f"{BUNDLE_VERSION} or later records: it was relabelled to a format checked more "
            "leniently",
        )
    if anchors.tsa_root and entries and entries[-1].get("timestamp"):
        try:
            stamped = _instant(
                verify_rfc3161(
                    base64.b64decode(entries[-1]["timestamp"]["token"]["der"]),
                    entries[-1]["entry_hash"],
                    list(anchors.tsa_root),
                )["time"]
            )
        except (signing.VerificationError, ValueError, KeyError, TypeError):
            stamped = None  # anchor_tsa_root says why
        if stamped is not None and stamped >= SUPERSEDED[claimed]:
            return CheckResult(
                "bundle_format",
                question,
                FAIL,
                f"the ledger's last entry was stamped at {_stamp(stamped)}, after bundle_version "
                f"{claimed} was superseded ({SUPERSEDED[claimed]:%Y-%m-%d}): a bundle exported "
                "then is not in that format, so this one was relabelled",
            )
    return CheckResult(
        "bundle_format",
        question,
        PASS,
        f"bundle_version {claimed}: nothing in the ledger was written by a later format's "
        "writer"
        + (
            ""
            if anchors.tsa_root
            else ", and without a TSA root you hold, when it was stamped proves nothing"
        ),
    )


# --- the software that wrote the record ----------------------------------------


def software_records(entries: list[dict[str, Any]]) -> list[tuple[int, dict[str, Any]]]:
    """(seq, record) of each ``report_generated`` entry that records which histor wrote
    the report and exported the bundle."""
    return [
        (int(e["seq"]), e["body"]["software"])
        for e in entries
        if e["entry_type"] == "report_generated" and isinstance(e["body"].get("software"), dict)
    ]


def check_software_release(
    entries: list[dict[str, Any]], releases: tuple[tuple[str, str], ...]
) -> CheckResult:
    """Was the histor that wrote the record a release, and one the reader holds?

    The ledger's word for it, chained and stamped but stated by the operator's own
    software: it says which code the operator says ran, and that a release names that
    code, not that it ran. A version is not enough, since every commit between two
    releases calls itself by the earlier one's version; so the commit is checked
    against the release's. Run only when the ledger records the software at all."""
    question = "was the histor that wrote this record a release you hold?"
    released = dict(releases)
    problems: list[str] = []
    seen: list[str] = []
    for seq, record in software_records(entries):
        version = str(record.get("version") or "")
        commit = str(record.get("commit") or "").lower()
        name = f"histor {version or '(no version)'}" + (f" at {commit[:12]}" if commit else "")
        if record.get("name", "histor") != "histor":
            return CheckResult(
                "software_release",
                question,
                FAIL,
                f"report_generated (seq {seq}) records software {record.get('name')!r}, not histor",
            )
        if releases and version in released and commit and commit != released[version]:
            return CheckResult(
                "software_release",
                question,
                FAIL,
                f"report_generated (seq {seq}) records {name}, but release {version} is "
                f"commit {released[version][:12]}: the software calls itself a release it "
                "is not",
            )
        if name not in seen:
            seen.append(name)
        if not commit:
            problems.append(f"seq {seq} records no commit, so which code ran is unknown")
        elif record.get("dirty"):
            problems.append(
                f"seq {seq}: {name} ran from a checkout with uncommitted changes, which "
                "no release or commit describes"
            )
        elif releases and released.get(version) != commit:
            problems.append(f"seq {seq}: {name} is not a release you hold")
    if problems:
        return CheckResult("software_release", question, WARN, "; ".join(problems))
    if not releases:
        return CheckResult(
            "software_release",
            question,
            PASS,
            f"the ledger says {', '.join(seen)} wrote the record; without the releases you "
            "hold (releases in --anchors, or --release), whether that is a release is not "
            "checked",
        )
    return CheckResult(
        "software_release",
        question,
        PASS,
        f"{', '.join(seen)}: a release you hold, by version and commit (as the operator's "
        "software states it)",
    )
