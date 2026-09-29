"""Does the signed exit report cover every language it was rendered in?

A plan's ``report.languages`` has the exit report and the written proof rendered in
each language from the same evidence (histor/report/renderings.py). The first is
authentic and is what the regulator signs; it names every other rendering by sha256,
and the ledger's ``report_generated`` entry records every rendering's file and hash.

From the bundle alone this checks that record against the plan: every language the
plan asks for, both documents in each, and the authentic report being the one the
ledger committed to. The reports are not in the bundle, so given the directory they
were written to it also hashes each file against the record and confirms that the
authentic report's text names each of the others: that is what makes one signature
cover them all.

``histor verify`` runs it whenever the ledger records a report, with the report's
directory from ``--report-dir`` or, failing that, the bundle's parent directory when it
holds every recorded file. A separate module, imported by
:func:`histor.verifier.checks.verify_bundle` when it runs; it imports nothing that
translates, and the verifier reports in English.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from histor.verifier.checks import FAIL, PASS, WARN, CheckResult

ID = "report_renderings"
QUESTION = (
    "is the exit report rendered in every language the plan names, each rendering named "
    "by hash in the authentic report?"
)
DOCUMENTS = frozenset({"exit_report", "written_proof"})
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _record_problems(body: dict[str, Any], declared: list[str]) -> list[str]:
    problems: list[str] = []
    recorded = body.get("renderings")
    if not isinstance(recorded, list) or not recorded:
        return ["the report_generated entry records no renderings"]
    if declared and body.get("languages") != declared:
        problems.append(
            f"the plan asks for {declared}; the report was rendered in {body.get('languages')}"
        )
    by_language: dict[str, set[str]] = {}
    for item in recorded:
        if not isinstance(item, dict):
            return ["a rendering record is not an object"]
        by_language.setdefault(str(item.get("language")), set()).add(str(item.get("document")))
        if not DIGEST.match(str(item.get("sha256"))):
            problems.append(f"{item.get('file')}: no sha256 recorded")
        name = str(item.get("file"))
        if not name or Path(name).name != name or name.startswith("."):
            problems.append(f"{name!r} is not a plain file name")
    for language, documents in sorted(by_language.items()):
        if documents != DOCUMENTS:
            problems.append(f"{language} lacks {sorted(DOCUMENTS - documents)}")
    if declared and len(by_language) != len(declared):
        problems.append(f"{len(by_language)} languages rendered, the plan names {len(declared)}")
    authentic = {
        str(i.get("document")): i for i in recorded if isinstance(i, dict) and i.get("authentic")
    }
    if set(authentic) != DOCUMENTS:
        problems.append("no single authentic exit report and written proof")
    else:
        if authentic["exit_report"].get("sha256") != body.get("report_sha256"):
            problems.append("the authentic rendering is not the report the ledger committed to")
        if authentic["written_proof"].get("sha256") != body.get("written_proof_sha256"):
            problems.append("the authentic written proof is not the one the report names")
    return problems


def _file_problems(recorded: list[dict[str, Any]], directory: Path) -> list[str]:
    problems: list[str] = []
    authentic_text = ""
    for item in recorded:
        path = directory / str(item["file"])
        if not path.is_file():
            problems.append(f"{item['file']} is not in {directory}")
            continue
        digest = _sha256(path)
        if digest != item["sha256"]:
            problems.append(
                f"{item['file']} hashes to {digest[:19]}…, recorded {item['sha256'][:19]}…"
            )
        if item.get("authentic") and item.get("document") == "exit_report":
            authentic_text = path.read_text(encoding="utf-8")
    if authentic_text:
        for item in recorded:
            if item.get("authentic") and item.get("document") == "exit_report":
                continue
            if str(item["sha256"]) not in authentic_text:
                problems.append(f"the authentic report does not name {item['file']} by hash")
    return problems


def check_report_renderings(
    entries: list[dict[str, Any]],
    plan: dict[str, Any] | None = None,
    report_dir: Path | None = None,
) -> CheckResult:
    """``plan`` is the plan in force at the report; ``report_dir`` where the report and
    its renderings were written, if the verifier holds them."""
    reports = [e for e in entries if e.get("entry_type") == "report_generated"]
    if not reports:
        return CheckResult(ID, QUESTION, WARN, "no report has been generated in this bundle")
    body = reports[-1].get("body") or {}
    declared = list(((plan or {}).get("report") or {}).get("languages") or [])
    if "renderings" not in body:
        if declared:
            return CheckResult(
                ID,
                QUESTION,
                FAIL,
                f"the plan asks for the report in {declared}; the report_generated entry "
                "records no renderings",
            )
        return CheckResult(
            ID, QUESTION, PASS, "the plan names no languages: one report, in English"
        )
    problems = _record_problems(body, declared)
    if problems:
        return CheckResult(ID, QUESTION, FAIL, "; ".join(problems[:5]))
    recorded: list[dict[str, Any]] = body["renderings"]
    languages = sorted({str(i["language"]) for i in recorded})
    if report_dir is None:
        return CheckResult(
            ID,
            QUESTION,
            WARN,
            f"{len(recorded)} renderings in {languages} are recorded, the authentic one in "
            f"{body.get('authentic_language')}; not checked against the files, which are not "
            "in the bundle: give the directory the report was written to (--report-dir)",
        )
    problems = _file_problems(recorded, report_dir)
    if problems:
        return CheckResult(ID, QUESTION, FAIL, "; ".join(problems[:5]))
    return CheckResult(
        ID,
        QUESTION,
        PASS,
        f"{len(recorded)} renderings in {languages}: each file hashes as recorded, and the "
        f"authentic report ({body.get('authentic_language')}) names every other by hash",
    )
