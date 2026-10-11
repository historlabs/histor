"""The exit report: who signed it, and the catalogues its translated
renderings were made with."""

from __future__ import annotations

import hashlib
from typing import Any

from histor.ledger.bundle import (
    CATALOGUE_FILE,
    Bundle,
)
from histor.verifier.anchors import Anchors
from histor.verifier.checks._common import FAIL, PASS, WARN, CheckResult
from histor.verifier.checks._parties import _claims, _login_time_problems, _party_problems

# --- 10. who signed the report ----------------------------------------------


def _plan_in_force(
    entries: list[dict[str, Any]], plans: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    """The plan version the last ``plan_signed`` entry put in force."""
    signed = [
        str(e["body"].get("plan_digest")) for e in entries if e["entry_type"] == "plan_signed"
    ]
    return plans.get(signed[-1]) if signed else None


def _report_head_problems(entry: dict[str, Any], entries: list[dict[str, Any]]) -> list[str]:
    """Whether the ledger head a report signature commits to is in this ledger, before
    the signature and at or after the report it signs.

    The IdP's signature covers the head (``histor.identity.signature``); the head's hash
    covers every entry before it. So a ledger rewritten or cut before that point, the
    ``report_generated`` entry and its bundle digest included, no longer holds the
    entry the regulator signed over."""
    head = entry["body"].get("ledger_head")
    if head is None:
        return []
    seq, hash_ = head.get("seq"), head.get("entry_hash")
    at = next((e for e in entries if e["seq"] == seq), None)
    if at is None or at["entry_hash"] != hash_:
        return [
            f"the regulator signed over the ledger as it stood at seq {seq} "
            f"({str(hash_)[:19]}…), and this ledger holds another entry there, or none: it "
            "is not the ledger the regulator signed"
        ]
    if int(seq) >= int(entry["seq"]):
        return [f"the ledger head it commits to, seq {seq}, is not before the signature"]
    report = entry["body"].get("report_sha256")
    generated = [
        int(e["seq"])
        for e in entries
        if e["entry_type"] == "report_generated"
        and e["body"].get("report_sha256") == report
        and int(e["seq"]) < int(entry["seq"])
    ]
    if generated and int(seq) < max(generated):
        return [
            f"the ledger head it commits to, seq {seq}, precedes the report it signs "
            f"(seq {max(generated)})"
        ]
    return []


def check_report_signature(
    entries: list[dict[str, Any]],
    plans: dict[str, dict[str, Any]] | None = None,
    anchors: Anchors | None = None,
) -> CheckResult:
    """Did the regulator sign the report the ledger says was generated?

    Art. 57(7). The signature is checked as a plan signature is, from the token
    alone, with the nonce recomputed over the report's sha256 under the report's own
    domain, and the signer must be someone the plan in force names as the regulator.
    The report file is not in the bundle; its hash is, in the ``report_generated``
    entry, and anyone holding the report can hash it and compare.
    """
    from histor.identity import signature

    anchors = anchors or Anchors()
    plan = _plan_in_force(entries, plans) if plans is not None else None
    question = "was the exit report signed by the regulator, through their own identity provider?"
    reports = [e for e in entries if e["entry_type"] == "report_generated"]
    recorded = [e for e in entries if e["entry_type"] == "report_signature"]
    if not reports:
        if recorded:
            return CheckResult(
                "report_signature", question, FAIL, "a report signature with no report"
            )
        return CheckResult(
            "report_signature", question, WARN, "no report has been generated in this bundle"
        )
    weak: list[str] = []
    for entry in recorded:
        body = entry["body"]
        problems = signature.verify(body) + _login_time_problems(entry)
        if not problems:
            problems += _report_head_problems(entry, entries)
        if body.get("party") != "regulator":
            problems.append(f"signed by the {body.get('party')}, not the regulator")
        elif not problems and plans is not None:
            found, loose = _party_problems(body, plan, anchors)
            problems += found
            weak += [w for w in loose if w not in weak]
        if problems:
            return CheckResult(
                "report_signature",
                question,
                FAIL,
                f"entry {entry['seq']}: {'; '.join(problems)}",
            )
    latest = str(reports[-1]["body"].get("report_sha256"))
    over = [e for e in recorded if e["body"].get("report_sha256") == latest]
    if not over:
        return CheckResult(
            "report_signature",
            question,
            WARN,
            f"report {latest[:19]}… was generated but nobody has signed it: it is a draft",
        )
    body = over[-1]["body"]
    if signature.is_development(body):
        return CheckResult(
            "report_signature",
            question,
            WARN,
            f"report {latest[:19]}… is signed through the development IdP, which issues a "
            "token for anyone: the signature identifies nobody",
        )
    detail = (
        f"report {latest[:19]}… signed by {_claims(body).get('email') or body.get('subject')} "
        f"via {body.get('idp')}, whom the plan names as the regulator; the token verifies "
        "and commits to the report's sha256"
    )
    head = body.get("ledger_head")
    if isinstance(head, dict):
        detail += (
            f" and to the ledger head at signing, seq {head.get('seq')} "
            f"({str(head.get('entry_hash'))[:19]}…), which this ledger holds"
        )
    else:
        weak.append(
            "the signature does not commit to the ledger head, as signatures made before "
            "2026-09-28 do not: the entries before it are held by the chain and the "
            "timestamps alone"
        )
    if weak:
        return CheckResult("report_signature", question, WARN, detail + ". But " + "; ".join(weak))
    return CheckResult("report_signature", question, PASS, detail)


# --- i18n catalogues ---------------------------------------------------------


# Languages a rendering reads no catalogue for: English is the source, and the
# pseudo-locale is generated from it (histor.i18n). Named here, not imported, so the
# verifier loads nothing that translates.
UNTRANSLATED_LANGUAGES = frozenset({"en", "en-xa"})


def check_i18n_catalogues(bundle: Bundle, entries: list[dict[str, Any]]) -> CheckResult:
    """Does the bundle carry the catalogue each translated rendering was made with?

    A rendering of the report in a language other than English is made with that
    language's compiled catalogue, and the ``report_generated`` entry records the
    catalogue's sha256 beside the rendering. The bundle carries the catalogue as
    ``i18n/<lang>/report.mo``. Each recorded catalogue must be there and hash as
    recorded; every catalogue there must be one a rendering records; and a translated
    rendering must record one, or nothing says which translation produced it."""
    question = (
        "is the catalogue each translated rendering of the report was made with in the "
        "bundle, as the ledger records it?"
    )
    reports = [e for e in entries if e.get("entry_type") == "report_generated"]
    body = reports[-1].get("body") if reports else None
    recorded_list = (body or {}).get("renderings") if isinstance(body, dict) else None
    i18n_dir = bundle.root / "i18n"
    present: dict[str, Any] = {}
    if i18n_dir.is_dir():
        for path in sorted(i18n_dir.rglob("*")):
            if path.is_file():
                present[str(path.relative_to(bundle.root))] = path
    if not isinstance(recorded_list, list) or not recorded_list:
        if present:
            return CheckResult(
                "i18n_catalogues",
                question,
                FAIL,
                f"the bundle carries {', '.join(sorted(present))}, but the ledger records "
                "no translated rendering of the report that was made with it",
            )
        return CheckResult(
            "i18n_catalogues",
            question,
            PASS,
            "the report was rendered in English only: no catalogue to carry",
        )
    expected: dict[str, str] = {}
    problems: list[str] = []
    for item in recorded_list:
        if not isinstance(item, dict):
            raise TypeError("a rendering record is not an object")
        lang = str(item.get("language", ""))
        sha = item.get("catalogue_sha256")
        if lang.lower() in UNTRANSLATED_LANGUAGES:
            if sha is not None:
                problems.append(f"the {lang} rendering records a catalogue, but {lang} reads none")
            continue
        if not isinstance(sha, str) or not sha.startswith("sha256:"):
            problems.append(
                f"the {lang} rendering of {item.get('document')} records no catalogue_sha256: "
                "nothing says which translation produced it"
            )
            continue
        if not lang.isalpha() or not lang.islower() or not 2 <= len(lang) <= 3:
            problems.append(f"{lang!r} is not a language a catalogue is carried under")
            continue
        if expected.setdefault(lang, sha) != sha:
            problems.append(f"the {lang} renderings record two different catalogues")
    for lang, sha in sorted(expected.items()):
        name = f"i18n/{lang}/{CATALOGUE_FILE}"
        path = present.pop(name, None)
        if path is None:
            problems.append(f"{name} is not in the bundle, though the {lang} rendering records it")
            continue
        found = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if found != sha:
            problems.append(f"{name} hashes to {found[:19]}…; the ledger records {sha[:19]}…")
    for name in sorted(present):
        problems.append(f"{name} is in the bundle, but no rendering records it")
    if problems:
        return CheckResult("i18n_catalogues", question, FAIL, "; ".join(problems[:5]))
    if not expected:
        return CheckResult(
            "i18n_catalogues",
            question,
            PASS,
            "every rendering is in English (or its pseudo-locale): no catalogue to carry",
        )
    return CheckResult(
        "i18n_catalogues",
        question,
        PASS,
        f"{len(expected)} catalogue(s) ({', '.join(sorted(expected))}) in the bundle, each "
        "hashing as the report_generated entry records it",
    )
