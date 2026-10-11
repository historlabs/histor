"""The ledger as a record: its hash chain, its runs' numbers, key deletion,
whether it ends as a finished participation does, and its timestamps."""

from __future__ import annotations

import base64
import datetime
from typing import Any

from histor.crypto import signing
from histor.crypto.timestamps import parse as parse_timestamp
from histor.crypto.timestamps import verify_token
from histor.ledger.bundle import (
    Bundle,
)
from histor.ledger.store import GENESIS, compute_hash
from histor.verifier.checks._common import (
    FAIL,
    PASS,
    RECORDED_AT_TOLERANCE,
    WARN,
    CheckResult,
    _instant,
    _stamp,
)

# --- 2. hash chain ----------------------------------------------------------


def check_hash_chain(entries: list[dict[str, Any]]) -> CheckResult:
    question = "is the ledger hash chain intact, with no gaps?"
    if not entries:
        return CheckResult("hash_chain", question, FAIL, "ledger is empty")

    previous = GENESIS
    for position, entry in enumerate(entries):
        expected_seq = position + 1
        if int(entry["seq"]) != expected_seq:
            return CheckResult(
                "hash_chain",
                question,
                FAIL,
                f"sequence jumps from {expected_seq - 1} to {entry['seq']}: an entry was removed",
            )
        if entry["prev_hash"] != previous:
            return CheckResult(
                "hash_chain",
                question,
                FAIL,
                f"entry {entry['seq']} claims prev_hash {entry['prev_hash'][:19]}…, "
                f"but the previous entry hashes to {previous[:19]}…",
            )
        recomputed = compute_hash(
            int(entry["seq"]),
            entry["sandbox_id"],
            entry["entry_type"],
            entry["recorded_at"],
            entry["body"],
            entry["prev_hash"],
        )
        if recomputed != entry["entry_hash"]:
            return CheckResult(
                "hash_chain",
                question,
                FAIL,
                f"entry {entry['seq']} ({entry['entry_type']}) does not hash to its stated "
                "entry_hash: its contents were altered after it was written",
            )
        previous = str(entry["entry_hash"])

    return CheckResult("hash_chain", question, PASS, f"{len(entries)} entries, chain intact")


# --- 3. run numbers ---------------------------------------------------------


def check_run_numbers(
    entries: list[dict[str, Any]], statements: list[dict[str, Any]]
) -> CheckResult:
    """Every run the gate started, once, ended in the ledger, and no other run.

    The gate records ``run_started`` before a run and ``run_attestation`` (or
    ``run_halted``) after it. Counting only the attestations would miss a run that was
    started and never reported, say because it failed and was run again under the same
    number: that attempt is the evidence."""
    question = "was every run started once, and ended in the ledger, with no unrecorded runs?"
    started: dict[int, list[int]] = {}
    ended: dict[int, list[int]] = {}
    attested: dict[int, list[int]] = {}
    for entry in entries:
        body = entry["body"]
        if "run_number" not in body:
            continue
        run, seq = int(body["run_number"]), int(entry["seq"])
        if entry["entry_type"] == "run_started":
            started.setdefault(run, []).append(seq)
        elif entry["entry_type"] in {"run_attestation", "run_halted"}:
            ended.setdefault(run, []).append(seq)
            if entry["entry_type"] == "run_attestation":
                attested.setdefault(run, []).append(seq)
    attested_runs = sorted(int(s["predicate"]["run_number"]) for s in statements)
    if not attested_runs:
        return CheckResult("run_numbers", question, FAIL, "no runs attested")

    problems = []
    twice = {run: seqs for run, seqs in started.items() if len(seqs) > 1}
    if twice:
        problems += [
            f"run {run} was started {len(seqs)} times (seq {', '.join(map(str, seqs))}): "
            "an attempt that ended unreported is hidden under the number of the one reported"
            for run, seqs in sorted(twice.items())
        ]
    expected = list(range(1, len(started) + 1))
    if sorted(started) != expected:
        problems.append(f"the runs started are {sorted(started)}, not contiguous from 1")
    for run, seqs in sorted(attested.items()):
        if len(seqs) > 1:
            problems.append(f"run {run} is attested {len(seqs)} times")
        if run not in started or min(started[run]) > min(seqs):
            problems.append(f"run {run} is attested but was never started through the gate")
    exited = any(
        e["entry_type"] == "gate_decision"
        and e["body"].get("action") == "exit"
        and e["body"].get("allow")
        for e in entries
    )
    last = max(started, default=0)
    open_runs = [
        run
        for run, seqs in sorted(started.items())
        if not any(seq > min(seqs) for seq in ended.get(run, []))
    ]
    unreported = [run for run in open_runs if exited or run != last]
    if unreported:
        problems.append(
            f"run(s) {unreported} were started and never attested or halted: a run was "
            "performed and not reported"
        )
    if sorted(attested) != attested_runs:
        problems.append(
            f"the ledger attests runs {sorted(attested)} but the bundle carries attestations "
            f"for {attested_runs}"
        )
    if problems:
        return CheckResult("run_numbers", question, FAIL, "; ".join(problems))
    if open_runs:
        return CheckResult(
            "run_numbers",
            question,
            WARN,
            f"runs {sorted(started)} started once each; run {open_runs[0]} has not ended, and "
            "the ledger ends while it runs",
        )
    return CheckResult(
        "run_numbers",
        question,
        PASS,
        f"runs {sorted(started)}, contiguous, each started once and ended in the ledger",
    )


# --- 7. deletion ------------------------------------------------------------


def check_deletion(entries: list[dict[str, Any]]) -> CheckResult:
    question = "were keys destroyed after exit?"
    # An exit the gate allowed; a refused request to exit is not an exit.
    exits = [
        e
        for e in entries
        if e["entry_type"] == "gate_decision"
        and e["body"].get("action") == "exit"
        and e["body"].get("allow") is True
    ]
    destroyed = [e for e in entries if e["entry_type"] == "keys_destroyed"]

    if not exits:
        if destroyed:
            return CheckResult(
                "deletion", question, FAIL, "keys were destroyed but no exit was recorded"
            )
        return CheckResult(
            "deletion", question, WARN, "the participation has not exited; deletion is not yet due"
        )
    if not destroyed:
        return CheckResult(
            "deletion",
            question,
            FAIL,
            "exit was recorded but no keys_destroyed entry followed: "
            "Art. 59(1)(g) deletion is unproven",
        )
    if min(int(e["seq"]) for e in destroyed) < min(int(e["seq"]) for e in exits):
        return CheckResult(
            "deletion", question, FAIL, "keys were destroyed before exit was requested"
        )
    scopes = sorted({s for e in destroyed for s in e["body"].get("key_scopes", [])})
    return CheckResult("deletion", question, PASS, f"keys destroyed after exit: {scopes}")


def check_completeness(
    bundle: Bundle,
    entries: list[dict[str, Any]],
    anchored: bool,
    in_progress: bool,
    before_report: bool = False,
) -> CheckResult:
    """Does the ledger end the way a participation that has ended does?

    The hash chain and the timestamps say nothing about the end of the ledger: cut
    after any entry, what is left is intact. So the end is checked for what an ended
    participation must have written, in order: the regulator's exit, the keys'
    destruction, the exit report, and the regulator's signature over it. And the last
    ``report_generated`` entry names the digest of the bundle as it was when the report
    was generated, which is recomputed here: every file as it is now, the ledger up to
    the entry before. A bundle cut short, or with files changed since the report,
    shows. Missing ends warn, and fail when you gave any anchor, unless you said the
    participation is still in progress (``--in-progress``).

    ``before_report`` is for the verification an exit report quotes, which runs before
    the ledger can record that report or the regulator's signature over it: those two
    are not asked of it, and the detail says they come after.
    """
    question = "does the ledger end as a participation that has ended does?"
    last = entries[-1] if entries else {"seq": 0, "entry_type": "nothing"}
    exits = [
        int(e["seq"])
        for e in entries
        if e["entry_type"] == "gate_decision"
        and e["body"].get("action") == "exit"
        and e["body"].get("allow")
    ]
    destroyed = [int(e["seq"]) for e in entries if e["entry_type"] == "keys_destroyed"]
    reports = [e for e in entries if e["entry_type"] == "report_generated"]
    missing = []
    if not exits:
        missing.append("the regulator's exit")
    if not [s for s in destroyed if exits and s > exits[0]]:
        missing.append("the keys' destruction after it")
    if not before_report and not [r for r in reports if destroyed and int(r["seq"]) > destroyed[0]]:
        missing.append("an exit report after that")
    if reports:
        report = reports[-1]
        latest = report["body"].get("report_sha256")
        signed = [
            e
            for e in entries
            if e["entry_type"] == "report_signature"
            and e["body"].get("report_sha256") == latest
            and e["body"].get("party") == "regulator"
            and int(e["seq"]) > int(report["seq"])
        ]
        if not signed and not before_report:
            missing.append("the regulator's signature over the last report")
        index = entries.index(report)
        then = bundle.digest(ledger_lines=index)
        if report["body"].get("bundle_digest") != then:
            return CheckResult(
                "completeness",
                question,
                FAIL,
                f"the report at seq {report['seq']} was generated over bundle "
                f"{str(report['body'].get('bundle_digest'))[:19]}…, but this bundle, up to the "
                f"entry before it, is {then[:19]}…: files were changed after the report",
            )
    if not missing and before_report:
        return CheckResult(
            "completeness",
            question,
            PASS,
            f"exit and keys destroyed, up to seq {last['seq']}. This is the verification "
            "the exit report quotes, run before the ledger records that report and the "
            "regulator's signature over it; verify the bundle to check those",
        )
    if not missing:
        return CheckResult(
            "completeness",
            question,
            PASS,
            f"exit, keys destroyed, the report and the regulator's signature over it, and "
            f"the report's bundle digest matches this bundle up to seq {reports[-1]['seq'] - 1}",
        )
    detail = (
        f"INCOMPLETE: the ledger ends at seq {last['seq']} ({last['entry_type']}) without "
        f"{', '.join(missing)}. Either the participation has not ended, or the ledger was "
        "cut short and nothing inside it can show that"
    )
    if in_progress:
        return CheckResult(
            "completeness",
            question,
            WARN,
            detail + "; you said it is in progress. What shows it was not cut is a head you "
            "hold from outside the bundle (--expect-head, --checkpoint)",
        )
    return CheckResult("completeness", question, FAIL if anchored else WARN, detail)


# --- 8. timestamps ----------------------------------------------------------


# How far one entry's signed time may lie before the previous entry's. One authority's
# clock only moves forward; two authorities (a failover) may disagree by a second or so.
ORDER_TOLERANCE = datetime.timedelta(seconds=5)


def signed_time_problem(
    entry: dict[str, Any],
    stated: Any,
    signed: Any,
    previous: datetime.datetime | None,
) -> str | None:
    """The genTime rules for one stamped entry, or None when it keeps them.

    ``stated`` is the ``timestamp`` written beside the token (outside its signature),
    ``signed`` the time the authority signed (an RFC 3161 ``genTime``, a development
    token's signed ``timestamp``), ``previous`` the latest signed time of the entries
    before it. The stated time must be the signed one; the signed time must lie within
    :data:`RECORDED_AT_TOLERANCE` of the entry's ``recorded_at``, and not before
    ``previous`` by more than :data:`ORDER_TOLERANCE`. One implementation, used by
    :func:`check_timestamps` and by ``histor ledger verify-db``
    (:func:`histor.ledger.tools.verify`)."""
    where = f"entry {entry.get('seq')} ({entry.get('entry_type')})"
    signed_at, stated_at = _instant(signed), _instant(stated)
    recorded = _instant(entry.get("recorded_at"))
    if signed_at is None or recorded is None or stated_at is None:
        return f"{where}: its times do not parse"
    if stated_at != signed_at:
        return (
            f"{where} states it was stamped at {stated}, but the authority signed "
            f"{_stamp(signed_at)}: the stated time is not the authority's"
        )
    if abs(signed_at - recorded) > RECORDED_AT_TOLERANCE:
        return (
            f"{where} says it was recorded at {entry.get('recorded_at')}, but the authority "
            f"stamped it at {_stamp(signed_at)}, more than "
            f"{int(RECORDED_AT_TOLERANCE.total_seconds() // 60)} minutes apart: it was "
            "written, or the ledger rebuilt, at another time than it says"
        )
    if previous is not None and signed_at < previous - ORDER_TOLERANCE:
        return (
            f"{where} was stamped at {_stamp(signed_at)}, before the entry preceding it "
            f"({_stamp(previous)}): the chain was not stamped in its order"
        )
    return None


def check_timestamps(entries: list[dict[str, Any]], public_keys: dict[str, str]) -> CheckResult:
    """Every entry stamped, over its own hash, by a token that verifies; and the time
    each token *signs* (an RFC 3161 token's ``genTime``, a development token's signed
    ``timestamp``) is the one that counts. The ``timestamp`` field beside the token is
    written by whoever assembled the bundle, so it must equal the signed time, the
    signed times must not go backwards along the chain (by more than
    :data:`ORDER_TOLERANCE`), and each must be within :data:`RECORDED_AT_TOLERANCE` of
    the entry's ``recorded_at``. A ledger rebuilt later and stamped afresh carries the
    later times, whatever its JSON says."""
    question = "are the timestamps valid, ordered, and external?"
    stamped = [e for e in entries if e.get("timestamp")]
    if not stamped:
        return CheckResult(
            "timestamps",
            question,
            FAIL,
            "no ledger entry carries a timestamp: the chain proves ordering but nothing "
            "anchors it to a clock",
        )

    # A token covers its entry's hash, but the hash does not cover the token: deleting
    # a token leaves the chain intact. So the rule is whole-ledger. A ledger is stamped
    # from its first entry to its last or not at all, and one unstamped entry among
    # stamped ones is a token removed, or an entry written around the authority.
    unstamped = [e for e in entries if not e.get("timestamp")]
    if unstamped:
        first = unstamped[0]
        return CheckResult(
            "timestamps",
            question,
            FAIL,
            f"{len(unstamped)} of {len(entries)} ledger entries carry no timestamp, the "
            f"first at entry {first['seq']} ({first['entry_type']}): in a stamped ledger "
            "every entry is stamped, so a token was removed or the entry was written "
            "around the timestamp authority",
        )

    kinds = set()
    anchors: set[str] = set()
    previous: datetime.datetime | None = None
    earliest: datetime.datetime | None = None
    for entry in stamped:
        token = parse_timestamp(entry["timestamp"])
        kinds.add(token.kind)
        if token.digest != entry["entry_hash"]:
            return CheckResult(
                "timestamps",
                question,
                FAIL,
                f"entry {entry['seq']} is timestamped over {token.digest[:19]}… but hashes to "
                f"{entry['entry_hash'][:19]}…",
            )
        try:
            attested = verify_token(entry["timestamp"], public_keys)
            if token.kind == "rfc3161":
                anchors.add(f"{token.authority} (root sha256:{attested['root_sha256'][:16]}…)")
        except (signing.VerificationError, NotImplementedError) as error:
            return CheckResult(
                "timestamps", question, FAIL, f"entry {entry['seq']} timestamp: {error}"
            )
        if token.kind == "dev" and attested.get("digest") != entry["entry_hash"]:
            # An RFC 3161 token's imprint is checked against its entry by
            # verify_rfc3161; a development token's signed digest is checked here.
            return CheckResult(
                "timestamps",
                question,
                FAIL,
                f"entry {entry['seq']}'s development timestamp signs "
                f"{str(attested.get('digest'))[:19]}…, not the entry's hash: it was issued "
                "over another entry",
            )
        signed_text = attested.get("time") if token.kind == "rfc3161" else attested.get("timestamp")
        problem = signed_time_problem(entry, token.timestamp, signed_text, previous)
        if problem:
            return CheckResult("timestamps", question, FAIL, problem)
        signed = _instant(signed_text) or datetime.datetime.min.replace(tzinfo=datetime.UTC)
        previous = signed if previous is None else max(previous, signed)
        earliest = earliest or signed

    if kinds == {"dev"}:
        return CheckResult(
            "timestamps",
            question,
            WARN,
            "every timestamp was issued by the sandbox operator's own development "
            "authority, not by a third party. The ordering is self-consistent and "
            "anchors nothing: an operator able to rebuild this ledger could reissue "
            "these timestamps with it.",
        )
    if kinds == {"rfc3161"}:
        span = f"{_stamp(earliest)} to {_stamp(previous)}" if earliest and previous else "?"
        return CheckResult(
            "timestamps",
            question,
            PASS,
            f"{len(stamped)} RFC 3161 timestamps from {', '.join(sorted(anchors))}, stamped "
            f"from {span} in chain order, each signed over its entry's hash within "
            f"{int(RECORDED_AT_TOLERANCE.total_seconds() // 60)} minutes of its recorded_at "
            "and chained to the pinned root",
        )
    return CheckResult(
        "timestamps",
        question,
        WARN,
        f"{len(stamped)} timestamps of mixed kinds {sorted(kinds)}: the development ones "
        "anchor nothing",
    )


def check_tsa_revocation(
    entries: list[dict[str, Any]], public_keys: dict[str, str], tsa_roots: tuple[str, ...]
) -> CheckResult:
    """Was the authority's certificate unrevoked when each token was stamped?

    The stamping code keeps the CA's answer beside each token (an OCSP response or a
    CRL, ``token["revocation"]``), fetched when it stamped. It is checked here offline:
    signed by the issuer in the token's own chain (or a responder it delegated to),
    about the signer certificate, current at the stamped time, and not saying revoked.
    A token without it warns: nothing shows the certificate was good then."""
    from histor.crypto.timestamps import TSA_ROOT_PREFIX, revocation_problem, verify_rfc3161

    question = "was the timestamp authority's certificate unrevoked when it stamped?"
    roots = list(tsa_roots) or [
        pem for key, pem in public_keys.items() if key.startswith(TSA_ROOT_PREFIX)
    ]
    tokens = [
        e for e in entries if isinstance(e.get("timestamp"), dict) and e["timestamp"].get("kind")
    ]
    external = [e for e in tokens if e["timestamp"]["kind"] == "rfc3161"]
    if not external:
        return CheckResult(
            "tsa_revocation",
            question,
            WARN,
            "no RFC 3161 timestamp in this ledger, so no authority certificate whose "
            "revocation could be checked: development timestamps carry none",
        )
    missing: list[int] = []
    kinds: set[str] = set()
    for entry in external:
        timestamp = entry["timestamp"]
        evidence = (timestamp.get("token") or {}).get("revocation")
        if evidence is None:
            missing.append(int(entry["seq"]))
            continue
        try:
            attested = verify_rfc3161(
                base64.b64decode(timestamp["token"]["der"]), timestamp["digest"], roots
            )
        except (signing.VerificationError, KeyError, TypeError, ValueError):
            continue  # timestamps (or anchor_tsa_root) says what is wrong with the token
        at = _instant(attested["time"])
        problem = (
            revocation_problem(evidence, attested["chain_der"], at)
            if at is not None
            else "its time does not parse"
        )
        if problem is not None:
            return CheckResult(
                "tsa_revocation",
                question,
                FAIL,
                f"entry {entry['seq']} ({entry['entry_type']}): {problem}",
            )
        kinds.add(str(evidence.get("kind")).upper())
    checked = len(external) - len(missing)
    if missing:
        return CheckResult(
            "tsa_revocation",
            question,
            WARN,
            f"{len(missing)} of {len(external)} RFC 3161 timestamps carry no revocation "
            f"evidence (the first at entry {missing[0]}): nothing shows the authority's "
            "certificate had not been revoked when it stamped them"
            + (
                f"; the other {checked} show it good ({', '.join(sorted(kinds))})"
                if checked
                else ""
            ),
        )
    return CheckResult(
        "tsa_revocation",
        question,
        PASS,
        f"each of {checked} RFC 3161 timestamps carries the CA's answer "
        f"({', '.join(sorted(kinds))}), signed by the authority certificate's issuer, "
        "current when it stamped, and not revoked",
    )
