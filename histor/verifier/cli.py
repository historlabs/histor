"""`histor verify` — check an evidence bundle, offline.

No network. No data. No trust in whoever produced the bundle.

A bundle carries the anchors it is checked against. Given from outside instead (a
plan digest, a timestamp authority root, an IdP key set, …; see ``histor.verifier.anchors``),
each is checked by name and fails on a mismatch; any not given is read from the bundle,
and the verdict warns that it was.

Exit codes: 0 verified, 1 a check failed, 2 the bundle could not be read (including a
bundle_version this verifier does not know). Warnings do not change the exit code, but
they are printed last and in full, because the output this tool must never produce is a
clean tick on a bundle that establishes nothing. Anchors that cannot be read exit 2
too: an anchor is never quietly replaced by the bundle's own.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from histor.ledger.bundle import SUPPORTED_BUNDLE_VERSIONS, Bundle
from histor.verifier import anchors as anchor_files
from histor.verifier.anchors import AnchorError, Anchors
from histor.verifier.checks import FAIL, PASS, WARN, CheckResult, Verdict, verify_bundle

MARK = {PASS: "ok  ", FAIL: "FAIL", WARN: "warn"}
COLOUR = {PASS: "\033[32m", FAIL: "\033[31m", WARN: "\033[33m"}
RESET = "\033[0m"


def render(verdict: Verdict, colour: bool) -> str:
    lines = []
    for result in verdict.results:
        mark = MARK[result.outcome]
        if colour:
            mark = f"{COLOUR[result.outcome]}{mark}{RESET}"
        lines.append(f"  {mark}  {result.id}: {result.question}")
        if result.detail:
            for wrapped in _wrap(result.detail, 72):
                lines.append(f"        {wrapped}")

    counts = verdict.to_json()["counts"]
    lines.append("")
    if verdict.verified:
        lines.append(f"VERIFIED — {counts[PASS]} checks passed, {counts[WARN]} warning(s)")
    else:
        lines.append(f"NOT VERIFIED — {counts[FAIL]} check(s) failed")

    if verdict.anchors:
        lines.append("")
        lines.append(
            "Anchors given from outside: " + (", ".join(verdict.anchors["external"]) or "none")
        )
        lines.append(
            "Anchors read from the bundle: " + (", ".join(verdict.anchors["from_bundle"]) or "none")
        )

    if verdict.caveats:
        lines.append("")
        lines.append("What this bundle does NOT establish:")
        for caveat in verdict.caveats:
            for index, wrapped in enumerate(_wrap(caveat, 72)):
                lines.append(("  - " if index == 0 else "    ") + wrapped)
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    if current:
        lines.append(current)
    return lines


def version() -> str:
    """This verifier's version and the bundle formats it reads, so whoever quotes a
    verdict can say which verifier reached it."""
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as installed

    try:
        package = installed("histor")
    except PackageNotFoundError:
        from histor import __version__ as package
    return f"histor verify {package} (bundle_version {', '.join(SUPPORTED_BUNDLE_VERSIONS)})"


def _anchors(args: argparse.Namespace) -> Anchors:
    """The anchors file, then each flag in place of the file's value for that anchor."""
    from_file = anchor_files.load(args.anchors) if args.anchors else Anchors()
    policy, harness = args.expect_policy_digest, args.expect_harness_digest
    given = [
        ("--expect-sandbox-id", args.expect_sandbox_id),
        ("--expect-policy-digest", policy),
        ("--expect-harness-digest", harness),
        ("--expect-head", args.expect_head),
        *(("--expect-audience", a) for a in args.expect_audience),
        *(("--expect-plan-digest", d) for d in args.expect_plan_digest),
    ]
    for flag, value in given:
        if value is not None and not str(value).strip():
            # Empty would read as not given, and the bundle's own value would be used.
            raise AnchorError(f"{flag}: empty")
    flags = Anchors(
        plan_digest=tuple(
            anchor_files.digest(d, "--expect-plan-digest") for d in args.expect_plan_digest
        ),
        sandbox_id=args.expect_sandbox_id,
        tsa_root=tuple(anchor_files.read_pem(path) for path in args.tsa_root),
        idp_keys=anchor_files.read_jwks(args.idp_keys) if args.idp_keys else (),
        policy_digest=anchor_files.digest(policy, "--expect-policy-digest") if policy else None,
        harness_digest=(
            anchor_files.digest(harness, "--expect-harness-digest") if harness else None
        ),
        signing_keys=tuple(_signing_key(value) for value in args.signing_key)
        + (anchor_files.read_key_set(args.control_plane_keys) if args.control_plane_keys else ()),
        audience=tuple(args.expect_audience),
        ledger_head=anchor_files.head(args.expect_head, "--expect-head")
        if args.expect_head is not None
        else None,
        checkpoints=tuple(anchor_files.read_checkpoint(path) for path in args.checkpoint),
        centre_keys=anchor_files.read_centre_keys(args.centre_keys) if args.centre_keys else (),
        vendor_roots=tuple(
            pem for path in args.vendor_roots for pem in anchor_files.read_vendor_roots(path)
        ),
    )
    return from_file.merged(flags)


def _signing_key(value: str) -> tuple[str, str]:
    key_id, separator, path = value.partition("=")
    if not separator or not path:
        raise AnchorError(f"--signing-key {value!r}: expected KEY_ID=PEM_FILE")
    return anchor_files.read_signing_key(key_id, Path(path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=version())
    parser.add_argument("bundle", type=Path, help="evidence bundle directory")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--in-progress",
        action="store_true",
        help="the participation has not ended: a ledger without exit, deletion and a signed "
        "report warns rather than fails when anchors are given",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        metavar="DIR",
        help="where the exit report and its renderings were written: each is hashed against "
        "the ledger's record (report_renderings). Default: the bundle's parent directory, "
        "when it holds them",
    )
    given = parser.add_argument_group(
        "anchors from outside the bundle",
        "each fails its own check on a mismatch; a flag takes the place of the same "
        "field in --anchors",
    )
    given.add_argument(
        "--anchors", type=Path, metavar="ANCHORS_YAML", help="a file holding any of the below"
    )
    given.add_argument(
        "--expect-plan-digest",
        action="append",
        default=[],
        metavar="DIGEST",
        help="a plan digest you signed (repeat for each amended version)",
    )
    given.add_argument("--expect-sandbox-id", metavar="ID", help="the participation's sandbox id")
    given.add_argument(
        "--tsa-root",
        type=Path,
        action="append",
        default=[],
        metavar="PEM",
        help="a timestamp authority root certificate (repeatable)",
    )
    given.add_argument(
        "--idp-keys", type=Path, metavar="JWKS_FILE", help="the signing IdPs' key set"
    )
    given.add_argument("--expect-policy-digest", metavar="DIGEST", help="network policy digest")
    given.add_argument("--expect-harness-digest", metavar="DIGEST", help="harness image digest")
    given.add_argument(
        "--expect-audience",
        action="append",
        default=[],
        metavar="CLIENT_ID",
        help="the client id the console has at a party's IdP: every plan and report "
        "signature's login must be for one of these (repeatable)",
    )
    given.add_argument(
        "--control-plane-keys",
        type=Path,
        metavar="KEYS_FILE",
        help="every version of the control plane's key: a JWKS of Ed25519 keys whose kid "
        "names each version (control-plane@v2), or a JSON object of key id to PEM",
    )
    given.add_argument(
        "--signing-key",
        action="append",
        default=[],
        metavar="KEY_ID=PEM",
        help="the public key that signs control-plane, harness or scorer statements (repeatable)",
    )
    given.add_argument(
        "--expect-head",
        metavar="SEQ:HASH",
        help="a ledger head you hold, <seq>:sha256:<hex> (the one the console showed when "
        "the report was signed, or your own record): the ledger must hold that entry",
    )
    given.add_argument(
        "--checkpoint",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="a head checkpoint the operator published and you were given: the ledger must "
        "extend it (repeatable)",
    )
    given.add_argument(
        "--centre-keys",
        type=Path,
        metavar="KEYS_FILE",
        help="the HPC centres' Ed25519 keys, from each centre: a JWKS whose kid is the "
        "centre's name, a JSON object of name to PEM, or one PEM (any centre)",
    )
    given.add_argument(
        "--vendor-roots",
        type=Path,
        action="append",
        default=[],
        metavar="PEM",
        help="TEE vendor root certificates, from the vendors (AMD's ARK, Intel's SGX root; "
        "for the mock platform, the mock root): every recorded attestation report's chain "
        "must end at one of them (repeatable; a file may hold several)",
    )
    args = parser.parse_args(argv)

    if not (args.bundle / "manifest.json").exists():
        print(f"{args.bundle}: not an evidence bundle (no manifest.json)", file=sys.stderr)
        return 2

    try:
        anchors = _anchors(args)
    except AnchorError as error:
        print(f"anchor: {error}", file=sys.stderr)
        return 2

    try:
        verdict = verify_bundle(
            Bundle(args.bundle),
            anchors,
            in_progress=args.in_progress,
            report_dir=args.report_dir,
        )
    except Exception as error:  # a verdict, never a traceback
        # Every check fails malformed input on its own; this is the last line, for input
        # none of them foresaw.
        verdict = Verdict()
        verdict.add(
            CheckResult(
                "malformed",
                "could the bundle be read at all?",
                FAIL,
                f"the verifier could not read this bundle ({type(error).__name__}: {error})",
            )
        )

    if args.json:
        print(json.dumps(verdict.to_json(), indent=2))
    else:
        print(render(verdict, colour=sys.stdout.isatty()))

    if any(r.id == "bundle_version" and r.outcome == FAIL for r in verdict.results):
        return 2  # not a bundle this verifier can read, so no verdict on it either way
    return 0 if verdict.verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
