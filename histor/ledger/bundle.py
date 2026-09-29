"""Evidence bundle: everything a verifier needs, and nothing it must fetch.

One directory (or one tarball) containing the ledger as JSON lines, the signed
attestations, the timestamp tokens, the public keys, the plan, and the policy files.
A notified body opens it on a laptop with the network off and can decide whether the
stated outcomes follow from what was run.

Three rules govern what goes in:

* **No test-subject data, ever.** Hashes, metrics, signatures and policy. Never an
  image, never a label, never an item-level output tied to an item of the held-out
  set. The run logs travel because they are the evidence behind their digests: the
  relay's log is hashes, the drop log is network metadata about the sandbox's own
  pods, and the model's decision log is keyed by random request ids that only
  segment A could map to items. What a bundle
  does hold is personal data about the parties' staff: who did what, and the ID
  token behind each signature made through an identity provider. The manifest says
  so, derived from the files (:meth:`Bundle.personal_data`).
* **No external references.** If verifying needs it, it is in the bundle. A bundle
  that says "fetch the public key from our registry" is a bundle that stops verifying
  the day the registry moves.
* **Self-describing.** The manifest says what each file is and which key signed what,
  so a verifier written five years from now has something to read.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BUNDLE_VERSION = "0.3"
# Every bundle_version this code can read. A verifier meeting any other refuses the
# bundle rather than guess at a layout it was not written for: a check it does not
# know to run is a check that silently passes. A 0.1 manifest carries a constant
# ``contains_personal_data: false`` where 0.2 carries ``personal_data``, a
# description of the staff data the bundle holds. 0.3 records the statement signing
# keys in the ledger (``signing_key_registered``) and the bundle's format in its
# ``report_generated`` entry.
SUPPORTED_BUNDLE_VERSIONS = ("0.1", "0.2", BUNDLE_VERSION)
# Read, with a warning that they carry weaker guarantees than the current format.
LEGACY_BUNDLE_VERSIONS = ("0.1", "0.2")

# An email address anywhere in a file, including inside a signed statement's payload.
# `_EMAIL.findall` is the definition; `emails` finds the same matches in linear time.
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_LOCAL_CHAR = re.compile(r"[\w.+-]")
_DOMAIN = re.compile(r"[\w-]+(?:\.[\w-]+)+")

# What each category of personal data is, as the manifest states it.
PERSONAL_DATA_CATEGORIES = {
    "staff_identifiers": "email addresses and identity-provider subject ids of the people "
    "who act for the parties: in the plan's roles and processors, and in the ledger "
    "entries that record who committed, requested, decided or signed what",
    "idp_id_tokens": "the raw OpenID Connect ID token behind each plan or report "
    "signature made through an identity provider, kept whole because the IdP's "
    "signature covers it; its claims name the signer and say when and how they logged in",
}

# Stated, not found: nothing export() writes can carry it.
TEST_SUBJECT_DATA_BASIS = (
    "none, by construction of the export: no image, no ground-truth label or age, no "
    "group label of an item and no item id of any dataset. Results are aggregates by "
    "group; the model's decision log gives its output per request, keyed by a random "
    "request id that nothing in the bundle links to an item"
)

# A run's logs, by file name, and where in its predicate the digest of each is kept.
RUN_LOGS = {
    "relay-log.jsonl": ("relay_log_digest",),
    "model-stdout.log": ("model_stdout_digest",),
    "drop-log.jsonl": ("isolation_evidence", "drop_log_digest"),
    # The hpc_centre arm: what the centre signed, carried so anyone can hash it.
    "job-record.txt": ("isolation_evidence", "job_record_digest"),
    "node-config.json": ("isolation_evidence", "node_config_digest"),
}
# A language's compiled catalogue, under i18n/<lang>/ (histor/i18n/locale holds it).
CATALOGUE_FILE = "report.mo"


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class Bundle:
    root: Path

    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    def read_manifest(self) -> dict[str, Any]:
        with self.manifest_path.open(encoding="utf-8") as handle:
            manifest: dict[str, Any] = json.load(handle)
        return manifest

    def read_json(self, name: str) -> Any:
        with (self.root / name).open(encoding="utf-8") as handle:
            return json.load(handle)

    def read_jsonl(self, name: str) -> list[Any]:
        lines = (self.root / name).read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def plan_versions(self) -> dict[str, Any]:
        """Every plan version in the bundle, keyed by digest.

        Falls back to the single current plan for a bundle written before plan
        versions were carried, so an older bundle still verifies.
        """
        directory = self.root / "plans"
        if not directory.is_dir():
            plan = self.read_json("plan.json")
            from histor.plan import digest as plan_digest

            return {plan_digest(plan): plan}
        versions = {}
        for path in sorted(directory.glob("*.json")):
            with path.open(encoding="utf-8") as handle:
                versions["sha256:" + path.stem] = json.load(handle)
        return versions

    def special_files(self) -> list[str]:
        """Every path under the bundle that is neither a regular file nor a directory
        (a symbolic link, a FIFO, a device), by its path in the bundle. Links are not
        followed."""
        import os
        import stat

        found = []
        for directory, dirs, files in os.walk(self.root, followlinks=False):
            for name in sorted(dirs + files):
                path = Path(directory) / name
                mode = path.lstat().st_mode
                if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    kind = "a symbolic link" if stat.S_ISLNK(mode) else "a special file"
                    found.append(f"{path.relative_to(self.root)} ({kind})")
        return sorted(found)

    def run_log(self, run_number: int, name: str) -> str | None:
        path = self.root / "runs" / str(run_number) / name
        return path.read_bytes().decode("utf-8") if path.is_file() else None

    def personal_data(self) -> dict[str, Any]:
        """What personal data the bundle holds, found in its files.

        Every file but the manifest is read, signed statements' payloads decoded, and
        each category counted with the files it is in. The manifest carries the result
        and the verifier derives it again, so a manifest that understates what its
        bundle holds fails.
        """
        identifiers: set[str] = set()
        found_in: set[str] = set()
        tokens = 0
        for path in sorted(self.root.rglob("*")):
            if path.is_dir() or path == self.manifest_path:
                continue
            text = path.read_bytes().decode("utf-8", errors="replace")
            name = _listed_as(path.relative_to(self.root))
            addresses = set(emails(text + "\n" + _payloads(text)))
            if addresses:
                identifiers |= addresses
                found_in.add(name)
            if name != "ledger.jsonl":
                continue
            for line in text.splitlines():
                entry = json.loads(line) if line.strip() else None
                body = entry.get("body") if isinstance(entry, dict) else None
                if isinstance(body, dict) and body.get("id_token"):
                    tokens += 1
                    identifiers.add(f"{body.get('issuer')} {body.get('sub')}")
                    found_in.add(name)
        categories: dict[str, Any] = {}
        if identifiers:
            categories["staff_identifiers"] = {
                "description": PERSONAL_DATA_CATEGORIES["staff_identifiers"],
                "count": len(identifiers),
                "files": sorted(found_in),
            }
        if tokens:
            categories["idp_id_tokens"] = {
                "description": PERSONAL_DATA_CATEGORIES["idp_id_tokens"],
                "count": tokens,
                "files": ["ledger.jsonl"],
            }
        return {
            "present": bool(categories),
            "categories": categories,
            "test_subject_data": False,
            "test_subject_data_basis": TEST_SUBJECT_DATA_BASIS,
        }

    def digest(self, ledger_lines: int | None = None) -> str:
        """Digest over every file in the bundle except the manifest itself.

        The exit report embeds this, so a report and the bundle it describes cannot
        be separated without it showing. With ``ledger_lines``, the digest the bundle
        had when its ledger held only that many entries, every other file as it is: the
        one a ``report_generated`` entry records, since the export writes the bundle and
        then the ledger records the report.
        """
        digest = hashlib.sha256()
        ledger = self.root / "ledger.jsonl"
        for path in sorted(self.root.rglob("*")):
            if path.is_dir() or path == self.manifest_path:
                continue
            content = path.read_bytes()
            if path == ledger and ledger_lines is not None:
                content = b"".join(content.splitlines(keepends=True)[:ledger_lines])
            digest.update(str(path.relative_to(self.root)).encode("utf-8"))
            digest.update(hashlib.sha256(content).digest())
        return "sha256:" + digest.hexdigest()


def emails(text: str) -> list[str]:
    """What ``_EMAIL.findall(text)`` returns, without its quadratic time.

    The regex engine tries every start position, and from each one inside a long run
    of word characters with no ``@`` after it (a base64 signature, a digest) it scans
    to the end of the run before failing: seconds on a bundle's ledger. Every address
    has an ``@``, so this starts from each one instead. The local part is the run of
    local-part characters before it, back to where the previous match ended (a start
    anywhere in that run reaches this same ``@``, so the leftmost is the one findall
    takes); the domain is the same pattern ``_EMAIL`` has after its ``@``.
    """
    found: list[str] = []
    resume = 0
    at = text.find("@")
    while at != -1:
        start = at
        while start > resume and _LOCAL_CHAR.match(text, start - 1):
            start -= 1
        domain = _DOMAIN.match(text, at + 1) if start < at else None
        if domain:
            found.append(text[start : domain.end()])
            resume = domain.end()
        at = text.find("@", max(at + 1, resume))
    return found


def _listed_as(relative: Path) -> str:
    """A file as the manifest names it: ``plans/<digest>.json`` is ``plans/``."""
    return relative.parts[0] + "/" if len(relative.parts) > 1 else relative.name


def _payloads(text: str) -> str:
    """The decoded payloads of the DSSE envelopes in a JSON-lines file, where an email
    address would otherwise be hidden in base64."""
    decoded = []
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        payload = record.get("payload") if isinstance(record, dict) else None
        if isinstance(payload, str):
            try:
                decoded.append(base64.b64decode(payload).decode("utf-8", errors="replace"))
            except (ValueError, binascii.Error):
                continue
    return "\n".join(decoded)


def export(
    root: Path,
    sandbox_id: str,
    entries: list[dict[str, Any]],
    attestations: list[dict[str, Any]],
    public_keys: dict[str, str],
    plan: dict[str, Any],
    policy_files: dict[str, str] | None = None,
    plan_versions: dict[str, dict[str, Any]] | None = None,
    run_logs: dict[int, dict[str, str]] | None = None,
    harness_statements: list[dict[str, Any]] | None = None,
    catalogues: dict[str, bytes] | None = None,
) -> Bundle:
    """Write an evidence bundle.

    ``plan`` is the current plan; ``plan_versions`` maps plan digest to the plan as
    it stood then. A participation whose plan was amended mid-course (Art. 57(5)
    allows it, signed by both parties) produced runs judged against different
    versions, and a bundle carrying only the final one would make every earlier run
    look like it ran against the wrong pins. Every version travels.

    ``catalogues`` maps a language to the compiled catalogue its renderings of the
    report were made with (``histor.report.renderings.catalogues``), written as
    ``i18n/<lang>/report.mo``: with the bundle and the catalogue, a rendering can be
    made again and hashed against the ledger's record. Optional and additive, so a
    bundle without it is the same format (docs/i18n.md).
    """
    root.mkdir(parents=True, exist_ok=True)

    (root / "ledger.jsonl").write_text(
        "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in entries),
        encoding="utf-8",
    )
    (root / "attestations.jsonl").write_text(
        "".join(json.dumps(a, sort_keys=True) + "\n" for a in attestations),
        encoding="utf-8",
    )
    (root / "public-keys.json").write_text(
        json.dumps(public_keys, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "plan.json").write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    versions = dict(plan_versions or {})
    if versions:
        plan_dir = root / "plans"
        plan_dir.mkdir(exist_ok=True)
        for version_digest, version in versions.items():
            name = version_digest.removeprefix("sha256:")
            (plan_dir / f"{name}.json").write_text(
                json.dumps(version, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )

    policies = policy_files or {}
    if policies:
        policy_dir = root / "policies"
        policy_dir.mkdir(exist_ok=True)
        for name, content in policies.items():
            (policy_dir / name).write_text(content, encoding="utf-8")

    if harness_statements:
        (root / "harness-statements.jsonl").write_text(
            "".join(json.dumps(h, sort_keys=True) + "\n" for h in harness_statements),
            encoding="utf-8",
        )

    for lang, compiled in sorted((catalogues or {}).items()):
        if not re.fullmatch(r"[a-z]{2,3}", lang):
            raise ValueError(f"{lang!r} is not a language a catalogue is written under")
        catalogue_dir = root / "i18n" / lang
        catalogue_dir.mkdir(parents=True, exist_ok=True)
        (catalogue_dir / CATALOGUE_FILE).write_bytes(compiled)

    for run_number, logs in sorted((run_logs or {}).items()):
        run_dir = root / "runs" / str(run_number)
        run_dir.mkdir(parents=True, exist_ok=True)
        for name, text in logs.items():
            if name not in RUN_LOGS:
                raise ValueError(f"{name} is not a run log the verifier knows how to check")
            # Bytes, not text mode: a digest is over bytes, and newline translation
            # would change them.
            (run_dir / name).write_bytes(text.encode("utf-8"))

    bundle = Bundle(root)
    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "sandbox_id": sandbox_id,
        "files": {
            "ledger.jsonl": "every ledger entry, in order, with prev_hash and entry_hash",
            "attestations.jsonl": "DSSE-signed in-toto statements, one per run",
            "public-keys.json": "key id -> PEM, for every key that signed anything here",
            "plan.json": "the sandbox plan these runs were judged against",
            **({"policies/": "network and gate policy files, by name"} if policies else {}),
            **(
                {
                    "harness-statements.jsonl": "DSSE-signed statements of what the harness "
                    "measured, signed in segment A, and for a run at a centre what the "
                    "driver observed there; each attestation cites them by digest"
                }
                if harness_statements
                else {}
            ),
            **(
                {
                    "runs/<n>/": "each run's logs, whose digests its attestation carries: "
                    + ", ".join(RUN_LOGS)
                }
                if run_logs
                else {}
            ),
            **(
                {"plans/<digest>.json": "every signed plan version, keyed by its digest"}
                if versions
                else {}
            ),
            **(
                {
                    f"i18n/<lang>/{CATALOGUE_FILE}": "the compiled catalogue each language's "
                    "rendering of the report was made with; the report_generated entry "
                    "records its sha256"
                }
                if catalogues
                else {}
            ),
        },
        "plan_versions": sorted(versions),
        "entry_count": len(entries),
        "attestation_count": len(attestations),
        "personal_data": bundle.personal_data(),
        "verify_with": "uv run histor verify <this directory>",
    }
    manifest["bundle_digest"] = bundle.digest()
    bundle.manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return bundle


def pack(bundle: Bundle, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "w:gz") as archive:
        archive.add(bundle.root, arcname=bundle.root.name)
    return destination


def pack_bytes(bundle: Bundle) -> bytes:
    """The bundle as a gzipped tarball in memory, for sending over the console's API.

    Regular files and directories only, under one top-level ``evidence-bundle/``, which
    is all :func:`unpack` accepts.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        archive.add(bundle.root, arcname="evidence-bundle")
    return buffer.getvalue()


def unpack(payload: bytes, destination: Path) -> Bundle:
    """The inverse of :func:`pack_bytes` and :func:`pack`, refusing anything a bundle
    does not contain.

    A tarball from the network is untrusted input: an absolute path, a ``..``, a link
    or a device would let it write outside ``destination``. Such an archive is refused
    whole rather than filtered, since a bundle never contains one. So is one with more
    than one top-level directory, since a bundle is one.
    """
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        members = archive.getmembers()
        tops = set()
        for member in members:
            path = Path(member.name)
            if (
                not (member.isfile() or member.isdir())
                or path.is_absolute()
                or ".." in path.parts
                or not path.parts
            ):
                raise ValueError(f"not an evidence bundle archive: refusing {member.name!r}")
            tops.add(path.parts[0])
        if len(tops) != 1:
            raise ValueError(f"not an evidence bundle archive: {len(tops)} top-level entries")
        archive.extractall(destination, members=members, filter="data")
    return Bundle(destination / tops.pop())
