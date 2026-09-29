"""The sample participation verifies, each tampered copy of it is rejected by the check
meant to catch it, and the package carries the core and nothing else."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from histor import cli as histor_cli
from histor.verifier import cli
from histor.verifier.checks import FAIL

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample-participation"
GOOD = SAMPLE / "evidence-bundle"
TAMPERED = ROOT / "examples" / "tampered"
PLAN = ROOT / "examples" / "age-estimation.plan.yaml"
ANCHORS = SAMPLE / "anchors.yaml"


def _tamper_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("tampered_build", TAMPERED / "build.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up there
    spec.loader.exec_module(module)
    return module


BUILDER = _tamper_builder()
COPIES = sorted(p.name for p in TAMPERED.iterdir() if (p / "evidence-bundle").is_dir())


def _verify(bundle: Path, *flags: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, Any]:
    code = cli.main([str(bundle), "--json", *flags])
    return code, json.loads(capsys.readouterr().out)


def _failed(verdict: Any) -> set[str]:
    return {r["id"] for r in verdict["results"] if r["outcome"] == FAIL}


class TestGoodSample:
    def test_it_verifies(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, verdict = _verify(GOOD, capsys=capsys)
        assert code == 0
        assert verdict["verified"] is True
        assert _failed(verdict) == set()

    def test_it_says_no_isolation_was_enforced(self, capsys: pytest.CaptureFixture[str]) -> None:
        _, verdict = _verify(GOOD, capsys=capsys)
        isolation = next(r for r in verdict["results"] if r["id"] == "isolation")
        assert "NO ISOLATION WAS ENFORCED" in isolation["detail"]

    def test_the_committed_verdict_is_what_the_verifier_says_now(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _, now = _verify(GOOD, capsys=capsys)
        assert now == json.loads((SAMPLE / "verify.json").read_text(encoding="utf-8"))

    def test_it_verifies_against_the_anchors_you_hold(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, verdict = _verify(GOOD, "--anchors", str(ANCHORS), capsys=capsys)
        assert code == 0
        assert _failed(verdict) == set()
        assert {"plan_digest", "sandbox_id", "signing_keys"} <= set(verdict["anchors"]["external"])
        committed = json.loads((SAMPLE / "verify-anchored.json").read_text(encoding="utf-8"))
        assert verdict == committed

    def test_a_plan_digest_you_did_not_sign_fails(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, verdict = _verify(GOOD, "--expect-plan-digest", "sha256:" + "0" * 64, capsys=capsys)
        assert code == 1
        assert "anchor_plan_digest" in _failed(verdict)


class TestTamperedCopies:
    def test_there_are_copies(self) -> None:
        assert len(COPIES) >= 4

    @pytest.mark.parametrize("name", COPIES)
    def test_it_is_rejected_by_the_check_meant_to_catch_it(
        self, name: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bundle = TAMPERED / name / "evidence-bundle"
        code, verdict = _verify(bundle, "--anchors", str(ANCHORS), capsys=capsys)
        assert code == 1
        assert verdict["verified"] is False
        assert _failed(verdict) & set(BUILDER.TAMPERS[name].checks)

    def test_the_committed_copies_are_what_the_builder_makes(self, tmp_path: Path) -> None:
        BUILDER.build(tmp_path, GOOD, COPIES)
        for name in COPIES:
            built, committed = tmp_path / name, TAMPERED / name
            files = sorted(p.relative_to(built) for p in built.rglob("*") if p.is_file())
            assert files == sorted(
                p.relative_to(committed) for p in committed.rglob("*") if p.is_file()
            )
            for relative in files:
                assert (built / relative).read_bytes() == (committed / relative).read_bytes()


class TestCommandLine:
    def test_version_names_the_bundle_formats(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exit_:
            cli.main(["--version"])
        assert exit_.value.code == 0
        assert re.match(r"histor verify \S+ \(bundle_version [\d., ]+\)", capsys.readouterr().out)

    def test_a_directory_that_is_not_a_bundle_exits_2(self, tmp_path: Path) -> None:
        assert cli.main([str(tmp_path)]) == 2

    def test_help_offers_only_what_this_package_can_run(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert histor_cli.main(["--help"]) == 0
        out = capsys.readouterr().out
        assert "  verify " in out and "  plan " in out
        offered = {c.words[0] for c in histor_cli.available()}
        assert offered == {"verify", "plan"}

    def test_the_example_plan_validates(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert histor_cli.main(["plan", "validate", str(PLAN)]) == 0
        assert "plan_digest=sha256:" in capsys.readouterr().out

    @pytest.mark.skipif(shutil.which("histor") is None, reason="not installed")
    @pytest.mark.parametrize(
        ("bundle", "code", "named"),
        [(GOOD, 0, "VERIFIED")] + [(TAMPERED / n / "evidence-bundle", 1, "FAIL  ") for n in COPIES],
    )
    def test_the_installed_command(self, bundle: Path, code: int, named: str) -> None:
        run = subprocess.run(
            ["histor", "verify", "--anchors", str(ANCHORS), str(bundle)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert run.returncode == code, run.stdout + run.stderr
        assert named in run.stdout


class TestNothingPrivate:
    """What the release carries under examples/ is synthetic and holds no secret."""

    FILES = sorted(p for p in (ROOT / "examples").rglob("*") if p.is_file())

    def test_every_address_is_on_a_reserved_domain(self) -> None:
        pattern = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
        for path in self.FILES:
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in pattern.finditer(text):
                assert match.group(0).endswith((".example", ".invalid")), f"{path}: {match}"

    def test_no_private_key(self) -> None:
        for path in self.FILES:
            assert "PRIVATE KEY" not in path.read_text(encoding="utf-8", errors="replace"), path


def test_the_core_loads_only_what_ships() -> None:
    """Every histor module the core commands load is a file in this package."""
    code = (
        "import json, sys, contextlib, io\n"
        "from histor.cli import main\n"
        "with contextlib.redirect_stdout(io.StringIO()):\n"
        "    codes = [main(['verify', sys.argv[1]]), main(['plan', 'validate', sys.argv[2]])]\n"
        "print(json.dumps([codes, sorted(m for m in sys.modules if m.startswith('histor'))]))\n"
    )
    run = subprocess.run(
        [sys.executable, "-c", code, str(GOOD), str(PLAN)],
        capture_output=True,
        text=True,
        check=True,
    )
    codes, modules = json.loads(run.stdout.strip().splitlines()[-1])
    assert codes == [0, 0]
    package = Path(histor_cli.__file__).resolve().parent.parent
    for name in modules:
        path = package.parent.joinpath(*name.split("."))
        assert path.with_suffix(".py").is_file() or (path / "__init__.py").is_file(), name
