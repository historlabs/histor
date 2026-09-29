"""``histor``: one command, with a subcommand for each thing the package does.

    histor verify BUNDLE              check an evidence bundle, offline
    histor plan validate PLAN ...     check a participation plan and print its digest
    histor run demo                   the demo, end to end on CPU
    histor <command> --help           what a command takes

Each subcommand is a module's ``main(argv)``, named here as ``"module:function"`` and
imported only when it is chosen. Nothing is imported at the top of this module but the
standard library, so ``histor --help`` and ``histor verify`` load the core and nothing
else (``tests/test_core_imports.py``). An engine command whose dependencies are not
installed says to install ``histor[engine]`` instead of failing with a traceback.

A release that carries only the core (the first public one: ``tools/public_export``)
ships the modules ``histor verify`` and ``histor plan validate`` need and none of the
engine's. A command whose module is not in the package is not offered at all, rather
than listed and then failing.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROG = "histor"


@dataclass(frozen=True)
class Command:
    words: tuple[str, ...]  # what follows `histor`, e.g. ("plan", "validate")
    target: str  # "module:function", the function taking argv and returning an exit code
    help: str
    engine: bool = True  # needs `histor[engine]`; False for what a plain install runs

    @property
    def name(self) -> str:
        return " ".join((PROG, *self.words))


COMMANDS: tuple[Command, ...] = (
    Command(("verify",), "histor.verifier.cli:main", "verify an evidence bundle, offline", False),
    Command(
        ("plan", "validate"),
        "histor.plan.cli:main",
        "validate participation plans and print their digests",
        False,
    ),
    Command(
        ("conformance",),
        "histor.tools.conformance.cli:main",
        "run a provider and check it against the inference profile",
    ),
    Command(("console",), "histor.console.app:main", "serve the supervisor console"),
    Command(
        ("ledger", "init"),
        "histor.ledger.postgres:main",
        "create the Postgres ledger's tables, grants and logins",
    ),
    Command(
        ("ledger", "export"),
        "histor.ledger.cli_tools:export_main",
        "export the whole ledger, with its head, for a backup or an authority",
        False,
    ),
    Command(
        ("ledger", "verify-db"),
        "histor.ledger.cli_tools:verify_db_main",
        "re-verify a live or restored ledger database, or an export",
        False,
    ),
    Command(
        ("ledger", "checkpoint"),
        "histor.ledger.cli_tools:checkpoint_main",
        "sign and stamp the ledger's head, for the regulator to keep",
    ),
    Command(
        ("ledger", "compare"),
        "histor.ledger.cli_tools:compare_main",
        "whether a restored ledger is identical to, or extends, a reference",
        False,
    ),
    Command(
        ("registry",),
        "histor.registry.cli:main",
        "ingest verified evidence bundles, export aggregate results",
    ),
    Command(("keys", "dev"), "histor.sandbox.devkeys:main", "generate local development keys"),
    Command(
        ("release",),
        "histor.sandbox.releaser:main",
        "the provider's weights releaser: encrypt, approve, serve",
    ),
    Command(
        ("model", "bringup"),
        "histor.tools.bringup.bringup:main",
        "bring a model up alone, with no data, and say why if it won't",
    ),
    Command(("run", "demo"), "histor.demo.scripts.run_demo:main", "the demo, end to end on CPU"),
    Command(
        ("run", "hosted"),
        "histor.demo.scripts.run_hosted:main",
        "a participation against a real VLM on a hosted API",
    ),
    Command(
        ("run", "kind"),
        "histor.demo.scripts.run_kind:main",
        "a participation on the kind cluster: harness Job, Cilium evidence, bundle",
    ),
    Command(
        ("run", "hpc"),
        "histor.demo.scripts.run_hpc:main",
        "a participation as a Slurm job at an HPC centre, over SSH",
    ),
    Command(
        ("run", "showcase"),
        "histor.demo.scripts.showcase:main",
        "the demo on the cluster: real isolation, offline verifier",
    ),
    Command(
        ("data", "gen"),
        "histor.demo.data.synthetic:main",
        "generate the synthetic development dataset",
    ),
    Command(
        ("testlab",),
        "histor.testlab.cli:main",
        "the test lab: validate, strip, commit and seal a held-out set",
    ),
    Command(
        ("check", "isolation"),
        "histor.tools.isolation.kind_check:main",
        "check the isolation on a live kind cluster, with mock-evil",
    ),
    Command(
        ("check", "licences"),
        "histor.tools.licence.cli:main",
        "the licence inventory of a model image, against a policy",
    ),
    Command(
        ("notify",),
        "histor.tools.notify.notifier:main",
        "tell someone when the ledger records a deviation",
    ),
)

# The words that group commands, and what the group is for.
GROUPS: dict[tuple[str, ...], str] = {
    (): "Histor: the trust layer for EU AI Act Article 57 regulatory sandboxes.",
    ("plan",): "the participation plan",
    ("ledger",): "the evidence ledger",
    ("keys",): "development keys",
    ("model",): "the model under test",
    ("run",): "run a participation",
    ("data",): "datasets",
    ("check",): "checks of a deployment",
}

ENGINE_HINT = "pip install 'histor[engine]'"

PACKAGE = Path(__file__).resolve().parent.parent


def shipped(command: Command) -> bool:
    """Whether the command's module is in this copy of the package. Looked up as a
    file, not imported: importing it would load what ``histor --help`` must not."""
    parts = command.target.split(":")[0].split(".")[1:]
    path = PACKAGE.joinpath(*parts)
    return path.with_suffix(".py").is_file() or (path / "__init__.py").is_file()


def available() -> tuple[Command, ...]:
    """The commands this copy of the package can run: every one, in a checkout."""
    return tuple(c for c in COMMANDS if shipped(c))


def find(words: Sequence[str]) -> Command | None:
    return next((c for c in available() if c.words == tuple(words)), None)


def _children(prefix: tuple[str, ...]) -> dict[str, str]:
    """The next words after ``prefix``, each with its help."""
    out: dict[str, str] = {}
    for command in available():
        if command.words[: len(prefix)] == prefix and len(command.words) > len(prefix):
            word = command.words[len(prefix)]
            child = (*prefix, word)
            out.setdefault(word, command.help if command.words == child else GROUPS[child])
    return out


def usage(prefix: tuple[str, ...] = ()) -> str:
    name = " ".join((PROG, *prefix))
    children = _children(prefix)
    width = max(len(word) for word in children) + 2
    lines = [f"usage: {name} <command> [arguments]", "", GROUPS[prefix], "", "commands:"]
    lines += [f"  {word:<{width}}{text}" for word, text in children.items()]
    lines += ["", f"Run `{name} <command> --help` for what a command takes."]
    if not prefix and any(c.engine for c in available()):
        core = " and ".join(f"`{c.name}`" for c in available() if not c.engine)
        lines += [f"A plain install runs {core}; the rest needs the engine: {ENGINE_HINT}."]
    return "\n".join(lines)


def load(command: Command) -> Callable[[list[str]], Any]:
    """The command's function. Raises :class:`SystemExit` with the install hint when
    an engine command's dependencies are missing."""
    module, function = command.target.split(":")
    try:
        loaded = importlib.import_module(module)
    except ModuleNotFoundError as error:
        missing = (error.name or "").split(".")[0]
        if missing == "histor" or not missing:
            raise
        raise SystemExit(
            f"{command.name} needs {missing}, which the engine brings: {ENGINE_HINT}"
        ) from None
    target: Callable[[list[str]], Any] = getattr(loaded, function)
    return target


def run(command: Command, argv: list[str]) -> int:
    """Run ``command`` with ``argv``. Its parser names itself ``histor <words>``."""
    target = load(command)
    # Operational logs (histor/obs/logs.py) on stderr. A command's output is what a
    # person reads, so by default only errors are logged beside it; HISTOR_LOG_LEVEL
    # asks for more. A service (the relay, the harness, the releaser) defaults to info.
    from histor.obs.logs import configure

    configure("ERROR")
    program = sys.argv[0] if sys.argv else PROG
    sys.argv[0:1] = [command.name]
    try:
        code = target(argv)
    finally:
        sys.argv[0:1] = [program]
    return int(code or 0)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] in (["--version"], ["-V"]):
        from histor import __version__

        print(f"{PROG} {__version__}")
        return 0
    prefix: tuple[str, ...] = ()
    while True:
        command = find(prefix)
        if command is not None:
            return run(command, args)
        if not args or args[0] in ("-h", "--help"):
            print(usage(prefix), file=sys.stdout if args else sys.stderr)
            return 0 if args else 2
        word = args.pop(0)
        if word not in _children(prefix):
            name = " ".join((PROG, *prefix))
            print(f"{name}: no command {word!r}\n\n{usage(prefix)}", file=sys.stderr)
            return 2
        prefix = (*prefix, word)
