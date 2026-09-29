"""Structured operational logs for every Histor service, on the standard library.

One JSON object per line on stderr, for whatever collects the container's or the
job's output, or one readable line per event on a terminal. The fields:

``ts``          RFC 3339, UTC, milliseconds (``2026-09-28T10:15:02.113Z``)
``level``       ``debug`` | ``info`` | ``warning`` | ``error`` | ``critical``
``logger``      the Python logger (``histor.gate``)
``msg``         what happened, in words, after redaction
``component``   the logger's name below ``histor.`` (``gate``, ``relay``, ``harness``,
                ``backends.kubernetes``, ``backends.slurm``, ``keybroker``,
                ``releaser``, ``ledger``); a third-party logger's own name
``sandbox_id``, ``run_id``, ``request_id``, ``ledger_seq``
                correlation, when the event has them: ``ledger_seq`` is the sequence
                number of the ledger entry the action produced, so a log line can be
                found in the evidence and the other way round
anything else   the event's own fields, sorted by name
``exc``         a traceback, redacted, when one was logged

**Not evidence.** The ledger, the relay's hash log, the harness's ``SANDBOX-RESULT``
line and the drop log have formats of their own, which verifiers parse, and none of
them goes through this module. A log line may be lost, reordered or rotated away; an
evidence record may not. So nothing is ever proven from a log line, and nothing a
verifier needs is only in one.

**Configuration**, read once by :func:`configure`:

``HISTOR_LOG_LEVEL``         ``debug`` | ``info`` | ``warning`` | ``error``; the default
                             is the caller's (``info`` for a service, ``warning`` for
                             the ``histor`` command)
``HISTOR_LOG_FORMAT``        ``json`` | ``text``; default ``text`` on a terminal and
                             ``json`` everywhere else (a container, a batch job, a pipe)
``HISTOR_LOG_ALLOW_EMAILS``  ``1`` to keep e-mail addresses (the gate's subjects) in
                             the logs; by default they are masked

**Redaction** (:class:`RedactionFilter`) runs on every record, whether or not
:func:`configure` was called: on the logger each :func:`get_logger` hands out, and on
the handler :func:`configure` installs, so a third-party library's records are covered
too. A field whose name says it holds a secret (a token, a password, a key's
material, a seed, a DSN) or test data (a label, an age, a group, an image, an item, a
model output) has its value replaced with ``[redacted]`` whatever it holds; every
string, the message included, is scrubbed of private keys, JWTs, bearer and Vault
tokens, ``token=…`` pairs, base64 payloads over :data:`BASE64_LIMIT` characters,
``age``/``label``/``group`` values and e-mail addresses. Redaction is the second
line: the first is that the code never passes those things to a logger at all.

For a service that already writes its own JSON (the console's access log), adopting
this is ``get_logger("console").info("request", method=…, path=…, status=…)`` in
place of the ``sys.stderr.write``, with ``configure()`` at start-up.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import re
import sys
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from typing import IO, Any, Final

ROOT: Final = "histor"
FIELDS_ATTR: Final = "histor_fields"
CORRELATION: Final = ("sandbox_id", "run_id", "request_id", "ledger_seq")
FORMATS: Final = ("json", "text")
REDACTED: Final = "[redacted]"
# A base64 run longer than this is a payload (an image, a sealed blob, a key file),
# never an identifier: a sha256 digest in hex is 64 characters, in base64 44.
BASE64_LIMIT: Final = 200

# --- redaction ---------------------------------------------------------------------

# Field names whose values are never logged, whatever they hold. Compared lower-case
# with dashes as underscores.
SECRET_KEYS: Final = frozenset(
    {
        "token",
        "tokens",
        "access_token",
        "id_token",
        "refresh_token",
        "run_token",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "authorization",
        "cookie",
        "set_cookie",
        "csrf",
        "api_key",
        "apikey",
        "private_key",
        "private_pem",
        "key_material",
        "material",
        "seed",
        "data_keys",
        "credential",
        "credentials",
        "dsn",
    }
)
SECRET_SUFFIXES: Final = ("_token", "_secret", "_password", "_seed", "_private_key", "_dsn")
# Test data and what a model said about it (docs/threat-model.md: plaintext test data
# exists only in segment A memory, and not in its logs either).
TEST_DATA_KEYS: Final = frozenset(
    {
        "label",
        "labels",
        "age",
        "ages",
        "true_age",
        "age_years",
        "group",
        "groups",
        "group_label",
        "demographic",
        "demographics",
        "skin_tone",
        "fitzpatrick",
        "gender",
        "sex",
        "ethnicity",
        "image",
        "images",
        "image_b64",
        "image_base64",
        "pixels",
        "exif",
        "item",
        "items",
        "item_id",
        "item_ids",
        "file_name",
        "filename",
        "output",
        "outputs",
        "prediction",
        "predictions",
        "estimate",
        "estimates",
        "answer",
        "answers",
        "body",
        "request_body",
        "response_body",
        "content",
        "messages",
    }
)

_TEXT_RULES: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*-----|$)", re.S),
        "[redacted private key]",
    ),
    (re.compile(r"data:image/[\w.+-]+;base64,[A-Za-z0-9+/=_-]*"), "[redacted image]"),
    (re.compile(r"\beyJ[\w-]{4,}\.[\w-]{4,}\.[\w-]*"), "[redacted jwt]"),
    (re.compile(r"(?i)\bbearer\s+[\w\-.~+/]+=*"), "Bearer [redacted]"),
    (re.compile(r"\b(?:hv[sbr]|s)\.[A-Za-z0-9_-]{20,}"), "[redacted vault token]"),
    (re.compile(r"\b(?:gh[pousr]_|github_pat_|sk-|xox[abpr]-)[A-Za-z0-9_-]{16,}"), REDACTED),
    (
        re.compile(
            r"(?i)\b((?:[a-z_]*_)?(?:token|password|passwd|secret|api[_-]?key|seed|csrf)"
            r"s?)(\"?\s*[=:]\s*\"?)[^\s\"',;&}]+"
        ),
        r"\1\2" + REDACTED,
    ),
    (
        re.compile(
            r"(?i)\b(true_age|ages?|labels?|groups?|skin_tone|fitzpatrick)"
            r"(\"?\s*[=:]\s*\"?)[^\s\"',;&}\]]+"
        ),
        r"\1\2" + REDACTED,
    ),
    # "age 34", "age 130 outside [0, 120]": a number after the word is an age.
    (re.compile(r"(?i)\b(true age|age)\s+(-?\d+(?:\.\d+)?)"), r"\1 " + REDACTED),
    (
        re.compile(
            r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{" + str(BASE64_LIMIT) + r",}={0,2}(?![A-Za-z0-9+/=])"
        ),
        "[redacted base64]",
    ),
)
_EMAIL: Final = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")

_settings: dict[str, bool] = {"allow_emails": False}


def _normal(key: str) -> str:
    return key.lower().replace("-", "_")


def is_sensitive_key(key: str) -> bool:
    """Whether a field of this name is never logged, whatever its value."""
    name = _normal(key)
    return (
        name in SECRET_KEYS
        or name in TEST_DATA_KEYS
        or any(name.endswith(suffix) for suffix in SECRET_SUFFIXES)
    )


def redact_text(text: str, allow_emails: bool | None = None) -> str:
    """``text`` with every secret and test-data pattern masked."""
    for pattern, replacement in _TEXT_RULES:
        text = pattern.sub(replacement, text)
    if not (_settings["allow_emails"] if allow_emails is None else allow_emails):
        text = _EMAIL.sub("[email]", text)
    return text


def redact(value: Any, allow_emails: bool | None = None) -> Any:
    """A copy of ``value`` fit to log: sensitive keys masked at every depth, every
    string scrubbed, bytes never shown."""
    if isinstance(value, str):
        return redact_text(value, allow_emails)
    if isinstance(value, bytes | bytearray | memoryview):
        return f"[{len(value)} bytes]"
    if isinstance(value, Mapping):
        return {
            str(k): REDACTED if is_sensitive_key(str(k)) else redact(v, allow_emails)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [redact(v, allow_emails) for v in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    return redact_text(str(value), allow_emails)


class RedactionFilter(logging.Filter):
    """Masks secrets and test data in a record's message, fields and traceback.

    Never drops a record: an operator should see that something happened, only not
    what it carried."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "_histor_redacted", False):
            return True
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        record.msg, record.args = redact_text(message), None
        fields = getattr(record, FIELDS_ATTR, None)
        if isinstance(fields, Mapping):
            setattr(record, FIELDS_ATTR, redact(fields))
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_text(record.stack_info)
        record.__dict__["_histor_redacted"] = True
        return True


# --- context -----------------------------------------------------------------------

_bound: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "histor_log_context", default=None
)
_process: dict[str, Any] = {}


def clear_context() -> None:
    """Forget every field :func:`set_context` set."""
    _process.clear()


def set_context(**fields: Any) -> None:
    """Fields every record in this process carries from now on (a harness's
    ``sandbox_id`` and ``run_id``). ``None`` removes one."""
    for key, value in fields.items():
        if value is None:
            _process.pop(key, None)
        else:
            _process[key] = value


@contextlib.contextmanager
def bind(**fields: Any) -> Iterator[None]:
    """Fields every record carries inside the ``with``, in this thread or task."""
    token = _bound.set({**(_bound.get() or {}), **fields})
    try:
        yield
    finally:
        _bound.reset(token)


def _context() -> dict[str, Any]:
    return {**_process, **(_bound.get() or {})}


# --- formatting --------------------------------------------------------------------


def _component(record: logging.LogRecord) -> str:
    name = record.name
    return name[len(ROOT) + 1 :] if name.startswith(ROOT + ".") else name


def _timestamp(record: logging.LogRecord) -> str:
    moment = datetime.fromtimestamp(record.created, UTC)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _fields(record: logging.LogRecord) -> dict[str, Any]:
    fields = getattr(record, FIELDS_ATTR, None)
    return dict(fields) if isinstance(fields, Mapping) else {}


def _exception(record: logging.LogRecord) -> str | None:
    text = record.exc_text
    if not text and record.exc_info:
        text = logging.Formatter().formatException(record.exc_info)
    return redact_text(text) if text else None


class JsonFormatter(logging.Formatter):
    """One JSON object per record, the fields in the module docstring's order."""

    def format(self, record: logging.LogRecord) -> str:
        fields = _fields(record)
        line: dict[str, Any] = {
            "ts": _timestamp(record),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
            "component": str(fields.pop("component", None) or _component(record)),
        }
        for key in CORRELATION:
            if fields.get(key) is not None:
                line[key] = fields.pop(key)
        for key in sorted(fields):
            if key not in line:
                line[key] = fields[key]
        exception = _exception(record)
        if exception:
            line["exc"] = exception
        return json.dumps(line, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """``ts LEVEL component: msg key=value …``, for a person at a terminal."""

    def format(self, record: logging.LogRecord) -> str:
        fields = _fields(record)
        component = str(fields.pop("component", None) or _component(record))
        ordered = [k for k in CORRELATION if fields.get(k) is not None]
        ordered += sorted(k for k in fields if k not in CORRELATION and fields[k] is not None)
        extras = "".join(f" {k}={json.dumps(fields[k], default=str)}" for k in ordered)
        text = (
            f"{_timestamp(record)} {record.levelname:<7} {component}: {record.getMessage()}{extras}"
        )
        exception = _exception(record)
        return f"{text}\n{exception}" if exception else text


# --- loggers -----------------------------------------------------------------------

_FILTER: Final = RedactionFilter()


class EventLogger:
    """A logger that takes the event's fields as keywords.

    ``log.info("run launched", run_id=…, sandbox_id=…)``. The fields bound with
    :func:`bind` or :func:`set_context` are added underneath; the call's own win."""

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    @property
    def name(self) -> str:
        return self.logger.name

    def isEnabledFor(self, level: int) -> bool:  # noqa: N802 - the stdlib's name
        return self.logger.isEnabledFor(level)

    def log(self, level: int, msg: str, /, *, exc_info: bool = False, **fields: Any) -> None:
        if not self.logger.isEnabledFor(level):
            return
        merged = {**_context(), **{k: v for k, v in fields.items() if v is not None}}
        self.logger.log(level, msg, exc_info=exc_info, extra={FIELDS_ATTR: merged}, stacklevel=3)

    def debug(self, msg: str, /, **fields: Any) -> None:
        self.log(logging.DEBUG, msg, **fields)

    def info(self, msg: str, /, **fields: Any) -> None:
        self.log(logging.INFO, msg, **fields)

    def warning(self, msg: str, /, **fields: Any) -> None:
        self.log(logging.WARNING, msg, **fields)

    def error(self, msg: str, /, **fields: Any) -> None:
        self.log(logging.ERROR, msg, **fields)

    def exception(self, msg: str, /, **fields: Any) -> None:
        self.log(logging.ERROR, msg, exc_info=True, **fields)


def get_logger(component: str) -> EventLogger:
    """The logger for ``component`` (``gate``, ``backends.slurm``…), redacting."""
    logger = logging.getLogger(f"{ROOT}.{component}")
    if _FILTER not in logger.filters:
        logger.addFilter(_FILTER)
    return EventLogger(logger)


def _level(value: str | int | None, default: str | int) -> int:
    for candidate in (value, default):
        if isinstance(candidate, int):
            return candidate
        if candidate:
            level = logging.getLevelName(str(candidate).strip().upper())
            if isinstance(level, int):
                return level
    return logging.INFO


def _format(value: str | None, stream: IO[str]) -> str:
    if value and value.strip().lower() in FORMATS:
        return value.strip().lower()
    try:
        return "text" if stream.isatty() else "json"
    except (AttributeError, ValueError):
        return "json"


class HistorHandler(logging.StreamHandler[IO[str]]):
    """The handler :func:`configure` installs, so a second call can find and replace it.

    Without a stream of its own it writes to whatever ``sys.stderr`` is when a record
    arrives, so a redirection made after start-up (a test's capture) is followed."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        super().__init__(stream or sys.stderr)
        self.follows_stderr = stream is None

    def emit(self, record: logging.LogRecord) -> None:
        if self.follows_stderr:
            self.stream = sys.stderr
        super().emit(record)


def configure(
    default_level: str | int = "INFO",
    *,
    level: str | int | None = None,
    fmt: str | None = None,
    stream: IO[str] | None = None,
    allow_emails: bool | None = None,
) -> logging.Handler:
    """Install the one handler on the root logger, replacing any this installed before.

    ``level`` and ``fmt`` override the environment (``HISTOR_LOG_LEVEL``,
    ``HISTOR_LOG_FORMAT``), which overrides ``default_level`` and the terminal test.
    Returns the handler, for a test to inspect."""
    resolved = _level(level or os.environ.get("HISTOR_LOG_LEVEL"), default_level)
    chosen = _format(fmt or os.environ.get("HISTOR_LOG_FORMAT"), stream or sys.stderr)
    if allow_emails is None:
        allow_emails = os.environ.get("HISTOR_LOG_ALLOW_EMAILS", "").strip() in {"1", "true"}
    _settings["allow_emails"] = allow_emails

    handler = HistorHandler(stream)
    handler.setFormatter(JsonFormatter() if chosen == "json" else TextFormatter())
    handler.addFilter(_FILTER)
    root = logging.getLogger()
    for old in [h for h in root.handlers if isinstance(h, HistorHandler)]:
        root.removeHandler(old)
    root.addHandler(handler)
    root.setLevel(resolved)
    return handler
