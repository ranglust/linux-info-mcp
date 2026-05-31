"""System info tools: uptime, who, last, lscpu, lsmem, dmidecode."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import (
    _reject_unsafe_chars,
    validate_host,
    validate_lines_int,
)
from . import ToolSpec


def _decode_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _bool(value, label: str) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a bool")
    return value


# ---------------------------------------------------------------------------
# uptime
# ---------------------------------------------------------------------------


def build_remote_cmd_uptime(*, pretty: bool = False, since: bool = False) -> str:
    """Build LC_ALL=C uptime command string."""
    if pretty and since:
        raise ValueError("pretty and since are mutually exclusive")
    parts = ["LC_ALL=C", "uptime"]
    if pretty:
        parts.append("-p")
    if since:
        parts.append("-s")
    return " ".join(parts)


def handle_uptime(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_uptime(
        pretty=_bool(args.get("pretty"), "pretty"),
        since=_bool(args.get("since"), "since"),
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


UPTIME_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pretty": {"type": ["boolean", "null"]},
        "since": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# who
# ---------------------------------------------------------------------------


def build_remote_cmd_who(
    *,
    all: bool = False,
    boot: bool = False,
    login: bool = False,
    runlevel: bool = False,
    users: bool = False,
) -> str:
    """Build LC_ALL=C who command string."""
    parts = ["LC_ALL=C", "who"]
    if all:
        parts.append("-a")
    if boot:
        parts.append("-b")
    if login:
        parts.append("-l")
    if runlevel:
        parts.append("-r")
    if users:
        parts.append("-q")
    return " ".join(parts)


def handle_who(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_who(
        all=_bool(args.get("all"), "all"),
        boot=_bool(args.get("boot"), "boot"),
        login=_bool(args.get("login"), "login"),
        runlevel=_bool(args.get("runlevel"), "runlevel"),
        users=_bool(args.get("users"), "users"),
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


WHO_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "all": {"type": ["boolean", "null"]},
        "boot": {"type": ["boolean", "null"]},
        "login": {"type": ["boolean", "null"]},
        "runlevel": {"type": ["boolean", "null"]},
        "users": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# last
# ---------------------------------------------------------------------------

_LAST_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]*\$?$")
_LAST_TTY_RE = re.compile(r"^[A-Za-z0-9./_-]{1,32}$")


def _validate_last_user(user) -> str:
    if not isinstance(user, str) or not user:
        raise ValueError("user must be a non-empty string")
    if len(user) > 32:
        raise ValueError("user must be at most 32 characters")
    _reject_unsafe_chars(user, "user")
    if not _LAST_USER_RE.fullmatch(user):
        raise ValueError(f"user does not match required pattern: {user!r}")
    return user


def _validate_last_tty(tty) -> str:
    if not isinstance(tty, str) or not tty:
        raise ValueError("tty must be a non-empty string")
    _reject_unsafe_chars(tty, "tty")
    if tty.startswith("-"):
        raise ValueError("tty must not start with '-'")
    if not _LAST_TTY_RE.fullmatch(tty):
        raise ValueError(f"tty does not match required pattern: {tty!r}")
    return tty


def build_remote_cmd_last(
    *,
    lines: int | None = None,
    user: str | None = None,
    tty: str | None = None,
) -> str:
    """Build LC_ALL=C last command string."""
    parts = ["LC_ALL=C", "last"]
    if lines is not None:
        parts += ["-n", str(lines)]
    positional = []
    if user is not None:
        positional.append(shlex.quote(user))
    if tty is not None:
        positional.append(shlex.quote(tty))
    if positional:
        parts.append("--")
        parts.extend(positional)
    return " ".join(parts)


def handle_last(args: dict) -> dict:
    host = validate_host(args["host"])
    lines_in = args.get("lines")
    lines = (
        validate_lines_int(lines_in, lo=1, hi=1000, label="lines") if lines_in is not None else None
    )
    user_in = args.get("user")
    user = _validate_last_user(user_in) if user_in is not None else None
    tty_in = args.get("tty")
    tty = _validate_last_tty(tty_in) if tty_in is not None else None
    cmd = build_remote_cmd_last(lines=lines, user=user, tty=tty)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


LAST_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "lines": {"type": ["integer", "null"]},
        "user": {"type": ["string", "null"]},
        "tty": {"type": ["string", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# lscpu
# ---------------------------------------------------------------------------


def build_remote_cmd_lscpu(
    *,
    json: bool = False,
    extended: bool = False,
    parseable: bool = False,
) -> str:
    """Build LC_ALL=C lscpu command string."""
    if json and extended:
        raise ValueError("json and extended are mutually exclusive")
    if json and parseable:
        raise ValueError("json and parseable are mutually exclusive")
    if extended and parseable:
        raise ValueError("extended and parseable are mutually exclusive")
    parts = ["LC_ALL=C", "lscpu"]
    if json:
        parts.append("-J")
    if extended:
        parts.append("-e")
    if parseable:
        parts.append("-p")
    return " ".join(parts)


def handle_lscpu(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_lscpu(
        json=_bool(args.get("json"), "json"),
        extended=_bool(args.get("extended"), "extended"),
        parseable=_bool(args.get("parseable"), "parseable"),
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


LSCPU_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "json": {"type": ["boolean", "null"]},
        "extended": {"type": ["boolean", "null"]},
        "parseable": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# lsmem
# ---------------------------------------------------------------------------


def build_remote_cmd_lsmem(
    *,
    json: bool = False,
    summary: bool = False,
    bytes: bool = False,
) -> str:
    """Build LC_ALL=C lsmem command string."""
    if json and summary:
        raise ValueError("json and summary are mutually exclusive")
    parts = ["LC_ALL=C", "lsmem"]
    if json:
        parts.append("-J")
    if summary:
        parts += ["-s", "only"]
    if bytes:
        parts.append("-b")
    return " ".join(parts)


def handle_lsmem(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_lsmem(
        json=_bool(args.get("json"), "json"),
        summary=_bool(args.get("summary"), "summary"),
        bytes=_bool(args.get("bytes"), "bytes"),
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


LSMEM_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "json": {"type": ["boolean", "null"]},
        "summary": {"type": ["boolean", "null"]},
        "bytes": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# dmidecode
# ---------------------------------------------------------------------------

_DMIDECODE_TYPES = {
    "bios",
    "system",
    "baseboard",
    "chassis",
    "processor",
    "memory",
    "cache",
    "connector",
    "slot",
}


def _validate_dmidecode_type(t) -> str:
    if not isinstance(t, str) or t not in _DMIDECODE_TYPES:
        raise ValueError(f"type must be one of {sorted(_DMIDECODE_TYPES)}")
    return t


def build_remote_cmd_dmidecode(*, type: str) -> str:
    """Build LC_ALL=C dmidecode command string."""
    return f"LC_ALL=C dmidecode -t {shlex.quote(type)}"


def handle_dmidecode(args: dict) -> dict:
    host = validate_host(args["host"])
    if "type" not in args or args["type"] is None:
        raise ValueError("type is required")
    t = _validate_dmidecode_type(args["type"])
    cmd = build_remote_cmd_dmidecode(type=t)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


DMIDECODE_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "type": {"type": "string"},
    },
    "required": ["host", "type"],
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="uptime",
        description=(
            "Run uptime on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=UPTIME_SCHEMA,
        handler=handle_uptime,
    ),
    ToolSpec(
        name="who",
        description=(
            "Run who on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=WHO_SCHEMA,
        handler=handle_who,
    ),
    ToolSpec(
        name="last",
        description=(
            "Run last on a remote host via SSH with optional user/tty filter. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=LAST_SCHEMA,
        handler=handle_last,
    ),
    ToolSpec(
        name="lscpu",
        description=(
            "Run lscpu on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=LSCPU_SCHEMA,
        handler=handle_lscpu,
    ),
    ToolSpec(
        name="lsmem",
        description=(
            "Run lsmem on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=LSMEM_SCHEMA,
        handler=handle_lsmem,
    ),
    ToolSpec(
        name="dmidecode",
        description=(
            "Run dmidecode on a remote host via SSH for a whitelisted type. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=DMIDECODE_SCHEMA,
        handler=handle_dmidecode,
    ),
]
