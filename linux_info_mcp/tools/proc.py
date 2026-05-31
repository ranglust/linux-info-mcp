"""Process tools: lsof, pgrep, pidof, top."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import (
    _reject_unsafe_chars,
    validate_host,
    validate_path,
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


_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]*\$?$")
_PROGRAM_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _validate_user(user, label: str = "user") -> str:
    if not isinstance(user, str) or not user:
        raise ValueError(f"{label} must be a non-empty string")
    if len(user) > 32:
        raise ValueError(f"{label} must be at most 32 characters")
    if not _USER_RE.fullmatch(user):
        raise ValueError(f"{label} does not match required pattern: {user!r}")
    return user


def _validate_pid(pid, label: str = "pid") -> int:
    if not isinstance(pid, int) or isinstance(pid, bool):
        raise ValueError(f"{label} must be an int")
    if pid < 1 or pid > 4194304:
        raise ValueError(f"{label} must be in range [1, 4194304]")
    return pid


# ---------------------------------------------------------------------------
# lsof
# ---------------------------------------------------------------------------


def build_remote_cmd_lsof(
    *,
    pid: int | None = None,
    user: str | None = None,
    path: str | None = None,
    network_only: bool = False,
) -> str:
    """Build LC_ALL=C lsof command string."""
    if pid is not None and user is not None:
        raise ValueError("pid and user are mutually exclusive")
    parts = ["LC_ALL=C", "lsof", "-n", "-P"]
    if network_only:
        parts.append("-i")
    if pid is not None:
        parts += ["-p", str(pid)]
    elif user is not None:
        parts += ["-u", shlex.quote(user)]
    if path is not None:
        parts.append("--")
        parts.append(shlex.quote(path))
    return " ".join(parts)


def handle_lsof(args: dict) -> dict:
    host = validate_host(args["host"])
    pid = args.get("pid")
    user = args.get("user")
    path = args.get("path")
    if pid is not None and user is not None:
        raise ValueError("pid and user are mutually exclusive")
    if pid is not None:
        pid = _validate_pid(pid)
    if user is not None:
        user = _validate_user(user)
    if path is not None:
        path = validate_path(path, label="path")
    cmd = build_remote_cmd_lsof(
        pid=pid,
        user=user,
        path=path,
        network_only=_bool(args.get("network_only"), "network_only"),
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


LSOF_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pid": {"type": ["integer", "null"]},
        "user": {"type": ["string", "null"]},
        "path": {"type": ["string", "null"]},
        "network_only": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# pgrep
# ---------------------------------------------------------------------------


def _validate_pgrep_pattern(pattern) -> str:
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty string")
    if len(pattern) > 256:
        raise ValueError("pattern must be at most 256 characters")
    _reject_unsafe_chars(pattern, "pattern")
    return pattern


def build_remote_cmd_pgrep(
    *,
    pattern: str,
    full: bool = False,
    exact: bool = False,
    list_name: bool = True,
    user: str | None = None,
    newest: bool = False,
    oldest: bool = False,
    parent_pid: int | None = None,
) -> str:
    """Build LC_ALL=C pgrep command string."""
    if newest and oldest:
        raise ValueError("newest and oldest are mutually exclusive")
    parts = ["LC_ALL=C", "pgrep"]
    if full:
        parts.append("-f")
    if exact:
        parts.append("-x")
    if list_name:
        parts.append("-l")
    if newest:
        parts.append("-n")
    if oldest:
        parts.append("-o")
    if user is not None:
        parts += ["-u", shlex.quote(user)]
    if parent_pid is not None:
        parts += ["-P", str(parent_pid)]
    parts.append("--")
    parts.append(shlex.quote(pattern))
    return " ".join(parts)


def handle_pgrep(args: dict) -> dict:
    host = validate_host(args["host"])
    pattern = _validate_pgrep_pattern(args.get("pattern"))
    user = args.get("user")
    if user is not None:
        user = _validate_user(user)
    parent_pid = args.get("parent_pid")
    if parent_pid is not None:
        parent_pid = _validate_pid(parent_pid, label="parent_pid")
    list_name = args.get("list_name")
    if list_name is None:
        list_name = True
    elif not isinstance(list_name, bool):
        raise ValueError("list_name must be a bool")
    cmd = build_remote_cmd_pgrep(
        pattern=pattern,
        full=_bool(args.get("full"), "full"),
        exact=_bool(args.get("exact"), "exact"),
        list_name=list_name,
        user=user,
        newest=_bool(args.get("newest"), "newest"),
        oldest=_bool(args.get("oldest"), "oldest"),
        parent_pid=parent_pid,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


PGREP_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pattern": {"type": "string"},
        "full": {"type": ["boolean", "null"]},
        "exact": {"type": ["boolean", "null"]},
        "list_name": {"type": ["boolean", "null"]},
        "user": {"type": ["string", "null"]},
        "newest": {"type": ["boolean", "null"]},
        "oldest": {"type": ["boolean", "null"]},
        "parent_pid": {"type": ["integer", "null"]},
    },
    "required": ["host", "pattern"],
}


# ---------------------------------------------------------------------------
# pidof
# ---------------------------------------------------------------------------


def _validate_program(program) -> str:
    if not isinstance(program, str) or not program:
        raise ValueError("program must be a non-empty string")
    if program.startswith("-"):
        raise ValueError("program must not start with '-'")
    if not _PROGRAM_RE.fullmatch(program):
        raise ValueError(f"program does not match required pattern: {program!r}")
    return program


def build_remote_cmd_pidof(
    *,
    program: str,
    single_shot: bool = False,
) -> str:
    """Build LC_ALL=C pidof command string."""
    parts = ["LC_ALL=C", "pidof"]
    if single_shot:
        parts.append("-s")
    parts.append("--")
    parts.append(shlex.quote(program))
    return " ".join(parts)


def handle_pidof(args: dict) -> dict:
    host = validate_host(args["host"])
    program = _validate_program(args.get("program"))
    cmd = build_remote_cmd_pidof(
        program=program,
        single_shot=_bool(args.get("single_shot"), "single_shot"),
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


PIDOF_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "program": {"type": "string"},
        "single_shot": {"type": ["boolean", "null"]},
    },
    "required": ["host", "program"],
}


# ---------------------------------------------------------------------------
# top
# ---------------------------------------------------------------------------

_TOP_SORT_MAP = {
    "cpu": "%CPU",
    "mem": "%MEM",
    "pid": "PID",
    "time": "TIME+",
}


def _validate_top_sort(sort) -> str:
    if not isinstance(sort, str) or sort not in _TOP_SORT_MAP:
        raise ValueError(f"sort must be one of {sorted(_TOP_SORT_MAP)}")
    return _TOP_SORT_MAP[sort]


def build_remote_cmd_top(
    *,
    user: str | None = None,
    sort_field: str | None = None,
) -> str:
    """Build LC_ALL=C top command string."""
    parts = ["LC_ALL=C", "top", "-bn1", "-w", "512"]
    if sort_field is not None:
        parts += ["-o", shlex.quote(sort_field)]
    if user is not None:
        parts += ["-u", shlex.quote(user)]
    return " ".join(parts)


def handle_top(args: dict) -> dict:
    host = validate_host(args["host"])
    user = args.get("user")
    if user is not None:
        user = _validate_user(user)
    sort = args.get("sort")
    sort_field = _validate_top_sort(sort) if sort is not None else None
    cmd = build_remote_cmd_top(user=user, sort_field=sort_field)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


TOP_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "user": {"type": ["string", "null"]},
        "sort": {"type": ["string", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="lsof",
        description=(
            "Run lsof on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=LSOF_SCHEMA,
        handler=handle_lsof,
    ),
    ToolSpec(
        name="pgrep",
        description=(
            "Run pgrep on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=PGREP_SCHEMA,
        handler=handle_pgrep,
    ),
    ToolSpec(
        name="pidof",
        description=(
            "Run pidof on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=PIDOF_SCHEMA,
        handler=handle_pidof,
    ),
    ToolSpec(
        name="top",
        description=(
            "Run a single batch iteration of top on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=TOP_SCHEMA,
        handler=handle_top,
    ),
]
