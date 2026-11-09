"""Process tools: lsof, pgrep, pidof, top, proc_limits, strace."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh, sudo_tokens
from ..validate import (
    reject_unsafe_chars,
    validate_host,
    validate_int_in_range,
    validate_path,
)
from . import ToolSpec
from ._common import (
    decode_text as _decode_text,
)
from ._common import (
    validate_bool as _bool,
)
from ._common import (
    validate_pid,
    validate_user,
)

_PROGRAM_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


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
        pid = validate_pid(pid)
    if user is not None:
        user = validate_user(user)
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
        "stderr_truncated": res.stderr_truncated,
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
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# pgrep
# ---------------------------------------------------------------------------


def _validate_pgrep_pattern(pattern) -> str:
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty string")
    if len(pattern) > 256:
        raise ValueError("pattern must be at most 256 characters")
    reject_unsafe_chars(pattern, "pattern")
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
        user = validate_user(user)
    parent_pid = args.get("parent_pid")
    if parent_pid is not None:
        parent_pid = validate_pid(parent_pid, label="parent_pid")
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
        "stderr_truncated": res.stderr_truncated,
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
    "additionalProperties": False,
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
        "stderr_truncated": res.stderr_truncated,
    }


PIDOF_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "program": {"type": "string"},
        "single_shot": {"type": ["boolean", "null"]},
    },
    "required": ["host", "program"],
    "additionalProperties": False,
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
        user = validate_user(user)
    sort = args.get("sort")
    sort_field = _validate_top_sort(sort) if sort is not None else None
    cmd = build_remote_cmd_top(user=user, sort_field=sort_field)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


TOP_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "user": {"type": ["string", "null"]},
        "sort": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# proc_limits
# ---------------------------------------------------------------------------


def build_remote_cmd_proc_limits(*, pid: int) -> str:
    """Build LC_ALL=C /proc/<pid>/limits read. pid is an int -> safe interpolation."""
    return f"LC_ALL=C cat /proc/{pid}/limits"


def handle_proc_limits(args: dict) -> dict:
    host = validate_host(args["host"])
    pid_in = args.get("pid")
    if pid_in is None:
        raise ValueError("pid is required")
    pid = validate_pid(pid_in)
    cmd = build_remote_cmd_proc_limits(pid=pid)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


PROC_LIMITS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pid": {"type": "integer"},
    },
    "required": ["host", "pid"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# strace
# ---------------------------------------------------------------------------

_SYSCALL_RE = re.compile(r"[a-z_][a-z0-9_]{0,63}")
_STRACE_CLASSES = {
    "%file",
    "%process",
    "%network",
    "%signal",
    "%ipc",
    "%desc",
    "%memory",
    "%creds",
    "%clock",
}


def _validate_syscalls(syscalls) -> list[str]:
    if not isinstance(syscalls, list) or not syscalls:
        raise ValueError("syscalls must be a non-empty list")
    if len(syscalls) > 64:
        raise ValueError("syscalls must have at most 64 entries")
    for s in syscalls:
        if not isinstance(s, str) or not (s in _STRACE_CLASSES or _SYSCALL_RE.fullmatch(s)):
            raise ValueError(
                f"syscalls entry must be a syscall name or one of {sorted(_STRACE_CLASSES)}"
            )
    return syscalls


def build_remote_cmd_strace(
    *,
    pid: int,
    duration: int = 5,
    summary: bool = True,
    follow_forks: bool = False,
    syscalls: list[str] | None = None,
    timestamps: bool = False,
    syscall_times: bool = False,
    string_limit: int | None = None,
) -> str:
    """Build LC_ALL=C timeout-bounded strace attach. Attach-only (-p); never launches a command."""
    if summary and (timestamps or syscall_times or string_limit is not None):
        raise ValueError("timestamps/syscall_times/string_limit are not allowed with summary")
    # timeout wraps sudo (not the reverse) so sudoers only needs to grant strace.
    parts = ["LC_ALL=C", "timeout", "--preserve-status", "-s", "INT", str(duration)]
    parts += [*sudo_tokens(), "strace", "-q", "-o", "/dev/stdout"]
    if summary:
        parts.append("-c")
    if follow_forks:
        parts.append("-f")
    if timestamps:
        parts.append("-tt")
    if syscall_times:
        parts.append("-T")
    if string_limit is not None:
        parts += ["-s", str(string_limit)]
    if syscalls is not None:
        parts += ["-e", shlex.quote("trace=" + ",".join(syscalls))]
    parts += ["-p", str(pid)]
    return " ".join(parts)


def handle_strace(args: dict) -> dict:
    host = validate_host(args["host"])
    pid_in = args.get("pid")
    if pid_in is None:
        raise ValueError("pid is required")
    pid = validate_pid(pid_in)
    duration = args.get("duration")
    duration = (
        5 if duration is None else validate_int_in_range(duration, lo=1, hi=20, label="duration")
    )
    summary = args.get("summary")
    if summary is None:
        summary = True
    elif not isinstance(summary, bool):
        raise ValueError("summary must be a bool")
    syscalls = args.get("syscalls")
    if syscalls is not None:
        syscalls = _validate_syscalls(syscalls)
    string_limit = args.get("string_limit")
    if string_limit is not None:
        string_limit = validate_int_in_range(string_limit, lo=0, hi=256, label="string_limit")
    cmd = build_remote_cmd_strace(
        pid=pid,
        duration=duration,
        summary=summary,
        follow_forks=_bool(args.get("follow_forks"), "follow_forks"),
        syscalls=syscalls,
        timestamps=_bool(args.get("timestamps"), "timestamps"),
        syscall_times=_bool(args.get("syscall_times"), "syscall_times"),
        string_limit=string_limit,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


STRACE_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pid": {"type": "integer"},
        "duration": {"type": ["integer", "null"]},
        "summary": {"type": ["boolean", "null"]},
        "follow_forks": {"type": ["boolean", "null"]},
        "syscalls": {"type": ["array", "null"], "items": {"type": "string"}},
        "timestamps": {"type": ["boolean", "null"]},
        "syscall_times": {"type": ["boolean", "null"]},
        "string_limit": {"type": ["integer", "null"]},
    },
    "required": ["host", "pid"],
    "additionalProperties": False,
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
    ToolSpec(
        name="proc_limits",
        description=(
            "Read /proc/<pid>/limits on a remote host via SSH (rlimits for a process). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=PROC_LIMITS_SCHEMA,
        handler=handle_proc_limits,
    ),
    ToolSpec(
        name="strace",
        description=(
            "Attach strace to an existing pid on a remote host via SSH for a bounded duration "
            "(1-20s, default 5). Default summary=true (-c syscall counts/times); summary=false "
            "gives a raw trace (optional timestamps, syscall_times, string_limit). syscalls "
            "filters by name or class (%file, %network, ...). follow_forks traces all threads. "
            "ptrace slows the target while attached. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=STRACE_SCHEMA,
        handler=handle_strace,
    ),
]
