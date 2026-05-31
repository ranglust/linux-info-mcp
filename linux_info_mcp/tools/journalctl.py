"""journalctl tool."""

from __future__ import annotations

import shlex

from ..ssh import run_ssh
from ..validate import (
    _reject_unsafe_chars,
    validate_host,
    validate_lines_int,
    validate_unit_name,
)
from . import ToolSpec

_PRIORITY_TOKENS = {
    "emerg",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
}
_OUTPUT_WHITELIST = {
    "short",
    "short-iso",
    "short-precise",
    "cat",
    "json",
    "json-pretty",
    "verbose",
}


def _decode_text(b: bytes) -> str:
    """Decode bytes as UTF-8 with replacement."""
    return b.decode("utf-8", errors="replace")


def validate_priority(p: str) -> str:
    """Accept priority token, digit 0-7, or token..token range."""
    if not isinstance(p, str) or not p:
        raise ValueError("priority must be a non-empty string")
    if ".." in p:
        lo, _, hi = p.partition("..")
        if lo not in _PRIORITY_TOKENS or hi not in _PRIORITY_TOKENS:
            raise ValueError(f"priority range {p!r} has invalid endpoint")
        return p
    if p not in _PRIORITY_TOKENS:
        raise ValueError(f"priority {p!r} not in whitelist")
    return p


def validate_time_string(s: str, label: str) -> str:
    """Reject NUL/newline; cap length 128."""
    if not isinstance(s, str) or not s:
        raise ValueError(f"{label} must be a non-empty string")
    _reject_unsafe_chars(s, label)
    if len(s) > 128:
        raise ValueError(f"{label} must be at most 128 characters")
    return s


def validate_grep_pattern_journal(s: str) -> str:
    """Reject NUL/newline; cap length 256."""
    if not isinstance(s, str) or not s:
        raise ValueError("grep_pattern must be a non-empty string")
    _reject_unsafe_chars(s, "grep_pattern")
    if len(s) > 256:
        raise ValueError("grep_pattern must be at most 256 characters")
    return s


def validate_boot(n) -> int:
    """Accept int in [-10, 0]."""
    if not isinstance(n, int) or isinstance(n, bool):
        raise ValueError("boot must be an int")
    if n < -10 or n > 0:
        raise ValueError("boot must be in range [-10, 0]")
    return n


def validate_output_format(fmt: str) -> str:
    """Whitelist output format."""
    if not isinstance(fmt, str) or fmt not in _OUTPUT_WHITELIST:
        raise ValueError(f"output must be one of {sorted(_OUTPUT_WHITELIST)}")
    return fmt


def build_remote_cmd_journalctl(
    *,
    lines: int = 100,
    unit: str | None = None,
    identifier: str | None = None,
    priority: str | None = None,
    boot: int | None = None,
    since: str | None = None,
    until: str | None = None,
    grep_pattern: str | None = None,
    reverse: bool = False,
    output: str = "short-iso",
) -> str:
    """Compose LC_ALL=C-prefixed shlex-quoted journalctl command string."""
    parts = ["LC_ALL=C", "journalctl", "--no-pager", "-n", shlex.quote(str(lines))]
    if unit is not None:
        parts += ["-u", shlex.quote(unit)]
    if identifier is not None:
        parts += ["-t", shlex.quote(identifier)]
    if priority is not None:
        parts += ["-p", shlex.quote(priority)]
    if boot is not None:
        parts += ["-b", shlex.quote(str(boot))]
    if since is not None:
        parts.append(f"--since={shlex.quote(since)}")
    if until is not None:
        parts.append(f"--until={shlex.quote(until)}")
    if grep_pattern is not None:
        parts.append(f"--grep={shlex.quote(grep_pattern)}")
    if reverse:
        parts.append("-r")
    parts += ["-o", shlex.quote(output)]
    return " ".join(parts)


def handle_journalctl(args: dict) -> dict:
    """Validate args, run journalctl over SSH, return response dict."""
    host = validate_host(args["host"])
    lines_in = args.get("lines")
    lines = (
        100 if lines_in is None else validate_lines_int(lines_in, lo=1, hi=100000, label="lines")
    )
    unit_in = args.get("unit")
    unit = validate_unit_name(unit_in) if unit_in is not None else None
    ident_in = args.get("identifier")
    identifier = validate_unit_name(ident_in, label="identifier") if ident_in is not None else None
    prio_in = args.get("priority")
    priority = validate_priority(prio_in) if prio_in is not None else None
    boot_in = args.get("boot")
    boot = validate_boot(boot_in) if boot_in is not None else None
    since_in = args.get("since")
    since = validate_time_string(since_in, "since") if since_in is not None else None
    until_in = args.get("until")
    until = validate_time_string(until_in, "until") if until_in is not None else None
    grep_in = args.get("grep_pattern")
    grep_pattern = validate_grep_pattern_journal(grep_in) if grep_in is not None else None
    reverse_in = args.get("reverse")
    if reverse_in is not None and not isinstance(reverse_in, bool):
        raise ValueError("reverse must be a boolean")
    reverse = bool(reverse_in)
    output_in = args.get("output")
    output = validate_output_format(output_in) if output_in is not None else "short-iso"

    cmd = build_remote_cmd_journalctl(
        lines=lines,
        unit=unit,
        identifier=identifier,
        priority=priority,
        boot=boot,
        since=since,
        until=until,
        grep_pattern=grep_pattern,
        reverse=reverse,
        output=output,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


JOURNALCTL_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "unit": {"type": ["string", "null"]},
        "lines": {"type": ["integer", "null"]},
        "since": {"type": ["string", "null"]},
        "until": {"type": ["string", "null"]},
        "priority": {"type": ["string", "null"]},
        "grep_pattern": {"type": ["string", "null"]},
        "identifier": {"type": ["string", "null"]},
        "boot": {"type": ["integer", "null"]},
        "reverse": {"type": ["boolean", "null"]},
        "output": {"type": ["string", "null"]},
    },
    "required": ["host"],
}


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="journalctl",
        description=(
            "Query systemd journal on a remote host via SSH with whitelisted flags. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=JOURNALCTL_SCHEMA,
        handler=handle_journalctl,
    ),
]
