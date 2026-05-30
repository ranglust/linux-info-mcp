"""Time tools: chronyc, timedatectl."""
from __future__ import annotations

import shlex

from ..ssh import run_ssh
from ..validate import _reject_unsafe_chars, validate_host
from . import ToolSpec


def _decode_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


_CHRONYC_SUBCOMMANDS = {
    "tracking",
    "sources",
    "sourcestats",
    "activity",
    "ntpdata",
    "clients",
    "serverstats",
    "selectdata",
    "smoothing",
}

_TIMEDATECTL_MODES = {
    "status",
    "show",
    "list-timezones",
    "show-timesync",
    "timesync-status",
}


def _validate_chronyc_subcommand(sub) -> str:
    if not isinstance(sub, str) or not sub:
        raise ValueError("subcommand must be a non-empty string")
    _reject_unsafe_chars(sub, "subcommand")
    if sub not in _CHRONYC_SUBCOMMANDS:
        raise ValueError(
            f"subcommand must be one of {sorted(_CHRONYC_SUBCOMMANDS)}"
        )
    return sub


def _validate_timedatectl_mode(mode) -> str:
    if not isinstance(mode, str) or not mode:
        raise ValueError("mode must be a non-empty string")
    _reject_unsafe_chars(mode, "mode")
    if mode not in _TIMEDATECTL_MODES:
        raise ValueError(
            f"mode must be one of {sorted(_TIMEDATECTL_MODES)}"
        )
    return mode


def build_remote_cmd_chronyc(*, subcommand: str) -> str:
    """Build LC_ALL=C chronyc command string."""
    return f"LC_ALL=C chronyc -n {shlex.quote(subcommand)}"


def handle_chronyc(args: dict) -> dict:
    host = validate_host(args["host"])
    subcommand = _validate_chronyc_subcommand(args.get("subcommand"))
    cmd = build_remote_cmd_chronyc(subcommand=subcommand)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


CHRONYC_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "subcommand": {"type": "string"},
    },
    "required": ["host", "subcommand"],
}


def build_remote_cmd_timedatectl(*, mode: str) -> str:
    """Build LC_ALL=C timedatectl command string."""
    return f"LC_ALL=C timedatectl --no-pager {shlex.quote(mode)}"


def handle_timedatectl(args: dict) -> dict:
    host = validate_host(args["host"])
    mode = _validate_timedatectl_mode(args.get("mode"))
    cmd = build_remote_cmd_timedatectl(mode=mode)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


TIMEDATECTL_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "mode": {"type": "string"},
    },
    "required": ["host", "mode"],
}


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="chronyc",
        description=(
            "Run chronyc on a remote host via SSH with a whitelisted read-only "
            "subcommand. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=CHRONYC_SCHEMA,
        handler=handle_chronyc,
    ),
    ToolSpec(
        name="timedatectl",
        description=(
            "Run timedatectl on a remote host via SSH with a whitelisted "
            "read-only mode. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=TIMEDATECTL_SCHEMA,
        handler=handle_timedatectl,
    ),
]
