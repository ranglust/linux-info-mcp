"""Package query tools: dpkg_list, rpm_list, apt_list_installed."""
from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import _reject_unsafe_chars, validate_host
from . import ToolSpec


_PKG_PATTERN_RE = re.compile(r"^[A-Za-z0-9._*?+-]{1,128}$")


def _decode_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _bool(value, label: str) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a bool")
    return value


def _validate_pkg_pattern(pattern) -> str:
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty string")
    _reject_unsafe_chars(pattern, "pattern")
    if pattern.startswith("-"):
        raise ValueError("pattern must not start with '-'")
    if not _PKG_PATTERN_RE.fullmatch(pattern):
        raise ValueError(
            "pattern must match ^[A-Za-z0-9._*?+-]{1,128}$"
        )
    return pattern


# ---------------------------------------------------------------------------
# dpkg_list
# ---------------------------------------------------------------------------


def build_remote_cmd_dpkg_list(*, pattern: str | None = None) -> str:
    """Build LC_ALL=C dpkg -l command string."""
    parts = ["LC_ALL=C", "dpkg", "-l"]
    if pattern is not None:
        parts += ["--", shlex.quote(pattern)]
    return " ".join(parts)


def handle_dpkg_list(args: dict) -> dict:
    host = validate_host(args["host"])
    pattern = args.get("pattern")
    if pattern is not None:
        pattern = _validate_pkg_pattern(pattern)
    cmd = build_remote_cmd_dpkg_list(pattern=pattern)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


DPKG_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pattern": {"type": ["string", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# rpm_list
# ---------------------------------------------------------------------------


def build_remote_cmd_rpm_list(
    *,
    pattern: str | None = None,
    last: bool = False,
) -> str:
    """Build LC_ALL=C rpm -qa command string."""
    parts = ["LC_ALL=C", "rpm", "-qa"]
    if last:
        parts.append("--last")
    if pattern is not None:
        parts += ["--", shlex.quote(pattern)]
    return " ".join(parts)


def handle_rpm_list(args: dict) -> dict:
    host = validate_host(args["host"])
    pattern = args.get("pattern")
    if pattern is not None:
        pattern = _validate_pkg_pattern(pattern)
    cmd = build_remote_cmd_rpm_list(
        pattern=pattern,
        last=_bool(args.get("last"), "last"),
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


RPM_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pattern": {"type": ["string", "null"]},
        "last": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# apt_list_installed
# ---------------------------------------------------------------------------


def build_remote_cmd_apt_list_installed(*, pattern: str | None = None) -> str:
    """Build LC_ALL=C apt list --installed command string."""
    parts = ["LC_ALL=C", "apt", "list", "--installed"]
    if pattern is not None:
        parts += ["--", shlex.quote(pattern)]
    return " ".join(parts)


def handle_apt_list_installed(args: dict) -> dict:
    host = validate_host(args["host"])
    pattern = args.get("pattern")
    if pattern is not None:
        pattern = _validate_pkg_pattern(pattern)
    cmd = build_remote_cmd_apt_list_installed(pattern=pattern)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


APT_LIST_INSTALLED_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pattern": {"type": ["string", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="dpkg_list",
        description=(
            "Run dpkg -l on a remote host via SSH. "
            "Optional pattern argument lists matching packages. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=DPKG_LIST_SCHEMA,
        handler=handle_dpkg_list,
    ),
    ToolSpec(
        name="rpm_list",
        description=(
            "Run rpm -qa on a remote host via SSH. "
            "Optional pattern filters; last sorts by install time. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=RPM_LIST_SCHEMA,
        handler=handle_rpm_list,
    ),
    ToolSpec(
        name="apt_list_installed",
        description=(
            "Run apt list --installed on a remote host via SSH. "
            "Optional pattern argument filters package names. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=APT_LIST_INSTALLED_SCHEMA,
        handler=handle_apt_list_installed,
    ),
]
