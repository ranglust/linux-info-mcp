"""LLDP tools: lldp_neighbors, lldp_interfaces, lldp_statistics, lldp_chassis (via lldpcli)."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import reject_unsafe_chars, validate_host
from . import ToolSpec
from ._common import decode_text as _decode_text

_LLDP_FORMAT_WHITELIST = {"keyvalue", "json", "json0", "xml", "plain"}
_LLDP_IFACE_RE = re.compile(r"^[A-Za-z0-9._@:-]{1,32}$")


def _validate_lldp_format(fmt) -> str:
    if fmt is None:
        return "keyvalue"
    if not isinstance(fmt, str) or fmt not in _LLDP_FORMAT_WHITELIST:
        raise ValueError(f"format must be one of {sorted(_LLDP_FORMAT_WHITELIST)}")
    return fmt


def _validate_lldp_iface(iface) -> str:
    if not isinstance(iface, str) or not iface:
        raise ValueError("iface must be a non-empty string")
    reject_unsafe_chars(iface, "iface")
    if iface.startswith("-"):
        raise ValueError("iface must not start with '-'")
    if not _LLDP_IFACE_RE.fullmatch(iface):
        raise ValueError("iface must match ^[A-Za-z0-9._@:-]{1,32}$")
    return iface


def build_remote_cmd_lldp(*, what: str, fmt: str = "keyvalue", iface: str | None = None) -> str:
    """Build LC_ALL=C lldpcli show command string. `what` is a fixed literal, not user input."""
    parts = ["LC_ALL=C", "lldpcli", "-f", shlex.quote(fmt), "show", what]
    if iface is not None:
        parts += ["ports", shlex.quote(iface)]
    return " ".join(parts)


def _run_lldp(args: dict, *, what: str, allow_iface: bool) -> dict:
    host = validate_host(args["host"])
    fmt = _validate_lldp_format(args.get("format"))
    iface = None
    if allow_iface:
        iface_in = args.get("iface")
        if iface_in is not None:
            iface = _validate_lldp_iface(iface_in)
    cmd = build_remote_cmd_lldp(what=what, fmt=fmt, iface=iface)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


def handle_lldp_neighbors(args: dict) -> dict:
    return _run_lldp(args, what="neighbors", allow_iface=True)


def handle_lldp_interfaces(args: dict) -> dict:
    return _run_lldp(args, what="interfaces", allow_iface=True)


def handle_lldp_statistics(args: dict) -> dict:
    return _run_lldp(args, what="statistics", allow_iface=True)


def handle_lldp_chassis(args: dict) -> dict:
    return _run_lldp(args, what="chassis", allow_iface=False)


_FORMAT_PROP = {
    "type": ["string", "null"],
    "enum": ["keyvalue", "json", "json0", "xml", "plain", None],
}

LLDP_NEIGHBORS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "format": _FORMAT_PROP,
        "iface": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}

LLDP_INTERFACES_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "format": _FORMAT_PROP,
        "iface": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}

LLDP_STATISTICS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "format": _FORMAT_PROP,
        "iface": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}

LLDP_CHASSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "format": _FORMAT_PROP,
    },
    "required": ["host"],
    "additionalProperties": False,
}


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="lldp_neighbors",
        description=(
            "Run 'lldpcli show neighbors' (discovered LLDP peers: switch, port, VLAN) on a "
            "remote host via SSH. format: keyvalue (default)|json|json0|xml|plain; optional "
            "iface scopes to one port. Needs lldpd running; may need privileges (passthrough). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=LLDP_NEIGHBORS_SCHEMA,
        handler=handle_lldp_neighbors,
    ),
    ToolSpec(
        name="lldp_interfaces",
        description=(
            "Run 'lldpcli show interfaces' (local ports lldpd manages) on a remote host via "
            "SSH. format: keyvalue (default)|json|json0|xml|plain; optional iface scopes to one "
            "port. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=LLDP_INTERFACES_SCHEMA,
        handler=handle_lldp_interfaces,
    ),
    ToolSpec(
        name="lldp_statistics",
        description=(
            "Run 'lldpcli show statistics' (per-port LLDP tx/rx/drop counters) on a remote host "
            "via SSH. format: keyvalue (default)|json|json0|xml|plain; optional iface scopes to "
            "one port. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=LLDP_STATISTICS_SCHEMA,
        handler=handle_lldp_statistics,
    ),
    ToolSpec(
        name="lldp_chassis",
        description=(
            "Run 'lldpcli show chassis' (local chassis info advertised by this host) on a "
            "remote host via SSH. format: keyvalue (default)|json|json0|xml|plain. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=LLDP_CHASSIS_SCHEMA,
        handler=handle_lldp_chassis,
    ),
]
