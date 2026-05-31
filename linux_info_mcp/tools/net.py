"""Net tools: ss, ip_addr, ip_route, lsof_net."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import _reject_unsafe_chars, validate_host
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
# ss
# ---------------------------------------------------------------------------

_SS_STATE_WHITELIST = {
    "established",
    "syn-sent",
    "syn-recv",
    "fin-wait-1",
    "fin-wait-2",
    "time-wait",
    "close",
    "close-wait",
    "last-ack",
    "listening",
    "closing",
    "all",
    "connected",
    "synchronized",
    "bucket",
    "big",
}

_SS_FAMILY_WHITELIST = {"inet", "inet6", "unix"}


def _validate_ss_state(state) -> str:
    if not isinstance(state, str) or state not in _SS_STATE_WHITELIST:
        raise ValueError(f"state must be one of {sorted(_SS_STATE_WHITELIST)}")
    return state


def _validate_ss_family(family) -> str:
    if not isinstance(family, str) or family not in _SS_FAMILY_WHITELIST:
        raise ValueError(f"family must be one of {sorted(_SS_FAMILY_WHITELIST)}")
    return family


def build_remote_cmd_ss(
    *,
    tcp: bool = False,
    udp: bool = False,
    listening: bool = False,
    all: bool = False,
    numeric: bool = False,
    processes: bool = False,
    extended: bool = False,
    summary: bool = False,
    memory: bool = False,
    state: str | None = None,
    family: str | None = None,
) -> str:
    """Build LC_ALL=C ss command string."""
    parts = ["LC_ALL=C", "ss"]
    if tcp:
        parts.append("-t")
    if udp:
        parts.append("-u")
    if listening:
        parts.append("-l")
    if all:
        parts.append("-a")
    if numeric:
        parts.append("-n")
    if processes:
        parts.append("-p")
    if extended:
        parts.append("-e")
    if summary:
        parts.append("-s")
    if memory:
        parts.append("-m")
    if family is not None:
        parts += ["-f", shlex.quote(family)]
    if state is not None:
        parts += ["state", shlex.quote(state)]
    return " ".join(parts)


def handle_ss(args: dict) -> dict:
    host = validate_host(args["host"])
    state = args.get("state")
    if state is not None:
        state = _validate_ss_state(state)
    family = args.get("family")
    if family is not None:
        family = _validate_ss_family(family)
    cmd = build_remote_cmd_ss(
        tcp=_bool(args.get("tcp"), "tcp"),
        udp=_bool(args.get("udp"), "udp"),
        listening=_bool(args.get("listening"), "listening"),
        all=_bool(args.get("all"), "all"),
        numeric=_bool(args.get("numeric"), "numeric"),
        processes=_bool(args.get("processes"), "processes"),
        extended=_bool(args.get("extended"), "extended"),
        summary=_bool(args.get("summary"), "summary"),
        memory=_bool(args.get("memory"), "memory"),
        state=state,
        family=family,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


SS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "tcp": {"type": ["boolean", "null"]},
        "udp": {"type": ["boolean", "null"]},
        "listening": {"type": ["boolean", "null"]},
        "all": {"type": ["boolean", "null"]},
        "numeric": {"type": ["boolean", "null"]},
        "processes": {"type": ["boolean", "null"]},
        "extended": {"type": ["boolean", "null"]},
        "summary": {"type": ["boolean", "null"]},
        "memory": {"type": ["boolean", "null"]},
        "state": {"type": ["string", "null"]},
        "family": {"type": ["string", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# ip_addr
# ---------------------------------------------------------------------------

_IFACE_RE = re.compile(r"^[A-Za-z0-9._@:-]{1,32}$")


def _validate_iface(iface) -> str:
    if not isinstance(iface, str) or not iface:
        raise ValueError("iface must be a non-empty string")
    _reject_unsafe_chars(iface, "iface")
    if iface.startswith("-"):
        raise ValueError("iface must not start with '-'")
    if not _IFACE_RE.fullmatch(iface):
        raise ValueError("iface must match ^[A-Za-z0-9._@:-]{1,32}$")
    return iface


def build_remote_cmd_ip_addr(*, iface: str | None = None) -> str:
    """Build LC_ALL=C ip -o addr show command string."""
    parts = ["LC_ALL=C", "ip", "-o", "addr", "show"]
    if iface is not None:
        parts += ["dev", shlex.quote(iface)]
    return " ".join(parts)


def handle_ip_addr(args: dict) -> dict:
    host = validate_host(args["host"])
    iface = args.get("iface")
    if iface is not None:
        iface = _validate_iface(iface)
    cmd = build_remote_cmd_ip_addr(iface=iface)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


IP_ADDR_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "iface": {"type": ["string", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# ip_route
# ---------------------------------------------------------------------------

_IP_ROUTE_TABLE_WHITELIST = {"main", "default", "local", "all"}
_IP_ROUTE_FAMILY_MAP = {"inet": "-4", "inet6": "-6"}


def _validate_ip_route_table(table) -> str:
    if not isinstance(table, str) or table not in _IP_ROUTE_TABLE_WHITELIST:
        raise ValueError(f"table must be one of {sorted(_IP_ROUTE_TABLE_WHITELIST)}")
    return table


def _validate_ip_route_family(family) -> str:
    if not isinstance(family, str) or family not in _IP_ROUTE_FAMILY_MAP:
        raise ValueError(f"family must be one of {sorted(_IP_ROUTE_FAMILY_MAP)}")
    return _IP_ROUTE_FAMILY_MAP[family]


def build_remote_cmd_ip_route(
    *,
    table: str | None = None,
    family_flag: str | None = None,
) -> str:
    """Build LC_ALL=C ip route show command string."""
    parts = ["LC_ALL=C", "ip"]
    if family_flag is not None:
        parts.append(family_flag)
    parts += ["route", "show"]
    if table is not None:
        parts += ["table", shlex.quote(table)]
    return " ".join(parts)


def handle_ip_route(args: dict) -> dict:
    host = validate_host(args["host"])
    table = args.get("table")
    if table is not None:
        table = _validate_ip_route_table(table)
    family = args.get("family")
    family_flag = _validate_ip_route_family(family) if family is not None else None
    cmd = build_remote_cmd_ip_route(table=table, family_flag=family_flag)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


IP_ROUTE_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "table": {"type": ["string", "null"]},
        "family": {"type": ["string", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# lsof_net
# ---------------------------------------------------------------------------

_LSOF_PROTO_WHITELIST = {"tcp", "udp", "tcp4", "tcp6", "udp4", "udp6"}


def _validate_lsof_protocol(proto) -> str:
    if not isinstance(proto, str) or proto not in _LSOF_PROTO_WHITELIST:
        raise ValueError(f"protocol must be one of {sorted(_LSOF_PROTO_WHITELIST)}")
    return proto


def _validate_lsof_port(port) -> int:
    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError("port must be an int")
    if port < 1 or port > 65535:
        raise ValueError("port must be in range [1, 65535]")
    return port


def build_remote_cmd_lsof_net(
    *,
    protocol: str | None = None,
    port: int | None = None,
) -> str:
    """Build LC_ALL=C lsof -i -n -P command string."""
    parts = ["LC_ALL=C", "lsof", "-n", "-P"]
    if protocol is None and port is None:
        parts.append("-i")
    else:
        spec = ""
        if protocol is not None:
            spec += protocol
        if port is not None:
            spec += f":{port}"
        parts += ["-i", shlex.quote(spec)]
    return " ".join(parts)


def handle_lsof_net(args: dict) -> dict:
    host = validate_host(args["host"])
    protocol = args.get("protocol")
    if protocol is not None:
        protocol = _validate_lsof_protocol(protocol)
    port = args.get("port")
    if port is not None:
        port = _validate_lsof_port(port)
    cmd = build_remote_cmd_lsof_net(protocol=protocol, port=port)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


LSOF_NET_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "protocol": {"type": ["string", "null"]},
        "port": {"type": ["integer", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="ss",
        description=(
            "Run ss (socket statistics) on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SS_SCHEMA,
        handler=handle_ss,
    ),
    ToolSpec(
        name="ip_addr",
        description=(
            "Run 'ip -o addr show' on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=IP_ADDR_SCHEMA,
        handler=handle_ip_addr,
    ),
    ToolSpec(
        name="ip_route",
        description=(
            "Run 'ip route show' on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=IP_ROUTE_SCHEMA,
        handler=handle_ip_route,
    ),
    ToolSpec(
        name="lsof_net",
        description=(
            "Run 'lsof -i -n -P' on a remote host via SSH for network connections. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=LSOF_NET_SCHEMA,
        handler=handle_lsof_net,
    ),
]
