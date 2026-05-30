"""Net tools: ss, ip_addr, ip_route, lsof_net."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import reject_unsafe_chars, validate_host
from . import ToolSpec
from ._common import decode_text as _decode_text
from ._common import validate_bool as _bool

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
        "stderr_truncated": res.stderr_truncated,
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
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# ip_addr
# ---------------------------------------------------------------------------

_IFACE_RE = re.compile(r"^[A-Za-z0-9._@:-]{1,32}$")


def _validate_iface(iface) -> str:
    if not isinstance(iface, str) or not iface:
        raise ValueError("iface must be a non-empty string")
    reject_unsafe_chars(iface, "iface")
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
        "stderr_truncated": res.stderr_truncated,
    }


IP_ADDR_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "iface": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
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
        "stderr_truncated": res.stderr_truncated,
    }


IP_ROUTE_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "table": {"type": ["string", "null"]},
        "family": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
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
        "stderr_truncated": res.stderr_truncated,
    }


LSOF_NET_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "protocol": {"type": ["string", "null"]},
        "port": {"type": ["integer", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# arp_table
# ---------------------------------------------------------------------------

_ARP_FAMILY_MAP = {"inet": "-4", "inet6": "-6"}


def _validate_arp_family(family) -> str:
    if not isinstance(family, str) or family not in _ARP_FAMILY_MAP:
        raise ValueError(f"family must be one of {sorted(_ARP_FAMILY_MAP)}")
    return _ARP_FAMILY_MAP[family]


def build_remote_cmd_arp_table(
    *,
    iface: str | None = None,
    family_flag: str | None = None,
) -> str:
    """Build LC_ALL=C ip neigh show command string."""
    parts = ["LC_ALL=C", "ip", "-o"]
    if family_flag is not None:
        parts.append(family_flag)
    parts += ["neigh", "show"]
    if iface is not None:
        parts += ["dev", shlex.quote(iface)]
    return " ".join(parts)


def handle_arp_table(args: dict) -> dict:
    host = validate_host(args["host"])
    iface = args.get("iface")
    if iface is not None:
        iface = _validate_iface(iface)
    family = args.get("family")
    family_flag = _validate_arp_family(family) if family is not None else None
    cmd = build_remote_cmd_arp_table(iface=iface, family_flag=family_flag)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


ARP_TABLE_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "iface": {"type": ["string", "null"]},
        "family": {"type": ["string", "null"], "enum": ["inet", "inet6", None]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# tc_qdisc
# ---------------------------------------------------------------------------


def build_remote_cmd_tc_qdisc(*, iface: str | None = None) -> str:
    """Build LC_ALL=C tc -s qdisc show command string."""
    parts = ["LC_ALL=C", "tc", "-s", "qdisc", "show"]
    if iface is not None:
        parts += ["dev", shlex.quote(iface)]
    return " ".join(parts)


def handle_tc_qdisc(args: dict) -> dict:
    host = validate_host(args["host"])
    iface = args.get("iface")
    if iface is not None:
        iface = _validate_iface(iface)
    cmd = build_remote_cmd_tc_qdisc(iface=iface)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


TC_QDISC_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "iface": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# ethtool
# ---------------------------------------------------------------------------

_ETHTOOL_MODE_MAP = {
    "stats": "-S",
    "driver": "-i",
    "ring": "-g",
    "features": "-k",
    "pause": "-a",
    "coalesce": "-c",
}


def _validate_ethtool_mode(mode) -> str:
    if mode is None:
        return _ETHTOOL_MODE_MAP["driver"]
    if not isinstance(mode, str) or mode not in _ETHTOOL_MODE_MAP:
        raise ValueError(f"mode must be one of {sorted(_ETHTOOL_MODE_MAP)}")
    return _ETHTOOL_MODE_MAP[mode]


def build_remote_cmd_ethtool(*, iface: str, mode_flag: str) -> str:
    """Build LC_ALL=C ethtool command string."""
    return f"LC_ALL=C ethtool {mode_flag} {shlex.quote(iface)}"


def handle_ethtool(args: dict) -> dict:
    host = validate_host(args["host"])
    iface_in = args.get("iface")
    if iface_in is None:
        raise ValueError("iface is required")
    iface = _validate_iface(iface_in)
    mode_flag = _validate_ethtool_mode(args.get("mode"))
    cmd = build_remote_cmd_ethtool(iface=iface, mode_flag=mode_flag)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


ETHTOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "iface": {"type": "string"},
        "mode": {
            "type": ["string", "null"],
            "enum": ["stats", "driver", "ring", "features", "pause", "coalesce", None],
        },
    },
    "required": ["host", "iface"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# conntrack
# ---------------------------------------------------------------------------

_CONNTRACK_MODES = {"list", "stats"}
_CONNTRACK_PROTO_WHITELIST = {"tcp", "udp", "icmp", "icmpv6", "dccp", "sctp", "gre"}


def _validate_conntrack_mode(mode) -> str:
    if mode is None:
        return "stats"
    if not isinstance(mode, str) or mode not in _CONNTRACK_MODES:
        raise ValueError(f"mode must be one of {sorted(_CONNTRACK_MODES)}")
    return mode


def _validate_conntrack_protocol(proto) -> str:
    if not isinstance(proto, str) or proto not in _CONNTRACK_PROTO_WHITELIST:
        raise ValueError(f"protocol must be one of {sorted(_CONNTRACK_PROTO_WHITELIST)}")
    return proto


def build_remote_cmd_conntrack(*, mode: str = "stats", protocol: str | None = None) -> str:
    """Build LC_ALL=C conntrack command string."""
    if mode == "stats":
        if protocol is not None:
            raise ValueError("protocol is only valid with mode=list")
        return "LC_ALL=C conntrack -S"
    parts = ["LC_ALL=C", "conntrack", "-L"]
    if protocol is not None:
        parts += ["-p", shlex.quote(protocol)]
    return " ".join(parts)


def handle_conntrack(args: dict) -> dict:
    host = validate_host(args["host"])
    mode = _validate_conntrack_mode(args.get("mode"))
    protocol = args.get("protocol")
    if protocol is not None:
        protocol = _validate_conntrack_protocol(protocol)
    cmd = build_remote_cmd_conntrack(mode=mode, protocol=protocol)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


CONNTRACK_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "mode": {"type": ["string", "null"], "enum": ["list", "stats", None]},
        "protocol": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# net_protocol_stats
# ---------------------------------------------------------------------------

_NET_PROTO_STATS_MAP = {"all": None, "tcp": "--tcp", "udp": "--udp", "ip": "--raw"}


def _validate_net_protocol_stats(proto):
    if proto is None:
        return None
    if not isinstance(proto, str) or proto not in _NET_PROTO_STATS_MAP:
        raise ValueError(f"protocol must be one of {sorted(_NET_PROTO_STATS_MAP)}")
    return _NET_PROTO_STATS_MAP[proto]


def build_remote_cmd_net_protocol_stats(*, proto_flag: str | None = None) -> str:
    """Build LC_ALL=C netstat -s command string."""
    parts = ["LC_ALL=C", "netstat", "-s"]
    if proto_flag is not None:
        parts.append(proto_flag)
    return " ".join(parts)


def handle_net_protocol_stats(args: dict) -> dict:
    host = validate_host(args["host"])
    proto_flag = _validate_net_protocol_stats(args.get("protocol"))
    cmd = build_remote_cmd_net_protocol_stats(proto_flag=proto_flag)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


NET_PROTOCOL_STATS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "protocol": {"type": ["string", "null"], "enum": ["all", "tcp", "udp", "ip", None]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# nft_list
# ---------------------------------------------------------------------------

_NFT_FAMILY_WHITELIST = {"ip", "ip6", "inet", "arp", "bridge", "netdev"}
_NFT_TABLE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _validate_nft_family(family) -> str:
    if not isinstance(family, str) or family not in _NFT_FAMILY_WHITELIST:
        raise ValueError(f"family must be one of {sorted(_NFT_FAMILY_WHITELIST)}")
    return family


def _validate_nft_table(table) -> str:
    if not isinstance(table, str) or not table:
        raise ValueError("table must be a non-empty string")
    reject_unsafe_chars(table, "table")
    if table.startswith("-"):
        raise ValueError("table must not start with '-'")
    if not _NFT_TABLE_RE.fullmatch(table):
        raise ValueError("table must match ^[A-Za-z0-9_.-]{1,64}$")
    return table


def build_remote_cmd_nft_list(*, family: str | None = None, table: str | None = None) -> str:
    """Build LC_ALL=C nft list command string."""
    if table is None and family is None:
        return "LC_ALL=C nft -nn list ruleset"
    if table is None or family is None:
        raise ValueError("table and family must be supplied together")
    return f"LC_ALL=C nft -nn list table {shlex.quote(family)} {shlex.quote(table)}"


def handle_nft_list(args: dict) -> dict:
    host = validate_host(args["host"])
    family = args.get("family")
    table = args.get("table")
    if (family is None) != (table is None):
        raise ValueError("table and family must be supplied together")
    if family is not None:
        family = _validate_nft_family(family)
    if table is not None:
        table = _validate_nft_table(table)
    cmd = build_remote_cmd_nft_list(family=family, table=table)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


NFT_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "family": {
            "type": ["string", "null"],
            "enum": ["ip", "ip6", "inet", "arp", "bridge", "netdev", None],
        },
        "table": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# iptables_list
# ---------------------------------------------------------------------------

_IPTABLES_TABLE_WHITELIST = {"filter", "nat", "mangle", "raw"}
_IPTABLES_FAMILY_MAP = {"ipv4": "iptables", "ipv6": "ip6tables"}


def _validate_iptables_table(table) -> str:
    if not isinstance(table, str) or table not in _IPTABLES_TABLE_WHITELIST:
        raise ValueError(f"table must be one of {sorted(_IPTABLES_TABLE_WHITELIST)}")
    return table


def _validate_iptables_family(family) -> str:
    if family is None:
        return _IPTABLES_FAMILY_MAP["ipv4"]
    if not isinstance(family, str) or family not in _IPTABLES_FAMILY_MAP:
        raise ValueError(f"family must be one of {sorted(_IPTABLES_FAMILY_MAP)}")
    return _IPTABLES_FAMILY_MAP[family]


def build_remote_cmd_iptables_list(*, binary: str, table: str | None = None) -> str:
    """Build LC_ALL=C iptables/ip6tables list command string."""
    parts = ["LC_ALL=C", binary, "-n", "-v", "-L"]
    if table is not None:
        parts += ["-t", shlex.quote(table)]
    return " ".join(parts)


def handle_iptables_list(args: dict) -> dict:
    host = validate_host(args["host"])
    binary = _validate_iptables_family(args.get("family"))
    table = args.get("table")
    if table is not None:
        table = _validate_iptables_table(table)
    cmd = build_remote_cmd_iptables_list(binary=binary, table=table)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


IPTABLES_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "table": {
            "type": ["string", "null"],
            "enum": ["filter", "nat", "mangle", "raw", None],
        },
        "family": {"type": ["string", "null"], "enum": ["ipv4", "ipv6", None]},
    },
    "required": ["host"],
    "additionalProperties": False,
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
    ToolSpec(
        name="arp_table",
        description=(
            "Run 'ip neigh show' (ARP/neighbor cache) on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=ARP_TABLE_SCHEMA,
        handler=handle_arp_table,
    ),
    ToolSpec(
        name="tc_qdisc",
        description=(
            "Run 'tc -s qdisc show' (queueing discipline stats: queue depth, drops) on a "
            "remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=TC_QDISC_SCHEMA,
        handler=handle_tc_qdisc,
    ),
    ToolSpec(
        name="ethtool",
        description=(
            "Run ethtool against an interface on a remote host via SSH using a preset mode "
            "(driver|stats|ring|features|pause|coalesce, default driver). Some modes need "
            "privileges (exit/stderr passthrough). Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=ETHTOOL_SCHEMA,
        handler=handle_ethtool,
    ),
    ToolSpec(
        name="conntrack",
        description=(
            "Run conntrack (-S stats default, or -L list with optional -p protocol) on a "
            "remote host via SSH. Root + nf_conntrack module required. List output can be "
            "large (truncation flagged). Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=CONNTRACK_SCHEMA,
        handler=handle_conntrack,
    ),
    ToolSpec(
        name="net_protocol_stats",
        description=(
            "Run 'netstat -s' (protocol counters: retransmits, drops, listen overflows) on a "
            "remote host via SSH. protocol: all|tcp|udp|ip (default all). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=NET_PROTOCOL_STATS_SCHEMA,
        handler=handle_net_protocol_stats,
    ),
    ToolSpec(
        name="nft_list",
        description=(
            "Run 'nft list ruleset' (or 'list table <family> <table>') on a remote host via "
            "SSH. Root required. Surfaces firewall rules/IPs. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=NFT_LIST_SCHEMA,
        handler=handle_nft_list,
    ),
    ToolSpec(
        name="iptables_list",
        description=(
            "Run 'iptables -n -v -L' (or ip6tables) on a remote host via SSH, optional -t table. "
            "Root required. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=IPTABLES_LIST_SCHEMA,
        handler=handle_iptables_list,
    ),
]
