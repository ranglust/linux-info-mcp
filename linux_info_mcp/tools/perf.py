"""Perf tools: iostat, vmstat, free, df, ps."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
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
from ._parsers import parse_df, parse_free

# ---------------------------------------------------------------------------
# iostat
# ---------------------------------------------------------------------------

_IOSTAT_DEV_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _validate_iostat_device(name) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError("device must be a non-empty string")
    if name.startswith("-"):
        raise ValueError("device must not start with '-'")
    reject_unsafe_chars(name, "device")
    if len(name) > 64:
        raise ValueError("device must be at most 64 characters")
    if not _IOSTAT_DEV_RE.fullmatch(name):
        raise ValueError(f"device contains characters outside [A-Za-z0-9._-]: {name!r}")
    return name


def _validate_iostat_devices(devices) -> list[str]:
    if devices is None:
        return []
    if not isinstance(devices, list):
        raise ValueError("devices must be a list")
    return [_validate_iostat_device(d) for d in devices]


def build_remote_cmd_iostat(
    *,
    extended: bool = False,
    kilobytes: bool = False,
    megabytes: bool = False,
    omit_zero: bool = False,
    device_only: bool = False,
    cpu_only: bool = False,
    interval: int | None = None,
    count: int | None = None,
    devices: list[str] | None = None,
) -> str:
    """Build LC_ALL=C iostat command string."""
    if kilobytes and megabytes:
        raise ValueError("kilobytes and megabytes are mutually exclusive")
    if device_only and cpu_only:
        raise ValueError("device_only and cpu_only are mutually exclusive")
    if count is not None and interval is None:
        raise ValueError("count requires interval")
    parts = ["LC_ALL=C", "iostat"]
    if extended:
        parts.append("-x")
    if kilobytes:
        parts.append("-k")
    if megabytes:
        parts.append("-m")
    if omit_zero:
        parts.append("-z")
    if device_only:
        parts.append("-d")
    if cpu_only:
        parts.append("-c")
    for dev in devices or []:
        parts += ["-p", shlex.quote(dev)]
    if interval is not None:
        parts.append(str(interval))
        if count is not None:
            parts.append(str(count))
    return " ".join(parts)


def handle_iostat(args: dict) -> dict:
    host = validate_host(args["host"])
    interval = args.get("interval")
    count = args.get("count")
    if interval is not None:
        interval = validate_int_in_range(interval, lo=1, hi=60, label="interval")
    if count is not None:
        count = validate_int_in_range(count, lo=1, hi=100, label="count")
    devices = _validate_iostat_devices(args.get("devices"))
    cmd = build_remote_cmd_iostat(
        extended=_bool(args.get("extended"), "extended"),
        kilobytes=_bool(args.get("kilobytes"), "kilobytes"),
        megabytes=_bool(args.get("megabytes"), "megabytes"),
        omit_zero=_bool(args.get("omit_zero"), "omit_zero"),
        device_only=_bool(args.get("device_only"), "device_only"),
        cpu_only=_bool(args.get("cpu_only"), "cpu_only"),
        interval=interval,
        count=count,
        devices=devices,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


IOSTAT_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "extended": {"type": ["boolean", "null"]},
        "kilobytes": {"type": ["boolean", "null"]},
        "megabytes": {"type": ["boolean", "null"]},
        "omit_zero": {"type": ["boolean", "null"]},
        "device_only": {"type": ["boolean", "null"]},
        "cpu_only": {"type": ["boolean", "null"]},
        "interval": {"type": ["integer", "null"]},
        "count": {"type": ["integer", "null"]},
        "devices": {"type": ["array", "null"], "items": {"type": "string"}},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# vmstat
# ---------------------------------------------------------------------------

_VMSTAT_UNITS = {"k", "K", "m", "M"}


def _validate_vmstat_unit(unit) -> str:
    if not isinstance(unit, str) or unit not in _VMSTAT_UNITS:
        raise ValueError(f"unit must be one of {sorted(_VMSTAT_UNITS)}")
    return unit


def build_remote_cmd_vmstat(
    *,
    wide: bool = False,
    active: bool = False,
    disk: bool = False,
    summary: bool = False,
    unit: str | None = None,
    interval: int | None = None,
    count: int | None = None,
) -> str:
    """Build LC_ALL=C vmstat command string."""
    if disk and summary:
        raise ValueError("disk and summary are mutually exclusive")
    if count is not None and interval is None:
        raise ValueError("count requires interval")
    parts = ["LC_ALL=C", "vmstat"]
    if wide:
        parts.append("-w")
    if active:
        parts.append("-a")
    if disk:
        parts.append("-d")
    if summary:
        parts.append("-s")
    if unit is not None:
        parts += ["-S", shlex.quote(unit)]
    if interval is not None:
        parts.append(str(interval))
        if count is not None:
            parts.append(str(count))
    return " ".join(parts)


def handle_vmstat(args: dict) -> dict:
    host = validate_host(args["host"])
    interval = args.get("interval")
    count = args.get("count")
    if interval is not None:
        interval = validate_int_in_range(interval, lo=1, hi=60, label="interval")
    if count is not None:
        count = validate_int_in_range(count, lo=1, hi=100, label="count")
    unit = args.get("unit")
    if unit is not None:
        unit = _validate_vmstat_unit(unit)
    cmd = build_remote_cmd_vmstat(
        wide=_bool(args.get("wide"), "wide"),
        active=_bool(args.get("active"), "active"),
        disk=_bool(args.get("disk"), "disk"),
        summary=_bool(args.get("summary"), "summary"),
        unit=unit,
        interval=interval,
        count=count,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


VMSTAT_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "wide": {"type": ["boolean", "null"]},
        "active": {"type": ["boolean", "null"]},
        "disk": {"type": ["boolean", "null"]},
        "summary": {"type": ["boolean", "null"]},
        "unit": {"type": ["string", "null"]},
        "interval": {"type": ["integer", "null"]},
        "count": {"type": ["integer", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# free
# ---------------------------------------------------------------------------

_FREE_UNIT_MAP = {
    "human": "-h",
    "bytes": "-b",
    "kilo": "-k",
    "mega": "-m",
    "giga": "-g",
    "tera": "--tera",
    "peta": "--peta",
}


def _validate_free_unit(unit) -> str:
    if not isinstance(unit, str) or unit not in _FREE_UNIT_MAP:
        raise ValueError(f"unit must be one of {sorted(_FREE_UNIT_MAP)}")
    return _FREE_UNIT_MAP[unit]


def build_remote_cmd_free(
    *,
    unit_flag: str | None = None,
    wide: bool = False,
    total: bool = False,
    interval: int | None = None,
    count: int | None = None,
) -> str:
    """Build LC_ALL=C free command string."""
    if count is not None and interval is None:
        raise ValueError("count requires interval")
    parts = ["LC_ALL=C", "free"]
    if unit_flag is not None:
        parts.append(unit_flag)
    if wide:
        parts.append("-w")
    if total:
        parts.append("-t")
    if interval is not None:
        parts += ["-s", str(interval)]
    if count is not None:
        parts += ["-c", str(count)]
    return " ".join(parts)


def handle_free(args: dict) -> dict:
    host = validate_host(args["host"])
    unit = args.get("unit")
    unit_flag = _validate_free_unit(unit) if unit is not None else None
    interval = args.get("interval")
    count = args.get("count")
    if interval is not None:
        interval = validate_int_in_range(interval, lo=1, hi=60, label="interval")
    if count is not None:
        count = validate_int_in_range(count, lo=1, hi=100, label="count")
    cmd = build_remote_cmd_free(
        unit_flag=unit_flag,
        wide=_bool(args.get("wide"), "wide"),
        total=_bool(args.get("total"), "total"),
        interval=interval,
        count=count,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


FREE_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "unit": {"type": ["string", "null"]},
        "wide": {"type": ["boolean", "null"]},
        "total": {"type": ["boolean", "null"]},
        "interval": {"type": ["integer", "null"]},
        "count": {"type": ["integer", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# df
# ---------------------------------------------------------------------------

_DF_BLOCK_SIZE_RE = re.compile(r"^[1-9][0-9]{0,9}[KMGT]?$")
_DF_FSTYPE_RE = re.compile(r"^[a-z0-9]+$")


def _validate_df_block_size(size) -> str:
    if not isinstance(size, str) or not _DF_BLOCK_SIZE_RE.fullmatch(size):
        raise ValueError("block_size must match ^[1-9][0-9]{0,9}[KMGT]?$")
    return size


def _validate_df_fstype(t) -> str:
    if not isinstance(t, str) or not t:
        raise ValueError("exclude_type entry must be a non-empty string")
    if len(t) > 32:
        raise ValueError("exclude_type entry must be at most 32 characters")
    if not _DF_FSTYPE_RE.fullmatch(t):
        raise ValueError(f"exclude_type entry must match ^[a-z0-9]+$: {t!r}")
    return t


def _validate_df_exclude_types(types) -> list[str]:
    if types is None:
        return []
    if not isinstance(types, list):
        raise ValueError("exclude_type must be a list")
    return [_validate_df_fstype(t) for t in types]


def _validate_df_paths(paths) -> list[str]:
    if paths is None:
        return []
    if not isinstance(paths, list):
        raise ValueError("paths must be a list")
    return [validate_path(p, label="paths entry") for p in paths]


def build_remote_cmd_df(
    *,
    human: bool = False,
    inodes: bool = False,
    local: bool = False,
    print_type: bool = False,
    block_size: str | None = None,
    exclude_type: list[str] | None = None,
    paths: list[str] | None = None,
) -> str:
    """Build LC_ALL=C df command string."""
    parts = ["LC_ALL=C", "df"]
    if human:
        parts.append("-h")
    if inodes:
        parts.append("-i")
    if local:
        parts.append("-l")
    if print_type:
        parts.append("-T")
    if block_size is not None:
        parts += ["-B", shlex.quote(block_size)]
    for t in exclude_type or []:
        parts += ["-x", shlex.quote(t)]
    if paths:
        parts.append("--")
        for p in paths:
            parts.append(shlex.quote(p))
    return " ".join(parts)


def handle_df(args: dict) -> dict:
    host = validate_host(args["host"])
    block_size = args.get("block_size")
    if block_size is not None:
        block_size = _validate_df_block_size(block_size)
    exclude_type = _validate_df_exclude_types(args.get("exclude_type"))
    paths = _validate_df_paths(args.get("paths"))
    cmd = build_remote_cmd_df(
        human=_bool(args.get("human"), "human"),
        inodes=_bool(args.get("inodes"), "inodes"),
        local=_bool(args.get("local"), "local"),
        print_type=_bool(args.get("print_type"), "print_type"),
        block_size=block_size,
        exclude_type=exclude_type,
        paths=paths,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


DF_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "human": {"type": ["boolean", "null"]},
        "inodes": {"type": ["boolean", "null"]},
        "local": {"type": ["boolean", "null"]},
        "print_type": {"type": ["boolean", "null"]},
        "block_size": {"type": ["string", "null"]},
        "exclude_type": {"type": ["array", "null"], "items": {"type": "string"}},
        "paths": {"type": ["array", "null"], "items": {"type": "string"}},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# ps
# ---------------------------------------------------------------------------

_PS_MODE_MAP = {
    "aux": "aux",
    "auxf": "auxf",
    "aux-sort-mem": "aux --sort=-rss",
    "aux-sort-cpu": "aux --sort=-pcpu",
    "ef": "-ef",
    "efH": "-efH",
    "forest": "-ef --forest",
}


def _validate_ps_mode(mode) -> str:
    if mode is None:
        return _PS_MODE_MAP["auxf"]
    if not isinstance(mode, str) or mode not in _PS_MODE_MAP:
        raise ValueError(f"mode must be one of {sorted(_PS_MODE_MAP)}")
    return _PS_MODE_MAP[mode]


def build_remote_cmd_ps(
    *,
    mode_args: str,
    user: str | None = None,
    pid: int | None = None,
) -> str:
    """Build LC_ALL=C ps command string."""
    if user is not None and pid is not None:
        raise ValueError("user and pid are mutually exclusive")
    parts = ["LC_ALL=C", "ps", mode_args]
    if user is not None:
        parts += ["-u", shlex.quote(user)]
    elif pid is not None:
        parts += ["-p", str(pid)]
    return " ".join(parts)


def handle_ps(args: dict) -> dict:
    host = validate_host(args["host"])
    user = args.get("user")
    pid = args.get("pid")
    if user is not None and pid is not None:
        raise ValueError("user and pid are mutually exclusive")
    if user is not None:
        user = validate_user(user)
    if pid is not None:
        pid = validate_pid(pid)
    mode_args = _validate_ps_mode(args.get("mode"))
    cmd = build_remote_cmd_ps(mode_args=mode_args, user=user, pid=pid)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


PS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "mode": {"type": ["string", "null"]},
        "user": {"type": ["string", "null"]},
        "pid": {"type": ["integer", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# psi_stats
# ---------------------------------------------------------------------------

_PSI_RESOURCES = {"cpu", "memory", "io", "all"}


def _validate_psi_resource(resource) -> str:
    if resource is None:
        return "all"
    if not isinstance(resource, str) or resource not in _PSI_RESOURCES:
        raise ValueError(f"resource must be one of {sorted(_PSI_RESOURCES)}")
    return resource


def build_remote_cmd_psi_stats(*, resource: str = "all") -> str:
    """Build LC_ALL=C /proc/pressure read command. resource is whitelist-validated."""
    if resource == "all":
        return "LC_ALL=C grep -H '' /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io"
    return f"LC_ALL=C cat /proc/pressure/{resource}"


def handle_psi_stats(args: dict) -> dict:
    host = validate_host(args["host"])
    resource = _validate_psi_resource(args.get("resource"))
    cmd = build_remote_cmd_psi_stats(resource=resource)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


PSI_STATS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "resource": {"type": ["string", "null"], "enum": ["cpu", "memory", "io", "all", None]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# meminfo
# ---------------------------------------------------------------------------

_MEMINFO_FIELD_RE = re.compile(r"^[A-Za-z0-9_()]+$")


def _validate_meminfo_field(f) -> str:
    if not isinstance(f, str) or not f:
        raise ValueError("fields entry must be a non-empty string")
    if len(f) > 64:
        raise ValueError("fields entry must be at most 64 characters")
    if not _MEMINFO_FIELD_RE.fullmatch(f):
        raise ValueError(f"fields entry must match ^[A-Za-z0-9_()]+$: {f!r}")
    return f


def _validate_meminfo_fields(fields) -> list[str]:
    if fields is None:
        return []
    if not isinstance(fields, list):
        raise ValueError("fields must be a list")
    return [_validate_meminfo_field(f) for f in fields]


def build_remote_cmd_meminfo(*, fields: list[str] | None = None) -> str:
    """Build LC_ALL=C /proc/meminfo read, optionally grep-filtered to named fields."""
    base = "LC_ALL=C cat /proc/meminfo"
    if not fields:
        return base
    pattern = "^(" + "|".join(fields) + "):"
    return f"{base} | grep -E {shlex.quote(pattern)} || [ $? -eq 1 ]"


def handle_meminfo(args: dict) -> dict:
    host = validate_host(args["host"])
    fields = _validate_meminfo_fields(args.get("fields"))
    cmd = build_remote_cmd_meminfo(fields=fields)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


MEMINFO_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "fields": {"type": ["array", "null"], "items": {"type": "string"}},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="iostat",
        description=(
            "Run iostat on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=IOSTAT_SCHEMA,
        handler=handle_iostat,
    ),
    ToolSpec(
        name="vmstat",
        description=(
            "Run vmstat on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=VMSTAT_SCHEMA,
        handler=handle_vmstat,
    ),
    ToolSpec(
        name="free",
        description=(
            "Run free on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=FREE_SCHEMA,
        handler=handle_free,
        parser=parse_free,
    ),
    ToolSpec(
        name="df",
        description=(
            "Run df on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=DF_SCHEMA,
        handler=handle_df,
        parser=parse_df,
    ),
    ToolSpec(
        name="ps",
        description=(
            "Run ps on a remote host via SSH using a preset mode. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=PS_SCHEMA,
        handler=handle_ps,
    ),
    ToolSpec(
        name="psi_stats",
        description=(
            "Read PSI pressure-stall info from /proc/pressure on a remote host via SSH. "
            "resource: cpu|memory|io|all (default all). Kernels <4.20 lack these files "
            "(nonzero exit passthrough). Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=PSI_STATS_SCHEMA,
        handler=handle_psi_stats,
    ),
    ToolSpec(
        name="meminfo",
        description=(
            "Read /proc/meminfo on a remote host via SSH, optionally filtered to named fields. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=MEMINFO_SCHEMA,
        handler=handle_meminfo,
    ),
]
