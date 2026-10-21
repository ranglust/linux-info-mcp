"""Filesystem inspection tools: mount, findmnt, stat_fs, stat."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import reject_unsafe_chars, validate_host, validate_path
from . import ToolSpec
from ._common import decode_text as _decode_text
from ._common import validate_bool as _bool

_FSTYPE_RE = re.compile(r"^[a-z0-9]{1,32}$")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9./_:-]{1,256}$")
_STAT_FS_FORMATS = {"default", "terse"}
_STAT_CACHED = {"always", "never", "default"}
_STAT_MAX_PATHS = 100
_STAT_MAX_FORMAT = 512
_STAT_FILE_SPECS = set("aAbBCdDfFgGhimnNostTuUwWxXyYzZrR") | {"Hd", "Ld", "Hr", "Lr"}
_STAT_FS_SPECS = set("abcdfilnsStT")
_STAT_SPEC_RE = re.compile(r"%(%|[-#0+ ']*[0-9]{0,3}(?:\.[0-9]{0,9})?(Hd|Ld|Hr|Lr|[A-Za-z]))")


def _validate_fstype(value) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("fstype must be a non-empty string")
    reject_unsafe_chars(value, "fstype")
    if value.startswith("-"):
        raise ValueError("fstype must not start with '-'")
    if not _FSTYPE_RE.fullmatch(value):
        raise ValueError("fstype must match ^[a-z0-9]{1,32}$")
    return value


def _validate_source(value) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("source must be a non-empty string")
    reject_unsafe_chars(value, "source")
    if value.startswith("-"):
        raise ValueError("source must not start with '-'")
    if not _SOURCE_RE.fullmatch(value):
        raise ValueError("source must match ^[A-Za-z0-9./_:-]{1,256}$")
    return value


def _validate_stat_fs_format(value) -> str:
    if not isinstance(value, str) or value not in _STAT_FS_FORMATS:
        raise ValueError(f"format must be one of {sorted(_STAT_FS_FORMATS)}")
    return value


# ---------------------------------------------------------------------------
# mount
# ---------------------------------------------------------------------------


def build_remote_cmd_mount(
    *,
    fstype: str | None = None,
    verbose: bool = False,
) -> str:
    """Build LC_ALL=C mount command string."""
    parts = ["LC_ALL=C", "mount"]
    if verbose:
        parts.append("-v")
    if fstype is not None:
        parts += ["-t", shlex.quote(fstype)]
    return " ".join(parts)


def handle_mount(args: dict) -> dict:
    host = validate_host(args["host"])
    fstype = args.get("fstype")
    if fstype is not None:
        fstype = _validate_fstype(fstype)
    cmd = build_remote_cmd_mount(
        fstype=fstype,
        verbose=_bool(args.get("verbose"), "verbose"),
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


MOUNT_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "fstype": {"type": ["string", "null"]},
        "verbose": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# findmnt
# ---------------------------------------------------------------------------


def build_remote_cmd_findmnt(
    *,
    json: bool = False,
    tree: bool = False,
    target: str | None = None,
    source: str | None = None,
    fstype: str | None = None,
) -> str:
    """Build LC_ALL=C findmnt command string."""
    if json and tree:
        raise ValueError("json and tree are mutually exclusive")
    parts = ["LC_ALL=C", "findmnt"]
    if json:
        parts.append("-J")
    if tree:
        parts.append("-T")
    if target is not None:
        parts.append(f"--target={shlex.quote(target)}")
    if source is not None:
        parts.append(f"--source={shlex.quote(source)}")
    if fstype is not None:
        parts += ["-t", shlex.quote(fstype)]
    return " ".join(parts)


def handle_findmnt(args: dict) -> dict:
    host = validate_host(args["host"])
    target = args.get("target")
    if target is not None:
        target = validate_path(target, label="target")
    source = args.get("source")
    if source is not None:
        source = _validate_source(source)
    fstype = args.get("fstype")
    if fstype is not None:
        fstype = _validate_fstype(fstype)
    cmd = build_remote_cmd_findmnt(
        json=_bool(args.get("json"), "json"),
        tree=_bool(args.get("tree"), "tree"),
        target=target,
        source=source,
        fstype=fstype,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


FINDMNT_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "json": {"type": ["boolean", "null"]},
        "tree": {"type": ["boolean", "null"]},
        "target": {"type": ["string", "null"]},
        "source": {"type": ["string", "null"]},
        "fstype": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# stat_fs
# ---------------------------------------------------------------------------


def build_remote_cmd_stat_fs(
    *,
    path: str,
    format: str = "default",
) -> str:
    """Build LC_ALL=C stat -f command string."""
    if format not in _STAT_FS_FORMATS:
        raise ValueError(f"format must be one of {sorted(_STAT_FS_FORMATS)}")
    parts = ["LC_ALL=C", "stat", "-f"]
    if format == "terse":
        parts.append("-t")
    parts += ["--", shlex.quote(path)]
    return " ".join(parts)


def handle_stat_fs(args: dict) -> dict:
    host = validate_host(args["host"])
    if "path" not in args or args["path"] is None:
        raise ValueError("path is required")
    path = validate_path(args["path"], label="path")
    fmt = args.get("format")
    fmt = _validate_stat_fs_format(fmt) if fmt is not None else "default"
    cmd = build_remote_cmd_stat_fs(path=path, format=fmt)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


STAT_FS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "path": {"type": "string"},
        "format": {"type": ["string", "null"]},
    },
    "required": ["host", "path"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# stat
# ---------------------------------------------------------------------------


def _validate_stat_format(value, *, file_system: bool) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("format must be a non-empty string")
    if len(value) > _STAT_MAX_FORMAT:
        raise ValueError(f"format must be at most {_STAT_MAX_FORMAT} characters")
    reject_unsafe_chars(value, "format")
    allowed = _STAT_FS_SPECS if file_system else _STAT_FILE_SPECS
    pos = 0
    while (i := value.find("%", pos)) != -1:
        m = _STAT_SPEC_RE.match(value, i)
        if not m:
            raise ValueError(f"format has invalid directive at offset {i}")
        spec = m.group(2)
        if spec is not None and spec not in allowed:
            mode = "file-system" if file_system else "file"
            raise ValueError(f"format directive %{spec} not allowed in {mode} mode")
        pos = m.end()
    return value


def _validate_stat_paths(value) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("paths must be a non-empty list")
    if len(value) > _STAT_MAX_PATHS:
        raise ValueError(f"paths must have at most {_STAT_MAX_PATHS} entries")
    return [validate_path(p, label="paths entry") for p in value]


def build_remote_cmd_stat(
    *,
    paths: list[str],
    dereference: bool = False,
    file_system: bool = False,
    terse: bool = False,
    format: str | None = None,
    cached: str | None = None,
) -> str:
    """Build LC_ALL=C stat command string."""
    if terse and format is not None:
        raise ValueError("terse and format are mutually exclusive")
    if cached is not None and cached not in _STAT_CACHED:
        raise ValueError(f"cached must be one of {sorted(_STAT_CACHED)}")
    parts = ["LC_ALL=C", "stat"]
    if dereference:
        parts.append("-L")
    if file_system:
        parts.append("-f")
    if terse:
        parts.append("-t")
    if format is not None:
        parts.append(f"--format={shlex.quote(format)}")
    if cached is not None:
        parts.append(f"--cached={cached}")
    parts.append("--")
    parts += [shlex.quote(p) for p in paths]
    return " ".join(parts)


def handle_stat(args: dict) -> dict:
    host = validate_host(args["host"])
    if args.get("paths") is None:
        raise ValueError("paths is required")
    paths = _validate_stat_paths(args["paths"])
    file_system = _bool(args.get("file_system"), "file_system")
    fmt = args.get("format")
    if fmt is not None:
        fmt = _validate_stat_format(fmt, file_system=file_system)
    cached = args.get("cached")
    if cached is not None and (not isinstance(cached, str) or cached not in _STAT_CACHED):
        raise ValueError(f"cached must be one of {sorted(_STAT_CACHED)}")
    cmd = build_remote_cmd_stat(
        paths=paths,
        dereference=_bool(args.get("dereference"), "dereference"),
        file_system=file_system,
        terse=_bool(args.get("terse"), "terse"),
        format=fmt,
        cached=cached,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


STAT_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": _STAT_MAX_PATHS,
        },
        "dereference": {"type": ["boolean", "null"]},
        "file_system": {"type": ["boolean", "null"]},
        "terse": {"type": ["boolean", "null"]},
        "format": {"type": ["string", "null"]},
        "cached": {"type": ["string", "null"], "enum": ["always", "never", "default", None]},
    },
    "required": ["host", "paths"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="mount",
        description=(
            "List mounted filesystems via the mount command on a remote host. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=MOUNT_SCHEMA,
        handler=handle_mount,
    ),
    ToolSpec(
        name="findmnt",
        description=(
            "Filtered mount listing via findmnt on a remote host. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=FINDMNT_SCHEMA,
        handler=handle_findmnt,
    ),
    ToolSpec(
        name="stat_fs",
        description=(
            "Run stat -f on a filesystem path on a remote host. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=STAT_FS_SCHEMA,
        handler=handle_stat_fs,
    ),
    ToolSpec(
        name="stat",
        description=(
            "Run stat on one or more paths on a remote host: mode, owner, size, "
            "inode, links, timestamps, SELinux context. Options: dereference (-L), "
            "file_system (-f), terse (-t), format (-c, e.g. '%n %U:%G %a %A'; "
            "printf-style directives validated per mode), cached (--cached). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=STAT_SCHEMA,
        handler=handle_stat,
    ),
]
