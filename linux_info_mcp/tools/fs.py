"""Filesystem mount inspection tools: mount, findmnt, stat_fs."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import _reject_unsafe_chars, validate_host, validate_path
from . import ToolSpec


def _decode_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _bool(value, label: str) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a bool")
    return value


_FSTYPE_RE = re.compile(r"^[a-z0-9]{1,32}$")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9./_:-]{1,256}$")
_STAT_FS_FORMATS = {"default", "terse", "human"}


def _validate_fstype(value) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("fstype must be a non-empty string")
    _reject_unsafe_chars(value, "fstype")
    if value.startswith("-"):
        raise ValueError("fstype must not start with '-'")
    if not _FSTYPE_RE.fullmatch(value):
        raise ValueError("fstype must match ^[a-z0-9]{1,32}$")
    return value


def _validate_source(value) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("source must be a non-empty string")
    _reject_unsafe_chars(value, "source")
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
    }


MOUNT_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "fstype": {"type": ["string", "null"]},
        "verbose": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
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
    }


STAT_FS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "path": {"type": "string"},
        "format": {"type": ["string", "null"]},
    },
    "required": ["host", "path"],
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
]
