"""Disk tools: du, lsblk, blkid, smartctl."""

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
from ._common import decode_text as _decode_text
from ._common import validate_bool as _bool

# ---------------------------------------------------------------------------
# du
# ---------------------------------------------------------------------------

_DU_THRESHOLD_RE = re.compile(r"^-?\d+[KMGT]?$")


def _validate_du_threshold(value) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("threshold must be a non-empty string")
    reject_unsafe_chars(value, "threshold")
    if not _DU_THRESHOLD_RE.fullmatch(value):
        raise ValueError("threshold must match ^-?\\d+[KMGT]?$")
    return value


def build_remote_cmd_du(
    *,
    path: str,
    human: bool = False,
    summary: bool = False,
    max_depth: int | None = None,
    apparent: bool = False,
    one_filesystem: bool = False,
    threshold: str | None = None,
) -> str:
    """Build LC_ALL=C du command string."""
    parts = ["LC_ALL=C", "du"]
    if human:
        parts.append("-h")
    if summary:
        parts.append("-s")
    if max_depth is not None:
        parts.append(f"--max-depth={max_depth}")
    if apparent:
        parts.append("--apparent-size")
    if one_filesystem:
        parts.append("-x")
    if threshold is not None:
        parts.append(f"--threshold={shlex.quote(threshold)}")
    parts.append("--")
    parts.append(shlex.quote(path))
    return " ".join(parts)


def handle_du(args: dict) -> dict:
    host = validate_host(args["host"])
    path = validate_path(args["path"], label="path")
    max_depth = args.get("max_depth")
    if max_depth is not None:
        max_depth = validate_int_in_range(max_depth, lo=0, hi=10, label="max_depth")
    threshold = args.get("threshold")
    if threshold is not None:
        threshold = _validate_du_threshold(threshold)
    cmd = build_remote_cmd_du(
        path=path,
        human=_bool(args.get("human"), "human"),
        summary=_bool(args.get("summary"), "summary"),
        max_depth=max_depth,
        apparent=_bool(args.get("apparent"), "apparent"),
        one_filesystem=_bool(args.get("one_filesystem"), "one_filesystem"),
        threshold=threshold,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


DU_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "path": {"type": "string"},
        "human": {"type": ["boolean", "null"]},
        "summary": {"type": ["boolean", "null"]},
        "max_depth": {"type": ["integer", "null"]},
        "apparent": {"type": ["boolean", "null"]},
        "one_filesystem": {"type": ["boolean", "null"]},
        "threshold": {"type": ["string", "null"]},
    },
    "required": ["host", "path"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# lsblk
# ---------------------------------------------------------------------------


def build_remote_cmd_lsblk(
    *,
    json_out: bool = False,
    tree: bool = True,
    pairs: bool = False,
    paths: bool = False,
    fs: bool = False,
    discard: bool = False,
    topology: bool = False,
    device: str | None = None,
) -> str:
    """Build LC_ALL=C lsblk command string."""
    if json_out and pairs:
        raise ValueError("json and pairs are mutually exclusive")
    if not tree and (json_out or pairs):
        raise ValueError("tree=false is incompatible with json or pairs output")
    parts = ["LC_ALL=C", "lsblk"]
    if json_out:
        parts.append("-J")
    if pairs:
        parts.append("-P")
    if not tree and not json_out and not pairs:
        parts.append("-l")
    if paths:
        parts.append("-p")
    if fs:
        parts.append("-f")
    if discard:
        parts.append("-D")
    if topology:
        parts.append("-t")
    if device is not None:
        parts.append("--")
        parts.append(shlex.quote(device))
    return " ".join(parts)


def handle_lsblk(args: dict) -> dict:
    host = validate_host(args["host"])
    device = args.get("device")
    if device is not None:
        device = validate_path(device, label="device")
    tree = args.get("tree")
    tree = True if tree is None else _bool(tree, "tree")
    cmd = build_remote_cmd_lsblk(
        json_out=_bool(args.get("json"), "json"),
        tree=tree,
        pairs=_bool(args.get("pairs"), "pairs"),
        paths=_bool(args.get("paths"), "paths"),
        fs=_bool(args.get("fs"), "fs"),
        discard=_bool(args.get("discard"), "discard"),
        topology=_bool(args.get("topology"), "topology"),
        device=device,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


LSBLK_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "json": {"type": ["boolean", "null"]},
        "tree": {"type": ["boolean", "null"]},
        "pairs": {"type": ["boolean", "null"]},
        "paths": {"type": ["boolean", "null"]},
        "fs": {"type": ["boolean", "null"]},
        "discard": {"type": ["boolean", "null"]},
        "topology": {"type": ["boolean", "null"]},
        "device": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# blkid
# ---------------------------------------------------------------------------


def build_remote_cmd_blkid(
    *,
    device: str | None = None,
    probe: bool = False,
) -> str:
    """Build LC_ALL=C blkid command string."""
    if probe and device is None:
        raise ValueError("probe requires device")
    parts = ["LC_ALL=C", "blkid"]
    if probe:
        parts.append("-p")
    if device is not None:
        parts.append("--")
        parts.append(shlex.quote(device))
    return " ".join(parts)


def handle_blkid(args: dict) -> dict:
    host = validate_host(args["host"])
    device = args.get("device")
    if device is not None:
        device = validate_path(device, label="device")
    cmd = build_remote_cmd_blkid(
        device=device,
        probe=_bool(args.get("probe"), "probe"),
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


BLKID_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "device": {"type": ["string", "null"]},
        "probe": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# smartctl
# ---------------------------------------------------------------------------

_SMARTCTL_MODE_MAP = {
    "info": "-i",
    "health": "-H",
    "attributes": "-A",
    "all": "-a",
    "capabilities": "-c",
}


def _validate_smartctl_mode(mode) -> str:
    if not isinstance(mode, str) or mode not in _SMARTCTL_MODE_MAP:
        raise ValueError(f"mode must be one of {sorted(_SMARTCTL_MODE_MAP)}")
    return _SMARTCTL_MODE_MAP[mode]


def build_remote_cmd_smartctl(*, device: str, mode_flag: str) -> str:
    """Build LC_ALL=C smartctl command string."""
    parts = ["LC_ALL=C", *sudo_tokens(), "smartctl", mode_flag, "--", shlex.quote(device)]
    return " ".join(parts)


def handle_smartctl(args: dict) -> dict:
    host = validate_host(args["host"])
    device = validate_path(args["device"], label="device")
    mode_flag = _validate_smartctl_mode(args.get("mode"))
    cmd = build_remote_cmd_smartctl(device=device, mode_flag=mode_flag)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


SMARTCTL_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "device": {"type": "string"},
        "mode": {"type": "string"},
    },
    "required": ["host", "device", "mode"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# blockdev
# ---------------------------------------------------------------------------


def build_remote_cmd_blockdev() -> str:
    """Build LC_ALL=C blockdev --report command string."""
    return "LC_ALL=C blockdev --report"


def handle_blockdev(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_blockdev()
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


BLOCKDEV_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="du",
        description=(
            "Run du on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=DU_SCHEMA,
        handler=handle_du,
    ),
    ToolSpec(
        name="lsblk",
        description=(
            "Run lsblk on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=LSBLK_SCHEMA,
        handler=handle_lsblk,
    ),
    ToolSpec(
        name="blkid",
        description=(
            "Run blkid on a remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=BLKID_SCHEMA,
        handler=handle_blkid,
    ),
    ToolSpec(
        name="smartctl",
        description=(
            "Run smartctl on a remote host via SSH using a preset mode. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SMARTCTL_SCHEMA,
        handler=handle_smartctl,
    ),
    ToolSpec(
        name="blockdev",
        description=(
            "Run 'blockdev --report' (block device sizes, sector/block sizes, RO/RA flags) on a "
            "remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=BLOCKDEV_SCHEMA,
        handler=handle_blockdev,
    ),
]
