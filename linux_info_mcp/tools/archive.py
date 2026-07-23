"""Archive tools: archive_list, archive_read (tar family + zip)."""

from __future__ import annotations

import base64
import shlex

from ..ssh import run_ssh
from ..validate import (
    validate_archive_format,
    validate_archive_member,
    validate_grep_flags,
    validate_grep_pattern,
    validate_host,
    validate_path,
)
from . import ToolSpec
from ._common import decode_text as _decode_text
from ._common import validate_bool

# tar compression flag per format. tar auto-detects on read, but be explicit
# (older tar predates zstd auto-detection).
_TAR_COMP = {
    "tar": [],
    "tar.gz": ["-z"],
    "tar.xz": ["-J"],
    "tar.bz2": ["-j"],
    "tar.zst": ["--zstd"],
}


def _tar_cmd(fmt: str, op: str, path: str, member: str | None) -> str:
    parts = ["LC_ALL=C", "tar", f"-{op}", *_TAR_COMP[fmt], "-f", shlex.quote(path)]
    if member is not None:
        parts += ["--", shlex.quote(member)]
    return " ".join(parts)


def build_remote_cmd_archive_list(fmt: str, path: str) -> str:
    if fmt == "zip":
        return f"LC_ALL=C unzip -l {shlex.quote(path)}"
    return _tar_cmd(fmt, "t", path, None)


def build_remote_cmd_archive_read(
    fmt: str,
    path: str,
    member: str,
    grep_pattern: str | None,
    grep_flags: list[str] | None,
    binary: bool,
) -> str:
    if fmt == "zip":
        src = f"LC_ALL=C unzip -p {shlex.quote(path)} {shlex.quote(member)}"
    else:
        src = _tar_cmd(fmt, "xO", path, member)
    if binary:
        return f"{src} | base64 -w 0"
    if grep_pattern is None:
        return src
    flags = " ".join(shlex.quote(f) for f in (grep_flags or []))
    flags_part = (flags + " ") if flags else ""
    return f"{src} | grep {flags_part}-e {shlex.quote(grep_pattern)} -- || [ $? -eq 1 ]"


def handle_archive_list(args: dict) -> dict:
    host = validate_host(args["host"])
    path = validate_path(args["path"])
    fmt = validate_archive_format(args.get("format"), path)
    cmd = build_remote_cmd_archive_list(fmt, path)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


def handle_archive_read(args: dict) -> dict:
    host = validate_host(args["host"])
    path = validate_path(args["path"])
    fmt = validate_archive_format(args.get("format"), path)
    member = validate_archive_member(args["member"])
    binary = validate_bool(args.get("binary"), "binary")
    grep_pattern = args.get("grep_pattern")
    grep_flags_in = args.get("grep_flags")
    if binary and grep_pattern is not None:
        raise ValueError("grep_pattern is not supported with binary=true")
    if grep_pattern is not None:
        grep_pattern = validate_grep_pattern(grep_pattern)
    grep_flags = validate_grep_flags(grep_flags_in)
    cmd = build_remote_cmd_archive_read(fmt, path, member, grep_pattern, grep_flags, binary)
    res = run_ssh(host, cmd)
    if not binary:
        return {
            "stdout": _decode_text(res.stdout),
            "stderr": _decode_text(res.stderr),
            "exit_code": res.exit_code,
            "truncated": res.truncated,
            "stderr_truncated": res.stderr_truncated,
        }
    stderr = res.stderr
    decode_failed = False
    try:
        decoded = base64.b64decode(b"".join(res.stdout.split()), validate=False)
    except Exception:
        decoded = b""
        decode_failed = True
        stderr = stderr + b"\n[base64 decode failed]"
    return {
        "data_base64": base64.b64encode(decoded).decode("ascii"),
        "bytes_read": len(decoded),
        "stderr": _decode_text(stderr),
        "exit_code": 1 if decode_failed and res.exit_code == 0 else res.exit_code,
        "truncated": res.truncated,
    }


_FORMAT_ENUM = ["tar", "tar.gz", "tar.xz", "tar.bz2", "tar.zst", "zip", None]

ARCHIVE_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "path": {"type": "string"},
        "format": {"type": ["string", "null"], "enum": _FORMAT_ENUM},
    },
    "required": ["host", "path"],
    "additionalProperties": False,
}

ARCHIVE_READ_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "path": {"type": "string"},
        "member": {"type": "string"},
        "format": {"type": ["string", "null"], "enum": _FORMAT_ENUM},
        "grep_pattern": {"type": ["string", "null"]},
        "grep_flags": {"type": ["array", "null"], "items": {"type": "string"}},
        "binary": {"type": ["boolean", "null"]},
    },
    "required": ["host", "path", "member"],
    "additionalProperties": False,
}


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="archive_list",
        description=(
            "List members of a tar (tar/tgz/tar.gz/tar.xz/tar.bz2/tar.zst) or zip archive "
            "on a remote host via SSH. Format auto-detects from the path extension; pass "
            "format= to override. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=ARCHIVE_LIST_SCHEMA,
        handler=handle_archive_list,
    ),
    ToolSpec(
        name="archive_read",
        description=(
            "Read a single member from a tar or zip archive on a remote host via SSH. "
            "Format auto-detects from the path extension; pass format= to override. "
            "Text mode (default) supports grep; set binary=true to return base64-encoded "
            "bytes (bytes_read/data_base64) instead. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=ARCHIVE_READ_SCHEMA,
        handler=handle_archive_read,
    ),
]
