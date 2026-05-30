"""File tools: read_file, find_files, read_binary."""
from __future__ import annotations

import base64

from .. import ssh as ssh_mod
from ..ssh import (
    build_remote_cmd_binary,
    build_remote_cmd_find,
    build_remote_cmd_read,
    run_ssh,
)
from ..validate import (
    validate_find_args,
    validate_grep_flags,
    validate_grep_pattern,
    validate_host,
    validate_offset_length,
    validate_path,
)
from . import ToolSpec


def _decode_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def handle_read_file(args: dict) -> dict:
    host = validate_host(args["host"])
    path = validate_path(args["path"])
    grep_pattern = args.get("grep_pattern")
    grep_flags_in = args.get("grep_flags")
    if grep_pattern is not None:
        grep_pattern = validate_grep_pattern(grep_pattern)
    grep_flags = validate_grep_flags(grep_flags_in)
    cmd = build_remote_cmd_read(path, grep_pattern, grep_flags)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


def handle_find_files(args: dict) -> dict:
    host = validate_host(args["host"])
    path = validate_path(args["path"])
    predicates = validate_find_args(
        name=args.get("name"),
        iname=args.get("iname"),
        type=args.get("type"),
        maxdepth=args.get("maxdepth"),
        mindepth=args.get("mindepth"),
        mtime=args.get("mtime"),
        size=args.get("size"),
        path_glob=args.get("path_glob"),
    )
    cmd = build_remote_cmd_find(path, predicates)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


def handle_read_binary(args: dict) -> dict:
    host = validate_host(args["host"])
    path = validate_path(args["path"])
    offset, length = validate_offset_length(
        args["offset"], args["length"], ssh_mod.max_bytes()
    )
    cmd = build_remote_cmd_binary(path, offset, length)
    res = run_ssh(host, cmd)
    raw = res.stdout
    stderr = res.stderr
    decode_failed = False
    try:
        decoded = base64.b64decode(b"".join(raw.split()), validate=False)
    except Exception:
        decoded = b""
        decode_failed = True
        stderr = stderr + b"\n[base64 decode failed]"
    data_b64 = base64.b64encode(decoded).decode("ascii")
    return {
        "data_base64": data_b64,
        "bytes_read": len(decoded),
        "stderr": _decode_text(stderr),
        "exit_code": 1 if decode_failed and res.exit_code == 0 else res.exit_code,
        "truncated": res.truncated,
    }


READ_FILE_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "path": {"type": "string"},
        "grep_pattern": {"type": ["string", "null"]},
        "grep_flags": {"type": ["array", "null"], "items": {"type": "string"}},
    },
    "required": ["host", "path"],
}

FIND_FILES_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "path": {"type": "string"},
        "name": {"type": ["string", "null"]},
        "iname": {"type": ["string", "null"]},
        "type": {"type": ["string", "null"]},
        "maxdepth": {"type": ["integer", "null"]},
        "mindepth": {"type": ["integer", "null"]},
        "mtime": {"type": ["string", "null"]},
        "size": {"type": ["string", "null"]},
        "path_glob": {"type": ["string", "null"]},
    },
    "required": ["host", "path"],
}

READ_BINARY_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "path": {"type": "string"},
        "offset": {"type": "integer"},
        "length": {"type": "integer"},
    },
    "required": ["host", "path", "offset", "length"],
}


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="read_file",
        description=(
            "Read a text file on a remote host via SSH, optionally filtered through grep. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=READ_FILE_SCHEMA,
        handler=handle_read_file,
    ),
    ToolSpec(
        name="find_files",
        description=(
            "Run find on a remote host via SSH with whitelisted predicates. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=FIND_FILES_SCHEMA,
        handler=handle_find_files,
    ),
    ToolSpec(
        name="read_binary",
        description=(
            "Read a byte range of a remote file via SSH. "
            "Returns base64-encoded data plus bytes_read, stderr, exit_code, truncated."
        ),
        input_schema=READ_BINARY_SCHEMA,
        handler=handle_read_binary,
    ),
]
