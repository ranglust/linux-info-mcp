"""Pure validators. Each raises ValueError on bad input."""

from __future__ import annotations

import os
import re

GREP_FLAG_WHITELIST = {"-i", "-E", "-v", "-n", "-w", "-F"}
_GREP_CONTEXT_RE = re.compile(r"^-C[1-9]$")
FIND_TYPE_WHITELIST = {"f", "d", "l", "b", "c", "p", "s"}
_MTIME_RE = re.compile(r"^[+-]?\d+$")
_SIZE_RE = re.compile(r"^[+-]?\d+[bcwkMG]?$")
_UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9@:._-]+$")


def _reject_unsafe_chars(value: str, label: str) -> None:
    if "\x00" in value:
        raise ValueError(f"{label} contains NUL byte")
    if "\n" in value or "\r" in value:
        raise ValueError(f"{label} contains newline")


def validate_host(host: str) -> str:
    if not isinstance(host, str) or not host:
        raise ValueError("host must be a non-empty string")
    _reject_unsafe_chars(host, "host")
    if any(c.isspace() for c in host):
        raise ValueError("host contains whitespace")
    if host.startswith("-"):
        raise ValueError("host must not start with '-'")
    allowlist_raw = os.environ.get("LINUX_INFO_HOSTS", "").strip()
    if allowlist_raw:
        allowlist = [h.strip() for h in allowlist_raw.split(",") if h.strip()]
        if host not in allowlist:
            raise ValueError(f"host {host!r} not in LINUX_INFO_HOSTS allowlist")
    return host


def validate_path(path: str, label: str = "path") -> str:
    if not isinstance(path, str) or not path:
        raise ValueError(f"{label} must be a non-empty string")
    _reject_unsafe_chars(path, label)
    return path


def validate_grep_pattern(pattern: str) -> str:
    if not isinstance(pattern, str):
        raise ValueError("grep_pattern must be a string")
    _reject_unsafe_chars(pattern, "grep_pattern")
    return pattern


def validate_grep_flags(flags):
    if flags is None:
        return []
    if not isinstance(flags, list):
        raise ValueError("grep_flags must be a list")
    out = []
    for f in flags:
        if not isinstance(f, str):
            raise ValueError("grep_flags entries must be strings")
        if f in GREP_FLAG_WHITELIST or _GREP_CONTEXT_RE.match(f):
            out.append(f)
        else:
            raise ValueError(f"grep flag not allowed: {f!r}")
    return out


def validate_find_args(
    *,
    name=None,
    iname=None,
    type=None,
    maxdepth=None,
    mindepth=None,
    mtime=None,
    size=None,
    path_glob=None,
):
    out = {}
    for label, val in (("name", name), ("iname", iname), ("path_glob", path_glob)):
        if val is not None:
            if not isinstance(val, str):
                raise ValueError(f"{label} must be a string")
            _reject_unsafe_chars(val, label)
            out[label] = val
    if type is not None:
        if not isinstance(type, str) or type not in FIND_TYPE_WHITELIST:
            raise ValueError(f"type must be one of {sorted(FIND_TYPE_WHITELIST)}")
        out["type"] = type
    for label, val in (("maxdepth", maxdepth), ("mindepth", mindepth)):
        if val is not None:
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValueError(f"{label} must be a non-negative int")
            out[label] = val
    if mtime is not None:
        if not isinstance(mtime, str) or not _MTIME_RE.match(mtime):
            raise ValueError("mtime must match ^[+-]?\\d+$")
        out["mtime"] = mtime
    if size is not None:
        if not isinstance(size, str) or not _SIZE_RE.match(size):
            raise ValueError("size must match ^[+-]?\\d+[bcwkMG]?$")
        out["size"] = size
    return out


def validate_unit_name(name: str, label: str = "unit") -> str:
    """systemd unit name / journalctl identifier. Alphanumerics + @ : . _ -, length <= 256."""
    if not isinstance(name, str) or not name:
        raise ValueError(f"{label} must be a non-empty string")
    if len(name) > 256:
        raise ValueError(f"{label} must be at most 256 characters")
    _reject_unsafe_chars(name, label)
    if name.startswith("-"):
        raise ValueError(f"{label} must not start with '-'")
    if not _UNIT_NAME_RE.fullmatch(name):
        raise ValueError(f"{label} contains characters outside [A-Za-z0-9@:._-]")
    return name


def validate_lines_int(value, *, lo: int, hi: int, label: str = "lines") -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an int")
    if value < lo or value > hi:
        raise ValueError(f"{label} must be in range [{lo}, {hi}]")
    return value


def binary_length_cap(max_bytes: int) -> int:
    """Max raw bytes whose base64 encoding (plus margin) fits within max_bytes stdout cap.

    base64(N bytes) = ceil(N/3)*4 chars, plus possible newlines from `base64` wrap.
    Reserve 64 bytes for safety margin (newlines, trailing whitespace).
    """
    return max((max_bytes - 64) * 3 // 4, 1)


def validate_offset_length(offset: int, length: int, max_bytes: int):
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("offset must be a non-negative int")
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        raise ValueError("length must be a positive int")
    cap = binary_length_cap(max_bytes)
    if length > cap:
        raise ValueError(
            f"length {length} exceeds binary read cap {cap} "
            f"(derived from LINUX_INFO_MAX_BYTES={max_bytes})"
        )
    return offset, length
