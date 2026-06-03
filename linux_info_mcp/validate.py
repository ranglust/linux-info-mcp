"""Pure validators. Each raises ValueError on bad input."""

from __future__ import annotations

import os
import re

HARD_MAX_HOSTS = 25
DEFAULT_MAX_HOSTS = 10
DEFAULT_PARALLELISM = 4

OUTPUT_MODES: frozenset[str] = frozenset({"raw", "parsed", "both"})

GREP_FLAG_WHITELIST = {"-i", "-E", "-v", "-n", "-w", "-F"}
_GREP_CONTEXT_RE = re.compile(r"^-C[1-9]$")
FIND_TYPE_WHITELIST = {"f", "d", "l", "b", "c", "p", "s"}
_MTIME_RE = re.compile(r"^[+-]?\d+$")
_SIZE_RE = re.compile(r"^[+-]?\d+[bcwkMG]?$")
_UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9@:._-]+$")
_CGROUP_PATH_RE = re.compile(r"^[A-Za-z0-9._:@/\-]+$")


def reject_unsafe_chars(value: str, label: str) -> None:
    if "\x00" in value:
        raise ValueError(f"{label} contains NUL byte")
    if "\n" in value or "\r" in value:
        raise ValueError(f"{label} contains newline")


def validate_host(host: str) -> str:
    if not isinstance(host, str) or not host:
        raise ValueError("host must be a non-empty string")
    reject_unsafe_chars(host, "host")
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


def effective_max_hosts() -> int:
    """Per-call host-list cap. LINUX_INFO_MAX_HOSTS (default 10), clamped to [1, HARD_MAX_HOSTS]."""
    raw = os.environ.get("LINUX_INFO_MAX_HOSTS", "").strip()
    if not raw:
        limit = DEFAULT_MAX_HOSTS
    else:
        try:
            limit = int(raw)
        except ValueError:
            limit = DEFAULT_MAX_HOSTS
        if limit < 1:
            limit = DEFAULT_MAX_HOSTS
    return min(limit, HARD_MAX_HOSTS)


def parallelism() -> int:
    """Fan-out worker count. LINUX_INFO_PARALLELISM (default 4), clamped to [1, HARD_MAX_HOSTS]."""
    raw = os.environ.get("LINUX_INFO_PARALLELISM", "").strip()
    if not raw:
        return DEFAULT_PARALLELISM
    try:
        n = int(raw)
    except ValueError:
        return DEFAULT_PARALLELISM
    if n < 1:
        return DEFAULT_PARALLELISM
    return min(n, HARD_MAX_HOSTS)


def validate_host_list(hosts) -> list[str]:
    """Validate a list of hosts; dedupe preserving order. Count checked before dedupe."""
    if not isinstance(hosts, list):
        raise ValueError("hosts must be a list of strings")
    if not hosts:
        raise ValueError("hosts must be a non-empty list")
    limit = effective_max_hosts()
    if len(hosts) > limit:
        raise ValueError(
            f"hosts count {len(hosts)} exceeds limit {limit} "
            f"(LINUX_INFO_MAX_HOSTS, hard max {HARD_MAX_HOSTS})"
        )
    out: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        vh = validate_host(h)
        if vh not in seen:
            seen.add(vh)
            out.append(vh)
    return out


def resolve_target_hosts(args) -> tuple[list[str], bool]:
    """Return (hosts, is_multi). is_multi True when caller passed `hosts`. Mutually exclusive with `host`."""
    has_hosts = isinstance(args, dict) and args.get("hosts") is not None
    has_host = isinstance(args, dict) and args.get("host") is not None
    if has_hosts and has_host:
        raise ValueError("provide either 'host' or 'hosts', not both")
    if has_hosts:
        return validate_host_list(args["hosts"]), True
    if has_host:
        return [validate_host(args["host"])], False
    raise ValueError("missing required 'host' (or 'hosts')")


def validate_path(path: str, label: str = "path") -> str:
    if not isinstance(path, str) or not path:
        raise ValueError(f"{label} must be a non-empty string")
    reject_unsafe_chars(path, label)
    if path.startswith("-"):
        raise ValueError(f"{label} must not start with '-'")
    return path


def validate_grep_pattern(pattern: str) -> str:
    if not isinstance(pattern, str):
        raise ValueError("grep_pattern must be a string")
    reject_unsafe_chars(pattern, "grep_pattern")
    return pattern


def validate_grep_flags(flags) -> list[str]:
    if flags is None:
        return []
    if not isinstance(flags, list):
        raise ValueError("grep_flags must be a list")
    out: list[str] = []
    for f in flags:
        if not isinstance(f, str):
            raise ValueError("grep_flags entries must be strings")
        reject_unsafe_chars(f, "grep_flags entry")
        if f in GREP_FLAG_WHITELIST or _GREP_CONTEXT_RE.fullmatch(f):
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
            reject_unsafe_chars(val, label)
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
        if not isinstance(mtime, str) or not _MTIME_RE.fullmatch(mtime):
            raise ValueError("mtime must match ^[+-]?\\d+$")
        out["mtime"] = mtime
    if size is not None:
        if not isinstance(size, str) or not _SIZE_RE.fullmatch(size):
            raise ValueError("size must match ^[+-]?\\d+[bcwkMG]?$")
        out["size"] = size
    return out


def validate_unit_name(name: str, label: str = "unit") -> str:
    """systemd unit name / journalctl identifier. Alphanumerics + @ : . _ -, length <= 256."""
    if not isinstance(name, str) or not name:
        raise ValueError(f"{label} must be a non-empty string")
    if len(name) > 256:
        raise ValueError(f"{label} must be at most 256 characters")
    reject_unsafe_chars(name, label)
    if name.startswith("-"):
        raise ValueError(f"{label} must not start with '-'")
    if not _UNIT_NAME_RE.fullmatch(name):
        raise ValueError(f"{label} contains characters outside [A-Za-z0-9@:._-]")
    return name


def validate_int_in_range(value, *, lo: int, hi: int, label: str = "value") -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an int")
    if value < lo or value > hi:
        raise ValueError(f"{label} must be in range [{lo}, {hi}]")
    return value


def binary_length_cap(max_bytes: int) -> int:
    """Max raw bytes whose base64 encoding fits within max_bytes (assumes `base64 -w 0`)."""
    return max((max_bytes - 8) * 3 // 4, 1)


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


def validate_output_mode(value: object) -> str:
    """Strict response-shape mode. Exactly raw/parsed/both; no case-folding."""
    if not isinstance(value, str):
        raise ValueError("output_mode must be a string")
    if value not in OUTPUT_MODES:
        raise ValueError(f"output_mode {value!r} invalid; must be one of {sorted(OUTPUT_MODES)}")
    return value


def resolve_output_mode(args) -> str:
    """Effective output mode. Env overrides arg; both validated. Default 'raw'."""
    arg = args.get("output_mode") if isinstance(args, dict) else None
    if arg is not None:
        validate_output_mode(arg)  # always validate — reject junk even if env wins
    env = os.environ.get("LINUX_INFO_OUTPUT_MODE", "").strip()
    if env:
        return validate_output_mode(env)
    if arg is not None:
        return arg
    return "raw"


def validate_cgroup_path(path: str, label: str = "cgroup_path") -> str:
    """Relative cgroup path under /sys/fs/cgroup. Traversal-safe; no leading slash, no '..'."""
    if not isinstance(path, str) or not path:
        raise ValueError(f"{label} must be a non-empty string")
    if len(path) > 1024:
        raise ValueError(f"{label} must be at most 1024 characters")
    reject_unsafe_chars(path, label)
    if path.startswith("/"):
        raise ValueError(f"{label} must not start with '/'")
    if path.startswith("-"):
        raise ValueError(f"{label} must not start with '-'")
    if not _CGROUP_PATH_RE.fullmatch(path):
        raise ValueError(f"{label} contains characters outside [A-Za-z0-9._:@/-]")
    if ".." in path.split("/"):
        raise ValueError(f"{label} must not contain '..' path segments")
    return path
