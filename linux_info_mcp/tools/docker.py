"""Docker tools: docker_ps, docker_inspect, docker_images."""
from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh
from ..validate import (
    _reject_unsafe_chars,
    validate_grep_flags,
    validate_grep_pattern,
    validate_host,
    validate_lines_int,
)
from . import ToolSpec


def _decode_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _bool(value, label: str) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a bool")
    return value


_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
_FILTER_VAL_RE = re.compile(r"^[A-Za-z0-9._:/=@+-]{1,256}$")


def _validate_ref(value, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if value.startswith("-"):
        raise ValueError(f"{label} must not start with '-'")
    _reject_unsafe_chars(value, label)
    if not _REF_RE.fullmatch(value):
        raise ValueError(f"{label} contains characters outside [A-Za-z0-9._:/@+-]: {value!r}")
    return value


def _validate_filter_value(value, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} value must be a non-empty string")
    if value.startswith("-"):
        raise ValueError(f"{label} value must not start with '-'")
    _reject_unsafe_chars(value, label)
    if not _FILTER_VAL_RE.fullmatch(value):
        raise ValueError(f"{label} value contains characters outside whitelist: {value!r}")
    return value


def _validate_filters(filters, allowed_keys: set[str]) -> list[tuple[str, str]]:
    if filters is None:
        return []
    if not isinstance(filters, dict):
        raise ValueError("filter must be an object")
    out: list[tuple[str, str]] = []
    for k, v in filters.items():
        if not isinstance(k, str) or k not in allowed_keys:
            raise ValueError(f"filter key not allowed: {k!r}")
        if isinstance(v, list):
            for item in v:
                out.append((k, _validate_filter_value(item, f"filter[{k}]")))
        else:
            out.append((k, _validate_filter_value(v, f"filter[{k}]")))
    return out


# ---------------------------------------------------------------------------
# docker_ps
# ---------------------------------------------------------------------------

_PS_FORMAT_MAP = {"table": None, "json": "--format=json"}
_PS_FILTER_KEYS = {
    "ancestor", "before", "exited", "health", "id", "is-task",
    "label", "name", "network", "publish", "expose", "since",
    "status", "volume",
}


def _validate_ps_format(fmt) -> str | None:
    if fmt is None:
        return None
    if not isinstance(fmt, str) or fmt not in _PS_FORMAT_MAP:
        raise ValueError(f"format must be one of {sorted(_PS_FORMAT_MAP)}")
    return _PS_FORMAT_MAP[fmt]


def build_remote_cmd_docker_ps(
    *,
    all: bool = False,
    size: bool = False,
    latest: bool = False,
    last: int | None = None,
    quiet: bool = False,
    no_trunc: bool = False,
    format_flag: str | None = None,
    filters: list[tuple[str, str]] | None = None,
) -> str:
    """Build LC_ALL=C docker ps command string."""
    if all and latest:
        raise ValueError("all and latest are mutually exclusive")
    if all and last is not None:
        raise ValueError("all and last are mutually exclusive")
    if latest and last is not None:
        raise ValueError("latest and last are mutually exclusive")
    parts = ["LC_ALL=C", "docker", "ps"]
    if all:
        parts.append("-a")
    if size:
        parts.append("-s")
    if latest:
        parts.append("-l")
    if last is not None:
        parts += ["-n", str(last)]
    if quiet:
        parts.append("-q")
    if no_trunc:
        parts.append("--no-trunc")
    if format_flag is not None:
        parts.append(format_flag)
    for k, v in filters or []:
        parts += ["--filter", shlex.quote(f"{k}={v}")]
    return " ".join(parts)


def handle_docker_ps(args: dict) -> dict:
    host = validate_host(args["host"])
    last = args.get("last")
    if last is not None:
        last = validate_lines_int(last, lo=1, hi=1000, label="last")
    fmt = _validate_ps_format(args.get("format"))
    filters = _validate_filters(args.get("filter"), _PS_FILTER_KEYS)
    cmd = build_remote_cmd_docker_ps(
        all=_bool(args.get("all"), "all"),
        size=_bool(args.get("size"), "size"),
        latest=_bool(args.get("latest"), "latest"),
        last=last,
        quiet=_bool(args.get("quiet"), "quiet"),
        no_trunc=_bool(args.get("no_trunc"), "no_trunc"),
        format_flag=fmt,
        filters=filters,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


DOCKER_PS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "all": {"type": ["boolean", "null"]},
        "size": {"type": ["boolean", "null"]},
        "latest": {"type": ["boolean", "null"]},
        "last": {"type": ["integer", "null"]},
        "quiet": {"type": ["boolean", "null"]},
        "no_trunc": {"type": ["boolean", "null"]},
        "format": {"type": ["string", "null"]},
        "filter": {"type": ["object", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# docker_inspect
# ---------------------------------------------------------------------------

_INSPECT_TYPES = {
    "container", "image", "network", "volume",
    "service", "node", "plugin", "secret", "task",
}
_INSPECT_FORMAT_MAP = {
    "json": None,
    "id": "--format={{.Id}}",
    "name": "--format={{.Name}}",
}


def _validate_inspect_type(t) -> str | None:
    if t is None:
        return None
    if not isinstance(t, str) or t not in _INSPECT_TYPES:
        raise ValueError(f"type must be one of {sorted(_INSPECT_TYPES)}")
    return t


def _validate_inspect_format(fmt) -> str | None:
    if fmt is None:
        return None
    if not isinstance(fmt, str) or fmt not in _INSPECT_FORMAT_MAP:
        raise ValueError(f"format must be one of {sorted(_INSPECT_FORMAT_MAP)}")
    return _INSPECT_FORMAT_MAP[fmt]


def _validate_targets(targets) -> list[str]:
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets must be a non-empty list")
    if len(targets) > 100:
        raise ValueError("targets must contain at most 100 entries")
    return [_validate_ref(t, "targets entry") for t in targets]


def build_remote_cmd_docker_inspect(
    *,
    targets: list[str],
    type_: str | None = None,
    format_flag: str | None = None,
    size: bool = False,
) -> str:
    """Build LC_ALL=C docker inspect command string."""
    parts = ["LC_ALL=C", "docker", "inspect"]
    if type_ is not None:
        parts.append(f"--type={shlex.quote(type_)}")
    if format_flag is not None:
        parts.append(format_flag)
    if size:
        parts.append("-s")
    parts.append("--")
    for t in targets:
        parts.append(shlex.quote(t))
    return " ".join(parts)


def handle_docker_inspect(args: dict) -> dict:
    host = validate_host(args["host"])
    targets = _validate_targets(args.get("targets"))
    type_ = _validate_inspect_type(args.get("type"))
    fmt = _validate_inspect_format(args.get("format"))
    cmd = build_remote_cmd_docker_inspect(
        targets=targets,
        type_=type_,
        format_flag=fmt,
        size=_bool(args.get("size"), "size"),
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


DOCKER_INSPECT_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "targets": {"type": "array", "items": {"type": "string"}},
        "type": {"type": ["string", "null"]},
        "format": {"type": ["string", "null"]},
        "size": {"type": ["boolean", "null"]},
    },
    "required": ["host", "targets"],
}


# ---------------------------------------------------------------------------
# docker_images
# ---------------------------------------------------------------------------

_IMAGES_FORMAT_MAP = {"table": None, "json": "--format=json"}
_IMAGES_FILTER_KEYS = {"dangling", "label", "before", "since", "reference"}


def _validate_images_format(fmt) -> str | None:
    if fmt is None:
        return None
    if not isinstance(fmt, str) or fmt not in _IMAGES_FORMAT_MAP:
        raise ValueError(f"format must be one of {sorted(_IMAGES_FORMAT_MAP)}")
    return _IMAGES_FORMAT_MAP[fmt]


def build_remote_cmd_docker_images(
    *,
    all: bool = False,
    digests: bool = False,
    quiet: bool = False,
    no_trunc: bool = False,
    format_flag: str | None = None,
    filters: list[tuple[str, str]] | None = None,
    repository: str | None = None,
) -> str:
    """Build LC_ALL=C docker images command string."""
    parts = ["LC_ALL=C", "docker", "images"]
    if all:
        parts.append("-a")
    if digests:
        parts.append("--digests")
    if quiet:
        parts.append("-q")
    if no_trunc:
        parts.append("--no-trunc")
    if format_flag is not None:
        parts.append(format_flag)
    for k, v in filters or []:
        parts += ["--filter", shlex.quote(f"{k}={v}")]
    if repository is not None:
        parts.append("--")
        parts.append(shlex.quote(repository))
    return " ".join(parts)


def handle_docker_images(args: dict) -> dict:
    host = validate_host(args["host"])
    fmt = _validate_images_format(args.get("format"))
    filters = _validate_filters(args.get("filter"), _IMAGES_FILTER_KEYS)
    repository = args.get("repository")
    if repository is not None:
        repository = _validate_ref(repository, "repository")
    cmd = build_remote_cmd_docker_images(
        all=_bool(args.get("all"), "all"),
        digests=_bool(args.get("digests"), "digests"),
        quiet=_bool(args.get("quiet"), "quiet"),
        no_trunc=_bool(args.get("no_trunc"), "no_trunc"),
        format_flag=fmt,
        filters=filters,
        repository=repository,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


DOCKER_IMAGES_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "all": {"type": ["boolean", "null"]},
        "digests": {"type": ["boolean", "null"]},
        "quiet": {"type": ["boolean", "null"]},
        "no_trunc": {"type": ["boolean", "null"]},
        "format": {"type": ["string", "null"]},
        "filter": {"type": ["object", "null"]},
        "repository": {"type": ["string", "null"]},
    },
    "required": ["host"],
}


# ---------------------------------------------------------------------------
# docker_logs
# ---------------------------------------------------------------------------


def _validate_logs_time(s, label: str) -> str:
    if not isinstance(s, str) or not s:
        raise ValueError(f"{label} must be a non-empty string")
    _reject_unsafe_chars(s, label)
    if len(s) > 128:
        raise ValueError(f"{label} must be at most 128 characters")
    return s


def build_remote_cmd_docker_logs(
    *,
    container: str,
    tail: int = 100,
    since: str | None = None,
    until: str | None = None,
    timestamps: bool = False,
    grep_pattern: str | None = None,
    grep_flags: list[str] | None = None,
) -> str:
    """Build LC_ALL=C docker logs command string."""
    parts = ["LC_ALL=C", "docker", "logs", "--tail", shlex.quote(str(tail))]
    if since is not None:
        parts.append(f"--since={shlex.quote(since)}")
    if until is not None:
        parts.append(f"--until={shlex.quote(until)}")
    if timestamps:
        parts.append("--timestamps")
    parts += ["--", shlex.quote(container)]
    cmd = " ".join(parts)
    if grep_pattern is not None:
        grep_parts = ["2>&1", "|", "grep"]
        for f in grep_flags or []:
            grep_parts.append(shlex.quote(f))
        grep_parts += ["--", shlex.quote(grep_pattern)]
        cmd += " " + " ".join(grep_parts)
    return cmd


def handle_docker_logs(args: dict) -> dict:
    host = validate_host(args["host"])
    container = _validate_ref(args.get("container"), "container")
    tail_in = args.get("tail")
    tail = (
        100
        if tail_in is None
        else validate_lines_int(tail_in, lo=1, hi=10000, label="tail")
    )
    since_in = args.get("since")
    since = _validate_logs_time(since_in, "since") if since_in is not None else None
    until_in = args.get("until")
    until = _validate_logs_time(until_in, "until") if until_in is not None else None
    timestamps = _bool(args.get("timestamps"), "timestamps")
    grep_in = args.get("grep_pattern")
    grep_pattern = validate_grep_pattern(grep_in) if grep_in is not None else None
    grep_flags = validate_grep_flags(args.get("grep_flags"))
    if grep_pattern is None and grep_flags:
        raise ValueError("grep_flags requires grep_pattern")
    cmd = build_remote_cmd_docker_logs(
        container=container,
        tail=tail,
        since=since,
        until=until,
        timestamps=timestamps,
        grep_pattern=grep_pattern,
        grep_flags=grep_flags,
    )
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
    }


DOCKER_LOGS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "container": {"type": "string"},
        "tail": {"type": ["integer", "null"]},
        "since": {"type": ["string", "null"]},
        "until": {"type": ["string", "null"]},
        "timestamps": {"type": ["boolean", "null"]},
        "grep_pattern": {"type": ["string", "null"]},
        "grep_flags": {"type": ["array", "null"], "items": {"type": "string"}},
    },
    "required": ["host", "container"],
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="docker_ps",
        description=(
            "List Docker containers on a remote host via SSH (read-only). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=DOCKER_PS_SCHEMA,
        handler=handle_docker_ps,
    ),
    ToolSpec(
        name="docker_inspect",
        description=(
            "Inspect Docker containers/images/networks/volumes on a remote host via SSH (read-only). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=DOCKER_INSPECT_SCHEMA,
        handler=handle_docker_inspect,
    ),
    ToolSpec(
        name="docker_images",
        description=(
            "List Docker images on a remote host via SSH (read-only). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=DOCKER_IMAGES_SCHEMA,
        handler=handle_docker_images,
    ),
    ToolSpec(
        name="docker_logs",
        description=(
            "Tail Docker container logs on a remote host via SSH (read-only). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=DOCKER_LOGS_SCHEMA,
        handler=handle_docker_logs,
    ),
]
