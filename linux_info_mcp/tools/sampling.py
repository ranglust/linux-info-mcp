"""Sampling/reporting perf tools: atop, sar, pmrep."""

from __future__ import annotations

import re
import shlex

from ..ssh import run_ssh, sudo_tokens
from ..validate import validate_host, validate_int_in_range, validate_path
from . import ToolSpec
from ._common import decode_text as _decode_text

_TIME_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?$")


def _validate_time(value, label: str) -> str:
    if not isinstance(value, str) or not _TIME_RE.fullmatch(value):
        raise ValueError(f"{label} must be HH:MM or HH:MM:SS")
    return value


def _result(res) -> dict:
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


# ---------------------------------------------------------------------------
# sar
# ---------------------------------------------------------------------------

_SAR_METRIC_MAP = {
    "cpu": ["-u"],
    "mem": ["-r"],
    "io": ["-b"],
    "net-dev": ["-n", "DEV"],
    "net-edev": ["-n", "EDEV"],
    "net-sock": ["-n", "SOCK"],
    "disk": ["-d", "-p"],
    "load": ["-q"],
    "swap": ["-W"],
    "paging": ["-B"],
    "ctxt": ["-w"],
}


def _validate_sar_metrics(metrics) -> list[str]:
    if metrics is None:
        return ["-u"]
    if not isinstance(metrics, list) or not metrics:
        raise ValueError("metrics must be a non-empty list")
    for m in metrics:
        if not isinstance(m, str) or (m != "all" and m not in _SAR_METRIC_MAP):
            raise ValueError(f"metrics entry must be one of {sorted([*_SAR_METRIC_MAP, 'all'])}")
    if "all" in metrics:
        return ["-A"]
    flags: list[str] = []
    seen: set[str] = set()
    for m in metrics:
        if m in seen:
            continue
        seen.add(m)
        flags += _SAR_METRIC_MAP[m]
    return flags


def build_remote_cmd_sar(
    *,
    metric_flags: list[str],
    file: str | None = None,
    start: str | None = None,
    end: str | None = None,
    interval: int | None = None,
    count: int | None = None,
) -> str:
    """Build LC_ALL=C sar command string."""
    if count is not None and interval is None:
        raise ValueError("count requires interval")
    if file is not None and (interval is not None or count is not None):
        raise ValueError("interval/count are for live sampling; not allowed with file")
    if (start is not None or end is not None) and file is None:
        raise ValueError("start/end require file")
    parts = ["LC_ALL=C", *sudo_tokens(), "sar", *metric_flags]
    if file is not None:
        parts += ["-f", shlex.quote(file)]
    if start is not None:
        parts += ["-s", shlex.quote(start)]
    if end is not None:
        parts += ["-e", shlex.quote(end)]
    if interval is not None:
        parts.append(str(interval))
        if count is not None:
            parts.append(str(count))
    return " ".join(parts)


def handle_sar(args: dict) -> dict:
    host = validate_host(args["host"])
    metric_flags = _validate_sar_metrics(args.get("metrics"))
    file = args.get("file")
    if file is not None:
        file = validate_path(file, label="file")
    start = args.get("start")
    if start is not None:
        start = _validate_time(start, "start")
    end = args.get("end")
    if end is not None:
        end = _validate_time(end, "end")
    interval = args.get("interval")
    if interval is not None:
        interval = validate_int_in_range(interval, lo=1, hi=60, label="interval")
    count = args.get("count")
    if count is not None:
        count = validate_int_in_range(count, lo=1, hi=100, label="count")
    cmd = build_remote_cmd_sar(
        metric_flags=metric_flags,
        file=file,
        start=start,
        end=end,
        interval=interval,
        count=count,
    )
    return _result(run_ssh(host, cmd))


SAR_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "metrics": {
            "type": ["array", "null"],
            "items": {"enum": [*_SAR_METRIC_MAP, "all"]},
        },
        "file": {"type": ["string", "null"]},
        "start": {"type": ["string", "null"]},
        "end": {"type": ["string", "null"]},
        "interval": {"type": ["integer", "null"]},
        "count": {"type": ["integer", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# atop
# ---------------------------------------------------------------------------

_ATOP_MODE_MAP = {
    "general": "-g",
    "memory": "-m",
    "disk": "-d",
    "network": "-n",
    "command": "-c",
    "scheduling": "-s",
    "various": "-v",
}

_ATOP_LABELS = {
    "CPU",
    "CPL",
    "MEM",
    "SWP",
    "PAG",
    "PSI",
    "LVM",
    "MDD",
    "DSK",
    "NFM",
    "NFC",
    "NFS",
    "NET",
    "PRG",
    "PRC",
    "PRM",
    "PRD",
    "PRN",
    "PRE",
    "ALL",
}


def _validate_atop_view(mode, labels) -> list[str]:
    if mode is not None and labels is not None:
        raise ValueError("mode and labels are mutually exclusive")
    if mode is not None:
        if not isinstance(mode, str) or mode not in _ATOP_MODE_MAP:
            raise ValueError(f"mode must be one of {sorted(_ATOP_MODE_MAP)}")
        return [_ATOP_MODE_MAP[mode]]
    if labels is not None:
        if not isinstance(labels, list) or not labels:
            raise ValueError("labels must be a non-empty list")
        for lbl in labels:
            if not isinstance(lbl, str) or lbl not in _ATOP_LABELS:
                raise ValueError(f"labels entry must be one of {sorted(_ATOP_LABELS)}")
        return ["-P", ",".join(labels)]
    return []


def build_remote_cmd_atop(
    *,
    view_tokens: list[str],
    file: str | None = None,
    begin: str | None = None,
    end: str | None = None,
    interval: int | None = None,
    count: int | None = None,
) -> str:
    """Build LC_ALL=C atop command string."""
    if file is not None and (interval is not None or count is not None):
        raise ValueError("interval/count are for live sampling; not allowed with file")
    if (begin is not None or end is not None) and file is None:
        raise ValueError("begin/end require file")
    parts = ["LC_ALL=C", *sudo_tokens(), "atop"]
    if file is not None:
        parts += ["-r", shlex.quote(file)]
        parts += view_tokens
        if begin is not None:
            parts += ["-b", shlex.quote(begin)]
        if end is not None:
            parts += ["-e", shlex.quote(end)]
    else:
        parts += view_tokens
        live_interval = 1 if interval is None else interval
        live_count = 1 if count is None else count
        parts += [str(live_interval), str(live_count)]
    return " ".join(parts)


def handle_atop(args: dict) -> dict:
    host = validate_host(args["host"])
    view_tokens = _validate_atop_view(args.get("mode"), args.get("labels"))
    file = args.get("file")
    if file is not None:
        file = validate_path(file, label="file")
    begin = args.get("begin")
    if begin is not None:
        begin = _validate_time(begin, "begin")
    end = args.get("end")
    if end is not None:
        end = _validate_time(end, "end")
    interval = args.get("interval")
    if interval is not None:
        interval = validate_int_in_range(interval, lo=1, hi=60, label="interval")
    count = args.get("count")
    if count is not None:
        count = validate_int_in_range(count, lo=1, hi=100, label="count")
    cmd = build_remote_cmd_atop(
        view_tokens=view_tokens,
        file=file,
        begin=begin,
        end=end,
        interval=interval,
        count=count,
    )
    return _result(run_ssh(host, cmd))


ATOP_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "mode": {"type": ["string", "null"], "enum": [*_ATOP_MODE_MAP, None]},
        "labels": {"type": ["array", "null"], "items": {"enum": sorted(_ATOP_LABELS)}},
        "file": {"type": ["string", "null"]},
        "begin": {"type": ["string", "null"]},
        "end": {"type": ["string", "null"]},
        "interval": {"type": ["integer", "null"]},
        "count": {"type": ["integer", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# pmrep
# ---------------------------------------------------------------------------

_PMREP_CONFIG_MAP = {
    "vmstat": ":vmstat",
    "iostat": ":iostat",
    "mpstat": ":mpstat",
    "pidstat": ":pidstat",
    "free": ":free",
    "sar": ":sar",
    "tcp": ":tcp",
}


def _validate_pmrep_config(config) -> str:
    if config is None:
        return _PMREP_CONFIG_MAP["vmstat"]
    if not isinstance(config, str) or config not in _PMREP_CONFIG_MAP:
        raise ValueError(f"config must be one of {sorted(_PMREP_CONFIG_MAP)}")
    return _PMREP_CONFIG_MAP[config]


def build_remote_cmd_pmrep(
    *,
    config: str,
    interval: int = 1,
    samples: int = 1,
    archive: str | None = None,
) -> str:
    """Build LC_ALL=C pmrep command string."""
    parts = ["LC_ALL=C", *sudo_tokens(), "pmrep"]
    if archive is not None:
        parts += ["-a", shlex.quote(archive)]
    parts += ["-t", str(interval), "-s", str(samples), config]
    return " ".join(parts)


def handle_pmrep(args: dict) -> dict:
    host = validate_host(args["host"])
    config = _validate_pmrep_config(args.get("config"))
    interval = args.get("interval")
    interval = (
        1 if interval is None else validate_int_in_range(interval, lo=1, hi=60, label="interval")
    )
    samples = args.get("samples")
    samples = (
        1 if samples is None else validate_int_in_range(samples, lo=1, hi=100, label="samples")
    )
    archive = args.get("archive")
    if archive is not None:
        archive = validate_path(archive, label="archive")
    cmd = build_remote_cmd_pmrep(config=config, interval=interval, samples=samples, archive=archive)
    return _result(run_ssh(host, cmd))


PMREP_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "config": {"type": ["string", "null"], "enum": [*_PMREP_CONFIG_MAP, None]},
        "interval": {"type": ["integer", "null"]},
        "samples": {"type": ["integer", "null"]},
        "archive": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="atop",
        description=(
            "Run atop on a remote host via SSH. Live parseable/display sampling, or replay a "
            "raw log (file) with an optional begin/end time window. mode (general|memory|disk|"
            "network|command|scheduling|various) or labels (-P) are mutually exclusive. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=ATOP_SCHEMA,
        handler=handle_atop,
    ),
    ToolSpec(
        name="sar",
        description=(
            "Run sar (sysstat) on a remote host via SSH. metrics select subsystems "
            "(cpu|mem|io|net-dev|net-edev|net-sock|disk|load|swap|paging|ctxt|all). Live sampling "
            "with interval/count, or read a saved sa file with an optional start/end window. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SAR_SCHEMA,
        handler=handle_sar,
    ),
    ToolSpec(
        name="pmrep",
        description=(
            "Run pmrep (PCP) on a remote host via SSH using a preset config "
            "(vmstat|iostat|mpstat|pidstat|free|sar|tcp). interval (-t) and samples (-s), or "
            "replay a PCP archive. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=PMREP_SCHEMA,
        handler=handle_pmrep,
    ),
]
