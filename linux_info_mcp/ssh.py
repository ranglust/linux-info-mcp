"""SSH command builders + run_ssh subprocess wrapper."""
from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass

from .log import get_logger

_log = get_logger("ssh")


def _ssh_argv() -> list[str]:
    cmd = os.environ.get("LINUX_INFO_SSH_CMD", "ssh").strip()
    return shlex.split(cmd) if cmd else ["ssh"]


def _timeout() -> float:
    return float(os.environ.get("LINUX_INFO_TIMEOUT", "30"))


def max_bytes() -> int:
    return int(os.environ.get("LINUX_INFO_MAX_BYTES", str(1024 * 1024)))


@dataclass
class SshResult:
    stdout: bytes
    stderr: bytes
    exit_code: int
    truncated: bool
    duration_ms: float = 0.0


def build_remote_cmd_read(path: str, grep_pattern: str | None, grep_flags: list[str] | None) -> str:
    qpath = shlex.quote(path)
    if grep_pattern is None:
        return f"LC_ALL=C cat -- {qpath}"
    flags = " ".join(shlex.quote(f) for f in (grep_flags or []))
    qpat = shlex.quote(grep_pattern)
    flags_part = (flags + " ") if flags else ""
    return f"LC_ALL=C cat -- {qpath} | grep {flags_part}-e {qpat} --"


def build_remote_cmd_find(path: str, predicates: dict) -> str:
    parts = ["LC_ALL=C", "find", shlex.quote(path)]
    if "maxdepth" in predicates:
        parts += ["-maxdepth", str(predicates["maxdepth"])]
    if "mindepth" in predicates:
        parts += ["-mindepth", str(predicates["mindepth"])]
    if "type" in predicates:
        parts += ["-type", predicates["type"]]
    if "name" in predicates:
        parts += ["-name", shlex.quote(predicates["name"])]
    if "iname" in predicates:
        parts += ["-iname", shlex.quote(predicates["iname"])]
    if "path_glob" in predicates:
        parts += ["-path", shlex.quote(predicates["path_glob"])]
    if "mtime" in predicates:
        parts += ["-mtime", predicates["mtime"]]
    if "size" in predicates:
        parts += ["-size", predicates["size"]]
    return " ".join(parts)


def build_remote_cmd_binary(path: str, offset: int, length: int) -> str:
    qpath = shlex.quote(path)
    return (
        f"LC_ALL=C dd if={qpath} ibs=1 skip={offset} count={length} status=none | base64"
    )


def run_ssh(host: str, remote_cmd: str) -> SshResult:
    argv = [*_ssh_argv(), host, "--", remote_cmd]
    cap = max_bytes()
    _log.trace(  # type: ignore[attr-defined]
        "ssh_call_start",
        extra={"host": host, "remote_cmd": remote_cmd},
    )
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            timeout=_timeout(),
        )
    except subprocess.TimeoutExpired as e:
        duration_ms = (time.perf_counter() - t0) * 1000.0
        out = e.stdout or b""
        err = e.stderr or b""
        truncated = len(out) >= cap
        if truncated:
            out = out[:cap]
        err = err[:cap] + b"\n[timeout]"
        result = SshResult(
            stdout=out, stderr=err, exit_code=124,
            truncated=truncated, duration_ms=duration_ms,
        )
        _log.info(
            "ssh_call",
            extra={
                "host": host,
                "exit_code": 124,
                "duration_ms": round(duration_ms, 3),
                "stdout_bytes": len(out),
                "stderr_bytes": len(err),
                "truncated": truncated,
                "outcome": "timeout",
            },
        )
        _log.trace(  # type: ignore[attr-defined]
            "ssh_call_io",
            extra={
                "host": host,
                "stdout": out.decode("utf-8", errors="replace"),
                "stderr": err.decode("utf-8", errors="replace"),
            },
        )
        return result
    duration_ms = (time.perf_counter() - t0) * 1000.0
    stdout = proc.stdout or b""
    stderr = proc.stderr or b""
    truncated = len(stdout) >= cap
    if truncated:
        stdout = stdout[:cap]
    if len(stderr) > cap:
        stderr = stderr[:cap]
    result = SshResult(
        stdout=stdout, stderr=stderr, exit_code=proc.returncode,
        truncated=truncated, duration_ms=duration_ms,
    )
    _log.info(
        "ssh_call",
        extra={
            "host": host,
            "exit_code": proc.returncode,
            "duration_ms": round(duration_ms, 3),
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "truncated": truncated,
            "outcome": "ok" if proc.returncode == 0 else "nonzero",
        },
    )
    _log.trace(  # type: ignore[attr-defined]
        "ssh_call_io",
        extra={
            "host": host,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        },
    )
    return result
