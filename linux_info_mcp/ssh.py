"""SSH command builders + run_ssh subprocess wrapper."""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import time
from dataclasses import dataclass

from .log import get_logger

_log = get_logger("ssh")

_MUX_OFF = {"0", "false", "no", "off"}


def _mux_opts() -> list[str]:
    """Default OpenSSH connection-multiplexing options. Empty when opted out.

    %C is a fixed-length connection hash, avoiding the ~104-char ControlPath
    socket limit that %r@%h:%p can exceed. Socket lives under $TMPDIR.
    """
    if os.environ.get("LINUX_INFO_SSH_MUX", "").strip().lower() in _MUX_OFF:
        return []
    ctl = os.path.join(tempfile.gettempdir(), "lim-%C")
    return [
        "-o",
        "ControlMaster=auto",
        "-o",
        f"ControlPath={ctl}",
        "-o",
        "ControlPersist=60s",
    ]


def _ssh_argv() -> list[str]:
    cmd = os.environ.get("LINUX_INFO_SSH_CMD", "").strip()
    if cmd:
        return shlex.split(cmd)  # caller owns full argv, including any mux config
    return ["ssh", *_mux_opts()]


def _timeout() -> float:
    return float(os.environ.get("LINUX_INFO_TIMEOUT", "30"))


def max_bytes() -> int:
    return int(os.environ.get("LINUX_INFO_MAX_BYTES", str(1024 * 1024)))


def sudo_enabled() -> bool:
    """True when LINUX_INFO_SUDO opts in to non-interactive sudo for privilege-prone tools."""
    return os.environ.get("LINUX_INFO_SUDO", "").strip().lower() in {"1", "true", "yes", "on"}


def sudo_tokens() -> list[str]:
    """['sudo', '-n'] when enabled, else []. -n never prompts; it fails fast without a tty."""
    return ["sudo", "-n"] if sudo_enabled() else []


def sudo_prefix() -> str:
    """'sudo -n ' when enabled, else ''. For f-string builders that don't use a parts list."""
    return "sudo -n " if sudo_enabled() else ""


@dataclass
class SshResult:
    stdout: bytes
    stderr: bytes
    exit_code: int
    truncated: bool
    duration_ms: float = 0.0
    stderr_truncated: bool = False


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
        parts += ["-maxdepth", shlex.quote(str(predicates["maxdepth"]))]
    if "mindepth" in predicates:
        parts += ["-mindepth", shlex.quote(str(predicates["mindepth"]))]
    if "type" in predicates:
        parts += ["-type", shlex.quote(predicates["type"])]
    if "name" in predicates:
        parts += ["-name", shlex.quote(predicates["name"])]
    if "iname" in predicates:
        parts += ["-iname", shlex.quote(predicates["iname"])]
    if "path_glob" in predicates:
        parts += ["-path", shlex.quote(predicates["path_glob"])]
    if "mtime" in predicates:
        parts += ["-mtime", shlex.quote(predicates["mtime"])]
    if "size" in predicates:
        parts += ["-size", shlex.quote(predicates["size"])]
    return " ".join(parts)


def build_remote_cmd_binary(path: str, offset: int, length: int) -> str:
    qpath = shlex.quote(path)
    return (
        f"LC_ALL=C dd if={qpath} ibs=1 skip={shlex.quote(str(offset))} "
        f"count={shlex.quote(str(length))} status=none | base64 -w 0"
    )


def _read_bounded(pipe, cap: int) -> tuple[bytes, bool]:
    """Read up to cap+1 bytes from pipe; return (bytes[:cap], overflowed)."""
    chunks: list[bytes] = []
    total = 0
    target = cap + 1
    while total < target:
        chunk = pipe.read(min(65536, target - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    data = b"".join(chunks)
    if len(data) > cap:
        return data[:cap], True
    return data, False


def run_ssh(host: str, remote_cmd: str) -> SshResult:
    argv = [*_ssh_argv(), host, "--", remote_cmd]
    cap = max_bytes()
    _log.trace(  # type: ignore[attr-defined]
        "ssh_call_start",
        extra={"host": host, "remote_cmd": remote_cmd},
    )
    t0 = time.perf_counter()
    proc = subprocess.Popen(
        argv,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    timed_out = False
    try:
        import threading

        out_box: dict[str, tuple[bytes, bool]] = {}
        err_box: dict[str, tuple[bytes, bool]] = {}

        def _drain_out():
            assert proc.stdout is not None
            out_box["v"] = _read_bounded(proc.stdout, cap)

        def _drain_err():
            assert proc.stderr is not None
            err_box["v"] = _read_bounded(proc.stderr, cap)

        t_out = threading.Thread(target=_drain_out, daemon=True)
        t_err = threading.Thread(target=_drain_err, daemon=True)
        t_out.start()
        t_err.start()
        try:
            proc.wait(timeout=_timeout())
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            proc.wait()
        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)
        stdout, stdout_over = out_box.get("v", (b"", False))
        stderr, stderr_over = err_box.get("v", (b"", False))
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()

    duration_ms = (time.perf_counter() - t0) * 1000.0
    if timed_out:
        exit_code = 124
        outcome = "timeout"
        stderr = stderr + b"\n[timeout]"
        if len(stderr) > cap:
            stderr = stderr[:cap]
            stderr_over = True
    else:
        exit_code = proc.returncode
        outcome = "ok" if exit_code == 0 else "nonzero"

    result = SshResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        truncated=stdout_over,
        duration_ms=duration_ms,
        stderr_truncated=stderr_over,
    )
    _log.info(
        "ssh_call",
        extra={
            "host": host,
            "exit_code": exit_code,
            "duration_ms": round(duration_ms, 3),
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "truncated": stdout_over,
            "stderr_truncated": stderr_over,
            "outcome": outcome,
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
