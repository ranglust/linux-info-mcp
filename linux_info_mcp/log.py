"""JSON file logging. Disabled unless LINUX_INFO_LOG_FILE is set."""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import uuid
from datetime import UTC, datetime

_call_ctx: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "linux_info_mcp_call_ctx", default=None
)


def set_call_ctx(tool: str) -> contextvars.Token:
    """Set per-call context (tool name, fresh request_id). Returns the reset token."""
    rid = uuid.uuid4().hex[:12]
    return _call_ctx.set({"tool": tool, "request_id": rid})


def reset_call_ctx(token: contextvars.Token) -> None:
    _call_ctx.reset(token)


def get_call_ctx() -> dict:
    return _call_ctx.get() or {}


class _CtxFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "pid"):
            record.pid = os.getpid()
        ctx = _call_ctx.get()
        if ctx:
            for k, v in ctx.items():
                if not hasattr(record, k):
                    setattr(record, k, v)
        return True


TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def _trace(self: logging.Logger, msg: str, *args, **kwargs) -> None:
    if self.isEnabledFor(TRACE):
        self._log(TRACE, msg, args, **kwargs)


logging.Logger.trace = _trace  # type: ignore[attr-defined]


_LEVEL_MAP = {
    "TRACE": TRACE,
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

_STD_LOGRECORD_KEYS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "message",
    "asctime",
    "taskName",
}


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        d = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k not in _STD_LOGRECORD_KEYS and not k.startswith("_"):
                d[k] = v
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d, default=str)


_CONFIGURED = False


def setup_logging() -> None:
    """Configure root logger from env vars. Idempotent. No-op if no log file set."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    log_file = os.environ.get("LINUX_INFO_LOG_FILE", "").strip()
    if not log_file:
        return

    level_raw = os.environ.get("LINUX_INFO_LOG_LEVEL", "INFO").strip().upper()
    level = _LEVEL_MAP.get(level_raw, logging.INFO)

    parent = os.path.dirname(os.path.abspath(log_file))
    if parent:
        os.makedirs(parent, exist_ok=True)

    handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(log_file, 0o600)
    handler.setFormatter(_JsonFormatter())
    handler.addFilter(_CtxFilter())

    root = logging.getLogger("linux_info_mcp")
    root.setLevel(level)
    root.addHandler(handler)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"linux_info_mcp.{name}")


def reset_for_tests() -> None:
    """Test helper: clear handlers and reset configured state."""
    global _CONFIGURED
    _CONFIGURED = False
    root = logging.getLogger("linux_info_mcp")
    for h in list(root.handlers):
        root.removeHandler(h)
        with contextlib.suppress(Exception):
            h.close()
    root.setLevel(logging.WARNING)
