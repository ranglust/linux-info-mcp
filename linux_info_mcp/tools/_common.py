"""Shared helpers for tool modules. Not auto-discovered (leading underscore)."""

from __future__ import annotations

import re

from ..validate import reject_unsafe_chars

_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]*\$?$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")


def decode_text(b: bytes) -> str:
    """Decode bytes as UTF-8 with replacement."""
    return b.decode("utf-8", errors="replace")


def validate_bool(value, label: str) -> bool:
    """Coerce optional bool; reject non-bool truthy values like strings."""
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a bool")
    return value


def validate_pid(value, label: str = "pid") -> int:
    """Linux pid_max upper bound + reject bool subclass of int."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an int")
    if value < 1 or value > 4194304:
        raise ValueError(f"{label} must be in range [1, 4194304]")
    return value


def validate_user(value, label: str = "user") -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if len(value) > 32:
        raise ValueError(f"{label} must be at most 32 characters")
    if value.startswith("-"):
        raise ValueError(f"{label} must not start with '-'")
    reject_unsafe_chars(value, label)
    if not _USER_RE.fullmatch(value):
        raise ValueError(f"{label} not a valid username: {value!r}")
    return value


def validate_ref(value, label: str = "ref") -> str:
    """Docker-style reference (container/image/volume name or id)."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if value.startswith("-"):
        raise ValueError(f"{label} must not start with '-'")
    reject_unsafe_chars(value, label)
    if not _REF_RE.fullmatch(value):
        raise ValueError(f"{label} contains characters outside [A-Za-z0-9._:/@+-]: {value!r}")
    return value
