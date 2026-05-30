"""Per-tool registration. Each module exports TOOLS: list[ToolSpec]."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

__all__ = ["ToolSpec"]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], dict]
