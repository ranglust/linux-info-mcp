"""Per-tool registration. Each module exports TOOLS: list[ToolSpec]."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], dict]
