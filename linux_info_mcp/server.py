"""MCP server entrypoint. Aggregates ToolSpec lists from each tools/* module."""

from __future__ import annotations

import asyncio
import importlib
import json
import pkgutil
import time

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import tools as tools_pkg
from .log import get_logger, reset_call_ctx, set_call_ctx, setup_logging
from .tools import ToolSpec

_log = get_logger("server")

server = Server("linux-info-mcp")


def _discover_tools() -> dict[str, ToolSpec]:
    """Import every submodule of linux_info_mcp.tools and collect their TOOLS lists."""
    out: dict[str, ToolSpec] = {}
    for mod_info in pkgutil.iter_modules(tools_pkg.__path__):
        if mod_info.name.startswith("_"):
            continue
        mod = importlib.import_module(f"{tools_pkg.__name__}.{mod_info.name}")
        specs = getattr(mod, "TOOLS", None)
        if not specs:
            continue
        for spec in specs:
            if not spec.name:
                raise RuntimeError(f"tool spec missing name in {mod_info.name}")
            if spec.name in out:
                raise RuntimeError(f"duplicate tool name: {spec.name}")
            out[spec.name] = spec
    return out


_TOOLS: dict[str, ToolSpec] = _discover_tools()


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    return [
        types.Tool(name=s.name, description=s.description, inputSchema=s.input_schema)
        for s in _TOOLS.values()
    ]


@server.call_tool()
async def _call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    args = arguments or {}
    host = args.get("host") if isinstance(args, dict) else None
    token = set_call_ctx(name)
    try:
        _log.trace(  # type: ignore[attr-defined]
            "tool_call_in",
            extra={"arguments": args},
        )
        t0 = time.perf_counter()
        spec = _TOOLS.get(name)
        outcome = "ok"
        error_msg: str | None = None
        exit_code: int | None = None
        if spec is None:
            outcome = "unknown_tool"
            error_msg = f"unknown tool: {name}"
            result: dict = {"error": error_msg}
        else:
            try:
                result = await asyncio.to_thread(spec.handler, args)
                if isinstance(result, dict):
                    exit_code = result.get("exit_code")
                    if isinstance(exit_code, int) and exit_code != 0:
                        outcome = "nonzero"
                else:
                    outcome = "handler_error"
                    error_msg = "handler returned non-dict"
                    result = {"error": error_msg}
            except ValueError as e:
                outcome = "validation_error"
                error_msg = str(e)
                result = {"error": error_msg}
            except Exception as e:
                outcome = "handler_error"
                error_msg = f"{type(e).__name__}: {e}"
                result = {"error": error_msg}
        duration_ms = (time.perf_counter() - t0) * 1000.0
        log_extra: dict = {
            "host": host,
            "duration_ms": round(duration_ms, 3),
            "exit_code": exit_code,
            "outcome": outcome,
        }
        if error_msg is not None:
            log_extra["error"] = error_msg
        _log.info("tool_call", extra=log_extra)
        _log.trace(  # type: ignore[attr-defined]
            "tool_call_out",
            extra={"result": result},
        )
        return [types.TextContent(type="text", text=json.dumps(result))]
    finally:
        reset_call_ctx(token)


async def _run() -> None:
    _log.info(
        "server_start",
        extra={"tools": sorted(_TOOLS), "tool_count": len(_TOOLS)},
    )
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
    finally:
        _log.info("server_stop")


def main() -> None:
    setup_logging()
    asyncio.run(_run())


if __name__ == "__main__":
    main()
