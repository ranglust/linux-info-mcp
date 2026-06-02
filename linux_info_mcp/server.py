"""MCP server entrypoint. Aggregates ToolSpec lists from each tools/* module."""

from __future__ import annotations

import asyncio
import contextvars
import copy
import importlib
import json
import pkgutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import tools as tools_pkg
from .log import get_logger, reset_call_ctx, set_call_ctx, setup_logging
from .tools import ToolSpec
from .validate import (
    DEFAULT_MAX_HOSTS,
    HARD_MAX_HOSTS,
    parallelism,
    resolve_target_hosts,
)

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

_HOSTS_PROP = {
    "type": ["array", "null"],
    "items": {"type": "string"},
    "description": (
        f"Optional list of target hosts to run on in parallel; alternative to `host` "
        f"(mutually exclusive). Up to LINUX_INFO_MAX_HOSTS hosts (default {DEFAULT_MAX_HOSTS}, "
        f"hard max {HARD_MAX_HOSTS}). Returns "
        f"{{multi_host, host_count, results: [{{host, ...}}]}}; per-host failures are isolated."
    ),
}


def _augment_schema(schema: dict) -> dict:
    """Advertise the multi-host `hosts` arg and relax single-`host` requirement."""
    s = copy.deepcopy(schema)
    props = s.setdefault("properties", {})
    if "hosts" not in props:
        props["hosts"] = copy.deepcopy(_HOSTS_PROP)
    req = s.get("required")
    if isinstance(req, list) and "host" in req:
        s["required"] = [r for r in req if r != "host"]
    return s


_AUGMENTED_SCHEMAS: dict[str, dict] = {
    name: _augment_schema(spec.input_schema) for name, spec in _TOOLS.items()
}


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name=s.name,
            description=s.description,
            inputSchema=_AUGMENTED_SCHEMAS.get(s.name, s.input_schema),
        )
        for s in _TOOLS.values()
    ]


def _run_handler_for_host(handler, base_args: dict, host: str) -> dict:
    """Invoke a sync handler for one host; capture errors per host instead of propagating."""
    a = {k: v for k, v in base_args.items() if k != "hosts"}
    a["host"] = host
    try:
        r = handler(a)
    except ValueError as e:
        return {"host": host, "error": str(e), "outcome": "validation_error"}
    except Exception as e:
        return {"host": host, "error": f"{type(e).__name__}: {e}", "outcome": "handler_error"}
    if not isinstance(r, dict):
        return {"host": host, "error": "handler returned non-dict", "outcome": "handler_error"}
    return {"host": host, **r}


def _run_multi_host(handler, base_args: dict, hosts: list[str]) -> list[dict]:
    """Fan a handler across hosts in a bounded thread pool. Results keep `hosts` order."""
    workers = max(1, min(parallelism(), len(hosts)))
    results: list[dict] = [{} for _ in hosts]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fut_to_idx = {}
        for i, h in enumerate(hosts):
            ctx = contextvars.copy_context()
            fut = ex.submit(ctx.run, _run_handler_for_host, handler, base_args, h)
            fut_to_idx[fut] = i
        for fut in as_completed(fut_to_idx):
            results[fut_to_idx[fut]] = fut.result()
    return results


def _multi_host_failed(per: list[dict]) -> int:
    """Count per-host entries that errored or returned a non-zero exit code."""
    bad = 0
    for r in per:
        if r.get("error") is not None:
            bad += 1
            continue
        ec = r.get("exit_code")
        if isinstance(ec, int) and ec != 0:
            bad += 1
    return bad


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
        host_count: int | None = None
        if spec is None:
            outcome = "unknown_tool"
            error_msg = f"unknown tool: {name}"
            result: dict = {"error": error_msg}
        else:
            try:
                hosts, is_multi = resolve_target_hosts(args)
            except ValueError as e:
                outcome = "validation_error"
                error_msg = str(e)
                result = {"error": error_msg}
            else:
                if is_multi:
                    host = None
                    host_count = len(hosts)
                    per = await asyncio.to_thread(_run_multi_host, spec.handler, args, hosts)
                    result = {
                        "multi_host": True,
                        "host_count": host_count,
                        "results": per,
                    }
                    failed = _multi_host_failed(per)
                    if failed:
                        outcome = "partial"
                        error_msg = f"{failed}/{host_count} host(s) failed"
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
        if host_count is not None:
            log_extra["host_count"] = host_count
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
