#!/usr/bin/env python3
"""Part 1 of e2e layer 3: capture handler-direct snapshots of every tool.

Run: uv run python tests/e2e/capture_samples.py --host HOST --out DIR

Iterates the same ToolSpec registry the MCP server dispatches through, calls each
handler directly with universal args from manifest.TOOL_ARGS, and writes one
self-describing JSON snapshot per arg-set. Part 2 (PROMPT.md) compares live MCP
results against these.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Script dir on sys.path[0] -> sibling manifest importable when run as a script.
from manifest import TOOL_ARGS

from linux_info_mcp.server import _discover_tools

_NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return text if _NO_COLOR else f"\033[{code}m{text}\033[0m"


def _bold(t: str) -> str:
    return _c("1", t)


def _green(t: str) -> str:
    return _c("32", t)


def _yellow(t: str) -> str:
    return _c("33", t)


def _red(t: str) -> str:
    return _c("31", t)


def _dim(t: str) -> str:
    return _c("2", t)


def _snapshot_name(tool: str, count: int, idx: int) -> str:
    return f"{tool}.json" if count == 1 else f"{tool}.{idx}.json"


def _outcome(result: dict) -> tuple[str, str, str]:
    """Return (key, colored_status, detail) describing a captured result."""
    if "error" in result and "exit_code" not in result:
        return "RAISED", _red("RAISED"), _dim(str(result["error"]))
    exit_code = result.get("exit_code")
    out = result.get("stdout") or result.get("data_base64") or ""
    trunc = " truncated" if result.get("truncated") else ""
    detail = _dim(f"exit={exit_code} bytes={len(out)}{trunc}")
    if exit_code == 0:
        return "OK", _green("OK"), detail
    return "NONZERO", _yellow("NONZERO"), detail


def _resolve_docker(tools: dict, host: str) -> dict[str, list[dict]]:
    """Point docker_inspect/_logs at the first real container (alphabetical).

    Falls back to the manifest placeholders (error baseline) if the host has no
    docker or no running containers.
    """
    if "docker_ps" not in tools:
        return {}
    res = tools["docker_ps"].handler({"host": host, "quiet": True})
    if res.get("exit_code") != 0:
        return {}
    ids = sorted(res.get("stdout", "").split())
    if not ids:
        return {}
    first = ids[0]
    print(_dim(f"  resolved docker container: {first}\n"), flush=True)
    return {
        "docker_inspect": [{"targets": [first]}],
        "docker_logs": [{"container": first, "tail": 50}],
    }


def capture(host: str, out_dir: str, only: set[str] | None) -> int:
    tools = _discover_tools()
    os.makedirs(out_dir, exist_ok=True)
    selected = [n for n in sorted(tools) if not only or n in only]
    overrides = (
        _resolve_docker(tools, host) if any(n.startswith("docker_") for n in selected) else {}
    )

    def arg_sets_for(n):
        return overrides.get(n) or TOOL_ARGS.get(n, [{}])

    total = sum(len(arg_sets_for(n)) for n in selected)

    print(_bold(f"Capturing {total} snapshot(s) from {host} -> {out_dir}\n"))

    written = 0
    counts = {"OK": 0, "NONZERO": 0, "RAISED": 0}
    width = max((len(n) for n in selected), default=0)
    for name in selected:
        spec = tools[name]
        arg_sets = arg_sets_for(name)
        for idx, args in enumerate(arg_sets):
            label = _snapshot_name(name, len(arg_sets), idx).removesuffix(".json")
            print(
                f"  {_bold(label.ljust(width))}  {_dim('testing ' + (json.dumps(args) if args else '{}'))}",
                flush=True,
            )
            try:
                result = spec.handler({**args, "host": host})
            except Exception as e:  # validators raise ValueError; capture all
                result = {"error": f"{type(e).__name__}: {e}"}
            path = os.path.join(out_dir, _snapshot_name(name, len(arg_sets), idx))
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {"tool": name, "args": args, "result": result},
                    fh,
                    indent=2,
                    default=str,
                    sort_keys=True,
                )
                fh.write("\n")
            written += 1
            key, status, detail = _outcome(result)
            counts[key] += 1
            print(f"  {' ' * width}  -> {status}  {detail}", flush=True)

    print(_bold("\nSummary: "), end="")
    print(
        f"{_green(str(counts['OK']) + ' ok')}, "
        f"{_yellow(str(counts['NONZERO']) + ' nonzero')}, "
        f"{_red(str(counts['RAISED']) + ' raised')}  "
        f"({written} file(s) in {out_dir})"
    )
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True, help="ssh target string")
    p.add_argument("--out", required=True, help="output directory for snapshots")
    p.add_argument(
        "--only",
        help="comma-separated tool names to capture (default: all)",
    )
    a = p.parse_args()
    only = {t.strip() for t in a.only.split(",")} if a.only else None
    return capture(a.host, a.out, only)


if __name__ == "__main__":
    sys.exit(main())
