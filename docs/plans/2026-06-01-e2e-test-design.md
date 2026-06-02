# e2e test design — linux-info-mcp

2026-06-01

## Goal

Two things at once:

1. **Agent-can-drive-MCP** — prove a real LLM agent, via the MCP protocol, gets
   usable results from each tool.
2. **Server correctness** — builders, validators, SSH wrapper, schema,
   truncation behave.

These are layered, not one test.

## Three layers

| Layer | Name | What it pins | Determinism | When |
|-------|------|--------------|-------------|------|
| 1 | golden | exact remote command string per `build_remote_cmd_*` for fixture args | zero flake | every PR, hard gate |
| 2 | smoke | live `exit_code` + response shape against one host | binary pass/fail | nightly / on-demand, advisory |
| 3 | agent-e2e | LLM drives MCP tools, semantic-compares to captured snapshots | LLM judge tolerates value drift | on-demand / manual |

Layers 1 and 2 are described in the prior-session notes and are out of scope for
this document. This document specifies **layer 3**.

## Layer 3 — agent-e2e

Two parts, as the user proposed.

### Part 1 — capture (`tests/e2e/capture_samples.py`)

A script. `--host H --out DIR`.

- Iterate the **ToolSpec registry** (`server._TOOLS` / `_discover_tools()`) —
  auto-covers every tool, uses the exact same dispatch the MCP server uses.
- Per tool, pull arg-sets from `manifest.TOOL_ARGS[name]`, default `[{}]`.
- Call the handler **directly** — `spec.handler({**args, "host": H})` — which is
  exactly the payload the LLM receives over MCP.
- Write a self-describing snapshot per arg-set:
  `{out}/{tool}.json` (or `{tool}.{i}.json` for multiple) containing
  `{"tool": name, "args": args, "result": result}`.
- Tools absent on the host (maybe docker/smartctl/dmidecode-without-root) record
  their error result. That is a valid baseline.

This is **handler-direct** capture, not a full MCP roundtrip — same payload,
simpler script, skips only the transport layer (which part 2 exercises).

### `manifest.py`

Universal safe args — portable across stock Linux, no per-host config. Fills
required non-host args with values present on almost any host
(`read_file:/etc/hostname`, `stat_fs:/`, `systemctl_status:systemd-journald.service`,
`uname:all`, etc.). `smartctl`/`dmidecode` get best-effort placeholder args; if
the host lacks them the snapshot is an error baseline and part 2 still matches
"both error consistently".

`docker_inspect`/`docker_logs` are **resolved dynamically** at capture time:
the script runs `docker_ps -q`, takes the first container ID (alphabetical), and
targets it. Placeholders in the manifest are the fallback when the host has no
docker or no containers. The resolved ID is written into the snapshot `args`, so
part 2 replays the exact same target.

### Part 2 — compare (`tests/e2e/PROMPT.md`)

A prompt handed to an agent that has the `linux-info` MCP server connected.

For each snapshot file:
1. Read `tool` + `args`.
2. Call the matching MCP tool with the same args + the target host.
3. **Schema-compare** the live result to the snapshot `result`:
   same keys, same columns/fields, `exit_code` agreement, `truncated`
   semantics. **Ignore** volatile values — numbers, row counts, PIDs,
   timestamps, uptimes.
4. Both-error-consistently (e.g. docker absent on both sides) = match.

Output: a markdown table, one row per tool — `tool | match/mismatch | note`.

## What each layer catches

- golden: builder drift, quoting regression, flag-injection holes.
- smoke: SSH wrapper break, real-host flag incompat, timeout regression.
- agent-e2e: MCP transport, agent-can-interpret, **output-shape regression**
  (host upgrade changes `df` columns → live diverges from snapshot).

Builder bugs are **not** caught by agent-e2e — both sides use the same builder,
so a builder bug hides identically. That is golden's job. Clean division.

## Host

Operator-supplied. `--host` is an ssh target string; auth is external (keys,
`~/.ssh/config`). Redirect the transport with `LINUX_INFO_SSH_CMD`
(e.g. `"tsh ssh"`). `LINUX_INFO_HOSTS` allowlist is honored on both sides
because both go through `run_ssh`. No disposable container; docker tools are
exercised only if the target host runs docker.

## Non-goals

- No byte-equal comparison (volatile output guarantees false negatives).
- No LLM judge in CI hard-gate (cost, nondeterminism) — layer 3 is on-demand.
- No host provisioning.
