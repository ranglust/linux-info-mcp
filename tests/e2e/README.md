# e2e — layer 3 (agent-driven)

Proves an LLM agent can drive the MCP server end-to-end and that tool output
shapes have not regressed, against an operator-supplied host. Design:
`docs/plans/2026-06-01-e2e-test-design.md`.

This is **not** part of `uv run pytest` (no host, LLM-in-loop). Run on demand.

## Part 1 — capture snapshots

```
uv run python tests/e2e/capture_samples.py --host HOST --out ./snapshots
```

`HOST` is an ssh target; auth is external (keys / `~/.ssh/config`). Redirect the
transport with `LINUX_INFO_SSH_CMD` (e.g. `LINUX_INFO_SSH_CMD="tsh ssh"`).
Honors `LINUX_INFO_HOSTS`. Args per tool come from `manifest.py`.

Writes one `<tool>.json` per tool (`{tool, args, result}`).

## Part 2 — agent compare

Open `PROMPT.md`, fill in `{HOST}` and `{SNAPSHOT_DIR}`, hand it to an agent that
has the `linux-info` MCP server connected. It calls each tool live, schema-
compares to the snapshot, and emits a markdown match/mismatch table.

## Layers

This is layer 3 of three (see design doc): golden (cmd strings) and smoke (live
exit+shape) are the deterministic layers; this one is the agent/protocol proof.
