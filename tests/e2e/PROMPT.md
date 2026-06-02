# e2e layer 3 — part 2: agent compare prompt

Hand this prompt to an agent that has the `linux-info` MCP server connected.
Fill in `{HOST}` and `{SNAPSHOT_DIR}` before running.

---

You are verifying the `linux-info` MCP server end-to-end against captured
baseline snapshots.

**Target host:** `{HOST}`
**Snapshot directory:** `{SNAPSHOT_DIR}`

Each file in the snapshot directory is JSON of the form:

```json
{ "tool": "<tool_name>", "args": { ... }, "result": { ... } }
```

`result` is exactly what the tool returned at capture time. Your job: for every
snapshot, call the live tool and decide whether the live result matches the
snapshot **schema-wise**.

## Steps

1. List the snapshot directory. For each `.json` file:
2. Read it. Take `tool` and `args`.
3. Call the MCP tool named `mcp__linux-info__<tool>` with those `args` plus
   `host: "{HOST}"`.
4. Compare the live result to the snapshot `result` using the rules below.
5. Record one verdict row.

## Comparison rules — compare SHAPE, not values

Match means the live result is the **same kind of answer**:

- Same top-level keys (`stdout`, `stderr`, `exit_code`, `truncated`; or for
  `read_binary`: `data_base64`, `bytes_read`, `stderr`, `exit_code`,
  `truncated`).
- `exit_code` agrees (both 0, or both non-zero).
- `stdout` has the same structure: same column headers / field labels / table
  shape, same general format.
- `truncated` semantics consistent (a tiny query should be `false` on both).

**Ignore** all volatile content:

- Numeric values (memory, sizes, percentages, load).
- Row counts (process lists, mounts, journal lines grow/shrink).
- PIDs, timestamps, dates, uptimes, hostnames-in-output.
- Ordering of rows.

**Both-error-consistently = match.** If the snapshot is an error baseline
(non-zero exit, "command not found", "no such container", permission denied)
and the live call errors the same way, that is a **match** — the tool behaves
consistently. Tools commonly in this bucket: `docker_*` (no docker / no such
container), `smartctl`, `dmidecode` (need root / real device).

**Mismatch** means a real schema regression: different keys, columns
appeared/disappeared, `exit_code` flipped 0↔non-zero unexpectedly, format
changed, or `truncated` disagrees on a small query.

## Output

A single markdown table, one row per snapshot, then a one-line summary:

```
| tool | verdict | note |
|------|---------|------|
| df   | match   | same Filesystem/Type/... columns |
| ...  | ...     | ... |

Summary: N match, M mismatch.
```

Do not fix anything. Report only.
