# output_mode — raw / parsed / both (2026-06-03)

Add per-call `output_mode` arg and `LINUX_INFO_OUTPUT_MODE` env var to control
response shape. `raw` = current behavior (stdout text). `parsed` = structured
object, stdout dropped (token saving). `both` = keep both. Bad values rejected
always, even when env overrides the arg.

---

## Decision log (already debated — don't re-litigate)

- **`parsed` drops `stdout`** to avoid doubling payload. `both` keeps both.
  Default `raw` = no behavior change.
- **Plumbed centrally in `server.py`**, not per tool. Handlers stay unchanged.
- **Parser is optional on `ToolSpec`.** Tools without one return
  `parse_status: "unsupported"` and fall back to raw — safe during rollout.
- **Env enforces; arg still validated.** Junk input rejected regardless of which wins.
- **`parsed` is accuracy/ergonomics, not a guaranteed token win.** JSON with
  repeated keys can exceed compact table output. Win is model not re-parsing
  columns + no misparse risk.
- **v1 ships two reference parsers**: `df` and `free`. Native-JSON tools wired later.

---

## Resolution semantics

```
effective_mode =
    env LINUX_INFO_OUTPUT_MODE  if set        (locks — caller arg ignored)
    else args["output_mode"]    if present
    else "raw"
```

- Arg is **always validated when present**, even if env overrides it.
- Env value validated too. Invalid env → `ValueError` → `validation_error` outcome.
- Value is **case-insensitive**, normalized to lowercase.

---

## Files to change

### 1. `linux_info_mcp/validate.py`

```python
OUTPUT_MODES: frozenset[str] = frozenset({"raw", "parsed", "both"})


def validate_output_mode(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("output_mode must be a non-empty string")
    normalized = value.strip().lower()
    if normalized not in OUTPUT_MODES:
        raise ValueError(
            f"output_mode {value!r} invalid; must be one of: {sorted(OUTPUT_MODES)}"
        )
    return normalized


def resolve_output_mode(args: dict) -> str:
    """Return effective output mode. Env overrides arg; both validated."""
    arg = args.get("output_mode") if isinstance(args, dict) else None
    if arg is not None:
        validate_output_mode(arg)          # always validate — reject junk even if env wins
    env = os.environ.get("LINUX_INFO_OUTPUT_MODE", "").strip()
    if env:
        return validate_output_mode(env)   # env override — raises on bad value
    if arg is not None:
        return arg.strip().lower()
    return "raw"
```

### 2. `linux_info_mcp/tools/__init__.py`

Add optional `parser` field to `ToolSpec`:

```python
@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], dict]
    parser: Callable[[str], object] | None = None
```

### 3. `linux_info_mcp/tools/_parsers.py` (new — leading `_` = not auto-discovered)

Pure functions, no SSH, fully unit-testable.

```python
"""Reference output parsers for tools that lack native JSON output."""

from __future__ import annotations


def parse_df(stdout: str) -> list[dict]:
    """Parse default df output (1K-blocks). Raises on unexpected header."""
    lines = [l for l in stdout.splitlines() if l.strip()]
    if not lines:
        return []
    header = lines[0].split()
    if header[:5] != ["Filesystem", "1K-blocks", "Used", "Available", "Use%"]:
        raise ValueError(f"unexpected df header: {lines[0]!r}")
    out = []
    for line in lines[1:]:
        parts = line.split(maxsplit=5)   # mount may contain spaces
        if len(parts) < 6:
            continue
        out.append({
            "fs": parts[0],
            "blocks_1k": int(parts[1]),
            "used_1k": int(parts[2]),
            "avail_1k": int(parts[3]),
            "use_pct": int(parts[4].rstrip("%")),
            "mount": parts[5].strip(),
        })
    return out


def parse_free(stdout: str) -> dict:
    """Parse free output (standard or -w wide). Returns {mem, swap}."""
    rows: dict[str, dict] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("total"):
            continue
        label, _, rest = line.partition(":")
        label = label.strip().lower()
        if label not in ("mem", "swap"):
            continue
        vals = rest.split()
        if label == "mem":
            if len(vals) >= 7:
                # wide mode (-w): total used free shared buffers cache available
                rows["mem"] = {
                    "total": int(vals[0]), "used": int(vals[1]), "free": int(vals[2]),
                    "shared": int(vals[3]), "buffers": int(vals[4]),
                    "cache": int(vals[5]), "available": int(vals[6]),
                }
            elif len(vals) >= 6:
                # standard: total used free shared buff/cache available
                rows["mem"] = {
                    "total": int(vals[0]), "used": int(vals[1]), "free": int(vals[2]),
                    "shared": int(vals[3]), "buff_cache": int(vals[4]),
                    "available": int(vals[5]),
                }
        elif label == "swap" and len(vals) >= 3:
            rows["swap"] = {
                "total": int(vals[0]), "used": int(vals[1]), "free": int(vals[2]),
            }
    return rows
```

### 4. `linux_info_mcp/tools/perf.py`

```python
from ._parsers import parse_df, parse_free

# Attach parsers to existing ToolSpec entries in TOOLS list:
ToolSpec(name="df", ..., parser=parse_df),
ToolSpec(name="free", ..., parser=parse_free),
```

### 5. `linux_info_mcp/server.py`

**Schema injection** — in `_augment_schema`, alongside `hosts`:

```python
_OUTPUT_MODE_PROP = {
    "type": ["string", "null"],
    "enum": ["raw", "parsed", "both", None],
    "description": (
        "Response shape: raw (stdout text, default) | parsed (structured, stdout dropped) "
        "| both. Locked server-side by LINUX_INFO_OUTPUT_MODE. Tools without a parser "
        "fall back to raw (parse_status=unsupported)."
    ),
}

# In _augment_schema:
if "output_mode" not in props:
    props["output_mode"] = copy.deepcopy(_OUTPUT_MODE_PROP)
```

**`apply_output_mode` helper** (add near `_annotate_privilege`):

```python
def apply_output_mode(result: dict, mode: str, parser) -> dict:
    if not isinstance(result, dict):
        return result
    if mode == "raw":
        result.pop("parsed", None)
        return result
    ec = result.get("exit_code")
    if isinstance(ec, int) and ec != 0:
        result["parse_status"] = "skipped_nonzero"
        return result
    if parser is None:
        result["parse_status"] = "unsupported"
        return result
    stdout = result.get("stdout")
    if not isinstance(stdout, str):
        result["parse_status"] = "unsupported"
        return result
    try:
        result["parsed"] = parser(stdout)
        result["parse_status"] = "ok"
    except Exception as e:
        result["parse_status"] = f"error: {type(e).__name__}"
        return result
    if mode == "parsed":
        result.pop("stdout", None)
    return result
```

**`_call_tool` changes:**
- Call `resolve_output_mode(args)` early; wrap in existing `ValueError → validation_error` path.
- After single-host handler returns: `apply_output_mode(result, mode, spec.parser)`.
- `_run_handler_for_host` needs `mode` + `parser` args so fan-out applies it per-host.

---

## New env var

| Var | Default | Purpose |
|-----|---------|---------|
| `LINUX_INFO_OUTPUT_MODE` | (unset) | Lock response shape to `raw`/`parsed`/`both`, overriding per-call arg. Invalid value → `validation_error`. |

---

## Tests (TDD — write first, watch fail, implement)

### `tests/test_validate.py` — `validate_output_mode` + `resolve_output_mode`

- accepts `"raw"`, `"parsed"`, `"both"`
- case-insensitive: `"Raw"`, `"PARSED"` normalize correctly
- rejects `"yourmoma"`, `""`, `123`, `None`, `["raw"]` → `ValueError`
- `resolve_output_mode`: no env + no arg → `"raw"`
- arg `"parsed"`, no env → `"parsed"`
- env `"both"` + arg `"raw"` → `"both"` (env wins)
- arg `"yourmoma"`, no env → `ValueError`
- arg `"yourmoma"` **with** env set → still `ValueError` (arg validated first)
- env `"yourmoma"` → `ValueError`
- use `monkeypatch.setenv`/`delenv`; never leak env between tests

### `tests/test_server.py` — `apply_output_mode` + call_tool integration

- schema includes injected `output_mode` enum
- `raw` → stdout present, no `parsed` key
- `parsed` + parser succeeds → `parsed` set, `stdout` absent, `parse_status=ok`
- `both` + parser → both present
- `parsed` + no parser → `parse_status=unsupported`, stdout kept
- parser raises → `parse_status` starts `"error:"`, stdout kept
- `exit_code != 0` → `parse_status=skipped_nonzero`
- multi-host: each per-host result gets mode applied
- env enforcement: `monkeypatch.setenv("LINUX_INFO_OUTPUT_MODE", "parsed")` + arg `"raw"` → parsed wins

### `tests/tools/test_parsers.py` (new)

`parse_df`:
- normal multi-row → correct fields
- mount path with spaces → captured intact in `mount`
- header-only → `[]`
- unexpected header → `ValueError`
- garbage → `ValueError` (not unhandled crash)

`parse_free`:
- standard layout (6 vals for Mem)
- wide layout (`-w`, 7 vals, `buffers`+`cache` split)
- missing Swap → `swap` key absent, no crash
- garbage → no unhandled exception

---

## Docs checklist

- `SPEC.md`: "Output modes" section near "Multi-host fan-out"; env table row; note `df`/`free` have parsers
- `README.md`: env var row + one usage example
- `AGENTS.md`: env var table row; `ToolSpec.parser` convention; parsers live in `tools/_parsers.py`
- `tests/e2e/manifest.py`: add `output_mode` exercise for `df`/`free` entries

---

## Out of scope (v1)

- Native-JSON tools (`lsblk`, `findmnt`, `lscpu`, `docker`, `journalctl`) — they only emit JSON
  when their own flag is set; `output_mode` does not auto-set it.
- Unifying `host_facts.facts` under `parsed`.
- Parsers for `ps`, `ss`, `iostat`, `vmstat` — add incrementally.

---

## Full improvement backlog (ranked this session)

| Prio | Item | Effort | Notes |
|------|------|--------|-------|
| P0 | SSH mux default + doc | Tiny | Default `ControlMaster=auto ControlPersist=60s ControlPath=$TMPDIR/lim-%r@%h:%p` in `_ssh_argv()` when `LINUX_INFO_SSH_CMD` unset. Already configurable via env; this is about the default + README perf note. ~5 lines `ssh.py`. |
| P0 | Error taxonomy `error_kind` | Small | Normalize ssh failures from exit code + stderr: `unreachable\|timeout\|auth\|dns\|not_found\|privilege\|ok`. Extends `_annotate_privilege` in `server.py`. No per-tool churn. |
| P1 | `triage` meta-tool | Medium | One SSH round trip: load-vs-nproc, mem/swap, disk %, failed units, PSI, OOM/dmesg → `{warnings, facts}`. Copies `host_facts` bundle pattern (`facts.py`). |
| P2 | Multi-host aggregation | Medium | Optional mode on `hosts`: `{common, outliers:[{host,diff}]}` instead of N raw blobs. |
| P3 | `output_mode` | Medium | **This plan.** |
| P4 | Sampling deltas | Small | `interval`/`count` on `iostat`/`vmstat`. `free` already has them (`perf.py:259`). |
| P4 | Pre-flight capability hint | Small | Surface `host_facts.capabilities` so model skips missing-binary round trips. |
