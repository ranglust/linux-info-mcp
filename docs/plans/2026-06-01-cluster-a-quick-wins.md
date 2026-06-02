# Cluster A — Quick Wins Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 6 read-only diagnostic tools (psi_stats, meminfo, proc_limits, arp_table, systemctl_list_timers, systemctl_list_sockets) to linux-info-mcp, taking the tool count 44 → 50.

**Architecture:** Each tool follows the existing per-tool pattern (see AGENTS.md): tool-local validators, a `build_remote_cmd_<tool>` returning a single `LC_ALL=C`-prefixed shlex-quoted string, a sync `handle_<tool>` returning `{stdout, stderr, exit_code, truncated, stderr_truncated}`, a `*_SCHEMA`, and a `TOOLS` append. Tools land in existing modules — `perf.py` (psi_stats, meminfo), `proc.py` (proc_limits), `net.py` (arp_table), `systemctl.py` (the two list tools). `server.py` auto-discovers them; no registration wiring needed.

**Tech Stack:** Python 3, `shlex.quote` for all interpolated values, `re.fullmatch` anchored validators, pytest with `run_ssh` monkeypatched at the module-import site.

**Reference:** Design doc `docs/plans/2026-06-01-new-diagnostic-tools-design.md` §"Cluster A". Authoritative spec `SPEC.md`.

**Conventions every task obeys:**
- Mock `run_ssh` at module site: `monkeypatch.setattr(mod, "run_ssh", fake)`.
- Handler return shape is the 5-key dict, identical to every existing handler.
- `SshResult(stdout, stderr, exit_code, truncated)` is positional; `stderr_truncated` defaults False.
- Adversarial test inputs required: `-oProxyCommand=evil`, `foo;rm -rf /`, `\n`, `\x00`.
- Every tool gets a truncation-propagation test: `SshResult(b"x", b"", 0, True)` → handler returns `truncated: True`.
- Run the full suite green before each commit: `uv run pytest -q`.

---

### Task 1: psi_stats (perf.py)

Pressure-stall info from `/proc/pressure/*` — the saturation dimension missing from iostat/vmstat/free.

**Files:**
- Modify: `linux_info_mcp/tools/perf.py` (append a new section before the `# Registration` block; add to `TOOLS`)
- Test: `tests/tools/test_perf.py` (append)

**Step 1: Write the failing tests**

Append to `tests/tools/test_perf.py`:

```python
# ---------------------------------------------------------------------------
# psi_stats
# ---------------------------------------------------------------------------


def test_psi_stats_default_builder():
    assert mod.build_remote_cmd_psi_stats(resource="all") == (
        "LC_ALL=C grep -H '' /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io"
    )


def test_psi_stats_single_builder():
    assert mod.build_remote_cmd_psi_stats(resource="cpu") == "LC_ALL=C cat /proc/pressure/cpu"
    assert mod.build_remote_cmd_psi_stats(resource="memory") == "LC_ALL=C cat /proc/pressure/memory"
    assert mod.build_remote_cmd_psi_stats(resource="io") == "LC_ALL=C cat /proc/pressure/io"


def test_psi_stats_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"some avg10\n", b"", 0, False))
    out = mod.handle_psi_stats({"host": "h1"})
    assert out == {
        "stdout": "some avg10\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == (
        "LC_ALL=C grep -H '' /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io"
    )


def test_psi_stats_handler_single(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_psi_stats({"host": "h1", "resource": "io"})
    assert captured["cmd"] == "LC_ALL=C cat /proc/pressure/io"


def test_psi_stats_rejects_bad_resource(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_psi_stats({"host": "h1", "resource": "disk"})


def test_psi_stats_rejects_resource_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_psi_stats({"host": "h1", "resource": "cpu; rm -rf /"})


def test_psi_stats_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_psi_stats({"host": "h1"})
    assert out["truncated"] is True
```

Confirm `test_perf.py` already imports `SshResult` and defines `_stub` (it does — same pattern as `test_net.py`). If not, mirror the `_stub` helper from `tests/tools/test_net.py`.

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/tools/test_perf.py -q -k psi_stats`
Expected: FAIL with `AttributeError: module ... has no attribute 'build_remote_cmd_psi_stats'`.

**Step 3: Implement in `perf.py`**

Insert before the `# Registration` block:

```python
# ---------------------------------------------------------------------------
# psi_stats
# ---------------------------------------------------------------------------

_PSI_RESOURCES = {"cpu", "memory", "io", "all"}


def _validate_psi_resource(resource) -> str:
    if resource is None:
        return "all"
    if not isinstance(resource, str) or resource not in _PSI_RESOURCES:
        raise ValueError(f"resource must be one of {sorted(_PSI_RESOURCES)}")
    return resource


def build_remote_cmd_psi_stats(*, resource: str = "all") -> str:
    """Build LC_ALL=C /proc/pressure read command. resource is whitelist-validated."""
    if resource == "all":
        return "LC_ALL=C grep -H '' /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io"
    return f"LC_ALL=C cat /proc/pressure/{resource}"


def handle_psi_stats(args: dict) -> dict:
    host = validate_host(args["host"])
    resource = _validate_psi_resource(args.get("resource"))
    cmd = build_remote_cmd_psi_stats(resource=resource)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


PSI_STATS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "resource": {"type": ["string", "null"], "enum": ["cpu", "memory", "io", "all", None]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Note: `resource` is whitelist-bound to `{cpu, memory, io}` before f-string interpolation, so the path cannot be influenced. This is the design's "file paths come only from the enum whitelist" guarantee.

Add to `TOOLS`:

```python
    ToolSpec(
        name="psi_stats",
        description=(
            "Read PSI pressure-stall info from /proc/pressure on a remote host via SSH. "
            "resource: cpu|memory|io|all (default all). Kernels <4.20 lack these files "
            "(nonzero exit passthrough). Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=PSI_STATS_SCHEMA,
        handler=handle_psi_stats,
    ),
```

**Step 4: Run tests to verify pass**

Run: `uv run pytest tests/tools/test_perf.py -q -k psi_stats`
Expected: PASS.

**Step 5: Commit** (only on explicit user instruction — do not self-authorize)

```bash
git add linux_info_mcp/tools/perf.py tests/tools/test_perf.py
git commit -m "feat: add psi_stats tool (PSI pressure-stall info)"
```

---

### Task 2: meminfo (perf.py)

Full `/proc/meminfo`, optionally filtered to named fields, for OOM/leak triage.

**Files:**
- Modify: `linux_info_mcp/tools/perf.py`
- Test: `tests/tools/test_perf.py`

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# meminfo
# ---------------------------------------------------------------------------


def test_meminfo_default_builder():
    assert mod.build_remote_cmd_meminfo() == "LC_ALL=C cat /proc/meminfo"


def test_meminfo_fields_builder():
    cmd = mod.build_remote_cmd_meminfo(fields=["MemFree", "Committed_AS"])
    assert cmd == "LC_ALL=C cat /proc/meminfo | grep -E '^(MemFree|Committed_AS):'"


def test_meminfo_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"MemTotal: 1 kB\n", b"", 0, False))
    out = mod.handle_meminfo({"host": "h1"})
    assert out["stdout"] == "MemTotal: 1 kB\n"
    assert captured["cmd"] == "LC_ALL=C cat /proc/meminfo"


def test_meminfo_handler_fields(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_meminfo({"host": "h1", "fields": ["Slab", "Dirty"]})
    assert captured["cmd"] == "LC_ALL=C cat /proc/meminfo | grep -E '^(Slab|Dirty):'"


def test_meminfo_rejects_field_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_meminfo({"host": "h1", "fields": ["MemFree; rm -rf /"]})


def test_meminfo_rejects_field_with_pipe(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_meminfo({"host": "h1", "fields": ["Mem|Free"]})


def test_meminfo_rejects_field_newline(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_meminfo({"host": "h1", "fields": ["Mem\nFree"]})


def test_meminfo_rejects_non_list_fields(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_meminfo({"host": "h1", "fields": "MemFree"})


def test_meminfo_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_meminfo({"host": "h1"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail**

Run: `uv run pytest tests/tools/test_perf.py -q -k meminfo`
Expected: FAIL (no `build_remote_cmd_meminfo`).

**Step 3: Implement in `perf.py`**

```python
# ---------------------------------------------------------------------------
# meminfo
# ---------------------------------------------------------------------------

_MEMINFO_FIELD_RE = re.compile(r"^[A-Za-z0-9_()]+$")


def _validate_meminfo_field(f) -> str:
    if not isinstance(f, str) or not f:
        raise ValueError("fields entry must be a non-empty string")
    if len(f) > 64:
        raise ValueError("fields entry must be at most 64 characters")
    if not _MEMINFO_FIELD_RE.fullmatch(f):
        raise ValueError(f"fields entry must match ^[A-Za-z0-9_()]+$: {f!r}")
    return f


def _validate_meminfo_fields(fields) -> list[str]:
    if fields is None:
        return []
    if not isinstance(fields, list):
        raise ValueError("fields must be a list")
    return [_validate_meminfo_field(f) for f in fields]


def build_remote_cmd_meminfo(*, fields: list[str] | None = None) -> str:
    """Build LC_ALL=C /proc/meminfo read, optionally grep-filtered to named fields."""
    base = "LC_ALL=C cat /proc/meminfo"
    if not fields:
        return base
    pattern = "^(" + "|".join(fields) + "):"
    return f"{base} | grep -E {shlex.quote(pattern)}"


def handle_meminfo(args: dict) -> dict:
    host = validate_host(args["host"])
    fields = _validate_meminfo_fields(args.get("fields"))
    cmd = build_remote_cmd_meminfo(fields=fields)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


MEMINFO_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "fields": {"type": ["array", "null"], "items": {"type": "string"}},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="meminfo",
        description=(
            "Read /proc/meminfo on a remote host via SSH, optionally filtered to named fields. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=MEMINFO_SCHEMA,
        handler=handle_meminfo,
    ),
```

**Step 4: Run to verify pass**

Run: `uv run pytest tests/tools/test_perf.py -q -k meminfo`
Expected: PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/perf.py tests/tools/test_perf.py
git commit -m "feat: add meminfo tool (/proc/meminfo with optional field filter)"
```

---

### Task 3: proc_limits (proc.py)

`/proc/<pid>/limits` — diagnose nofile/core/OOM limits; pairs with lsof/pgrep.

**Files:**
- Modify: `linux_info_mcp/tools/proc.py`
- Test: `tests/tools/test_proc.py`

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# proc_limits
# ---------------------------------------------------------------------------


def test_proc_limits_builder():
    assert mod.build_remote_cmd_proc_limits(pid=1234) == "LC_ALL=C cat /proc/1234/limits"


def test_proc_limits_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"Limit ...\n", b"", 0, False))
    out = mod.handle_proc_limits({"host": "h1", "pid": 1})
    assert out == {
        "stdout": "Limit ...\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C cat /proc/1/limits"


def test_proc_limits_requires_pid(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises((ValueError, KeyError)):
        mod.handle_proc_limits({"host": "h1"})


def test_proc_limits_rejects_pid_zero(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_proc_limits({"host": "h1", "pid": 0})


def test_proc_limits_rejects_pid_too_high(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_proc_limits({"host": "h1", "pid": 4194305})


def test_proc_limits_rejects_pid_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_proc_limits({"host": "h1", "pid": True})


def test_proc_limits_rejects_pid_string(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_proc_limits({"host": "h1", "pid": "1; rm -rf /"})


def test_proc_limits_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_proc_limits({"host": "h1", "pid": 1})
    assert out["truncated"] is True
```

(Confirm `test_proc.py` imports `SshResult` and defines `_stub`; mirror from `test_net.py` if missing. The handler reads `args["pid"]` — for the missing-pid case, accept `KeyError` or `ValueError`. To keep it a clean `ValueError`, the implementation below uses `args.get("pid")` and validates None explicitly.)

**Step 2: Run to verify fail**

Run: `uv run pytest tests/tools/test_proc.py -q -k proc_limits`
Expected: FAIL.

**Step 3: Implement in `proc.py`**

Insert before the `# Registration` block:

```python
# ---------------------------------------------------------------------------
# proc_limits
# ---------------------------------------------------------------------------


def build_remote_cmd_proc_limits(*, pid: int) -> str:
    """Build LC_ALL=C /proc/<pid>/limits read. pid is an int → safe interpolation."""
    return f"LC_ALL=C cat /proc/{pid}/limits"


def handle_proc_limits(args: dict) -> dict:
    host = validate_host(args["host"])
    pid_in = args.get("pid")
    if pid_in is None:
        raise ValueError("pid is required")
    pid = validate_pid(pid_in)
    cmd = build_remote_cmd_proc_limits(pid=pid)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


PROC_LIMITS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pid": {"type": "integer"},
    },
    "required": ["host", "pid"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="proc_limits",
        description=(
            "Read /proc/<pid>/limits on a remote host via SSH (rlimits for a process). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=PROC_LIMITS_SCHEMA,
        handler=handle_proc_limits,
    ),
```

`validate_pid` is already imported in `proc.py`.

**Step 4: Run to verify pass**

Run: `uv run pytest tests/tools/test_proc.py -q -k proc_limits`
Expected: PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/proc.py tests/tools/test_proc.py
git commit -m "feat: add proc_limits tool (/proc/<pid>/limits)"
```

---

### Task 4: arp_table (net.py)

Neighbor/ARP cache — stale/FAILED entries, MAC visibility.

**Files:**
- Modify: `linux_info_mcp/tools/net.py`
- Test: `tests/tools/test_net.py`

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# arp_table
# ---------------------------------------------------------------------------


def test_arp_table_default_builder():
    assert mod.build_remote_cmd_arp_table() == "LC_ALL=C ip -o neigh show"


def test_arp_table_iface_builder():
    assert mod.build_remote_cmd_arp_table(iface="eth0") == "LC_ALL=C ip -o neigh show dev eth0"


def test_arp_table_family_builder():
    assert mod.build_remote_cmd_arp_table(family_flag="-4") == "LC_ALL=C ip -o -4 neigh show"


def test_arp_table_family_and_iface_builder():
    cmd = mod.build_remote_cmd_arp_table(family_flag="-6", iface="ens3")
    assert cmd == "LC_ALL=C ip -o -6 neigh show dev ens3"


def test_arp_table_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"n\n", b"", 0, False))
    out = mod.handle_arp_table({"host": "h1", "family": "inet", "iface": "eth0"})
    assert out == {
        "stdout": "n\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C ip -o -4 neigh show dev eth0"


def test_arp_table_rejects_bad_family(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_arp_table({"host": "h1", "family": "ipx"})


def test_arp_table_rejects_iface_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_arp_table({"host": "h1", "iface": "eth0; rm -rf /"})


def test_arp_table_rejects_iface_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_arp_table({"host": "h1", "iface": "-oProxyCommand=evil"})


def test_arp_table_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_arp_table({"host": "h1"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail**

Run: `uv run pytest tests/tools/test_net.py -q -k arp_table`
Expected: FAIL.

**Step 3: Implement in `net.py`**

Insert before the `# Registration` block. Reuse the existing `_validate_iface`:

```python
# ---------------------------------------------------------------------------
# arp_table
# ---------------------------------------------------------------------------

_ARP_FAMILY_MAP = {"inet": "-4", "inet6": "-6"}


def _validate_arp_family(family) -> str:
    if not isinstance(family, str) or family not in _ARP_FAMILY_MAP:
        raise ValueError(f"family must be one of {sorted(_ARP_FAMILY_MAP)}")
    return _ARP_FAMILY_MAP[family]


def build_remote_cmd_arp_table(
    *,
    iface: str | None = None,
    family_flag: str | None = None,
) -> str:
    """Build LC_ALL=C ip neigh show command string."""
    parts = ["LC_ALL=C", "ip", "-o"]
    if family_flag is not None:
        parts.append(family_flag)
    parts += ["neigh", "show"]
    if iface is not None:
        parts += ["dev", shlex.quote(iface)]
    return " ".join(parts)


def handle_arp_table(args: dict) -> dict:
    host = validate_host(args["host"])
    iface = args.get("iface")
    if iface is not None:
        iface = _validate_iface(iface)
    family = args.get("family")
    family_flag = _validate_arp_family(family) if family is not None else None
    cmd = build_remote_cmd_arp_table(iface=iface, family_flag=family_flag)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


ARP_TABLE_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "iface": {"type": ["string", "null"]},
        "family": {"type": ["string", "null"], "enum": ["inet", "inet6", None]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="arp_table",
        description=(
            "Run 'ip neigh show' (ARP/neighbor cache) on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=ARP_TABLE_SCHEMA,
        handler=handle_arp_table,
    ),
```

Update the registry-names test at the bottom of `test_net.py` to expect `arp_table` appended:

```python
    assert names == ["ss", "ip_addr", "ip_route", "lsof_net", "arp_table"]
```

**Step 4: Run to verify pass**

Run: `uv run pytest tests/tools/test_net.py -q`
Expected: PASS (including the updated registry test).

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/net.py tests/tools/test_net.py
git commit -m "feat: add arp_table tool (ip neigh show)"
```

---

### Task 5: systemctl_list_timers (systemctl.py)

Timer units with next/last fire times.

**Files:**
- Modify: `linux_info_mcp/tools/systemctl.py`
- Test: `tests/tools/test_systemctl.py`

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# systemctl_list_timers
# ---------------------------------------------------------------------------


def test_list_timers_default_builder():
    assert mod.build_remote_cmd_systemctl_list_timers(all_flag=False) == (
        "LC_ALL=C systemctl list-timers --no-pager"
    )


def test_list_timers_all_builder():
    assert mod.build_remote_cmd_systemctl_list_timers(all_flag=True) == (
        "LC_ALL=C systemctl list-timers --no-pager --all"
    )


def test_list_timers_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"t\n", b"", 0, False))
    out = mod.handle_systemctl_list_timers({"host": "h1"})
    assert out == {
        "stdout": "t\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C systemctl list-timers --no-pager"


def test_list_timers_handler_all(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list_timers({"host": "h1", "all": True})
    assert captured["cmd"] == "LC_ALL=C systemctl list-timers --no-pager --all"


def test_list_timers_rejects_non_bool_all(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_systemctl_list_timers({"host": "h1", "all": "yes"})


def test_list_timers_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_systemctl_list_timers({"host": "h1"})
    assert out["truncated"] is True
```

(Confirm `test_systemctl.py` imports `SshResult` and has a `_stub` helper; mirror from `test_net.py` if needed.)

**Step 2: Run to verify fail**

Run: `uv run pytest tests/tools/test_systemctl.py -q -k list_timers`
Expected: FAIL.

**Step 3: Implement in `systemctl.py`**

Import the bool coercer at the top (add to the existing `from ._common import ...` line):

```python
from ._common import decode_text as _decode_text
from ._common import validate_bool as _bool
```

Insert before the `TOOLS` list:

```python
def build_remote_cmd_systemctl_list_timers(*, all_flag: bool = False) -> str:
    """Build remote command for systemctl list-timers."""
    parts = ["LC_ALL=C", "systemctl", "list-timers", "--no-pager"]
    if all_flag:
        parts.append("--all")
    return " ".join(parts)


def handle_systemctl_list_timers(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_systemctl_list_timers(all_flag=_bool(args.get("all"), "all"))
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


SYSTEMCTL_LIST_TIMERS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "all": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="systemctl_list_timers",
        description=(
            "List systemd timer units (with next/last fire times) on a remote host via SSH. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SYSTEMCTL_LIST_TIMERS_SCHEMA,
        handler=handle_systemctl_list_timers,
    ),
```

**Step 4: Run to verify pass**

Run: `uv run pytest tests/tools/test_systemctl.py -q -k list_timers`
Expected: PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/systemctl.py tests/tools/test_systemctl.py
git commit -m "feat: add systemctl_list_timers tool"
```

---

### Task 6: systemctl_list_sockets (systemctl.py)

Socket units with listen address + owning service.

**Files:**
- Modify: `linux_info_mcp/tools/systemctl.py`
- Test: `tests/tools/test_systemctl.py`

**Step 1: Write the failing tests** (mirror Task 5, swapping `timers`→`sockets`)

```python
# ---------------------------------------------------------------------------
# systemctl_list_sockets
# ---------------------------------------------------------------------------


def test_list_sockets_default_builder():
    assert mod.build_remote_cmd_systemctl_list_sockets(all_flag=False) == (
        "LC_ALL=C systemctl list-sockets --no-pager"
    )


def test_list_sockets_all_builder():
    assert mod.build_remote_cmd_systemctl_list_sockets(all_flag=True) == (
        "LC_ALL=C systemctl list-sockets --no-pager --all"
    )


def test_list_sockets_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"s\n", b"", 0, False))
    out = mod.handle_systemctl_list_sockets({"host": "h1"})
    assert out["stdout"] == "s\n"
    assert captured["cmd"] == "LC_ALL=C systemctl list-sockets --no-pager"


def test_list_sockets_handler_all(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_systemctl_list_sockets({"host": "h1", "all": True})
    assert captured["cmd"] == "LC_ALL=C systemctl list-sockets --no-pager --all"


def test_list_sockets_rejects_non_bool_all(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_systemctl_list_sockets({"host": "h1", "all": "yes"})


def test_list_sockets_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_systemctl_list_sockets({"host": "h1"})
    assert out["truncated"] is True
```

Also update the registry-names test at the bottom of `test_systemctl.py` to expect the two new tools appended in order:

```python
    assert names == [
        "systemctl_status",
        "systemctl_list",
        "systemctl_list_timers",
        "systemctl_list_sockets",
    ]
```

**Step 2: Run to verify fail**

Run: `uv run pytest tests/tools/test_systemctl.py -q -k list_sockets`
Expected: FAIL.

**Step 3: Implement in `systemctl.py`**

```python
def build_remote_cmd_systemctl_list_sockets(*, all_flag: bool = False) -> str:
    """Build remote command for systemctl list-sockets."""
    parts = ["LC_ALL=C", "systemctl", "list-sockets", "--no-pager"]
    if all_flag:
        parts.append("--all")
    return " ".join(parts)


def handle_systemctl_list_sockets(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_systemctl_list_sockets(all_flag=_bool(args.get("all"), "all"))
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


SYSTEMCTL_LIST_SOCKETS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "all": {"type": ["boolean", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="systemctl_list_sockets",
        description=(
            "List systemd socket units (listen address + owning service) on a remote host "
            "via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SYSTEMCTL_LIST_SOCKETS_SCHEMA,
        handler=handle_systemctl_list_sockets,
    ),
```

**Step 4: Run to verify pass**

Run: `uv run pytest tests/tools/test_systemctl.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/systemctl.py tests/tools/test_systemctl.py
git commit -m "feat: add systemctl_list_sockets tool"
```

---

### Task 7: Docs + full-suite gate

**Files:**
- Modify: `SPEC.md` (add §45–§50 for the 6 new tools, mirroring the format of existing sections)
- Modify: `README.md` (add the 6 tools to the user-facing tool list)
- Modify: `AGENTS.md` (update the tool count "44 tools" → "50 tools" in the "What this is" line, and add the new tools to the per-module inventory: perf gets `psi_stats`/`meminfo`, proc gets `proc_limits`, net gets `arp_table`, systemd-area list gets the two new list tools)

**Step 1: Update the three docs** matching existing entry style (arg schema, command, safety notes per SPEC; one-line entry per README; counts/inventory per AGENTS).

**Step 2: Run the full suite**

Run: `uv run pytest -q`
Expected: PASS, all green, no skips introduced.

**Step 3: Sanity-check discovery** — confirm the server registers 50 tools:

Run: `uv run python -c "from linux_info_mcp.server import _discover_tools; print(len(_discover_tools()))"`
Expected: `50` (adjust the helper name/call if `_discover_tools` has a different signature — check `linux_info_mcp/server.py`).

**Step 4: Commit**

```bash
git add SPEC.md README.md AGENTS.md
git commit -m "docs: document Cluster A tools; tool count 44 -> 50"
```

---

## Done criteria
- 6 new tools registered and discoverable.
- `uv run pytest -q` fully green from a clean `uv sync`.
- Each tool: builder test (default + every arg), whitelist-rejection test, injection-rejection test, truncation-propagation test.
- SPEC.md / README.md / AGENTS.md updated; tool count reads 50.
