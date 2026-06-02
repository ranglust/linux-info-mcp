# Cluster C — Kernel/Perf Tools Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 5 read-only diagnostic tools (slabtop, numastat, cgroup_stats, systemd_analyze in `kernel.py`; blockdev in `disk.py`) plus one new shared validator (`validate_cgroup_path` in `validate.py`), taking the tool count 56 → 61 (assumes Clusters A+B landed).

**Architecture:** Same per-tool pattern as prior clusters. Four tools land in `kernel.py`, one in `disk.py`. `cgroup_stats` introduces a traversal-safe path validator shared in `validate.py` plus a belt-and-suspenders whitelist of leaf files per controller — the path is shell-quoted AND the leaf filenames are fixed literals, so neither the directory nor the filename can be attacker-influenced. Root-only / package-dependent tools (slabtop, numastat) degrade via exit_code/stderr passthrough.

**Tech Stack:** Python 3, `shlex.quote`, anchored `re.fullmatch` validators (following the `validate_unit_name` precedent), pytest with `run_ssh` monkeypatched at module site.

**Reference:** Design doc `docs/plans/2026-06-01-new-diagnostic-tools-design.md` §"Cluster C". `SPEC.md`.

**Conventions:** identical to prior clusters (mock at module site; 5-key return dict; adversarial inputs incl. `../../etc/shadow` for cgroup path; truncation-propagation test per tool; full suite green before each commit).

---

### Task 1: validate_cgroup_path (validate.py)

Shared traversal-safe path validator, consumed by cgroup_stats. Build it first so the tool task can import it.

**Files:**
- Modify: `linux_info_mcp/validate.py`
- Test: `tests/test_validate.py`

**Step 1: Write the failing tests**

Append to `tests/test_validate.py`:

```python
# ---------------------------------------------------------------------------
# validate_cgroup_path
# ---------------------------------------------------------------------------


def test_validate_cgroup_path_accepts_normal():
    from linux_info_mcp.validate import validate_cgroup_path

    assert validate_cgroup_path("system.slice/sshd.service") == "system.slice/sshd.service"


def test_validate_cgroup_path_accepts_simple():
    from linux_info_mcp.validate import validate_cgroup_path

    assert validate_cgroup_path("user.slice") == "user.slice"


def test_validate_cgroup_path_rejects_empty():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("")


def test_validate_cgroup_path_rejects_leading_slash():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("/system.slice")


def test_validate_cgroup_path_rejects_dotdot_segment():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("system.slice/../../etc/shadow")


def test_validate_cgroup_path_rejects_bare_dotdot():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("..")


def test_validate_cgroup_path_rejects_nul():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("system.slice\x00")


def test_validate_cgroup_path_rejects_newline():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("system.slice\nfoo")


def test_validate_cgroup_path_rejects_bad_char():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("system.slice/foo;rm -rf /")


def test_validate_cgroup_path_rejects_too_long():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("a" * 1025)
```

(Confirm `tests/test_validate.py` imports `pytest`.)

**Step 2: Run to verify fail**

Run: `uv run pytest tests/test_validate.py -q -k cgroup_path`
Expected: FAIL with `ImportError: cannot import name 'validate_cgroup_path'`.

**Step 3: Implement in `validate.py`**

Add the regex near the other module-level regexes:

```python
_CGROUP_PATH_RE = re.compile(r"^[A-Za-z0-9._:@/-]+$")
```

Add the function (mirrors `validate_unit_name`'s anchored-fullmatch style):

```python
def validate_cgroup_path(path: str, label: str = "cgroup_path") -> str:
    """Relative cgroup path under /sys/fs/cgroup. Traversal-safe; no leading slash, no '..'."""
    if not isinstance(path, str) or not path:
        raise ValueError(f"{label} must be a non-empty string")
    if len(path) > 1024:
        raise ValueError(f"{label} must be at most 1024 characters")
    reject_unsafe_chars(path, label)
    if path.startswith("/"):
        raise ValueError(f"{label} must not start with '/'")
    if path.startswith("-"):
        raise ValueError(f"{label} must not start with '-'")
    if not _CGROUP_PATH_RE.fullmatch(path):
        raise ValueError(f"{label} contains characters outside [A-Za-z0-9._:@/-]")
    if ".." in path.split("/"):
        raise ValueError(f"{label} must not contain '..' path segments")
    return path
```

**Step 4: Run to verify pass**

Run: `uv run pytest tests/test_validate.py -q -k cgroup_path`
Expected: PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/validate.py tests/test_validate.py
git commit -m "feat: add validate_cgroup_path shared validator"
```

---

### Task 2: slabtop (kernel.py)

`slabtop -o` (one-shot). Root-only → degrade via exit/stderr.

**Files:** Modify `linux_info_mcp/tools/kernel.py`; test `tests/tools/test_kernel.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# slabtop
# ---------------------------------------------------------------------------


def test_slabtop_builder():
    assert mod.build_remote_cmd_slabtop() == "LC_ALL=C slabtop -o"


def test_slabtop_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"slab\n", b"", 0, False))
    out = mod.handle_slabtop({"host": "h1"})
    assert out == {
        "stdout": "slab\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C slabtop -o"


def test_slabtop_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_slabtop({"host": "-evil"})


def test_slabtop_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_slabtop({"host": "h1"})
    assert out["truncated"] is True
```

(Confirm `test_kernel.py` imports `SshResult` and defines `_stub`.)

**Step 2: Run to verify fail** — `uv run pytest tests/tools/test_kernel.py -q -k slabtop` → FAIL.

**Step 3: Implement in `kernel.py`**

```python
# ---------------------------------------------------------------------------
# slabtop
# ---------------------------------------------------------------------------


def build_remote_cmd_slabtop() -> str:
    """Build LC_ALL=C slabtop one-shot command string."""
    return "LC_ALL=C slabtop -o"


def handle_slabtop(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_slabtop()
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


SLABTOP_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="slabtop",
        description=(
            "Run 'slabtop -o' (one-shot kernel slab cache stats) on a remote host via SSH. "
            "Root required. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SLABTOP_SCHEMA,
        handler=handle_slabtop,
    ),
```

**Step 4: Run to verify pass** — `... -k slabtop` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/kernel.py tests/tools/test_kernel.py
git commit -m "feat: add slabtop tool"
```

---

### Task 3: numastat (kernel.py)

`numastat [-p <pid>]`. numactl package may be absent → 127 passthrough.

**Files:** Modify `kernel.py`; test `test_kernel.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# numastat
# ---------------------------------------------------------------------------


def test_numastat_default_builder():
    assert mod.build_remote_cmd_numastat() == "LC_ALL=C numastat"


def test_numastat_pid_builder():
    assert mod.build_remote_cmd_numastat(pid=1234) == "LC_ALL=C numastat -p 1234"


def test_numastat_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"n\n", b"", 0, False))
    mod.handle_numastat({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C numastat"


def test_numastat_handler_pid(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_numastat({"host": "h1", "pid": 42})
    assert captured["cmd"] == "LC_ALL=C numastat -p 42"


def test_numastat_rejects_pid_zero(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_numastat({"host": "h1", "pid": 0})


def test_numastat_rejects_pid_bool(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_numastat({"host": "h1", "pid": True})


def test_numastat_rejects_pid_string(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_numastat({"host": "h1", "pid": "1; rm -rf /"})


def test_numastat_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_numastat({"host": "h1"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail** — `... -k numastat` → FAIL.

**Step 3: Implement in `kernel.py`**

Add the import for `validate_pid` to the existing `from ._common import ...` block:

```python
from ._common import decode_text as _decode_text
from ._common import validate_bool as _bool
from ._common import validate_pid
```

Implement:

```python
# ---------------------------------------------------------------------------
# numastat
# ---------------------------------------------------------------------------


def build_remote_cmd_numastat(*, pid: int | None = None) -> str:
    """Build LC_ALL=C numastat command string. pid is an int → safe interpolation."""
    parts = ["LC_ALL=C", "numastat"]
    if pid is not None:
        parts += ["-p", str(pid)]
    return " ".join(parts)


def handle_numastat(args: dict) -> dict:
    host = validate_host(args["host"])
    pid = args.get("pid")
    if pid is not None:
        pid = validate_pid(pid)
    cmd = build_remote_cmd_numastat(pid=pid)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


NUMASTAT_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "pid": {"type": ["integer", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="numastat",
        description=(
            "Run numastat (NUMA memory allocation stats, optional -p pid) on a remote host via "
            "SSH. numactl package may be absent (127 passthrough). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=NUMASTAT_SCHEMA,
        handler=handle_numastat,
    ),
```

**Step 4: Run to verify pass** — `... -k numastat` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/kernel.py tests/tools/test_kernel.py
git commit -m "feat: add numastat tool"
```

---

### Task 4: cgroup_stats (kernel.py)

Read controller stat files under `/sys/fs/cgroup/<path>/`. Path is traversal-safe-validated AND leaf filenames are a fixed whitelist per controller.

Controller → file list:
- `cpu` → `cpu.stat`
- `memory` → `memory.current memory.stat memory.pressure`
- `io` → `io.stat io.pressure`
- `all` → union of the above (in cpu, memory, io order)

Command: `grep -H '' /sys/fs/cgroup/<path>/<file1> /sys/fs/cgroup/<path>/<file2> ...` — the `<path>` segment is shell-quoted per file; the filenames are literals.

**Files:** Modify `kernel.py`; test `test_kernel.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# cgroup_stats
# ---------------------------------------------------------------------------


def test_cgroup_stats_cpu_builder():
    cmd = mod.build_remote_cmd_cgroup_stats(cgroup_path="user.slice", controller="cpu")
    assert cmd == "LC_ALL=C grep -H '' /sys/fs/cgroup/user.slice/cpu.stat"


def test_cgroup_stats_memory_builder():
    cmd = mod.build_remote_cmd_cgroup_stats(cgroup_path="user.slice", controller="memory")
    assert cmd == (
        "LC_ALL=C grep -H '' "
        "/sys/fs/cgroup/user.slice/memory.current "
        "/sys/fs/cgroup/user.slice/memory.stat "
        "/sys/fs/cgroup/user.slice/memory.pressure"
    )


def test_cgroup_stats_io_builder():
    cmd = mod.build_remote_cmd_cgroup_stats(cgroup_path="user.slice", controller="io")
    assert cmd == (
        "LC_ALL=C grep -H '' "
        "/sys/fs/cgroup/user.slice/io.stat "
        "/sys/fs/cgroup/user.slice/io.pressure"
    )


def test_cgroup_stats_all_builder():
    cmd = mod.build_remote_cmd_cgroup_stats(cgroup_path="x", controller="all")
    assert cmd == (
        "LC_ALL=C grep -H '' "
        "/sys/fs/cgroup/x/cpu.stat "
        "/sys/fs/cgroup/x/memory.current "
        "/sys/fs/cgroup/x/memory.stat "
        "/sys/fs/cgroup/x/memory.pressure "
        "/sys/fs/cgroup/x/io.stat "
        "/sys/fs/cgroup/x/io.pressure"
    )


def test_cgroup_stats_handler_default_is_all(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"c\n", b"", 0, False))
    mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "user.slice"})
    assert captured["cmd"].startswith("LC_ALL=C grep -H '' /sys/fs/cgroup/user.slice/cpu.stat")


def test_cgroup_stats_requires_path(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises((ValueError, KeyError)):
        mod.handle_cgroup_stats({"host": "h1"})


def test_cgroup_stats_rejects_bad_controller(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "x", "controller": "pids"})


def test_cgroup_stats_rejects_traversal(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "../../etc/shadow"})


def test_cgroup_stats_rejects_leading_slash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "/etc"})


def test_cgroup_stats_rejects_path_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "x; rm -rf /"})


def test_cgroup_stats_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_cgroup_stats({"host": "h1", "cgroup_path": "x"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail** — `... -k cgroup_stats` → FAIL.

**Step 3: Implement in `kernel.py`**

Add to the imports from `..validate` (the existing block):

```python
from ..validate import (
    reject_unsafe_chars,
    validate_cgroup_path,
    validate_host,
    validate_int_in_range,
)
```

Implement:

```python
# ---------------------------------------------------------------------------
# cgroup_stats
# ---------------------------------------------------------------------------

_CGROUP_CONTROLLER_FILES = {
    "cpu": ["cpu.stat"],
    "memory": ["memory.current", "memory.stat", "memory.pressure"],
    "io": ["io.stat", "io.pressure"],
}
_CGROUP_ALL_ORDER = ["cpu", "memory", "io"]


def _validate_cgroup_controller(controller) -> str:
    if controller is None:
        return "all"
    valid = set(_CGROUP_CONTROLLER_FILES) | {"all"}
    if not isinstance(controller, str) or controller not in valid:
        raise ValueError(f"controller must be one of {sorted(valid)}")
    return controller


def _cgroup_files_for(controller: str) -> list[str]:
    if controller == "all":
        files: list[str] = []
        for c in _CGROUP_ALL_ORDER:
            files += _CGROUP_CONTROLLER_FILES[c]
        return files
    return _CGROUP_CONTROLLER_FILES[controller]


def build_remote_cmd_cgroup_stats(*, cgroup_path: str, controller: str = "all") -> str:
    """Build LC_ALL=C grep over whitelisted cgroup stat files. Path quoted, filenames literal."""
    files = _cgroup_files_for(controller)
    base = shlex.quote(cgroup_path)
    targets = " ".join(f"/sys/fs/cgroup/{base}/{f}" for f in files)
    return f"LC_ALL=C grep -H '' {targets}"


def handle_cgroup_stats(args: dict) -> dict:
    host = validate_host(args["host"])
    path_in = args.get("cgroup_path")
    if path_in is None:
        raise ValueError("cgroup_path is required")
    cgroup_path = validate_cgroup_path(path_in)
    controller = _validate_cgroup_controller(args.get("controller"))
    cmd = build_remote_cmd_cgroup_stats(cgroup_path=cgroup_path, controller=controller)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


CGROUP_STATS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "cgroup_path": {"type": "string"},
        "controller": {
            "type": ["string", "null"],
            "enum": ["cpu", "memory", "io", "all", None],
        },
    },
    "required": ["host", "cgroup_path"],
    "additionalProperties": False,
}
```

Note: `shlex.quote("user.slice")` returns `user.slice` unquoted (no metachars), so the builder test expectations with bare paths hold. A path with quotable chars would be wrapped — but such chars are already rejected by `validate_cgroup_path` at the handler boundary; the builder quote is the belt-and-suspenders layer.

Add to `TOOLS`:

```python
    ToolSpec(
        name="cgroup_stats",
        description=(
            "Read cgroup v2 controller stat files (cpu|memory|io|all) under "
            "/sys/fs/cgroup/<path> on a remote host via SSH. Path is traversal-safe; leaf "
            "files are whitelisted. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=CGROUP_STATS_SCHEMA,
        handler=handle_cgroup_stats,
    ),
```

**Step 4: Run to verify pass** — `... -k cgroup_stats` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/kernel.py tests/tools/test_kernel.py
git commit -m "feat: add cgroup_stats tool (whitelisted controller files)"
```

---

### Task 5: systemd_analyze (kernel.py)

`systemd-analyze <mode> [--no-pager] [<unit>]`. mode enum `time|blame|critical-chain` (default `time`); optional `unit` (validate_unit_name) for critical-chain.

**Files:** Modify `kernel.py`; test `test_kernel.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# systemd_analyze
# ---------------------------------------------------------------------------


def test_systemd_analyze_default_builder():
    assert mod.build_remote_cmd_systemd_analyze(mode="time") == (
        "LC_ALL=C systemd-analyze time --no-pager"
    )


def test_systemd_analyze_blame_builder():
    assert mod.build_remote_cmd_systemd_analyze(mode="blame") == (
        "LC_ALL=C systemd-analyze blame --no-pager"
    )


def test_systemd_analyze_critical_chain_builder():
    assert mod.build_remote_cmd_systemd_analyze(mode="critical-chain") == (
        "LC_ALL=C systemd-analyze critical-chain --no-pager"
    )


def test_systemd_analyze_critical_chain_unit_builder():
    cmd = mod.build_remote_cmd_systemd_analyze(mode="critical-chain", unit="sshd.service")
    assert cmd == "LC_ALL=C systemd-analyze critical-chain --no-pager sshd.service"


def test_systemd_analyze_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"t\n", b"", 0, False))
    mod.handle_systemd_analyze({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C systemd-analyze time --no-pager"


def test_systemd_analyze_rejects_bad_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_systemd_analyze({"host": "h1", "mode": "dump"})


def test_systemd_analyze_rejects_unit_without_critical_chain(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_systemd_analyze({"host": "h1", "mode": "time", "unit": "sshd.service"})


def test_systemd_analyze_rejects_unit_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_systemd_analyze(
            {"host": "h1", "mode": "critical-chain", "unit": "sshd; rm -rf /"}
        )


def test_systemd_analyze_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_systemd_analyze({"host": "h1"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail** — `... -k systemd_analyze` → FAIL.

**Step 3: Implement in `kernel.py`**

Add `validate_unit_name` to the `..validate` import block.

```python
# ---------------------------------------------------------------------------
# systemd_analyze
# ---------------------------------------------------------------------------

_SYSTEMD_ANALYZE_MODES = {"time", "blame", "critical-chain"}


def _validate_systemd_analyze_mode(mode) -> str:
    if mode is None:
        return "time"
    if not isinstance(mode, str) or mode not in _SYSTEMD_ANALYZE_MODES:
        raise ValueError(f"mode must be one of {sorted(_SYSTEMD_ANALYZE_MODES)}")
    return mode


def build_remote_cmd_systemd_analyze(*, mode: str = "time", unit: str | None = None) -> str:
    """Build LC_ALL=C systemd-analyze command string."""
    parts = ["LC_ALL=C", "systemd-analyze", mode, "--no-pager"]
    if unit is not None:
        parts.append(shlex.quote(unit))
    return " ".join(parts)


def handle_systemd_analyze(args: dict) -> dict:
    host = validate_host(args["host"])
    mode = _validate_systemd_analyze_mode(args.get("mode"))
    unit = args.get("unit")
    if unit is not None:
        if mode != "critical-chain":
            raise ValueError("unit is only valid with mode=critical-chain")
        unit = validate_unit_name(unit)
    cmd = build_remote_cmd_systemd_analyze(mode=mode, unit=unit)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


SYSTEMD_ANALYZE_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "mode": {
            "type": ["string", "null"],
            "enum": ["time", "blame", "critical-chain", None],
        },
        "unit": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="systemd_analyze",
        description=(
            "Run systemd-analyze (time|blame|critical-chain, default time) on a remote host via "
            "SSH; optional unit for critical-chain. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=SYSTEMD_ANALYZE_SCHEMA,
        handler=handle_systemd_analyze,
    ),
```

Update the registry-names test at the bottom of `test_kernel.py` to expect the four kernel additions appended after the existing `["dmesg", "uname", "sysctl"]`:

```python
    assert names == [
        "dmesg",
        "uname",
        "sysctl",
        "slabtop",
        "numastat",
        "cgroup_stats",
        "systemd_analyze",
    ]
```

**Step 4: Run to verify pass** — `uv run pytest tests/tools/test_kernel.py -q` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/kernel.py tests/tools/test_kernel.py
git commit -m "feat: add systemd_analyze tool"
```

---

### Task 6: blockdev (disk.py)

`blockdev --report` (all devices; no per-device arg → no injection surface). Complements lsblk/smartctl.

**Files:** Modify `linux_info_mcp/tools/disk.py`; test `tests/tools/test_disk.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# blockdev
# ---------------------------------------------------------------------------


def test_blockdev_builder():
    assert mod.build_remote_cmd_blockdev() == "LC_ALL=C blockdev --report"


def test_blockdev_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"RO RA ...\n", b"", 0, False))
    out = mod.handle_blockdev({"host": "h1"})
    assert out == {
        "stdout": "RO RA ...\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "stderr_truncated": False,
    }
    assert captured["cmd"] == "LC_ALL=C blockdev --report"


def test_blockdev_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_blockdev({"host": "-evil"})


def test_blockdev_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_blockdev({"host": "h1"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail** — `uv run pytest tests/tools/test_disk.py -q -k blockdev` → FAIL.

**Step 3: Implement in `disk.py`**

```python
# ---------------------------------------------------------------------------
# blockdev
# ---------------------------------------------------------------------------


def build_remote_cmd_blockdev() -> str:
    """Build LC_ALL=C blockdev --report command string."""
    return "LC_ALL=C blockdev --report"


def handle_blockdev(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_blockdev()
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


BLOCKDEV_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="blockdev",
        description=(
            "Run 'blockdev --report' (block device sizes, sector/block sizes, RO/RA flags) on a "
            "remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=BLOCKDEV_SCHEMA,
        handler=handle_blockdev,
    ),
```

Update the registry-names test at the bottom of `test_disk.py` to expect `blockdev` appended after `["du", "lsblk", "blkid", "smartctl"]`.

**Step 4: Run to verify pass** — `uv run pytest tests/tools/test_disk.py -q` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/disk.py tests/tools/test_disk.py
git commit -m "feat: add blockdev tool"
```

---

### Task 7: Docs + full-suite gate

**Files:** `SPEC.md` (5 new tool sections + a note on `validate_cgroup_path`), `README.md` (5 entries), `AGENTS.md` (tool count 56 → 61; kernel.py inventory gains 4 tools, disk.py gains blockdev; add `validate_cgroup_path` to the shared-validators list).

**Step 1: Update docs.**

**Step 2: Full suite** — `uv run pytest -q` → PASS.

**Step 3: Discovery count** — `uv run python -c "from linux_info_mcp.server import _discover_tools; print(len(_discover_tools()))"` → `61`.

**Step 4: Commit**

```bash
git add SPEC.md README.md AGENTS.md
git commit -m "docs: document Cluster C kernel/perf tools; tool count 56 -> 61"
```

---

## Done criteria
- 5 new tools + `validate_cgroup_path` registered/available.
- `uv run pytest -q` fully green.
- cgroup_stats: traversal/leading-slash/injection rejections proven; builder emits only whitelisted leaf files.
- Root/package-dependent tools documented; degrade via passthrough.
- Docs updated; tool count reads 61.
