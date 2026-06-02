# Cluster D — host_facts Meta-Tool Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a single `host_facts` meta-tool in a new module `facts.py` that runs one SSH round-trip, bundling several read-only probes, and returns a structured `facts` dict plus the raw output — taking the tool count 61 → 62 (assumes Clusters A+B+C landed).

**Architecture:** One tool, **one SSH round-trip**. The remote command is a fixed bundled shell script (no user interpolation beyond the validated host) wrapped as `LC_ALL=C sh -c <quoted-script>`. Each probe is wrapped `2>/dev/null || true` so one missing binary never aborts the rest. The script emits delimiter-marked sections (`===name===`); a pure `_parse_facts(stdout)` function parses them into a structured dict. The parser is the primary unit under test — it is decoupled from SSH so it can be tested against representative blobs. `server.py` auto-discovers the new module; no wiring needed.

**Tech Stack:** Python 3, `shlex.quote` on the script, pytest. The handler return shape extends the standard dict with a parsed `facts` key.

**Reference:** Design doc `docs/plans/2026-06-01-new-diagnostic-tools-design.md` §"Cluster D". `SPEC.md`.

**Conventions:** new module mirrors existing module structure (module docstring, imports from `..ssh`/`..validate`/`.`/`._common`, `TOOLS` list). Mock `run_ssh` at module site in handler tests. The standard 5 keys (`stdout, stderr, exit_code, truncated, stderr_truncated`) are present; `facts` is added.

---

### Task 1: Bundled-script builder + facts parser (new module facts.py)

Create `facts.py` with `build_remote_cmd_host_facts()` (fixed script) and `_parse_facts(text)` (pure parser). No SSH yet — this task is the script string and the parser, both unit-tested in isolation.

**Files:**
- Create: `linux_info_mcp/tools/facts.py`
- Create: `tests/tools/test_facts.py`

**Step 1: Write the failing tests**

Create `tests/tools/test_facts.py`:

```python
import pytest

import linux_info_mcp.tools.facts as mod
from linux_info_mcp.ssh import SshResult


def _stub(monkeypatch, result):
    captured = {}

    def fake(host, cmd):
        captured["host"] = host
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(mod, "run_ssh", fake)
    return captured


# A representative bundled-output blob, in the exact section order the builder emits.
SAMPLE = """===os_release===
NAME="Ubuntu"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
===uname===
Linux 5.15.0-91-generic x86_64
===nproc===
8
===mem_total===
MemTotal:       16384000 kB
===virt===
kvm
===container===
none
===dmi_vendor===
QEMU
===dmi_product===
Standard PC (Q35 + ICH9, 2009)
===capabilities===
docker yes
podman no
systemctl yes
nft no
conntrack no
ethtool yes
smartctl yes
numastat no
slabtop yes
===uptime===
123456.78 987654.32
===now_utc===
2026-06-01T12:00:00Z
===whoami===
root
===END===
"""


# ---- builder ----


def test_host_facts_builder_is_fixed_and_quoted():
    cmd = mod.build_remote_cmd_host_facts()
    assert cmd.startswith("LC_ALL=C sh -c ")
    # No host or user value is interpolated; the script is a constant.
    assert "===os_release===" in cmd
    assert "===END===" in cmd


# ---- parser ----


def test_parse_facts_distro():
    f = mod._parse_facts(SAMPLE)
    assert f["distro"]["ID"] == "ubuntu"
    assert f["distro"]["VERSION_ID"] == "22.04"
    assert f["distro"]["PRETTY_NAME"] == "Ubuntu 22.04.3 LTS"


def test_parse_facts_kernel_arch():
    f = mod._parse_facts(SAMPLE)
    assert f["kernel"] == "5.15.0-91-generic"
    assert f["arch"] == "x86_64"


def test_parse_facts_nproc_and_mem():
    f = mod._parse_facts(SAMPLE)
    assert f["nproc"] == 8
    assert f["mem_total_kb"] == 16384000


def test_parse_facts_virt():
    f = mod._parse_facts(SAMPLE)
    assert f["hypervisor"] == "kvm"
    assert f["container"] == "none"
    assert f["dmi_vendor"] == "QEMU"
    assert f["dmi_product"].startswith("Standard PC")
    assert f["is_virtual"] is True


def test_parse_facts_is_virtual_false_on_bare_metal():
    blob = SAMPLE.replace("kvm", "none").replace("QEMU", "Dell Inc.")
    f = mod._parse_facts(blob)
    assert f["hypervisor"] == "none"
    assert f["is_virtual"] is False


def test_parse_facts_is_virtual_true_from_dmi_only():
    # hypervisor=none but DMI vendor is a VM signature
    blob = SAMPLE.replace("kvm", "none").replace("QEMU", "VMware, Inc.")
    f = mod._parse_facts(blob)
    assert f["hypervisor"] == "none"
    assert f["is_virtual"] is True


def test_parse_facts_capabilities():
    f = mod._parse_facts(SAMPLE)
    caps = f["capabilities"]
    assert caps["docker"] is True
    assert caps["podman"] is False
    assert caps["nft"] is False
    assert caps["slabtop"] is True


def test_parse_facts_uptime_now_whoami():
    f = mod._parse_facts(SAMPLE)
    assert f["uptime_s"] == 123456
    assert f["now_utc"] == "2026-06-01T12:00:00Z"
    assert f["whoami"] == "root"


def test_parse_facts_tolerates_missing_sections():
    # Empty probes (missing binary) must not crash the parser.
    blob = """===os_release===
===uname===
===nproc===
===mem_total===
===virt===
===container===
===dmi_vendor===
===dmi_product===
===capabilities===
===uptime===
===now_utc===
===whoami===
===END===
"""
    f = mod._parse_facts(blob)
    assert f["distro"] == {}
    assert f["kernel"] is None
    assert f["arch"] is None
    assert f["nproc"] is None
    assert f["mem_total_kb"] is None
    assert f["hypervisor"] == "none"
    assert f["capabilities"] == {}
    assert f["uptime_s"] is None
    assert f["is_virtual"] is False
```

**Step 2: Run to verify fail**

Run: `uv run pytest tests/tools/test_facts.py -q`
Expected: FAIL — `ModuleNotFoundError`/`AttributeError` (no `facts.py`).

**Step 3: Implement `facts.py`**

```python
"""Host facts meta-tool: one SSH round-trip, bundled read-only probes."""

from __future__ import annotations

import shlex

from ..ssh import run_ssh
from ..validate import validate_host
from . import ToolSpec
from ._common import decode_text as _decode_text

_CAP_TOOLS = [
    "docker",
    "podman",
    "systemctl",
    "nft",
    "conntrack",
    "ethtool",
    "smartctl",
    "numastat",
    "slabtop",
]

_VM_DMI_SIGNATURES = (
    "vmware",
    "qemu",
    "kvm",
    "xen",
    "virtualbox",
    "innotek",
    "microsoft",
    "bochs",
    "bhyve",
    "parallels",
    "oracle",
)

# Fixed bundled script. No user interpolation. Each probe degrades to empty via 2>/dev/null||true.
_SCRIPT = (
    "echo '===os_release==='; cat /etc/os-release 2>/dev/null || true; "
    "echo '===uname==='; uname -srm 2>/dev/null || true; "
    "echo '===nproc==='; nproc 2>/dev/null || true; "
    "echo '===mem_total==='; grep -i MemTotal /proc/meminfo 2>/dev/null || true; "
    "echo '===virt==='; systemd-detect-virt 2>/dev/null || true; "
    "echo '===container==='; systemd-detect-virt -c 2>/dev/null || true; "
    "echo '===dmi_vendor==='; cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true; "
    "echo '===dmi_product==='; cat /sys/class/dmi/id/product_name 2>/dev/null || true; "
    "echo '===capabilities==='; "
    "for t in " + " ".join(_CAP_TOOLS) + "; do "
    "if command -v \"$t\" >/dev/null 2>&1; then echo \"$t yes\"; else echo \"$t no\"; fi; "
    "done; "
    "echo '===uptime==='; cat /proc/uptime 2>/dev/null || true; "
    "echo '===now_utc==='; date -u +%FT%TZ 2>/dev/null || true; "
    "echo '===whoami==='; id -un 2>/dev/null || true; "
    "echo '===END==='"
)


def build_remote_cmd_host_facts() -> str:
    """Build the fixed bundled probe script as a single LC_ALL=C sh -c command."""
    return "LC_ALL=C sh -c " + shlex.quote(_SCRIPT)


def _split_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("===") and line.endswith("===") and len(line) > 6:
            current = line[3:-3]
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return sections


def _section_text(sections: dict, name: str) -> str:
    return "\n".join(sections.get(name, [])).strip()


def _parse_kv(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k:
            out[k] = v
    return out


def _first_int(s: str):
    for tok in s.split():
        if tok.isdigit():
            return int(tok)
    return None


def _parse_facts(text: str) -> dict:
    sec = _split_sections(text)

    os_rel = _parse_kv(sec.get("os_release", []))
    distro = {k: os_rel[k] for k in ("ID", "VERSION_ID", "PRETTY_NAME") if k in os_rel}

    uname = _section_text(sec, "uname").split()
    kernel = uname[1] if len(uname) >= 2 else None
    arch = uname[-1] if len(uname) >= 3 else None

    nproc = _first_int(_section_text(sec, "nproc"))
    mem_total_kb = _first_int(_section_text(sec, "mem_total"))

    hypervisor = _section_text(sec, "virt") or "none"
    container = _section_text(sec, "container") or "none"
    dmi_vendor = _section_text(sec, "dmi_vendor")
    dmi_product = _section_text(sec, "dmi_product")

    dmi_blob = (dmi_vendor + " " + dmi_product).lower()
    dmi_is_vm = any(sig in dmi_blob for sig in _VM_DMI_SIGNATURES)
    is_virtual = (hypervisor not in ("", "none")) or dmi_is_vm

    capabilities: dict[str, bool] = {}
    for line in sec.get("capabilities", []):
        parts = line.split()
        if len(parts) == 2:
            capabilities[parts[0]] = parts[1] == "yes"

    uptime_field = _section_text(sec, "uptime").split()
    uptime_s = None
    if uptime_field:
        try:
            uptime_s = int(float(uptime_field[0]))
        except ValueError:
            uptime_s = None

    now_utc = _section_text(sec, "now_utc") or None
    whoami = _section_text(sec, "whoami") or None

    return {
        "distro": distro,
        "kernel": kernel,
        "arch": arch,
        "nproc": nproc,
        "mem_total_kb": mem_total_kb,
        "hypervisor": hypervisor,
        "container": container,
        "dmi_vendor": dmi_vendor or None,
        "dmi_product": dmi_product or None,
        "is_virtual": is_virtual,
        "capabilities": capabilities,
        "uptime_s": uptime_s,
        "now_utc": now_utc,
        "whoami": whoami,
    }


def handle_host_facts(args: dict) -> dict:
    host = validate_host(args["host"])
    cmd = build_remote_cmd_host_facts()
    res = run_ssh(host, cmd)
    stdout = _decode_text(res.stdout)
    return {
        "facts": _parse_facts(stdout),
        "stdout": stdout,
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


HOST_FACTS_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
    "additionalProperties": False,
}


TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="host_facts",
        description=(
            "Gather host facts in one SSH round-trip: distro, kernel/arch, nproc, mem, "
            "virtualization (hypervisor/container/DMI + derived is_virtual), tool capabilities, "
            "uptime, now_utc, whoami. Returns {facts, stdout, stderr, exit_code, truncated}."
        ),
        input_schema=HOST_FACTS_SCHEMA,
        handler=handle_host_facts,
    ),
]
```

**Step 4: Run to verify pass**

Run: `uv run pytest tests/tools/test_facts.py -q`
Expected: builder + parser tests PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/facts.py tests/tools/test_facts.py
git commit -m "feat: add host_facts builder and facts parser"
```

---

### Task 2: host_facts handler + registration tests

Add handler-level tests (SSH mocked) and a discovery test.

**Files:**
- Modify: `tests/tools/test_facts.py`

**Step 1: Write the failing tests**

Append:

```python
# ---- handler ----


def test_host_facts_handler_parses_and_passes_through(monkeypatch):
    captured = _stub(monkeypatch, SshResult(SAMPLE.encode(), b"", 0, False))
    out = mod.handle_host_facts({"host": "h1"})
    assert captured["cmd"] == mod.build_remote_cmd_host_facts()
    assert out["exit_code"] == 0
    assert out["truncated"] is False
    assert out["stderr_truncated"] is False
    assert out["stdout"] == SAMPLE
    assert out["facts"]["distro"]["ID"] == "ubuntu"
    assert out["facts"]["capabilities"]["docker"] is True
    assert out["facts"]["is_virtual"] is True


def test_host_facts_handler_rejects_bad_host(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_host_facts({"host": "-evil"})


def test_host_facts_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(SAMPLE.encode(), b"", 0, True))
    out = mod.handle_host_facts({"host": "h1"})
    assert out["truncated"] is True


def test_host_facts_handles_empty_stdout(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"boom", 1, False))
    out = mod.handle_host_facts({"host": "h1"})
    assert out["exit_code"] == 1
    assert out["facts"]["distro"] == {}
    assert out["facts"]["is_virtual"] is False


def test_tools_registry():
    names = [t.name for t in mod.TOOLS]
    assert names == ["host_facts"]
    spec = mod.TOOLS[0]
    assert spec.input_schema["required"] == ["host"]
    assert callable(spec.handler)
```

**Step 2: Run to verify fail/pass**

Run: `uv run pytest tests/tools/test_facts.py -q`
Expected: the new handler tests pass against the Task 1 implementation (the handler already exists). If any fail, fix the handler — do not weaken the test. (This task is mostly test coverage hardening; if all already green, that is the expected outcome.)

**Step 3: Verify discovery picks up the new module**

Run: `uv run python -c "from linux_info_mcp.server import _discover_tools; ts=_discover_tools(); print(len(ts)); print('host_facts' in [t.name for t in ts])"`
Expected: `62` then `True` (adjust to the actual `_discover_tools` signature in `linux_info_mcp/server.py`).

If `test_server.py` asserts a fixed total tool count, update it 61 → 62.

**Step 4: Run the full suite**

Run: `uv run pytest -q`
Expected: PASS, all green.

**Step 5: Commit**

```bash
git add tests/tools/test_facts.py tests/test_server.py
git commit -m "test: host_facts handler + discovery coverage"
```

(Only stage `tests/test_server.py` if you actually modified it.)

---

### Task 3: Docs + final gate

**Files:** `SPEC.md` (new §62 for host_facts, documenting the bundled probes, the parsed `facts` shape, and that it is a single round-trip), `README.md` (one entry), `AGENTS.md` (tool count 61 → 62; add the `facts.py` module to the module map and the per-area inventory; also — per the design doc cross-cutting note — correct any stale "4-key" return-shape note to "5-key", and note host_facts adds a parsed `facts` key).

**Step 1: Update docs.**

**Step 2: Full suite from clean state**

Run: `uv sync && uv run pytest -q`
Expected: PASS.

**Step 3: Commit**

```bash
git add SPEC.md README.md AGENTS.md
git commit -m "docs: document host_facts meta-tool; tool count 61 -> 62"
```

---

## Done criteria
- `host_facts` registered and discoverable; total tool count 62.
- `_parse_facts` covered against a full blob, a bare-metal blob, a DMI-only-VM blob, and an all-empty blob.
- Single SSH round-trip; every probe degrades independently (`2>/dev/null || true`).
- No user interpolation in the remote command beyond the validated host.
- `uv run pytest -q` fully green from a clean `uv sync`.
- Docs updated; tool count reads 62; stale 4-key note corrected to 5-key.

---

## Deferred (explicitly NOT in this batch, per design doc)
- TTL/session caching of host_facts and other slow-changing data.
- Structured/parsed output for the other (non-facts) tools.
