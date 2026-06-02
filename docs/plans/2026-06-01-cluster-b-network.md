# Cluster B — Network Tools Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 6 read-only network diagnostic tools (tc_qdisc, ethtool, conntrack, net_protocol_stats, nft_list, iptables_list) to `net.py`, taking the tool count 50 → 56 (assumes Cluster A landed first).

**Architecture:** Same per-tool pattern as Cluster A. All six tools land in `linux_info_mcp/tools/net.py`. Several require root or specific kernel modules/packages; missing privileges or binaries surface via the existing `exit_code`/`stderr` passthrough (127 fast for a missing binary, permission text in stderr for root tools). Root requirements go in each tool description. No tool mutates remote state — every command is a `show`/`list`/`-S` read.

**Tech Stack:** Python 3, `shlex.quote` on all interpolated values, whitelist enums mapped to fixed flags, pytest with `run_ssh` monkeypatched at module site.

**Reference:** Design doc `docs/plans/2026-06-01-new-diagnostic-tools-design.md` §"Cluster B". `SPEC.md`.

**Decisions locked for this plan (resolving design-doc ambiguity):**
- `nft_list`: args are optional `table` (identifier) AND optional `family` (enum `ip|ip6|inet|arp|bridge|netdev`). Default (no table) → `nft -nn list ruleset`. If `table` is given, `family` is **required** (nft requires a family to address a table) → `nft -nn list table <family> <table>`. Supplying `family` without `table` is rejected.
- `net_protocol_stats`: enum `all|tcp|udp|ip` → `netstat -s` with `all`→no flag, `tcp`→`--tcp`, `udp`→`--udp`, `ip`→`--raw` (per design doc's `[--tcp|--udp|--raw]`).
- `iptables_list`: `family` default `ipv4` (`iptables`), `ipv6`→`ip6tables`.

**Conventions:** identical to Cluster A (mock `run_ssh` at module site; 5-key return dict; adversarial inputs `-oProxyCommand=evil`/`foo;rm -rf /`/`\n`/`\x00`; truncation-propagation test per tool; full suite green before each commit). Reuse the existing `_validate_iface` already in `net.py`.

---

### Task 1: tc_qdisc

`tc -s qdisc show [dev <iface>]` — queue depth/drops. Non-root readable.

**Files:** Modify `linux_info_mcp/tools/net.py`; test `tests/tools/test_net.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# tc_qdisc
# ---------------------------------------------------------------------------


def test_tc_qdisc_default_builder():
    assert mod.build_remote_cmd_tc_qdisc() == "LC_ALL=C tc -s qdisc show"


def test_tc_qdisc_iface_builder():
    assert mod.build_remote_cmd_tc_qdisc(iface="eth0") == "LC_ALL=C tc -s qdisc show dev eth0"


def test_tc_qdisc_handler_happy(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"q\n", b"", 0, False))
    out = mod.handle_tc_qdisc({"host": "h1", "iface": "ens3"})
    assert out["stdout"] == "q\n"
    assert captured["cmd"] == "LC_ALL=C tc -s qdisc show dev ens3"


def test_tc_qdisc_rejects_iface_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_tc_qdisc({"host": "h1", "iface": "eth0; rm -rf /"})


def test_tc_qdisc_rejects_iface_dash(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_tc_qdisc({"host": "h1", "iface": "-oProxyCommand=evil"})


def test_tc_qdisc_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_tc_qdisc({"host": "h1"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail** — `uv run pytest tests/tools/test_net.py -q -k tc_qdisc` → FAIL.

**Step 3: Implement in `net.py`**

```python
# ---------------------------------------------------------------------------
# tc_qdisc
# ---------------------------------------------------------------------------


def build_remote_cmd_tc_qdisc(*, iface: str | None = None) -> str:
    """Build LC_ALL=C tc -s qdisc show command string."""
    parts = ["LC_ALL=C", "tc", "-s", "qdisc", "show"]
    if iface is not None:
        parts += ["dev", shlex.quote(iface)]
    return " ".join(parts)


def handle_tc_qdisc(args: dict) -> dict:
    host = validate_host(args["host"])
    iface = args.get("iface")
    if iface is not None:
        iface = _validate_iface(iface)
    cmd = build_remote_cmd_tc_qdisc(iface=iface)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


TC_QDISC_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "iface": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="tc_qdisc",
        description=(
            "Run 'tc -s qdisc show' (queueing discipline stats: queue depth, drops) on a "
            "remote host via SSH. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=TC_QDISC_SCHEMA,
        handler=handle_tc_qdisc,
    ),
```

**Step 4: Run to verify pass** — `uv run pytest tests/tools/test_net.py -q -k tc_qdisc` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/net.py tests/tools/test_net.py
git commit -m "feat: add tc_qdisc tool"
```

---

### Task 2: ethtool

`ethtool <mode-flag> <iface>` — driver/stats/ring/features/pause/coalesce. `iface` required. Some modes need privileges (exit/stderr passthrough).

**Files:** Modify `net.py`; test `test_net.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# ethtool
# ---------------------------------------------------------------------------


def test_ethtool_default_mode_builder():
    assert mod.build_remote_cmd_ethtool(iface="eth0", mode_flag="-i") == "LC_ALL=C ethtool -i eth0"


def test_ethtool_stats_builder():
    assert mod.build_remote_cmd_ethtool(iface="eth0", mode_flag="-S") == "LC_ALL=C ethtool -S eth0"


def test_ethtool_handler_default_is_driver(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"drv\n", b"", 0, False))
    out = mod.handle_ethtool({"host": "h1", "iface": "eth0"})
    assert out["stdout"] == "drv\n"
    assert captured["cmd"] == "LC_ALL=C ethtool -i eth0"


def test_ethtool_handler_each_mode(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    expect = {
        "stats": "-S",
        "driver": "-i",
        "ring": "-g",
        "features": "-k",
        "pause": "-a",
        "coalesce": "-c",
    }
    for mode, flag in expect.items():
        mod.handle_ethtool({"host": "h1", "iface": "eth0", "mode": mode})
        assert captured["cmd"] == f"LC_ALL=C ethtool {flag} eth0"


def test_ethtool_requires_iface(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises((ValueError, KeyError)):
        mod.handle_ethtool({"host": "h1"})


def test_ethtool_rejects_bad_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ethtool({"host": "h1", "iface": "eth0", "mode": "reset"})


def test_ethtool_rejects_iface_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_ethtool({"host": "h1", "iface": "eth0; rm -rf /"})


def test_ethtool_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_ethtool({"host": "h1", "iface": "eth0"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail** — `uv run pytest tests/tools/test_net.py -q -k ethtool` → FAIL.

**Step 3: Implement in `net.py`**

```python
# ---------------------------------------------------------------------------
# ethtool
# ---------------------------------------------------------------------------

_ETHTOOL_MODE_MAP = {
    "stats": "-S",
    "driver": "-i",
    "ring": "-g",
    "features": "-k",
    "pause": "-a",
    "coalesce": "-c",
}


def _validate_ethtool_mode(mode) -> str:
    if mode is None:
        return _ETHTOOL_MODE_MAP["driver"]
    if not isinstance(mode, str) or mode not in _ETHTOOL_MODE_MAP:
        raise ValueError(f"mode must be one of {sorted(_ETHTOOL_MODE_MAP)}")
    return _ETHTOOL_MODE_MAP[mode]


def build_remote_cmd_ethtool(*, iface: str, mode_flag: str) -> str:
    """Build LC_ALL=C ethtool command string."""
    return f"LC_ALL=C ethtool {mode_flag} {shlex.quote(iface)}"


def handle_ethtool(args: dict) -> dict:
    host = validate_host(args["host"])
    iface_in = args.get("iface")
    if iface_in is None:
        raise ValueError("iface is required")
    iface = _validate_iface(iface_in)
    mode_flag = _validate_ethtool_mode(args.get("mode"))
    cmd = build_remote_cmd_ethtool(iface=iface, mode_flag=mode_flag)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


ETHTOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "iface": {"type": "string"},
        "mode": {
            "type": ["string", "null"],
            "enum": ["stats", "driver", "ring", "features", "pause", "coalesce", None],
        },
    },
    "required": ["host", "iface"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="ethtool",
        description=(
            "Run ethtool against an interface on a remote host via SSH using a preset mode "
            "(driver|stats|ring|features|pause|coalesce, default driver). Some modes need "
            "privileges (exit/stderr passthrough). Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=ETHTOOL_SCHEMA,
        handler=handle_ethtool,
    ),
```

**Step 4: Run to verify pass** — `uv run pytest tests/tools/test_net.py -q -k ethtool` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/net.py tests/tools/test_net.py
git commit -m "feat: add ethtool tool (preset modes)"
```

---

### Task 3: conntrack

`conntrack -S` (stats) or `conntrack -L [-p <proto>]` (list). Root + nf_conntrack module. List output can be large → truncation flagged via passthrough.

**Files:** Modify `net.py`; test `test_net.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# conntrack
# ---------------------------------------------------------------------------


def test_conntrack_default_stats_builder():
    assert mod.build_remote_cmd_conntrack(mode="stats") == "LC_ALL=C conntrack -S"


def test_conntrack_list_builder():
    assert mod.build_remote_cmd_conntrack(mode="list") == "LC_ALL=C conntrack -L"


def test_conntrack_list_proto_builder():
    cmd = mod.build_remote_cmd_conntrack(mode="list", protocol="tcp")
    assert cmd == "LC_ALL=C conntrack -L -p tcp"


def test_conntrack_handler_default_is_stats(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"s\n", b"", 0, False))
    mod.handle_conntrack({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C conntrack -S"


def test_conntrack_handler_list_udp(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_conntrack({"host": "h1", "mode": "list", "protocol": "udp"})
    assert captured["cmd"] == "LC_ALL=C conntrack -L -p udp"


def test_conntrack_rejects_protocol_with_stats(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_conntrack({"host": "h1", "mode": "stats", "protocol": "tcp"})


def test_conntrack_rejects_bad_mode(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_conntrack({"host": "h1", "mode": "flush"})


def test_conntrack_rejects_bad_protocol(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_conntrack({"host": "h1", "mode": "list", "protocol": "sctp; rm -rf /"})


def test_conntrack_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_conntrack({"host": "h1"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail** — `... -k conntrack` → FAIL.

**Step 3: Implement in `net.py`**

```python
# ---------------------------------------------------------------------------
# conntrack
# ---------------------------------------------------------------------------

_CONNTRACK_MODES = {"list", "stats"}
_CONNTRACK_PROTO_WHITELIST = {"tcp", "udp", "icmp", "icmpv6", "dccp", "sctp", "gre"}


def _validate_conntrack_mode(mode) -> str:
    if mode is None:
        return "stats"
    if not isinstance(mode, str) or mode not in _CONNTRACK_MODES:
        raise ValueError(f"mode must be one of {sorted(_CONNTRACK_MODES)}")
    return mode


def _validate_conntrack_protocol(proto) -> str:
    if not isinstance(proto, str) or proto not in _CONNTRACK_PROTO_WHITELIST:
        raise ValueError(f"protocol must be one of {sorted(_CONNTRACK_PROTO_WHITELIST)}")
    return proto


def build_remote_cmd_conntrack(*, mode: str = "stats", protocol: str | None = None) -> str:
    """Build LC_ALL=C conntrack command string."""
    if mode == "stats":
        if protocol is not None:
            raise ValueError("protocol is only valid with mode=list")
        return "LC_ALL=C conntrack -S"
    parts = ["LC_ALL=C", "conntrack", "-L"]
    if protocol is not None:
        parts += ["-p", shlex.quote(protocol)]
    return " ".join(parts)


def handle_conntrack(args: dict) -> dict:
    host = validate_host(args["host"])
    mode = _validate_conntrack_mode(args.get("mode"))
    protocol = args.get("protocol")
    if protocol is not None:
        protocol = _validate_conntrack_protocol(protocol)
    cmd = build_remote_cmd_conntrack(mode=mode, protocol=protocol)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


CONNTRACK_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "mode": {"type": ["string", "null"], "enum": ["list", "stats", None]},
        "protocol": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="conntrack",
        description=(
            "Run conntrack (-S stats default, or -L list with optional -p protocol) on a "
            "remote host via SSH. Root + nf_conntrack module required. List output can be "
            "large (truncation flagged). Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=CONNTRACK_SCHEMA,
        handler=handle_conntrack,
    ),
```

**Step 4: Run to verify pass** — `... -k conntrack` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/net.py tests/tools/test_net.py
git commit -m "feat: add conntrack tool (stats/list)"
```

---

### Task 4: net_protocol_stats

`netstat -s [--tcp|--udp|--raw]` — retransmits, drops, listen-overflow counters.

**Files:** Modify `net.py`; test `test_net.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# net_protocol_stats
# ---------------------------------------------------------------------------


def test_net_protocol_stats_default_builder():
    assert mod.build_remote_cmd_net_protocol_stats(proto_flag=None) == "LC_ALL=C netstat -s"


def test_net_protocol_stats_flag_builders():
    assert mod.build_remote_cmd_net_protocol_stats(proto_flag="--tcp") == "LC_ALL=C netstat -s --tcp"
    assert mod.build_remote_cmd_net_protocol_stats(proto_flag="--udp") == "LC_ALL=C netstat -s --udp"
    assert mod.build_remote_cmd_net_protocol_stats(proto_flag="--raw") == "LC_ALL=C netstat -s --raw"


def test_net_protocol_stats_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"n\n", b"", 0, False))
    mod.handle_net_protocol_stats({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C netstat -s"


def test_net_protocol_stats_handler_each(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    for proto, flag in {"tcp": "--tcp", "udp": "--udp", "ip": "--raw"}.items():
        mod.handle_net_protocol_stats({"host": "h1", "protocol": proto})
        assert captured["cmd"] == f"LC_ALL=C netstat -s {flag}"


def test_net_protocol_stats_all_no_flag(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_net_protocol_stats({"host": "h1", "protocol": "all"})
    assert captured["cmd"] == "LC_ALL=C netstat -s"


def test_net_protocol_stats_rejects_bad_protocol(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_net_protocol_stats({"host": "h1", "protocol": "sctp"})


def test_net_protocol_stats_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_net_protocol_stats({"host": "h1"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail** — `... -k net_protocol_stats` → FAIL.

**Step 3: Implement in `net.py`**

```python
# ---------------------------------------------------------------------------
# net_protocol_stats
# ---------------------------------------------------------------------------

_NET_PROTO_STATS_MAP = {"all": None, "tcp": "--tcp", "udp": "--udp", "ip": "--raw"}


def _validate_net_protocol_stats(proto):
    if proto is None:
        return None
    if not isinstance(proto, str) or proto not in _NET_PROTO_STATS_MAP:
        raise ValueError(f"protocol must be one of {sorted(_NET_PROTO_STATS_MAP)}")
    return _NET_PROTO_STATS_MAP[proto]


def build_remote_cmd_net_protocol_stats(*, proto_flag: str | None = None) -> str:
    """Build LC_ALL=C netstat -s command string."""
    parts = ["LC_ALL=C", "netstat", "-s"]
    if proto_flag is not None:
        parts.append(proto_flag)
    return " ".join(parts)


def handle_net_protocol_stats(args: dict) -> dict:
    host = validate_host(args["host"])
    proto_flag = _validate_net_protocol_stats(args.get("protocol"))
    cmd = build_remote_cmd_net_protocol_stats(proto_flag=proto_flag)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


NET_PROTOCOL_STATS_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "protocol": {"type": ["string", "null"], "enum": ["all", "tcp", "udp", "ip", None]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="net_protocol_stats",
        description=(
            "Run 'netstat -s' (protocol counters: retransmits, drops, listen overflows) on a "
            "remote host via SSH. protocol: all|tcp|udp|ip (default all). "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=NET_PROTOCOL_STATS_SCHEMA,
        handler=handle_net_protocol_stats,
    ),
```

**Step 4: Run to verify pass** — `... -k net_protocol_stats` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/net.py tests/tools/test_net.py
git commit -m "feat: add net_protocol_stats tool (netstat -s)"
```

---

### Task 5: nft_list

`nft -nn list ruleset` (default) or `nft -nn list table <family> <table>`. Root. Surfaces firewall rules/IPs — same exposure class as existing ip_addr/ss; documented.

**Files:** Modify `net.py`; test `test_net.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# nft_list
# ---------------------------------------------------------------------------


def test_nft_list_default_builder():
    assert mod.build_remote_cmd_nft_list() == "LC_ALL=C nft -nn list ruleset"


def test_nft_list_table_builder():
    cmd = mod.build_remote_cmd_nft_list(family="inet", table="filter")
    assert cmd == "LC_ALL=C nft -nn list table inet filter"


def test_nft_list_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"r\n", b"", 0, False))
    mod.handle_nft_list({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C nft -nn list ruleset"


def test_nft_list_handler_table(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_nft_list({"host": "h1", "family": "ip", "table": "nat"})
    assert captured["cmd"] == "LC_ALL=C nft -nn list table ip nat"


def test_nft_list_table_requires_family(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_nft_list({"host": "h1", "table": "filter"})


def test_nft_list_family_requires_table(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_nft_list({"host": "h1", "family": "inet"})


def test_nft_list_rejects_bad_family(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_nft_list({"host": "h1", "family": "ipx", "table": "filter"})


def test_nft_list_rejects_table_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_nft_list({"host": "h1", "family": "inet", "table": "filter; rm -rf /"})


def test_nft_list_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_nft_list({"host": "h1"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail** — `... -k nft_list` → FAIL.

**Step 3: Implement in `net.py`**

```python
# ---------------------------------------------------------------------------
# nft_list
# ---------------------------------------------------------------------------

_NFT_FAMILY_WHITELIST = {"ip", "ip6", "inet", "arp", "bridge", "netdev"}
_NFT_TABLE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _validate_nft_family(family) -> str:
    if not isinstance(family, str) or family not in _NFT_FAMILY_WHITELIST:
        raise ValueError(f"family must be one of {sorted(_NFT_FAMILY_WHITELIST)}")
    return family


def _validate_nft_table(table) -> str:
    if not isinstance(table, str) or not table:
        raise ValueError("table must be a non-empty string")
    reject_unsafe_chars(table, "table")
    if table.startswith("-"):
        raise ValueError("table must not start with '-'")
    if not _NFT_TABLE_RE.fullmatch(table):
        raise ValueError("table must match ^[A-Za-z0-9_.-]{1,64}$")
    return table


def build_remote_cmd_nft_list(*, family: str | None = None, table: str | None = None) -> str:
    """Build LC_ALL=C nft list command string."""
    if table is None and family is None:
        return "LC_ALL=C nft -nn list ruleset"
    if table is None or family is None:
        raise ValueError("table and family must be supplied together")
    return f"LC_ALL=C nft -nn list table {shlex.quote(family)} {shlex.quote(table)}"


def handle_nft_list(args: dict) -> dict:
    host = validate_host(args["host"])
    family = args.get("family")
    table = args.get("table")
    if (family is None) != (table is None):
        raise ValueError("table and family must be supplied together")
    if family is not None:
        family = _validate_nft_family(family)
    if table is not None:
        table = _validate_nft_table(table)
    cmd = build_remote_cmd_nft_list(family=family, table=table)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


NFT_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "family": {
            "type": ["string", "null"],
            "enum": ["ip", "ip6", "inet", "arp", "bridge", "netdev", None],
        },
        "table": {"type": ["string", "null"]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="nft_list",
        description=(
            "Run 'nft list ruleset' (or 'list table <family> <table>') on a remote host via "
            "SSH. Root required. Surfaces firewall rules/IPs. "
            "Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=NFT_LIST_SCHEMA,
        handler=handle_nft_list,
    ),
```

**Step 4: Run to verify pass** — `... -k nft_list` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/net.py tests/tools/test_net.py
git commit -m "feat: add nft_list tool"
```

---

### Task 6: iptables_list

`iptables -n -v -L [-t <table>]` (or `ip6tables` for ipv6). Root.

**Files:** Modify `net.py`; test `test_net.py`.

**Step 1: Write the failing tests**

```python
# ---------------------------------------------------------------------------
# iptables_list
# ---------------------------------------------------------------------------


def test_iptables_list_default_builder():
    assert mod.build_remote_cmd_iptables_list(binary="iptables") == "LC_ALL=C iptables -n -v -L"


def test_iptables_list_table_builder():
    cmd = mod.build_remote_cmd_iptables_list(binary="iptables", table="nat")
    assert cmd == "LC_ALL=C iptables -n -v -L -t nat"


def test_iptables_list_ip6_builder():
    cmd = mod.build_remote_cmd_iptables_list(binary="ip6tables", table="filter")
    assert cmd == "LC_ALL=C ip6tables -n -v -L -t filter"


def test_iptables_list_handler_default(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"r\n", b"", 0, False))
    mod.handle_iptables_list({"host": "h1"})
    assert captured["cmd"] == "LC_ALL=C iptables -n -v -L"


def test_iptables_list_handler_ipv6_table(monkeypatch):
    captured = _stub(monkeypatch, SshResult(b"", b"", 0, False))
    mod.handle_iptables_list({"host": "h1", "family": "ipv6", "table": "mangle"})
    assert captured["cmd"] == "LC_ALL=C ip6tables -n -v -L -t mangle"


def test_iptables_list_rejects_bad_table(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_iptables_list({"host": "h1", "table": "bogus"})


def test_iptables_list_rejects_bad_family(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_iptables_list({"host": "h1", "family": "ipx"})


def test_iptables_list_rejects_table_injection(monkeypatch):
    _stub(monkeypatch, SshResult(b"", b"", 0, False))
    with pytest.raises(ValueError):
        mod.handle_iptables_list({"host": "h1", "table": "filter; rm -rf /"})


def test_iptables_list_truncated_propagates(monkeypatch):
    _stub(monkeypatch, SshResult(b"x", b"", 0, True))
    out = mod.handle_iptables_list({"host": "h1"})
    assert out["truncated"] is True
```

**Step 2: Run to verify fail** — `... -k iptables_list` → FAIL.

**Step 3: Implement in `net.py`**

```python
# ---------------------------------------------------------------------------
# iptables_list
# ---------------------------------------------------------------------------

_IPTABLES_TABLE_WHITELIST = {"filter", "nat", "mangle", "raw"}
_IPTABLES_FAMILY_MAP = {"ipv4": "iptables", "ipv6": "ip6tables"}


def _validate_iptables_table(table) -> str:
    if not isinstance(table, str) or table not in _IPTABLES_TABLE_WHITELIST:
        raise ValueError(f"table must be one of {sorted(_IPTABLES_TABLE_WHITELIST)}")
    return table


def _validate_iptables_family(family) -> str:
    if family is None:
        return _IPTABLES_FAMILY_MAP["ipv4"]
    if not isinstance(family, str) or family not in _IPTABLES_FAMILY_MAP:
        raise ValueError(f"family must be one of {sorted(_IPTABLES_FAMILY_MAP)}")
    return _IPTABLES_FAMILY_MAP[family]


def build_remote_cmd_iptables_list(*, binary: str, table: str | None = None) -> str:
    """Build LC_ALL=C iptables/ip6tables list command string."""
    parts = ["LC_ALL=C", binary, "-n", "-v", "-L"]
    if table is not None:
        parts += ["-t", shlex.quote(table)]
    return " ".join(parts)


def handle_iptables_list(args: dict) -> dict:
    host = validate_host(args["host"])
    binary = _validate_iptables_family(args.get("family"))
    table = args.get("table")
    if table is not None:
        table = _validate_iptables_table(table)
    cmd = build_remote_cmd_iptables_list(binary=binary, table=table)
    res = run_ssh(host, cmd)
    return {
        "stdout": _decode_text(res.stdout),
        "stderr": _decode_text(res.stderr),
        "exit_code": res.exit_code,
        "truncated": res.truncated,
        "stderr_truncated": res.stderr_truncated,
    }


IPTABLES_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "table": {
            "type": ["string", "null"],
            "enum": ["filter", "nat", "mangle", "raw", None],
        },
        "family": {"type": ["string", "null"], "enum": ["ipv4", "ipv6", None]},
    },
    "required": ["host"],
    "additionalProperties": False,
}
```

Add to `TOOLS`:

```python
    ToolSpec(
        name="iptables_list",
        description=(
            "Run 'iptables -n -v -L' (or ip6tables) on a remote host via SSH, optional -t table. "
            "Root required. Returns stdout, stderr, exit_code, truncated."
        ),
        input_schema=IPTABLES_LIST_SCHEMA,
        handler=handle_iptables_list,
    ),
```

Update the registry-names test at the bottom of `test_net.py` to include all Cluster A+B net tools in order:

```python
    assert names == [
        "ss",
        "ip_addr",
        "ip_route",
        "lsof_net",
        "arp_table",
        "tc_qdisc",
        "ethtool",
        "conntrack",
        "net_protocol_stats",
        "nft_list",
        "iptables_list",
    ]
```

(If Cluster A has not landed, drop `arp_table` from the expected list and adjust.)

**Step 4: Run to verify pass** — `uv run pytest tests/tools/test_net.py -q` → PASS.

**Step 5: Commit**

```bash
git add linux_info_mcp/tools/net.py tests/tools/test_net.py
git commit -m "feat: add iptables_list tool"
```

---

### Task 7: Docs + full-suite gate

**Files:** `SPEC.md` (6 new sections), `README.md` (6 entries), `AGENTS.md` (tool count 50 → 56; net.py inventory gains the 6 tools).

**Step 1: Update docs** matching existing style.

**Step 2: Full suite** — `uv run pytest -q` → PASS.

**Step 3: Discovery count** — `uv run python -c "from linux_info_mcp.server import _discover_tools; print(len(_discover_tools()))"` → `56`.

**Step 4: Commit**

```bash
git add SPEC.md README.md AGENTS.md
git commit -m "docs: document Cluster B network tools; tool count 50 -> 56"
```

---

## Done criteria
- 6 new net tools registered and discoverable.
- `uv run pytest -q` fully green.
- Each tool: builder test, whitelist-rejection, injection-rejection, mutual-exclusion where applicable (conntrack stats+protocol, nft table/family pairing), truncation propagation.
- Root-required tools documented as such in descriptions and SPEC.
- Docs updated; tool count reads 56.
