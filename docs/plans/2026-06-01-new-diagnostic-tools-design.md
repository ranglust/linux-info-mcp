# New Diagnostic Tools — Design (2026-06-01)

Adds 18 read-only diagnostic tools to linux-info-mcp across 4 clusters. Count 44 → 62.
Delivery is phased by cluster (A → B → C → D); each cluster lands with green tests before the next.

All tools follow the existing per-tool pattern (AGENTS.md): tool-local validators, `build_remote_cmd_<tool>`
returning a single `LC_ALL=C`-prefixed shlex-quoted string, sync `handle_<tool>` returning
`{stdout, stderr, exit_code, truncated, stderr_truncated}`, a `*_SCHEMA`, and a `TOOLS` append.
Every interpolated value passes a validator; positional/glob values go after `--`; flag-prone values use equals-form.

Graceful degradation relies on the existing exit_code/stderr passthrough: a missing binary returns 127 fast
(not a 30s timeout), and permission-denied (root tools) surfaces in stderr. Root requirements are stated in each
tool description. No tool mutates remote state.

---

## Cluster A — Quick wins (6 tools) → perf.py, proc.py, net.py, systemctl.py

### psi_stats (perf.py)
- Purpose: CPU/memory/IO pressure stall info — the saturation dimension missing from iostat/vmstat/free.
- Arg: `resource` enum `cpu|memory|io|all` (default `all`).
- Cmd: all → `grep -H '' /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io`; single → `cat /proc/pressure/<resource>`.
- Safety: file paths come only from the enum whitelist; no free interpolation. Kernels <4.20 lack the files → exit≠0 passthrough.

### meminfo (perf.py)
- Purpose: full `/proc/meminfo` (Slab, Committed_AS, PageTables, Dirty…) for OOM/leak triage.
- Args: optional `fields` (list of strings, each `re.fullmatch(^[A-Za-z0-9_()]+$)`).
- Cmd: `cat /proc/meminfo`; with fields → `... | grep -E '^(<f1>|<f2>):'` (alternation built from validated tokens).

### proc_limits (proc.py)
- Purpose: `/proc/<pid>/limits` — diagnose nofile/core/OOM limits; pairs with lsof/pgrep.
- Arg: `pid` (required, `validate_pid`, 1..4194304).
- Cmd: `cat /proc/<pid>/limits` (pid is int → safe interpolation).

### arp_table (net.py)
- Purpose: neighbor/ARP cache — stale/FAILED entries, MAC visibility.
- Args: optional `iface` (`_validate_iface`), optional `family` (`inet`→`-4`, `inet6`→`-6`).
- Cmd: `ip -o [family] neigh show [dev <iface>]`.

### systemctl_list_timers (systemctl.py)
- Purpose: timer units with next/last fire times.
- Arg: `all` (bool).
- Cmd: `systemctl list-timers [--all] --no-pager`. Reuses existing unit-table handling.

### systemctl_list_sockets (systemctl.py)
- Purpose: socket units with listen address + owning service.
- Arg: `all` (bool).
- Cmd: `systemctl list-sockets [--all] --no-pager`.

---

## Cluster B — Network (6 tools) → net.py

### tc_qdisc
- Cmd: `tc -s qdisc show [dev <iface>]`. Arg: optional `iface`. Queue depth/drops; non-root readable.

### ethtool
- Args: `iface` (required, `_validate_iface`), `mode` enum → flag: `stats`→`-S`, `driver`→`-i`, `ring`→`-g`, `features`→`-k`, `pause`→`-a`, `coalesce`→`-c` (default `driver`).
- Cmd: `ethtool <flag> <iface>`. Some modes need privileges → exit/stderr passthrough.

### conntrack
- Args: `mode` enum `list|stats` (default `stats`), optional `protocol` whitelist `{tcp,udp,icmp,...}`.
- Cmd: `conntrack -S` | `conntrack -L [-p <proto>]`. Root + nf_conntrack module. List output can be large → truncation flagged.

### net_protocol_stats
- Args: `protocol` enum `all|tcp|udp|ip` → `netstat -s [--tcp|--udp|--raw]`.
- Purpose: retransmits, drops, listen-overflow counters.

### nft_list (split per decision)
- Args: optional `table` (validated identifier).
- Cmd: `nft -nn list ruleset` (or `list table <family> <table>`). Root. Surfaces firewall rules/IPs — same exposure class as existing ip_addr/ss; documented.

### iptables_list (split per decision)
- Args: optional `table` enum `filter|nat|mangle|raw`, optional `family` `ipv4|ipv6` → `iptables`/`ip6tables`.
- Cmd: `iptables -n -v -L [-t <table>]`. Root.

---

## Cluster C — Kernel/perf (5 tools) → kernel.py (cgroup/slabtop/numastat/systemd_analyze), disk.py (blockdev)

### slabtop (kernel.py)
- Cmd: `slabtop -o` (one-shot). Root-only → degrade via exit/stderr.

### numastat (kernel.py)
- Args: optional `pid` (`validate_pid`). Cmd: `numastat [-p <pid>]`. numactl pkg may be absent → 127 passthrough.

### cgroup_stats (kernel.py)
- Args: `cgroup_path` (required), `controller` enum `cpu|memory|io|all` (default `all`).
- New validator `validate_cgroup_path` (in validate.py): reject empty/NUL/newline, reject leading `/`,
  reject any `..` path segment, require `re.fullmatch(^[A-Za-z0-9._:@/-]+$)`, cap length 1024.
- Controller → fixed file list (whitelist, no user-named files):
  - cpu → `cpu.stat`; memory → `memory.current memory.stat memory.pressure`; io → `io.stat io.pressure`; all → union.
- Cmd: `grep -H '' /sys/fs/cgroup/<path>/<file1> /sys/fs/cgroup/<path>/<file2> ...` (path quoted, files literal).
- Belt + suspenders: traversal-safe path AND whitelisted leaf files.

### systemd_analyze (kernel.py)
- Args: `mode` enum `time|blame|critical-chain` (default `time`); optional `unit` (`validate_unit_name`) for critical-chain.
- Cmd: `systemd-analyze <mode> [--no-pager] [<unit>]`.

### blockdev (disk.py)
- Cmd: `blockdev --report` (all devices, no per-device arg → no injection surface). Complements lsblk/smartctl.

---

## Cluster D — host_facts meta-tool (1 tool) → new module facts.py

One tool, **single SSH round-trip**, fixed bundled read-only script (no user interpolation beyond host →
injection-safe). Handler parses stdout into a structured dict; each probe wrapped `2>/dev/null || true` so one
missing binary doesn't abort the rest.

Bundled probes:
- `cat /etc/os-release` → `distro` (ID, VERSION_ID, PRETTY_NAME)
- `uname -srm` → `kernel`, `arch`
- `nproc`, meminfo `MemTotal` → `nproc`, `mem_total_kb`
- **virtualization**:
  - `systemd-detect-virt` → `hypervisor` (kvm/vmware/xen/microsoft/oracle/none)
  - `systemd-detect-virt -c` → `container` (lxc/docker/podman/none)
  - `/sys/class/dmi/id/sys_vendor`, `/sys/class/dmi/id/product_name` → `dmi_vendor`, `dmi_product` (e.g. "VMware Virtual Platform", "QEMU")
  - derived `is_virtual` (bool), from hypervisor≠none or DMI signature
- capabilities: `command -v docker podman systemctl nft conntrack ethtool smartctl numastat slabtop` → `capabilities{tool: bool}`
- `uptime -s` / `/proc/uptime` → `uptime_s`; `date -u +%FT%TZ` → `now_utc`; `id -un` → `whoami`
- Return `{facts: {...}, raw: <stdout>, stderr, exit_code, truncated}`.

Value: lets the agent (and other tools) know os_family, virt status, and which tools exist before calling them —
avoids blind 127s and informs tool selection. Memoizable per session later (separate caching idea).

---

## Cross-cutting

- Result shape matches existing 5-key dict (`stdout, stderr, exit_code, truncated, stderr_truncated`); host_facts adds parsed `facts`.
- New shared validator: `validate_cgroup_path` in validate.py (anchored `re.fullmatch`, follows validate_unit_name precedent).
- Tests per tool: defaults, every flag/mode, mutual-exclusions, whitelist rejections, real injection strings
  (`-oProxyCommand=evil`, `foo;rm -rf /`, `\n`, `\x00`, `../../etc/shadow` for cgroup), and a truncation-propagation test.
- Docs per cluster: SPEC.md sections, README.md tool list, AGENTS.md tool count (correct the stale "4-key" note to 5 while there).

## Open / deferred (not in this batch)
- TTL caching of host_facts and other slow-changing data (separate idea).
- Structured/parsed output for these tools (separate big-bet).
