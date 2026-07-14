# AGENTS.md — linux-info-mcp

Operating notes for AI coding agents working in this repo. Authoritative spec is `SPEC.md`; this file is a quick orientation + binding conventions.

## What this is

MCP (Model Context Protocol) server, Python, SSH-based read-only diagnostics. Per call targets a single `host` or a bounded parallel `hosts` fan-out. Exposes 77 tools today across 18 modules: files (`read_file`, `find_files`, `read_binary`), archive (`archive_list`, `archive_read`), systemd (`systemctl_status`, `systemctl_list`, `systemctl_list_timers`, `systemctl_list_sockets`, `journalctl`), perf (`iostat`, `vmstat`, `free`, `df`, `ps`, `psi_stats`, `meminfo`), sampling (`sar`, `atop`, `pmrep`), net (`ss`, `ip_addr`, `ip_route`, `lsof_net`, `arp_table`, `tc_qdisc`, `ethtool`, `conntrack`, `net_protocol_stats`, `nft_list`, `iptables_list`, `dig`), lldp (`lldp_neighbors`, `lldp_interfaces`, `lldp_statistics`, `lldp_chassis`), proc (`lsof`, `pgrep`, `pidof`, `top`, `proc_limits`), disk (`du`, `lsblk`, `blkid`, `smartctl`, `blockdev`), kernel (`dmesg`, `uname`, `sysctl`, `slabtop`, `numastat`, `cgroup_stats`, `systemd_analyze`), pkg (`dpkg_list`, `rpm_list`, `apt_list_installed`, `reboot_required`), sys (`uptime`, `who`, `last`, `lscpu`, `lsmem`, `dmidecode`, `lspci`, `lsusb`, `sensors`), time (`chronyc`, `timedatectl`), fs (`mount`, `findmnt`, `stat_fs`), docker (`docker_ps`, `docker_inspect`, `docker_images`, `docker_logs`), facts (`host_facts`), triage (`triage`). Auto-discovers tools from `linux_info_mcp/tools/*.py`.

Read `SPEC.md` first before implementing or modifying any tool. SPEC defines arg schemas, validators, env vars, security model, logging events, and architecture. Drift from SPEC = bug.

## Layout

```
linux_info_mcp/
  server.py        # MCP entrypoint; auto-discovers tools/* and registers
  ssh.py           # run_ssh() central subprocess wrapper; SshResult; legacy file-tool builders
  validate.py      # shared validators (host/path/grep/find/unit/lines/offset_length)
  log.py           # JSON file logging, TRACE level, ContextVar correlation
  tools/
    __init__.py    # ToolSpec dataclass (name/description/input_schema/handler)
    _parsers.py    # reference output parsers (parse_df, parse_free); not auto-discovered
    files.py       # read_file (+decompress), find_files, read_binary (+decompress)
    archive.py     # archive_list, archive_read
    systemctl.py   # systemctl_status, systemctl_list
    journalctl.py  # journalctl
    perf.py        # iostat, vmstat, free, df, ps, psi_stats, meminfo
    sampling.py    # sar, atop, pmrep
    net.py         # ss, ip_addr, ip_route, lsof_net
    lldp.py        # lldp_neighbors, lldp_interfaces, lldp_statistics, lldp_chassis
    proc.py        # lsof, pgrep, pidof, top
    disk.py        # du, lsblk, blkid, smartctl
    kernel.py      # dmesg, uname, sysctl
    pkg.py         # dpkg_list, rpm_list, apt_list_installed, reboot_required
    sys.py         # uptime, who, last, lscpu, lsmem, dmidecode, lspci, lsusb, sensors
    time.py        # chronyc, timedatectl
    fs.py          # mount, findmnt, stat_fs
    docker.py      # docker_ps, docker_inspect, docker_images, docker_logs
    facts.py       # host_facts
    triage.py      # triage (one-round-trip health summary)
tests/             # pytest. test_validate, test_ssh, test_server, test_log + tests/tools/*
tests/e2e/         # layer 3 agent-driven e2e (manifest.py, capture_samples.py, PROMPT.md) — not part of `uv run pytest`
server.py          # top-level shim → linux_info_mcp.server.main()
SPEC.md            # authoritative spec
README.md          # user-facing
pyproject.toml     # uv + hatchling. Entry point: linux-info-mcp = linux_info_mcp.server:main
```

## Commands

```
uv sync                    # install
uv run pytest -q           # run tests (must stay green)
uv run linux-info-mcp      # run server (stdio)
uv run python server.py    # alt run
```

Python: `uv` only. Never `python3`/`pip3`.

## Hard rules

1. **Never weaken a security control.** If a task seems to require it, stop and ask.
2. **Never run write/mutate commands on remote hosts.** This server is read-only by design and by global policy. No `systemctl restart`, `kill`, `rm`, file edits, package installs, HTTP writes, DB writes, etc.
3. **Never put builds, logs, or scratch files in `/tmp/`.** Use `$TMPDIR`.
4. **Never commit secrets.**
5. **No `Co-Authored-By` lines on commits.** No amends to published commits. No `git add/commit/push/rebase/revert/amend` without explicit per-action authorisation.
6. **No emojis** in code, comments, commits, PRs, or chat unless explicitly asked.

## Coding conventions

### Per-tool module pattern

Each `tools/<area>.py` exports `TOOLS: list[ToolSpec]`. A ToolSpec is `(name, description, input_schema, handler, parser=None)`. `server.py` discovers them via `pkgutil.iter_modules`. Submodules whose name starts with `_` are skipped. Names must be unique and non-empty.

`parser` is an optional `Callable[[str], object]` that turns a tool's `stdout` into a structured value for `output_mode=parsed|both`. It is pure (no SSH), lives in `tools/_parsers.py` (not auto-discovered), and is unit-tested in `tests/tools/test_parsers.py`. Central plumbing in `server.py` (`apply_output_mode`) handles `parse_status`, drops `stdout` in `parsed` mode, and never parses truncated/non-zero output — tools just attach a `parser=`. See SPEC.md §Output modes.

A handler receives a `dict`, validates it, builds the remote command string, calls `run_ssh(host, remote_cmd)`, and returns a dict with shape `{stdout, stderr, exit_code, truncated, stderr_truncated}` (or, for `read_binary`, `{data_base64, bytes_read, stderr, exit_code, truncated}`; for `host_facts`, adds a parsed `facts` key).

Handlers always operate on a single `args["host"]`. **Multi-host fan-out is centralized in `server.py` — never add `hosts` handling to a tool.** `_call_tool` calls `resolve_target_hosts(args)`; if the caller passed `hosts` (array, mutually exclusive with `host`), it dispatches `_run_multi_host`, which invokes the unchanged handler once per host in a `ThreadPoolExecutor` (size `LINUX_INFO_PARALLELISM`, default 4) and aggregates into `{multi_host, host_count, results: [{host, ...}]}`. Each worker runs under a copied `contextvars.Context` so logging correlation reaches per-host `run_ssh` lines. The `hosts` schema property is injected automatically in `_list_tools`; do not add it to per-tool schemas. Caps: `LINUX_INFO_MAX_HOSTS` (default 10, hard max 25). See SPEC.md §Multi-host fan-out.

Handlers stay **sync**. The async server entrypoint (`_call_tool` in `server.py`) wraps dispatch with `await asyncio.to_thread(spec.handler, args)` so the blocking `subprocess.run` inside `run_ssh` doesn't pin the event loop, and concurrent MCP requests truly parallelize. Don't make handlers async — that breaks the assumption that `to_thread` is the only thread-pool entry point and would also break ContextVar propagation if you forgot to copy the context manually.

### Security invariants

- Local exec: `subprocess.run([...argv], shell=False, ...)`. Never `shell=True`.
- Remote exec: shell unavoidable for pipes. Build remote command as a single string. **Every interpolated value passes through `shlex.quote`.** Prefix with `LC_ALL=C`.
- Reject NUL and newline before quoting. Use `_reject_unsafe_chars` from `validate.py`.
- Reject hosts that contain whitespace or start with `-`. Honor `LINUX_INFO_HOSTS` allowlist.
- Whitelists are exact-match (set / dict membership), not prefix/regex unless the regex fully anchors with `re.fullmatch` and no character class permits leading `-`.
- Flag-injection-prone values (e.g. `journalctl --since=`, `--grep=`) use the equals-form so the value can't be misparsed as a separate flag.
- Positional/glob args (find name, systemctl_list pattern, df paths) go after `--`.
- Never add raw flag passthrough to a tool. `ps` uses preset modes only.
- Sudo: if a new tool needs root, prefix it with `sudo_tokens()` (parts builders) or `sudo_prefix()` (f-string builders) from `ssh.py`, inserted right after `LC_ALL=C` and before the privileged binary so a pipeline's later stages stay unprivileged. Per-tool only — never wrap the whole command in `sudo sh -c` (that needs passwordless `sudo sh` = unconstrainable root). Off unless `LINUX_INFO_SUDO` is set. Don't prefix tools that don't need root. The privilege boundary lives in the operator's sudoers, not here.

### Validators

Shared validators live in `validate.py` (`validate_host`, `validate_path`, `validate_grep_pattern`, `validate_grep_flags`, `validate_find_args`, `validate_offset_length`, `validate_unit_name`, `validate_lines_int`, `binary_length_cap`, `validate_cgroup_path`). Tool-specific validators live in the tool module.

`validate_unit_name` uses `re.fullmatch` (Python `$` matches before trailing `\n` with `.match()`; bug-prone). All new validators should follow that pattern.

### Logging

JSON file logging via `linux_info_mcp/log.py`. Disabled when `LINUX_INFO_LOG_FILE` is unset.

- Central timing points: `run_ssh` (SSH-call) and `_call_tool` (tool-call). Per-tool handlers do not log.
- Custom level `TRACE = 5` for full I/O dumps. Default `LINUX_INFO_LOG_LEVEL=INFO`.
- Every log line during a tool call automatically carries `tool` and `request_id` fields via a `ContextVar`-backed `logging.Filter`. Don't manually pass `tool=name` in `extra=`.
- INFO `tool_call` fields: `tool`, `host`, `duration_ms`, `exit_code`, `outcome`. INFO `ssh_call` fields: `host`, `exit_code`, `duration_ms`, `stdout_bytes`, `stderr_bytes`, `truncated`, `outcome`. See SPEC.md §Logging for the full table.
- `SshResult.duration_ms` is also returned to callers.

### Tests

- `pytest`. Add tests for any new validator, builder, handler, or log event.
- Mock `run_ssh` at the module-import site (e.g. `monkeypatch.setattr(linux_info_mcp.tools.files, "run_ssh", fake)`), not at `linux_info_mcp.ssh`.
- For SSH-layer tests, monkeypatch `subprocess.run` to a fake that returns / raises as needed.
- Adversarial inputs required: real injection strings (e.g. `-oProxyCommand=evil`, `foo;rm -rf /`, `\n`, `\x00`), not just nice inputs.
- New module + handler must include at least one truncation-propagation test (`SshResult(..., truncated=True)` → handler returns `truncated: True`).
- Tests must run from a clean checkout via `uv sync && uv run pytest -q`.

### Style

- Default: no comments. Add only when WHY is non-obvious.
- One-line module docstring max. One-line per public function. No multi-paragraph docstrings.
- Reference code with `file_path:line_number`.
- Short, factual responses. No filler.

## Adding a new tool — checklist

1. Read SPEC.md to find the section for the tool (or add one).
2. Decide: does it fit an existing module (`tools/perf.py` for system perf, `tools/systemctl.py` for systemd, etc.) or warrant a new one?
3. Implement validators (tool-local, in the same module).
4. Implement `build_remote_cmd_<tool>` returning a single shell-quoted string with `LC_ALL=C` prefix.
5. Implement `handle_<tool>` returning `{stdout, stderr, exit_code, truncated, stderr_truncated}`.
6. Define `<TOOL>_SCHEMA` JSON Schema.
7. Append to module's `TOOLS` list.
8. Tests under `tests/tools/test_<area>.py`. Cover defaults, every flag, mutual-exclusions, whitelist rejections, injection attempts, truncation propagation.
9. **Keep the e2e suite current.** Add the new tool to `tests/e2e/manifest.py` (`TOOL_ARGS`) with universal safe args that succeed on stock Linux (or an error-baseline placeholder). This is mandatory for every new tool/feature, not optional — `capture_samples.py` iterates the full registry, so a tool with no manifest entry is still captured with `{}` but goes undocumented and unexercised with meaningful args.
10. Update SPEC.md (per-tool section + counts), README.md tool list if user-visible, and AGENTS.md tool count + module list + layout at top.
11. `uv run pytest -q` must stay green.

## Configuration env vars (current)

| Var | Default | Purpose |
|-----|---------|---------|
| `LINUX_INFO_SSH_CMD` | `ssh` | Argv prefix; parsed with `shlex.split`. When set, owns full argv (no mux auto-injected). |
| `LINUX_INFO_SSH_MUX` | on | When `LINUX_INFO_SSH_CMD` unset, default `ssh` gets ControlMaster mux (`ControlPath=$TMPDIR/lim-%C`, `ControlPersist=60s`). `0`/`false`/`no`/`off` disables. |
| `LINUX_INFO_HOSTS` | (empty) | Comma-list host allowlist; empty = any. |
| `LINUX_INFO_TIMEOUT` | `30` | Seconds, subprocess timeout. |
| `LINUX_INFO_MAX_BYTES` | `1048576` | 1 MiB cap on stdout and stderr. |
| `LINUX_INFO_MAX_HOSTS` | `10` | Max hosts per `hosts` fan-out call. Clamped to [1, 25] (hard ceiling). |
| `LINUX_INFO_PARALLELISM` | `4` | Fan-out worker threads. Clamped to [1, 25], capped at host count. |
| `LINUX_INFO_SUDO` | (off) | `1`/`true`/`yes`/`on` prefixes `sudo -n` on privilege-prone tools only. Off by default. |
| `LINUX_INFO_OUTPUT_MODE` | (unset) | Locks response shape `raw`/`parsed`/`both`, overriding per-call `output_mode`. Strict lowercase; invalid → `validation_error`. |
| `LINUX_INFO_LOG_FILE` | (empty) | JSONL log path; unset = logging disabled. |
| `LINUX_INFO_LOG_LEVEL` | `INFO` | TRACE/DEBUG/INFO/WARNING/ERROR/CRITICAL. |

## Key file pointers

- Tool registration contract: `linux_info_mcp/tools/__init__.py:8`
- Auto-discovery: `linux_info_mcp/server.py:_discover_tools`
- Central SSH wrapper + timing: `linux_info_mcp/ssh.py:run_ssh`
- Logging setup + ContextVar filter: `linux_info_mcp/log.py:setup_logging`
- Shared validators: `linux_info_mcp/validate.py`
- Spec sections per tool: SPEC.md §1–§77
