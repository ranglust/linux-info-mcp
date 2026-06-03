# linux-info-mcp

![tests](https://github.com/ranglust/linux-info-mcp/actions/workflows/tests.yml/badge.svg)
[![codecov](https://codecov.io/gh/ranglust/linux-info-mcp/branch/main/graph/badge.svg)](https://codecov.io/gh/ranglust/linux-info-mcp)

MCP server that runs read-only diagnostic commands on remote hosts via SSH. 67 tools across 16 modules:

- files: `read_file`, `find_files`, `read_binary`
- systemctl: `systemctl_status`, `systemctl_list`, `systemctl_list_timers`, `systemctl_list_sockets`
- journalctl: `journalctl`
- perf: `iostat`, `vmstat`, `free`, `df`, `ps`, `psi_stats`, `meminfo`
- net: `ss`, `ip_addr`, `ip_route`, `lsof_net`, `arp_table`, `tc_qdisc`, `ethtool`, `conntrack`, `net_protocol_stats`, `nft_list`, `iptables_list`
- lldp: `lldp_neighbors`, `lldp_interfaces`, `lldp_statistics`, `lldp_chassis`
- proc: `lsof`, `pgrep`, `pidof`, `top`, `proc_limits`
- disk: `du`, `lsblk`, `blkid`, `smartctl`, `blockdev`
- kernel: `dmesg`, `uname`, `sysctl`, `slabtop`, `numastat`, `cgroup_stats`, `systemd_analyze`
- pkg: `dpkg_list`, `rpm_list`, `apt_list_installed`
- sys: `uptime`, `who`, `last`, `lscpu`, `lsmem`, `dmidecode`
- time: `chronyc`, `timedatectl`
- fs: `mount`, `findmnt`, `stat_fs`
- docker: `docker_ps`, `docker_inspect`, `docker_images`, `docker_logs`
- facts: `host_facts`
- triage: `triage`

## Project context for agents

Authoritative spec: [`SPEC.md`](./SPEC.md).
Agent operating notes (conventions, hard rules, security invariants, test discipline, add-a-tool checklist): [`AGENTS.md`](./AGENTS.md).
Claude Code automatically loads `CLAUDE.md`, which `@`-includes `AGENTS.md` so a single source feeds both Claude Code and any tool that reads `AGENTS.md` (Cursor, OpenAI Codex, etc.).

## Install

```
uv sync
```

## Run

```
uv run linux-info-mcp
# or
uv run python server.py
```

Both start a stdio MCP server.

## Test

```
uv run pytest -q
```

## Environment variables

| Var | Default | Meaning |
|-----|---------|---------|
| `LINUX_INFO_SSH_CMD` | `ssh` | Command + flags parsed via `shlex.split` (shell-style: quotes/escapes honored); becomes argv prefix. Example: `ssh -F /home/me/.ssh/config -o ConnectTimeout=5`. When set, you own the full argv (no mux auto-injected). |
| `LINUX_INFO_SSH_MUX` | on | When `LINUX_INFO_SSH_CMD` is unset, default `ssh` gets OpenSSH connection multiplexing (`ControlMaster=auto`, `ControlPath=$TMPDIR/lim-%C`, `ControlPersist=60s`) so repeated calls reuse one connection instead of paying a handshake each time. Set `0`/`false`/`no`/`off` to disable. |
| `LINUX_INFO_HOSTS` | `` | Comma-separated allowlist of exact hostnames. Empty = any host. |
| `LINUX_INFO_TIMEOUT` | `30` | Seconds before subprocess kill. On timeout: `exit_code=124`, `[timeout]` appended to `stderr`. |
| `LINUX_INFO_MAX_BYTES` | `1048576` | 1 MiB cap on both stdout and stderr. `read_binary` `length` is further capped at `floor((MAX_BYTES - 64) * 3 / 4)` so its base64 stream fits. |
| `LINUX_INFO_MAX_HOSTS` | `10` | Max hosts per multi-host (`hosts`) call. Clamped to `[1, 25]`; 25 is a hard ceiling to prevent an SSH storm. |
| `LINUX_INFO_PARALLELISM` | `4` | Worker threads for multi-host fan-out. Clamped to `[1, 25]` and never exceeds the host count. |
| `LINUX_INFO_SUDO` | `` (off) | `1`/`true`/`yes`/`on` prefixes `sudo -n` on privilege-prone tools (see [Privilege](#privilege)). Off by default. Only as safe as your sudoers. |
| `LINUX_INFO_OUTPUT_MODE` | `` (unset) | Locks response shape to `raw`/`parsed`/`both`, overriding the per-call `output_mode` arg (see [Output modes](#output-modes)). Invalid value → `validation_error`. |
| `LINUX_INFO_LOG_FILE` | `` | Absolute path to JSONL log file. Empty / unset = logging disabled. |
| `LINUX_INFO_LOG_LEVEL` | `INFO` | `TRACE`, `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. `TRACE` adds full tool-call I/O and the remote SSH command/output (verbose). |

## MCP client config

```json
{
  "mcpServers": {
    "linux-info": {
      "command": "uv",
      "args": ["run", "--directory", "/abs/path/to/linux-info-mcp", "python", "server.py"],
      "env": {
        "LINUX_INFO_SSH_CMD": "ssh",
        "LINUX_INFO_SSH_MUX": "on",
        "LINUX_INFO_HOSTS": "",
        "LINUX_INFO_TIMEOUT": "30",
        "LINUX_INFO_MAX_BYTES": "1048576",
        "LINUX_INFO_MAX_HOSTS": "10",
        "LINUX_INFO_PARALLELISM": "4",
        "LINUX_INFO_SUDO": "",
        "LINUX_INFO_OUTPUT_MODE": "",
        "LINUX_INFO_LOG_FILE": "",
        "LINUX_INFO_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

## Security notes

- Read-only by construction. No `-exec`, `-delete`, write redirection, or raw passthrough of `find` predicates.
- Local `subprocess.run` always uses `shell=False`. The remote command is a single shell-quoted string passed as one ssh argument.
- Every interpolated value goes through `shlex.quote`. Inputs containing NUL or newline are rejected before quoting.
- `grep_flags` are validated against a whitelist (`-i`, `-E`, `-v`, `-n`, `-w`, `-F`, and `-C1`..`-C9`).
- `find` accepts only named, validated predicates: `name`, `iname`, `type`, `maxdepth`, `mindepth`, `mtime`, `size`, `path_glob`.
- Hosts are rejected if they contain whitespace or start with `-`. If `LINUX_INFO_HOSTS` is set, hosts must match an entry exactly.
- Remote command is prefixed with `LC_ALL=C` for stable output.

## Logging

JSONL file logging, off by default. Set `LINUX_INFO_LOG_FILE=/path/to/log.jsonl` to enable. Each line is one event:

```json
{"ts":"2026-05-30T12:34:56.789+00:00","level":"INFO","logger":"linux_info_mcp.ssh","msg":"ssh_call","host":"h1","exit_code":0,"duration_ms":42.5,"stdout_bytes":1234,"truncated":false,"outcome":"ok","pid":12345,"tool":"read_file","request_id":"a1b2c3d4e5f6"}
```

INFO level emits `server_start`, `server_stop`, `tool_call` (with `tool`, `host`, `duration_ms`, `exit_code`, `outcome`; multi-host calls add `host_count`, set `host` to `null`, and report `outcome: partial` when any host fails), and `ssh_call` (with `host`, `exit_code`, `duration_ms`, `stdout_bytes`, `stderr_bytes`, `truncated`; one entry per host in a fan-out, all sharing the call's `request_id`). TRACE additionally emits the full tool arguments, tool result, remote command string, and remote stdout/stderr. See SPEC.md §Logging for the full table.

`run_ssh` is the central timing/logging point; it stamps `duration_ms` onto `SshResult` and emits one `ssh_call` log entry per call. `_call_tool` is the central tool-level timing/logging point covering validation + dispatch.

Every log line during a tool call carries `tool` (MCP tool name) and `request_id` (12-hex-char per-call id). Server logs and SSH logs join on `request_id`; `ssh_call` shows which tool triggered it. Every log line — including those outside a tool call — also carries `pid` (process id), so concurrent server processes sharing one log file stay separable.

## Concurrency

Tool handlers are sync (they call blocking `subprocess.run` for `ssh`). The async MCP entrypoint dispatches each handler via `asyncio.to_thread`, so concurrent `call_tool` requests from the agent run on a thread pool instead of serializing on the event loop. Wall time for N parallel tool calls is therefore `max(durations)` rather than `sum(durations)` — particularly relevant for teleport-backed SSH where each handshake costs 0.5–2s.

## Multi-host fan-out

Every tool takes either a single `host` (string) or a list of `hosts` (array) — mutually exclusive. With `hosts`, the tool runs on each host in parallel and returns:

```json
{"multi_host": true, "host_count": 2, "results": [
  {"host": "h1", "stdout": "...", "stderr": "", "exit_code": 0, "truncated": false, "stderr_truncated": false},
  {"host": "h2", "error": "RuntimeError: ...", "outcome": "handler_error"}
]}
```

`results` follows the input order (deduped). Per-host failures are isolated — one bad host does not abort the others; the overall `tool_call` outcome is then `partial`. Host count is capped by `LINUX_INFO_MAX_HOSTS` (default 10, hard max 25); fan-out runs `LINUX_INFO_PARALLELISM` workers (default 4). A single `host` returns the normal flat dict, unchanged.

## Output modes

Pass `output_mode` to control the response shape: `raw` (default, `stdout` text), `parsed` (structured object, `stdout` dropped), or `both`. `LINUX_INFO_OUTPUT_MODE` locks it server-side, overriding the arg. Tools with a parser (currently `df`, `free`) populate `parsed`; others report `parse_status: "unsupported"` and fall back to raw. Truncated or non-zero output is never parsed.

```json
// df with {"host": "h1", "output_mode": "parsed"}
{"parsed": [
  {"fs": "/dev/sda1", "blocks_1k": 41252336, "used_1k": 8765432,
   "avail_1k": 30387654, "use_pct": 23, "mount": "/"}
], "stderr": "", "exit_code": 0, "truncated": false,
 "stderr_truncated": false, "parse_status": "ok"}
```

## Privilege

The server runs as your SSH login user and never escalates on its own. Tools that need root (`smartctl`, `dmidecode`, `nft_list`, `iptables_list`, `conntrack`, often `dmesg`, `ethtool` for some modes, the `lldp_*` tools) otherwise fail with a permission error.

**Detection (always on):** a failed command whose stderr looks like a permission error gets `privilege_error: true` added to its result, so the agent knows to use a privileged path instead of guessing. Every result also carries `error_kind` (`ok`/`timeout`/`auth`/`dns`/`unreachable`/`not_found`/`privilege`/`nonzero`) so the agent can pick retry vs switch-host vs escalate vs give-up.

**Escalation (opt-in):** set `LINUX_INFO_SUDO=1` to prefix `sudo -n` (non-interactive) on the privilege-prone tools listed above — and only those. The server is just the mechanism; **what it can actually do is decided entirely by your sudoers.** Scope it tightly:

```
# /etc/sudoers.d/linux-info  — dedicated read-only diag account
diag ALL=(root) NOPASSWD: /usr/sbin/smartctl, /usr/sbin/dmidecode, \
  /usr/sbin/nft -nn list *, /usr/sbin/iptables -n -v -L *, /usr/sbin/conntrack
```

`LINUX_INFO_SUDO=1` plus a sloppy sudoers (`NOPASSWD: ALL`) hands an LLM effective root — the server cannot prevent that. Never use a blanket `sudo sh -c`; per-tool `sudo -n` is the only shape a constrained sudoers can lock down. (For Docker, prefer adding the login user to the `docker` group over sudo.)

## Limitations

- One-shot response per call. No streaming; stdout is capped at `LINUX_INFO_MAX_BYTES` and `truncated: true` is set when the cap is hit.
- SSH authentication is delegated to the user's ssh config / agent. This server never handles credentials.

## Security

See [`SECURITY.md`](./SECURITY.md) for the vulnerability reporting policy and threat model.

## License

MIT. See [`LICENSE`](./LICENSE).
