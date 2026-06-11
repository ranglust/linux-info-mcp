# linux-info-mcp — Specification

MCP server that runs read-only diagnostic commands on remote hosts via SSH. Exposes per-tool wrappers around common Linux inspection commands. 68 tools across 16 modules (files, systemd, journalctl, perf, net, lldp, proc, disk, kernel, pkg, sys, time, fs, docker, facts, triage). Each tool targets a single `host` or, via `hosts`, a bounded parallel fan-out (see below).

## Goals & Non-Goals

**Goals**
- Read-only remote inspection over SSH.
- Safe by construction: no command injection, no flag injection, no `-exec`-style escape hatches.
- Configurable SSH invocation (so `ssh`, `ssh -F file`, `pt ro`, `tshctx ssh`, etc. all work).
- Single-file install via `uv`; runnable from any MCP client (Claude Desktop, Claude Code).
- Bounded multi-host fan-out: run a tool across a small list of hosts in parallel.

**Non-goals**
- Any write/mutate operation on remote host.
- Streaming output (single response, byte-capped).
- Authentication management (delegate to user's SSH agent / config).

## Multi-host fan-out

Every tool accepts either a single `host` (string) or a list of `hosts` (array of strings); the two are mutually exclusive.

- `host` provided → response is the tool's normal single-host dict (unchanged shape).
- `hosts` provided → response is `{multi_host: true, host_count: N, results: [ {host, ...tool-dict} | {host, error, outcome}, ... ]}`. `results` preserves the order of the input `hosts` list, deduped (each distinct host run once).
- Host count is capped by `LINUX_INFO_MAX_HOSTS` (default 10), itself clamped to a hard maximum of 25 to prevent an SSH storm. Exceeding the effective cap is a `validation_error` for the whole call.
- Hosts run concurrently in a thread pool of `LINUX_INFO_PARALLELISM` workers (default 4, clamped to [1, 25], and never more than the host count).
- Per-host failures are isolated: a host whose handler raises returns `{host, error, outcome}` (`validation_error` / `handler_error`) in its slot; other hosts still run. The overall `tool_call` outcome is `partial` when any host errored or returned a non-zero exit code.
- Each host is validated independently (allowlist, leading-dash, NUL/newline) exactly as the single-host path.

Per-tool sections below list `host: str (required)` for brevity; read it as "`host` or `hosts` (one required)".

## Output modes

Every tool accepts an optional `output_mode` arg controlling response shape:

- `raw` (default) — current behavior: `stdout` text, no change.
- `parsed` — structured object under `parsed`; `stdout` is dropped to avoid doubling the payload.
- `both` — keep `stdout` and add `parsed`.

Resolution: `LINUX_INFO_OUTPUT_MODE` (env), if set, locks the mode and overrides the per-call arg. Otherwise the arg wins, else `raw`. The value is strict lowercase (`raw`/`parsed`/`both`); anything else — in the arg or the env — is a `validation_error` (the arg is validated even when the env overrides it). The mode applies per-host on `hosts` fan-out.

Parsing is **optional per tool** (`ToolSpec.parser`). When `output_mode` is non-`raw`, the result carries `parse_status`:

| `parse_status` | Meaning | `stdout` kept? |
|----------------|---------|----------------|
| `ok` | Parsed successfully; `parsed` populated. | only in `both` |
| `unsupported` | Tool has no parser (or `stdout` not a string). | yes |
| `skipped_nonzero` | Command exited non-zero; output not parsed. | yes |
| `skipped_truncated` | Output hit `LINUX_INFO_MAX_BYTES`; not parsed (partial data would mislead). | yes |
| `error: <ExcName>` | Parser raised; exception type recorded. | yes |

`raw` mode sets no `parse_status` (zero behavior change). v1 ships reference parsers for `df` (list of mount rows) and `free` (list of samples, each `{mem, swap}`); `interval`/`count` multi-sample `free` parses to one entry per sample. Native-JSON tools (`lsblk`, `findmnt`, etc.) are out of scope — they emit JSON only when their own flag is set.

## Tools

### 1. `read_file`
**Args**
- `host: str` (required)
- `path: str` (required, absolute path recommended)
- `grep_pattern: str | None`
- `grep_flags: list[str] | None` — whitelist: `-i`, `-E`, `-v`, `-n`, `-w`, `-F`, and `-C<N>` where `N` is digits 1–9.

**Behavior**
- If `grep_pattern` is `None`: remote command is `cat -- <path>`.
- Else: `cat -- <path> | grep <flags...> -e <pattern> --`.
- `grep_pattern` is passed via `-e <pat>` so a pattern beginning with `-` is not interpreted as a flag.
- Truncate stdout at `LINUX_INFO_MAX_BYTES`. If truncated, response includes `truncated: true`.

**Returns** (JSON object)
```
{
  "stdout": "<text>",
  "stderr": "<text>",
  "exit_code": 0,
  "truncated": false
}
```

### 2. `find_files`
**Args**
- `host: str` (required)
- `path: str` (required)
- `name: str | None` — `-name <glob>`
- `iname: str | None` — `-iname <glob>`
- `type: str | None` — one of `f`, `d`, `l`, `b`, `c`, `p`, `s`. Else reject.
- `maxdepth: int | None` — non-negative int.
- `mindepth: int | None` — non-negative int.
- `mtime: str | None` — must match `^[+-]?\d+$`.
- `size: str | None` — must match `^[+-]?\d+[bcwkMG]?$`.
- `path_glob: str | None` — `-path <glob>`.

**Behavior**
- Build argv with whitelisted predicates only. No raw passthrough. No `-exec`, `-delete`, `-fprint`, etc.
- Remote command: `find <path> [predicates...]`.
- Same truncation semantics as `read_file`.

**Returns** Same shape as `read_file`.

### 3. `read_binary`
**Args**
- `host: str` (required)
- `path: str` (required)
- `offset: int` (required, non-negative)
- `length: int` (required, positive). Hard cap = `floor((LINUX_INFO_MAX_BYTES - 8) * 3 / 4)` so the base64-encoded stream fits within the stdout cap. The remote `base64 -w 0` produces a single line so the only overhead is a trailing newline + small margin. Validator rejects above the cap rather than silently clamping.

**Behavior**
- Remote command: `dd if=<path> ibs=1 skip=<offset> count=<length> status=none | base64 -w 0`.
- Decode base64 server-side, return bytes re-encoded as base64 in response (so MCP transport stays text-safe).
- If `run_ssh` truncated stdout, propagate `truncated: true`.
- If base64 decode of remote output fails, return `bytes_read: 0`, `exit_code: 1` (only if remote exit_code was 0; otherwise pass through), and append `[base64 decode failed]` to `stderr`.

**Returns**
```
{
  "data_base64": "<b64>",
  "bytes_read": <int>,
  "stderr": "<text>",
  "exit_code": 0,
  "truncated": false
}
```

### 4. `systemctl_status`
**Args**
- `host: str` (required)
- `unit: str` (required) — validated against `^[A-Za-z0-9@:._-]+$`, length ≤ 256.
- `lines: int | None` — default 10, range 0–10000.

**Behavior**
- Remote command: `systemctl status --no-pager --lines=<N> -- <unit>`.
- `exit_code` passes through (systemctl exits non-zero for inactive/failed units; that is data, not an error).

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 5. `systemctl_list`
**Args**
- `host: str` (required)
- `kind: str | None` — `"units"` (default) or `"unit-files"`. Anything else rejected.
- `unit_type: str | None` — comma-separated list. Each element must be in `{service, timer, socket, target, mount, path, slice, scope, device, automount, swap}`. Forwarded as `-t <list>`.
- `state: str | None` — comma-separated list. Each element matches `^[a-z][a-z-]*$`. No fixed enum (states differ between `units` and `unit-files`; let systemctl reject bad ones). Forwarded as `--state=<list>`.
- `all: bool | None` — if true, append `--all`.
- `pattern: str | None` — positional glob (e.g. `"*.timer"`). NUL/newline rejected, shlex-quoted, placed after `--`.

**Behavior**
- Remote command: `systemctl list-<kind> --no-pager --no-legend --plain [-t <types>] [--state=<states>] [--all] [-- <pattern>]`.
- `--plain` strips tree-drawing characters; `--no-legend` drops the trailing summary.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 6. `journalctl`
**Args** (all optional except host):
- `host: str` (required)
- `unit: str | None` — `-u <unit>`. Same validator as `systemctl_status`.
- `lines: int | None` — default 100, range 1–100000. → `-n <N>`.
- `since: str | None` — `--since=<s>`. Free-form (e.g. `"2 hours ago"`, `"2026-05-30"`). NUL/newline rejected, shlex-quoted, length ≤ 128.
- `until: str | None` — `--until=<s>`. Same validation as `since`.
- `priority: str | None` — `-p <p>`. Whitelist: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`, `0`–`7`, or range form `<lo>..<hi>` where each side is one of the above tokens.
- `grep_pattern: str | None` — `--grep=<pat>`. NUL/newline rejected, shlex-quoted, length ≤ 256.
- `identifier: str | None` — `-t <id>`. Same validator as `unit`.
- `boot: int | None` — `-b <N>`. Range `-10`–`0`.
- `reverse: bool | None` — if true, append `-r`.
- `output: str | None` — `-o <fmt>`. Whitelist: `short`, `short-iso`, `short-precise`, `cat`, `json`, `json-pretty`, `verbose`. Default `short-iso`.

**Behavior**
- Remote command: `journalctl --no-pager [flags...]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 7. `iostat`
**Args**
- `host: str` (required)
- `extended: bool | None` — `-x`.
- `kilobytes: bool | None` — `-k`. Mutually exclusive with `megabytes`.
- `megabytes: bool | None` — `-m`.
- `omit_zero: bool | None` — `-z`.
- `device_only: bool | None` — `-d`.
- `cpu_only: bool | None` — `-c`.
- `interval: int | None` — positional sample interval in seconds, range 1–60.
- `count: int | None` — positional sample count, range 1–100. Requires `interval`.
- `devices: list[str] | None` — explicit device names (each matches `^[A-Za-z0-9._-]+$`, length ≤ 64). Forwarded as `-p <name>` per device or as positional after interval/count per iostat semantics.

**Behavior**
- Remote command: `iostat [-x] [-k|-m] [-z] [-d|-c] [-p <dev>...] [<interval> [<count>]]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 8. `vmstat`
**Args**
- `host: str` (required)
- `wide: bool | None` — `-w`.
- `active: bool | None` — `-a`.
- `disk: bool | None` — `-d`. Mutually exclusive with `summary`.
- `summary: bool | None` — `-s`.
- `unit: str | None` — `-S <unit>`. Whitelist: `k`, `K`, `m`, `M`.
- `interval: int | None` — positional, range 1–60.
- `count: int | None` — positional, range 1–100. Requires `interval`.

**Behavior**
- Remote command: `vmstat [-w] [-a] [-d|-s] [-S <unit>] [<interval> [<count>]]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 9. `free`
**Args**
- `host: str` (required)
- `unit: str | None` — one of `human`, `bytes`, `kilo`, `mega`, `giga`, `tera`, `peta` mapped to `-h`, `-b`, `-k`, `-m`, `-g`, `--tera`, `--peta`. Default omit.
- `wide: bool | None` — `-w`.
- `total: bool | None` — `-t`.
- `count: int | None` — `-c <N>`, range 1–100. Requires `interval`.
- `interval: int | None` — `-s <N>`, range 1–60.

**Behavior**
- Remote command: `free [unit-flag] [-w] [-t] [-s <interval>] [-c <count>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 10. `df`
**Args**
- `host: str` (required)
- `human: bool | None` — `-h`.
- `inodes: bool | None` — `-i`.
- `local: bool | None` — `-l`.
- `print_type: bool | None` — `-T`.
- `block_size: str | None` — `-B <size>`. Regex `^[1-9][0-9]{0,9}[KMGT]?$`.
- `exclude_type: list[str] | None` — `-x <type>` per element. Each element regex `^[a-z0-9]+$`, length ≤ 32.
- `paths: list[str] | None` — positional path list. Each validated via `validate_path`.

**Behavior**
- Remote command: `df [-h] [-i] [-l] [-T] [-B <size>] [-x <type>...] [-- <path>...]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 11. `ps`
**Args**
- `host: str` (required)
- `mode: str | None` — preset, default `"auxf"`. Whitelist: `aux`, `auxf`, `aux-sort-mem`, `aux-sort-cpu`, `ef`, `efH`, `forest`. The handler maps each to a fixed flag string (e.g. `aux-sort-mem` → `aux --sort=-rss`); raw flag passthrough is **not** accepted.
- `user: str | None` — `-u <user>`. Username whitelist regex `^[a-z_][a-z0-9_-]*\$?$`, length ≤ 32. Mutually exclusive with `pid`.
- `pid: int | None` — `-p <pid>`, range 1–4194304.

**Behavior**
- Remote command: `ps <mode-args> [-u <user> | -p <pid>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 12. `ss`
**Args**
- `host: str` (required)
- `tcp: bool | None` — `-t`.
- `udp: bool | None` — `-u`.
- `listening: bool | None` — `-l`.
- `all: bool | None` — `-a`.
- `numeric: bool | None` — `-n`.
- `processes: bool | None` — `-p`.
- `extended: bool | None` — `-e`.
- `summary: bool | None` — `-s`.
- `memory: bool | None` — `-m`.
- `state: str | None` — `state <s>`. Whitelist: `established`, `syn-sent`, `syn-recv`, `fin-wait-1`, `fin-wait-2`, `time-wait`, `close`, `close-wait`, `last-ack`, `listening`, `closing`, `all`, `connected`, `synchronized`, `bucket`, `big`.
- `family: str | None` — `-f <fam>`. Whitelist: `inet`, `inet6`, `unix`.

**Behavior**
- Remote command: `ss [-t] [-u] [-l] [-a] [-n] [-p] [-e] [-s] [-m] [-f <fam>] [state <s>]`. No raw filter passthrough.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 13. `ip_addr`
**Args**
- `host: str` (required)
- `iface: str | None` — interface name. Regex `^[A-Za-z0-9._@:-]{1,32}$`, must not start with `-`.

**Behavior**
- Remote command: `ip -o addr show [dev <iface>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 14. `ip_route`
**Args**
- `host: str` (required)
- `table: str | None` — whitelist: `main`, `default`, `local`, `all`.
- `family: str | None` — whitelist: `inet`, `inet6` → `-4` / `-6`.

**Behavior**
- Remote command: `ip [-4|-6] route show [table <t>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 15. `lsof_net`
**Args**
- `host: str` (required)
- `protocol: str | None` — whitelist: `tcp`, `udp`, `tcp4`, `tcp6`, `udp4`, `udp6`.
- `port: int | None` — range 1–65535.

**Behavior**
- Remote command: `lsof -i[<proto>][:<port>] -n -P`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 16. `lsof`
**Args**
- `host: str` (required)
- `pid: int | None` — range 1–4194304. Mutually exclusive with `user`.
- `user: str | None` — username regex `^[a-z_][a-z0-9_-]*\$?$`, length ≤ 32.
- `path: str | None` — validated path, positional after `--`.
- `network_only: bool | None` — `-i`.

**Behavior**
- Remote command: `lsof -n -P [-p <pid> | -u <user>] [-i] [-- <path>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 17. `pgrep`
**Args**
- `host: str` (required)
- `pattern: str` (required) — NUL/newline rejected, length ≤ 256, positional after `--`.
- `full: bool | None` — `-f`.
- `exact: bool | None` — `-x`.
- `list_name: bool | None` — `-l` (default true).
- `user: str | None` — same regex as `lsof.user`. → `-u <user>`.
- `newest: bool | None` — `-n`. Mutually exclusive with `oldest`.
- `oldest: bool | None` — `-o`.
- `parent_pid: int | None` — `-P <pid>`, range 1–4194304.

**Behavior**
- Remote command: `pgrep [flags...] [-- <pattern>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 18. `pidof`
**Args**
- `host: str` (required)
- `program: str` (required) — regex `^[A-Za-z0-9._-]{1,128}$`, must not start with `-`. Positional after `--`.
- `single_shot: bool | None` — `-s`.

**Behavior**
- Remote command: `pidof [-s] -- <program>`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 19. `top`
**Args**
- `host: str` (required)
- `user: str | None` — same regex as `lsof.user`. → `-u <user>`.
- `sort: str | None` — whitelist: `cpu`, `mem`, `pid`, `time` mapped to `%CPU` / `%MEM` / `PID` / `TIME+`. → `-o <field>`.

**Behavior**
- Always invoked as `top -bn1 -w 512` (single batch iteration, fixed width). No raw flag passthrough.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 20. `du`
**Args**
- `host: str` (required)
- `path: str` (required) — validated path, positional after `--`.
- `human: bool | None` — `-h`.
- `summary: bool | None` — `-s`.
- `max_depth: int | None` — range 0–10. → `--max-depth=<N>`.
- `apparent: bool | None` — `--apparent-size`.
- `one_filesystem: bool | None` — `-x`.
- `threshold: str | None` — regex `^-?\d+[KMGT]?$`. → `-t <val>`.

**Behavior**
- Remote command: `du [flags...] -- <path>`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 21. `lsblk`
**Args**
- `host: str` (required)
- `json: bool | None` — `-J`. Mutually exclusive with `pairs`.
- `pairs: bool | None` — `-P`.
- `tree: bool | None` — default true. False → `-l`.
- `paths: bool | None` — `-p`.
- `fs: bool | None` — `-f`.
- `discard: bool | None` — `-D`.
- `topology: bool | None` — `-t`.
- `device: str | None` — validated path, positional after `--`.

**Behavior**
- Remote command: `lsblk [flags...] [-- <device>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 22. `blkid`
**Args**
- `host: str` (required)
- `device: str | None` — validated path, positional after `--`.
- `probe: bool | None` — `-p`. Requires `device`.

**Behavior**
- Remote command: `blkid [-p] [-- <device>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 23. `smartctl`
**Args**
- `host: str` (required)
- `device: str` (required) — validated path, positional after `--`.
- `mode: str` (required) — whitelist: `info`, `health`, `attributes`, `all`, `capabilities` mapped to `-i`, `-H`, `-A`, `-a`, `-c`. No raw flag passthrough.

**Behavior**
- Remote command: `smartctl <mode-flag> -- <device>`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 24. `dmesg`
**Args**
- `host: str` (required)
- `human: bool | None` — `-H`. Mutually exclusive with `time_iso`.
- `time_iso: bool | None` — `--time-format=iso`.
- `kernel_only: bool | None` — `-k`. Restricts output to kernel-facility messages.
- `level: str | None` — whitelist: `emerg`, `alert`, `crit`, `err`, `warn`, `notice`, `info`, `debug`. → `--level=<val>`.
- `facility: str | None` — whitelist: `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`. → `--facility=<val>`.
- `tail_lines: int | None` — range 1–10000. → pipe `| tail -n <N>`.

**Behavior**
- Remote command: `dmesg --no-pager [flags...] [| tail -n <N>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 25. `uname`
**Args**
- `host: str` (required)
- `mode: str` (required) — whitelist: `all`, `kernel-name`, `kernel-release`, `kernel-version`, `machine`, `processor`, `hardware-platform`, `operating-system` mapped to `-a`, `-s`, `-r`, `-v`, `-m`, `-p`, `-i`, `-o`.

**Behavior**
- Remote command: `uname <mode-flag>`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 26. `sysctl`
**Args**
- `host: str` (required)
- `key: str | None` — regex `^[a-zA-Z0-9._-]{1,256}$`, no leading `-`. Mutually exclusive with `all`.
- `all: bool | None` — `-a`.
- `pattern: str | None` — regex `^[a-zA-Z0-9._*-]{1,256}$`, no leading `-`. → `--pattern=<val>`.

**Behavior**
- Exactly one of `key` / `all` required. `pattern` requires `all=true`. Remote command: `sysctl [-a | <key>] [--pattern=<val>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 27. `dpkg_list`
**Args**
- `host: str` (required)
- `pattern: str | None` — regex `^[A-Za-z0-9._*?+-]{1,128}$`, no leading `-`. Positional after `--`.

**Behavior**
- Remote command: `dpkg -l [-- <pattern>]`. Read-only view; no install/remove flags ever.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 28. `rpm_list`
**Args**
- `host: str` (required)
- `pattern: str | None` — same validator as `dpkg_list.pattern`. Positional after `--`.
- `last: bool | None` — `--last`.

**Behavior**
- Remote command: `rpm -qa [--last] [-- <pattern>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 29. `apt_list_installed`
**Args**
- `host: str` (required)
- `pattern: str | None` — same validator as `dpkg_list.pattern`. Positional after `--`.

**Behavior**
- Remote command: `apt list --installed [-- <pattern>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 30. `uptime`
**Args**
- `host: str` (required)
- `pretty: bool | None` — `-p`. Mutually exclusive with `since`.
- `since: bool | None` — `-s`.

**Behavior**
- Remote command: `uptime [-p | -s]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 31. `who`
**Args**
- `host: str` (required)
- `all: bool | None` — `-a`.
- `boot: bool | None` — `-b`.
- `login: bool | None` — `-l`.
- `runlevel: bool | None` — `-r`.
- `users: bool | None` — `-q`.

**Behavior**
- Remote command: `who [flags...]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 32. `last`
**Args**
- `host: str` (required)
- `lines: int | None` — range 1–1000. → `-n <N>`.
- `user: str | None` — username regex `^[a-z_][a-z0-9_-]*\$?$`, length ≤ 32. Positional after `--`.
- `tty: str | None` — regex `^[A-Za-z0-9./_-]{1,32}$`, no leading `-`. Positional after `--` after user.

**Behavior**
- Remote command: `last [-n <N>] [-- <user> [<tty>]]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 33. `lscpu`
**Args**
- `host: str` (required)
- `json: bool | None` — `-J`. Mutually exclusive with `extended` and `parseable`.
- `extended: bool | None` — `-e`. Mutually exclusive with `parseable`.
- `parseable: bool | None` — `-p`.

**Behavior**
- Remote command: `lscpu [-J | -e | -p]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 34. `lsmem`
**Args**
- `host: str` (required)
- `json: bool | None` — `-J`. Mutually exclusive with `summary`.
- `summary: bool | None` — `-s only`.
- `bytes: bool | None` — `-b`.

**Behavior**
- Remote command: `lsmem [-J | -s only] [-b]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 35. `dmidecode`
**Args**
- `host: str` (required)
- `type: str` (required) — whitelist: `bios`, `system`, `baseboard`, `chassis`, `processor`, `memory`, `cache`, `connector`, `slot`. → `-t <type>`.

**Behavior**
- Remote command: `dmidecode -t <type>`. Requires root on remote; non-root produces an error in stderr and non-zero exit (passed through as data).

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 36. `chronyc`
**Args**
- `host: str` (required)
- `subcommand: str` (required) — whitelist: `tracking`, `sources`, `sourcestats`, `activity`, `ntpdata`, `clients`, `serverstats`, `selectdata`, `smoothing`. All read-only.

**Behavior**
- Remote command: `chronyc -n <subcommand>` (`-n` suppresses DNS). No write subcommands (no `makestep`, `add server`, etc.) ever.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 37. `timedatectl`
**Args**
- `host: str` (required)
- `mode: str` (required) — whitelist: `status`, `show`, `list-timezones`, `show-timesync`, `timesync-status`. All read-only.

**Behavior**
- Remote command: `timedatectl --no-pager <mode>`. No `set-*` subcommands ever.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 38. `mount`
**Args**
- `host: str` (required)
- `fstype: str | None` — regex `^[a-z0-9]{1,32}$`, no leading `-`. → `-t <fstype>`.
- `verbose: bool | None` — `-v`.

**Behavior**
- Remote command: `mount [-v] [-t <fstype>]`. List-only — no `-o remount`, no source/target args.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 39. `findmnt`
**Args**
- `host: str` (required)
- `json: bool | None` — `-J`. Mutually exclusive with `tree`.
- `tree: bool | None` — `-T`.
- `target: str | None` — validated path. → `--target=<path>`.
- `source: str | None` — regex `^[A-Za-z0-9./_:-]{1,256}$`, no leading `-`. → `--source=<src>`.
- `fstype: str | None` — same validator as `mount.fstype`. → `-t <fstype>`.

**Behavior**
- Remote command: `findmnt [-J | -T] [--target=<p>] [--source=<s>] [-t <fstype>]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 40. `stat_fs`
**Args**
- `host: str` (required)
- `path: str` (required) — validated path, positional after `--`.
- `format: str | None` — whitelist: `default`, `terse`. `terse` → `-t`. `default` → omit (default verbose).

**Behavior**
- Remote command: `stat -f [-t] -- <path>`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 41. `docker_ps`
**Args**
- `host: str` (required)
- `all: bool | None` — `-a`. Mutually exclusive with `latest` and `last`.
- `size: bool | None` — `-s`.
- `latest: bool | None` — `-l`. Mutually exclusive with `last`.
- `last: int | None` — range 1–1000. → `-n <N>`.
- `quiet: bool | None` — `-q`.
- `no_trunc: bool | None` — `--no-trunc`.
- `format: str | None` — whitelist: `table` (omit), `json` (`--format=json`). No raw template strings.
- `filter: object | None` — keys whitelist: `ancestor`, `before`, `exited`, `health`, `id`, `is-task`, `label`, `name`, `network`, `publish`, `expose`, `since`, `status`, `volume`. Values regex `^[A-Za-z0-9._:/=@+-]{1,256}$`, no leading `-`. Each k=v passed via `--filter <k>=<v>`. Lists allowed per key (repeated `--filter`).

**Behavior**
- Remote command: `docker ps [flags...] [--filter <k>=<v> ...]`. List-only. No raw flag passthrough.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 42. `docker_inspect`
**Args**
- `host: str` (required)
- `targets: list[str]` (required, 1–100) — container/image/network/volume IDs or names. Each regex `^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$`, no leading `-`. Positional after `--`.
- `type: str | None` — whitelist: `container`, `image`, `network`, `volume`, `service`, `node`, `plugin`, `secret`, `task`. → `--type=<t>`.
- `format: str | None` — whitelist: `json` (omit, default), `id` (`--format={{.Id}}`), `name` (`--format={{.Name}}`). No raw template strings.
- `size: bool | None` — `-s`.

**Behavior**
- Remote command: `docker inspect [--type=<t>] [--format=<preset>] [-s] -- <target>...`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 43. `docker_images`
**Args**
- `host: str` (required)
- `all: bool | None` — `-a`.
- `digests: bool | None` — `--digests`.
- `quiet: bool | None` — `-q`.
- `no_trunc: bool | None` — `--no-trunc`.
- `format: str | None` — whitelist: `table` (omit), `json` (`--format=json`).
- `filter: object | None` — keys whitelist: `dangling`, `label`, `before`, `since`, `reference`. Same value regex as `docker_ps.filter`. Lists allowed per key.
- `repository: str | None` — image ref. Regex `^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$`, no leading `-`. Positional after `--`.

**Behavior**
- Remote command: `docker images [flags...] [--filter <k>=<v> ...] [-- <repository>]`. List-only.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 44. `docker_logs`

Tail a container's stdout+stderr log on a remote host. Read-only.

**Args**
- `host: str` — required. Same rules as everywhere else.
- `container: str` — required. Container name or ID. Regex `^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$`, no leading `-`.
- `tail: int | None` — `--tail N`. Default `100`. Range `[1, 10000]`.
- `since: str | None` — `--since=<value>`. Free-form (Docker accepts duration like `42m`, RFC3339, Unix ts). NUL/newline rejected, max 128 chars.
- `until: str | None` — `--until=<value>`. Same constraints as `since`.
- `timestamps: bool | None` — `--timestamps`. Default `false`.
- `grep_pattern: str | None` — when set, output piped to `grep -- <pattern>`. NUL/newline rejected.
- `grep_flags: list[str] | None` — same whitelist as `read_file.grep_flags`. Requires `grep_pattern`; rejected otherwise.

**Behavior**
- Remote command: `docker logs --tail <N> [--since=<v>] [--until=<v>] [--timestamps] -- <container>` followed by `2>&1 | grep [<flags>] -- <pattern> || [ $? -eq 1 ]` when `grep_pattern` is set. The `2>&1` merge is required because Docker writes container stderr to its own stderr stream; merging is the only way `grep` can filter both. The `|| [ $? -eq 1 ]` masks grep's no-match exit (1) so the pipeline returns 0 when no lines match while still propagating real grep errors (exit 2+). Side-effect: server-side stdout/stderr split is collapsed when grep is in use.
- Default `tail=100` keeps responses small; long-running containers can produce GBs.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 45. `psi_stats`

Read PSI pressure-stall information from `/proc/pressure/*` on a remote host. Read-only.

**Args**
- `host: str` — required.
- `resource: str | None` — one of `cpu`, `memory`, `io`, `all`. Default `all`.

**Behavior**
- `resource=all`: `LC_ALL=C grep -H '' /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io` (labels each file).
- Single resource: `LC_ALL=C cat /proc/pressure/<resource>`. `resource` comes only from the enum whitelist; no interpolation risk.
- Kernels before 4.20 lack these files; nonzero exit is passed through unchanged.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 46. `meminfo`

Read `/proc/meminfo` on a remote host, optionally filtered to named fields. Read-only.

**Args**
- `host: str` — required.
- `fields: list[str] | None` — field names to extract. Each must match `^[A-Za-z0-9_()]+$`, max 64 chars. Omit or `null` = return full file.

**Behavior**
- No fields: `LC_ALL=C cat /proc/meminfo`.
- With fields: `LC_ALL=C cat /proc/meminfo | grep -E <pattern>` where pattern is `^(Field1|Field2|...):`. Pattern is `shlex.quote`-escaped before interpolation.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 47. `proc_limits`

Read `/proc/<pid>/limits` (process rlimits) on a remote host. Read-only.

**Args**
- `host: str` — required.
- `pid: int` — required. Range `[1, 4194304]`. `bool` subtype rejected.

**Behavior**
- Remote command: `LC_ALL=C cat /proc/<pid>/limits`. `pid` is an integer so no quoting is needed; no shell-injection risk.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 48. `arp_table`

Run `ip neigh show` (ARP/neighbor cache) on a remote host. Read-only.

**Args**
- `host: str` — required.
- `iface: str | None` — interface name. Regex `^[A-Za-z0-9._@:-]{1,32}$`, no leading `-`.
- `family: str | None` — `inet` or `inet6`. Maps to `-4` / `-6` flag respectively.

**Behavior**
- Remote command: `LC_ALL=C ip -o [-4|-6] neigh show [dev <iface>]`.
- `iface` is `shlex.quote`-escaped. `family` is whitelist-mapped; never interpolated directly.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 49. `systemctl_list_timers`

List systemd timer units with next/last fire times on a remote host. Read-only.

**Args**
- `host: str` — required.
- `all: bool | None` — include inactive timers (`--all`). Default `false`.

**Behavior**
- Remote command: `LC_ALL=C systemctl list-timers --no-pager [--all]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 50. `systemctl_list_sockets`

List systemd socket units with listen address and owning service on a remote host. Read-only.

**Args**
- `host: str` — required.
- `all: bool | None` — include inactive sockets (`--all`). Default `false`.

**Behavior**
- Remote command: `LC_ALL=C systemctl list-sockets --no-pager [--all]`.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 51. `tc_qdisc`

Run `tc -s qdisc show [dev <iface>]` (queueing discipline stats: queue depth, drops) on a remote host. Non-root readable. Read-only.

**Args**
- `host: str` — required.
- `iface: str | None` — interface name. Regex `^[A-Za-z0-9._@:-]{1,32}$`, no leading `-`. Omit for all interfaces.

**Behavior**
- Remote command: `LC_ALL=C tc -s qdisc show [dev <iface>]`. `iface` is `shlex.quote`-escaped.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 52. `ethtool`

Run ethtool against an interface on a remote host using a preset mode. Some modes require privileges (exit/stderr passthrough). Read-only.

**Args**
- `host: str` — required.
- `iface: str` — required. Regex `^[A-Za-z0-9._@:-]{1,32}$`, no leading `-`.
- `mode: str | None` — one of `driver` (default), `stats`, `ring`, `features`, `pause`, `coalesce`. Maps to `-i|-S|-g|-k|-a|-c`.

**Behavior**
- Remote command: `LC_ALL=C ethtool <mode_flag> <iface>`. `iface` is `shlex.quote`-escaped. `mode_flag` comes only from the whitelist map.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 53. `conntrack`

Run `conntrack -S` (stats, default) or `conntrack -L [-p <proto>]` (list) on a remote host. Requires root and the `nf_conntrack` kernel module. Read-only.

**Args**
- `host: str` — required.
- `mode: str | None` — `stats` (default) or `list`.
- `protocol: str | None` — whitelist: `tcp`, `udp`, `icmp`, `icmpv6`, `dccp`, `sctp`, `gre`. Only valid with `mode=list`; rejected otherwise.

**Behavior**
- `mode=stats`: `LC_ALL=C conntrack -S`.
- `mode=list`: `LC_ALL=C conntrack -L [-p <proto>]`. `proto` is `shlex.quote`-escaped from the whitelist.
- List output can be large; truncation flagged via the passthrough `truncated` field.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 54. `net_protocol_stats`

Run `netstat -s [--tcp|--udp|--raw]` (protocol counters: retransmits, drops, listen overflows) on a remote host. Read-only.

**Args**
- `host: str` — required.
- `protocol: str | None` — one of `all` (default, no flag), `tcp` (`--tcp`), `udp` (`--udp`), `ip` (`--raw`).

**Behavior**
- Remote command: `LC_ALL=C netstat -s [<flag>]`. Flag comes only from the whitelist map; never interpolated directly.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 55. `nft_list`

Run `nft -nn list ruleset` (default) or `nft -nn list table <family> <table>` on a remote host. Root required. Surfaces firewall rules/IPs — same exposure class as existing `ip_addr`/`ss`. Read-only.

**Args**
- `host: str` — required.
- `family: str | None` — one of `ip`, `ip6`, `inet`, `arp`, `bridge`, `netdev`. Required when `table` is given.
- `table: str | None` — table name. Regex `^[A-Za-z0-9_.-]{1,64}$`, no leading `-`. Required when `family` is given.

**Behavior**
- No args: `LC_ALL=C nft -nn list ruleset`.
- With table: `LC_ALL=C nft -nn list table <family> <table>`. Both values are `shlex.quote`-escaped; `family` also comes from the whitelist.
- Supplying only one of `family`/`table` is rejected.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 56. `iptables_list`

Run `iptables -n -v -L [-t <table>]` (or `ip6tables` for IPv6) on a remote host. Root required. Read-only.

**Args**
- `host: str` — required.
- `family: str | None` — `ipv4` (default, uses `iptables`) or `ipv6` (uses `ip6tables`).
- `table: str | None` — whitelist: `filter`, `nat`, `mangle`, `raw`. Omit for all chains.

**Behavior**
- Remote command: `LC_ALL=C iptables -n -v -L [-t <table>]`. Binary selected from `family` whitelist map; `table` from its own whitelist; both are `shlex.quote`-escaped.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 57. `slabtop`

Run `slabtop -o` (one-shot kernel slab cache stats) on a remote host. Root required. Read-only.

**Args**
- `host: str` — required.

**Behavior**
- Remote command: `LC_ALL=C slabtop -o`. No interpolated values.
- Root required; missing privileges surface via nonzero exit and stderr.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 58. `numastat`

Run `numastat [-p <pid>]` (NUMA memory allocation stats) on a remote host. `numactl` package may be absent (127 passthrough). Read-only.

**Args**
- `host: str` — required.
- `pid: int | None` — optional. Range `[1, 4194304]`. `bool` subtype rejected. Passed as `-p <int>`.

**Behavior**
- Remote command: `LC_ALL=C numastat [-p <pid>]`. `pid` is an integer; no quoting needed.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 59. `cgroup_stats`

Read cgroup v2 controller stat files under `/sys/fs/cgroup/<path>` on a remote host. Path is traversal-safe; leaf filenames are a fixed whitelist per controller. Read-only.

**Args**
- `host: str` — required.
- `cgroup_path: str` — required. Relative path under `/sys/fs/cgroup`. Validated by `validate_cgroup_path`: regex `^[A-Za-z0-9._:@/-]+$`, max 1024 chars, no leading `/`, no `..` segments.
- `controller: str | None` — one of `cpu`, `memory`, `io`, `all` (default). Selects whitelisted leaf files.

**Behavior**
- Controller → files: `cpu` → `cpu.stat`; `memory` → `memory.current memory.stat memory.pressure`; `io` → `io.stat io.pressure`; `all` → union in that order.
- Remote command: `LC_ALL=C grep -H '' /sys/fs/cgroup/<path>/<file> ...`. `<path>` is `shlex.quote`-escaped; filenames are string literals from the whitelist — no attacker-controlled interpolation.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 60. `systemd_analyze`

Run `systemd-analyze <mode> --no-pager [<unit>]` on a remote host. Read-only.

**Args**
- `host: str` — required.
- `mode: str | None` — one of `time` (default), `blame`, `critical-chain`.
- `unit: str | None` — optional unit name (validated by `validate_unit_name`). Only valid with `mode=critical-chain`; rejected otherwise.

**Behavior**
- Remote command: `LC_ALL=C systemd-analyze <mode> --no-pager [<unit>]`. `unit` is `shlex.quote`-escaped and additionally validated.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

### 61. `blockdev`

Run `blockdev --report` (block device sizes, sector/block sizes, RO/RA flags) on a remote host. Read-only.

**Args**
- `host: str` — required.

**Behavior**
- Remote command: `LC_ALL=C blockdev --report`. No interpolated values; no per-device arg to avoid injection surface.

**Returns** `{stdout, stderr, exit_code, truncated}`.

### 62. `host_facts`

Gather host facts in a **single SSH round-trip** by running a fixed bundled shell script that emits delimiter-marked sections (`===name===`). Each probe wraps with `2>/dev/null || true` so one missing binary never aborts the rest. No user values are interpolated into the remote command beyond the validated host. Read-only.

**Args**
- `host: str` — required.

**Bundled probes (in order):** `os_release` (via `/etc/os-release`), `uname -srm`, `nproc`, `MemTotal` from `/proc/meminfo`, `systemd-detect-virt` (hypervisor + container), DMI `sys_vendor`/`product_name`, tool capability checks (`command -v`), `/proc/uptime`, `date -u`, `id -un`.

**Behavior**
- Remote command: `LC_ALL=C sh -c <quoted-script>`. Script is a fixed constant; no interpolation.
- Output is parsed by `_parse_facts(stdout)` into a structured dict.

**Returns** `{facts, stdout, stderr, exit_code, truncated, stderr_truncated}`.

**`facts` dict shape:**

| Key | Type | Notes |
|-----|------|-------|
| `distro` | `dict` | Keys: `ID`, `VERSION_ID`, `PRETTY_NAME` (subset of `/etc/os-release`) |
| `kernel` | `str \| None` | Kernel version from `uname -srm` (field 2) |
| `arch` | `str \| None` | Machine arch from `uname -srm` (field 3) |
| `nproc` | `int \| None` | CPU count |
| `mem_total_kb` | `int \| None` | Total RAM in kB |
| `hypervisor` | `str` | `systemd-detect-virt` output or `"none"` |
| `container` | `str` | `systemd-detect-virt -c` output or `"none"` |
| `dmi_vendor` | `str \| None` | `/sys/class/dmi/id/sys_vendor` |
| `dmi_product` | `str \| None` | `/sys/class/dmi/id/product_name` |
| `is_virtual` | `bool` | `True` if hypervisor ≠ none OR DMI matches VM signature |
| `capabilities` | `dict[str, bool]` | Per-binary `command -v` result. Covers the optional binaries behind tool groups so a caller can skip a round-trip when one is absent (see mapping below). |
| `uptime_s` | `int \| None` | Integer seconds from `/proc/uptime` |
| `now_utc` | `str \| None` | ISO-8601 UTC timestamp |
| `whoami` | `str \| None` | Effective username |

**Capability → tool mapping.** `capabilities` probes: `docker`/`podman` (docker_* tools), `systemctl` (systemctl_*, systemd_analyze), `nft` (nft_list), `iptables` (iptables_list), `conntrack` (conntrack), `ethtool` (ethtool), `tc` (tc_qdisc), `ss` (ss), `lsof` (lsof, lsof_net), `smartctl` (smartctl), `blockdev` (blockdev), `lsblk` (lsblk), `numastat` (numastat), `slabtop` (slabtop), `lldpctl` (lldp_*), `chronyc` (chronyc), `dmidecode` (dmidecode), `iostat` (iostat), `vmstat` (vmstat), `dpkg` (dpkg_list, apt_list_installed), `rpm` (rpm_list). A `False` entry means that tool will fail with `not_found`; call `host_facts` first to avoid the round-trip.

---

### 63. `lldp_neighbors`

Discovered LLDP peers (upstream switch, remote port, VLAN, management address) via `lldpcli show neighbors`. Read-only.

**Args**
- `host: str` — required.
- `format: str` — optional, one of `keyvalue` (default), `json`, `json0`, `xml`, `plain`. Whitelist; default `keyvalue` for stable parsing.
- `iface: str` — optional. Scopes to one local port (`ports <iface>`). Validated `^[A-Za-z0-9._@:-]{1,32}$`.

**Behavior**
- Remote command: `LC_ALL=C lldpcli -f <format> show neighbors [ports <iface>]`. The `show` subcommand is a fixed literal; `format`/`iface` are validated + `shlex.quote`d.
- Requires `lldpd` running; the daemon socket may require privileges — exit code / stderr pass through unchanged.

**Returns** `{stdout, stderr, exit_code, truncated, stderr_truncated}`.

### 64. `lldp_interfaces`

Local interfaces `lldpd` manages and what it advertises, via `lldpcli show interfaces`. Read-only.

**Args**
- `host: str` — required.
- `format: str` — optional, same whitelist as §63 (default `keyvalue`).
- `iface: str` — optional, same validation as §63.

**Behavior**
- Remote command: `LC_ALL=C lldpcli -f <format> show interfaces [ports <iface>]`.

**Returns** `{stdout, stderr, exit_code, truncated, stderr_truncated}`.

### 65. `lldp_statistics`

Per-port LLDP frame counters (tx, rx, discarded, unrecognized, aged out) via `lldpcli show statistics`. Read-only.

**Args**
- `host: str` — required.
- `format: str` — optional, same whitelist as §63 (default `keyvalue`).
- `iface: str` — optional, same validation as §63.

**Behavior**
- Remote command: `LC_ALL=C lldpcli -f <format> show statistics [ports <iface>]`.

**Returns** `{stdout, stderr, exit_code, truncated, stderr_truncated}`.

### 66. `lldp_chassis`

Local chassis information this host advertises (chassis id, name, description, capabilities) via `lldpcli show chassis`. Read-only.

**Args**
- `host: str` — required.
- `format: str` — optional, same whitelist as §63 (default `keyvalue`).

**Behavior**
- Remote command: `LC_ALL=C lldpcli -f <format> show chassis`. No `iface` argument.

**Returns** `{stdout, stderr, exit_code, truncated, stderr_truncated}`.

### 67. `triage`

One SSH round-trip health summary. Runs a fixed bundled probe script (no user interpolation, like §62 `host_facts`) and returns a prioritized `warnings` list plus a `facts` bundle. Read-only; each probe degrades to empty via `2>/dev/null || true` when its source is restricted or absent.

**Args**
- `host: str` — required. (No other args in v1; thresholds are fixed.)

**Behavior**
- Remote command: `LC_ALL=C sh -c '<script>'` bundling: `/proc/loadavg`, `nproc`, filtered `/proc/meminfo` (`MemTotal`/`MemAvailable`/`SwapTotal`/`SwapFree`), `df -P -l -x tmpfs -x devtmpfs -x overlay` (overlay excluded so docker layer mounts don't duplicate their backing fs), `systemctl --failed --no-legend --plain`, `/proc/pressure/{cpu,memory,io}`, and recent `dmesg` OOM/kill lines.
- Parsing is pure and never raises; missing sections yield `null`/empty fields, not errors.

**Thresholds** (warning kinds): `high_load` (load1/nproc ≥ 1.5, `crit` ≥ 4.0), `low_memory` (MemAvailable < 10% of total, `crit` < 5%), `swap_pressure` (swap > 50% used), `disk_full` (mount ≥ 90%, `crit` ≥ 95%; one per mount), `failed_units` (any failed unit), `pressure` (PSI some avg10 > 20 per resource), `oom_recent` (recent OOM/kill lines).

**Returns**
```
{
  "warnings": [ {"kind": "...", "severity": "warn"|"crit", "detail": "..."} ],
  "facts": {
    "load1": float|null, "load5": float|null, "load15": float|null, "nproc": int|null,
    "mem_total_kb": int|null, "mem_available_kb": int|null,
    "swap_total_kb": int|null, "swap_free_kb": int|null,
    "disks": [ {"mount": str, "use_pct": int} ],
    "failed_units": [str],
    "psi": {"cpu": float|null, "memory": float|null, "io": float|null},
    "oom_recent": [str]
  },
  "stdout": "...", "stderr": "...", "exit_code": 0,
  "truncated": false, "stderr_truncated": false
}
```
Empty `warnings` = healthy.

---

### 68. `dig`

Run `dig` (DNS lookup) on a remote host. Read-only.

**Args**
- `host: str` — required.
- `name: str` — required. Query name (domain) or, with `reverse`, an IP address. Regex `^[A-Za-z0-9_.:-]{1,253}$`, no leading `-`.
- `record_type: str | None` — whitelist `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `PTR`, `SRV`, `CAA`, `DS`, `DNSKEY`, `NAPTR`, `ANY` (case-insensitive, upcased). Rejected when `reverse` is set. Omitted ⇒ dig default (`A`).
- `server: str | None` — DNS server to query (`@server`). Same regex as `name`.
- `reverse: bool | None` — `dig -x <name>` reverse (PTR) lookup.
- `short: bool | None` — `+short`.
- `tcp: bool | None` — `+tcp`.
- `trace: bool | None` — `+trace`.
- `dnssec: bool | None` — `+dnssec`.

**Behavior**
- Remote command: `LC_ALL=C dig [@server] [-x name | name [type]] [+short] [+tcp] [+trace] [+dnssec]`. Every interpolated value (`name`, `server`, `record_type`) is `shlex.quote`-escaped; `record_type` also comes from the whitelist. `+`-options are fixed literals.
- No root required.

**Returns** `{stdout, stderr, exit_code, truncated}`.

---

## Configuration (environment variables)

| Var | Default | Meaning |
|-----|---------|---------|
| `LINUX_INFO_SSH_CMD` | `ssh` | Command + flags. Parsed with `shlex.split` (shell-style: quotes/escapes honored); becomes argv prefix. Final argv shape is `[<prefix>...] <host> -- <remote_cmd>`. The `--` separator is included so OpenSSH stops option parsing before the remote command; wrappers that don't recognise `--` (some teleport `tsh ssh` forks, etc.) may need the `--` stripped externally. Example: `ssh -F /home/me/.ssh/config -o ConnectTimeout=5`. |
| `LINUX_INFO_SSH_MUX` | on | Only when `LINUX_INFO_SSH_CMD` is unset: the default `ssh` argv gets connection multiplexing (`-o ControlMaster=auto -o ControlPath=$TMPDIR/lim-%C -o ControlPersist=60s`), so repeated/fan-out calls reuse one master and skip per-call handshakes. `%C` is a fixed-length connection hash (avoids the ~104-char socket-path limit). Set `0`/`false`/`no`/`off` to disable. When `LINUX_INFO_SSH_CMD` is set, the operator owns the full argv and no mux is injected. |
| `LINUX_INFO_HOSTS` | `` (empty) | Comma-separated allowlist. Empty = any host. Hostnames matched exactly. |
| `LINUX_INFO_TIMEOUT` | `30` | Seconds before subprocess kill. On timeout: `exit_code=124`, `[timeout]` appended to `stderr`. |
| `LINUX_INFO_MAX_BYTES` | `1048576` | 1 MiB cap applied to both stdout and stderr. Stdout truncation sets `truncated: true`. |
| `LINUX_INFO_MAX_HOSTS` | `10` | Max hosts per `hosts` fan-out call. Clamped to `[1, 25]` (25 is a hard ceiling). Invalid / `<1` falls back to 10. |
| `LINUX_INFO_PARALLELISM` | `4` | Worker threads for `hosts` fan-out. Clamped to `[1, 25]`; effective workers also capped at the host count. Invalid / `<1` falls back to 4. |
| `LINUX_INFO_SUDO` | `` (off) | When set to `1`/`true`/`yes`/`on`, privilege-prone tools prefix their remote command with `sudo -n` (see §Privilege escalation). Off by default. Anything else = off. |
| `LINUX_INFO_OUTPUT_MODE` | `` (unset) | Locks response shape to `raw`/`parsed`/`both`, overriding the per-call `output_mode` arg (see §Output modes). Strict lowercase; invalid value → `validation_error`. |
| `LINUX_INFO_LOG_FILE` | `` (empty) | Absolute path to JSONL log file. Empty / unset = logging fully disabled. |
| `LINUX_INFO_LOG_LEVEL` | `INFO` | One of `TRACE`, `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Unknown values fall back to `INFO`. Only honored when `LINUX_INFO_LOG_FILE` is set. |

### Grep flag whitelist details
- Exact-match set: `-i`, `-E`, `-v`, `-n`, `-w`, `-F`.
- Context flag: `-C<N>` where `N` is a single digit `1`–`9`.

## Privilege handling

Many diagnostics need root (`smartctl`, `dmidecode`, `nft_list`, `iptables_list`, `conntrack`, often `dmesg` under `kernel.dmesg_restrict`, `ethtool` for some modes, the `lldp_*` tools' daemon socket). The server runs as the SSH login user and never escalates on its own. Two independent mechanisms address this:

### Privilege-error detection (always on)

After any handler returns, if `exit_code != 0` and `stderr` matches a privilege signature (`permission denied`, `operation not permitted`, `must be root/superuser`, `are you root`, `you need/must be root`, `requires root/CAP_`, `docker.sock`), the result dict gains `privilege_error: true`. Pure output annotation — no change to what runs, no new attack surface. Applied on both the single-host path and each multi-host per-host result. Lets the caller distinguish "needs privilege" from other failures without guessing.

### Error taxonomy (always on)

Every result with an integer `exit_code` also gains `error_kind`, normalized from exit code + stderr into one of: `ok` (exit 0), `timeout` (exit 124), `auth`, `dns`, `unreachable`, `not_found` (exit 127 or `command not found`), `privilege`, or `nonzero` (any other failure). Precedence is `ok → timeout → auth → dns → unreachable → not_found → privilege → nonzero`, so SSH-transport failures are classified before remote-command failures. Pure central annotation (no per-tool code); applied on the single-host path and each per-host result. `error_kind == "privilege"` is the same condition as `privilege_error` (kept for back-compat). Lets the caller decide retry vs switch-host vs escalate vs give-up.

### Privilege escalation (opt-in, off by default)

`LINUX_INFO_SUDO=1` makes the **privilege-prone** tools prefix their remote command with `sudo -n` (`-n` = non-interactive: it fails fast instead of hanging on a password prompt). The set is exactly those tools that plausibly need root: `smartctl`, `dmidecode`, `dmesg`, `ethtool`, `nft_list`, `iptables_list`, `conntrack`, `lldp_neighbors`, `lldp_interfaces`, `lldp_statistics`, `lldp_chassis`. Non-privileged tools are never prefixed (no point, and it would needlessly widen the required sudoers).

**Design:** the server is mechanism; **sudoers is policy.** `sudo -n` is applied per-tool to the specific binary (e.g. `LC_ALL=C sudo -n smartctl ...`), never as a blanket `sudo sh -c '<pipeline>'` — the latter would require passwordless `sudo sh` (effective root, unconstrainable by sudoers) and defeat the point. What the escalation can actually do is bounded entirely by the operator's sudoers file, which they already control. The feature grants nothing the login user is not already granted.

**This is only as safe as your sudoers.** Scope it to specific read-only binaries, e.g.:

```
# /etc/sudoers.d/linux-info  — dedicated read-only diagnostic account
diag ALL=(root) NOPASSWD: /usr/sbin/smartctl, /usr/sbin/dmidecode, \
  /usr/sbin/nft -nn list *, /usr/sbin/iptables -n -v -L *, /usr/sbin/conntrack
```

A broad grant (`NOPASSWD: ALL`) combined with `LINUX_INFO_SUDO=1` hands an LLM effective root; the server cannot detect or prevent that.

## Security Model

- Local exec: `subprocess.run([...argv], shell=False, timeout=..., capture_output=True)`. Never `shell=True`.
- Remote exec: shell unavoidable for pipes. Build remote command as single string, every interpolated value passed through `shlex.quote`. Prefix with `LC_ALL=C` for stable output.
- Reject any path or string containing NUL bytes or newlines before quoting.
- `grep_flags`: regex-validated each. Reject anything not in whitelist.
- `find` predicates: only the named kwargs accepted; no raw arg list.
- Host: if allowlist set, exact-match check; reject otherwise. Always reject hosts containing whitespace or starting with `-`.

## Architecture

```
linux-info-mcp/
  server.py                  # entrypoint shim → linux_info_mcp.server:main
  linux_info_mcp/
    __init__.py
    ssh.py                   # run_ssh + SshResult + builders for the file tools
    validate.py              # shared validators + whitelists + multi-host resolution
    log.py                   # JSONL logging, TRACE level, ContextVar correlation
    server.py                # MCP server: auto-discovers tools/*, registers, dispatches (single + multi-host)
    tools/
      __init__.py            # ToolSpec dataclass
      _common.py             # shared per-tool helpers (underscore = skipped by discovery)
      files.py               # read_file, find_files, read_binary
      systemctl.py           # systemctl_status, systemctl_list, systemctl_list_timers, systemctl_list_sockets
      journalctl.py          # journalctl
      perf.py                # iostat, vmstat, free, df, ps, psi_stats, meminfo
      net.py                 # ss, ip_addr, ip_route, lsof_net, arp_table, tc_qdisc, ethtool, conntrack, net_protocol_stats, nft_list, iptables_list, dig
      lldp.py                # lldp_neighbors, lldp_interfaces, lldp_statistics, lldp_chassis
      proc.py                # lsof, pgrep, pidof, top, proc_limits
      disk.py                # du, lsblk, blkid, smartctl, blockdev
      kernel.py              # dmesg, uname, sysctl, slabtop, numastat, cgroup_stats, systemd_analyze
      pkg.py                 # dpkg_list, rpm_list, apt_list_installed
      sys.py                 # uptime, who, last, lscpu, lsmem, dmidecode
      time.py                # chronyc, timedatectl
      fs.py                  # mount, findmnt, stat_fs
      docker.py              # docker_ps, docker_inspect, docker_images, docker_logs
      facts.py               # host_facts
      triage.py              # triage
  tests/
    conftest.py
    test_validate.py
    test_ssh.py
    test_server.py
    test_log.py
    tools/
      __init__.py
      test_files.py
      test_systemctl.py
      test_journalctl.py
      test_perf.py
      test_net.py
      test_lldp.py
      test_proc.py
      test_disk.py
      test_kernel.py
      test_pkg.py
      test_sys.py
      test_time.py
      test_fs.py
      test_docker.py
      test_facts.py
    e2e/                     # layer 3 agent-driven e2e (manifest.py, capture_samples.py, PROMPT.md); not run by `uv run pytest`
  pyproject.toml
  README.md
  SPEC.md                    # this file
  AGENTS.md                  # agent operating notes
  SECURITY.md                # threat model + reporting
```

68 tools across 16 modules. `server.py` auto-discovers every non-underscore submodule of `tools/` via `pkgutil.iter_modules` and aggregates each module's `TOOLS` list — adding a tool needs no edit to `server.py`.

Per-tool registration contract (`linux_info_mcp/tools/__init__.py`):

```python
from dataclasses import dataclass
from typing import Callable

@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict           # JSON Schema for MCP inputSchema
    handler: Callable[[dict], dict]  # validates args, builds remote cmd, runs ssh, returns dict
```

Each `tools/<area>.py` module exports `TOOLS: list[ToolSpec]`. `server.py` imports every module's `TOOLS` and registers them with the `mcp` SDK (single `list_tools` and `call_tool` decorator pair, dispatching by name).

- `validate.py`: pure shared validators only — `validate_host`, `validate_host_list`, `resolve_target_hosts`, `effective_max_hosts`, `parallelism`, `validate_path`, `validate_grep_flags`, `validate_grep_pattern`, `validate_find_args`, `validate_offset_length`, `binary_length_cap`, `validate_unit_name`, `validate_int_in_range`, `reject_unsafe_chars`. Tool-specific validators may live inside the tool module.
- `tools/_common.py`: shared per-tool helpers — `decode_text`, `validate_bool`, `validate_user`, `validate_pid`, `validate_ref`. Module name is underscore-prefixed so the auto-discovery loop in `server.py` skips it (only modules without a leading `_` register `TOOLS`).
- `ssh.py`: `run_ssh(host, remote_cmd) -> SshResult`, plus the file-tool builders. Each tool module builds its own remote command string (calls `shlex.quote` itself) and uses `run_ssh` for execution.
- `server.py`: imports `TOOLS` from every `tools/*.py`, builds a single dispatch dict, registers MCP tools. Handlers are sync (they call blocking `subprocess.run` via `run_ssh`); `_call_tool` runs each via `await asyncio.to_thread(spec.handler, args)` so concurrent MCP `call_tool` requests truly parallelize instead of serializing on the event loop. ContextVar (`tool`, `request_id`) propagates into the worker thread because `asyncio.to_thread` snapshots and replays the current `contextvars.Context`. `_call_tool` calls `resolve_target_hosts(args)` to decide single vs multi; for multi it dispatches `_run_multi_host` (a `ThreadPoolExecutor` fan-out) via the same `to_thread` hop. Each fan-out worker is submitted as `contextvars.copy_context().run(...)` so the `tool`/`request_id` context reaches per-host `run_ssh` log lines. `_list_tools` advertises an augmented schema per tool (adds the `hosts` array property, drops `host` from `required`); the original `ToolSpec.input_schema` handlers see is left unchanged.

## Logging

JSONL file logging, off by default.

- Configured by `LINUX_INFO_LOG_FILE` (path) and `LINUX_INFO_LOG_LEVEL`.
- If `LINUX_INFO_LOG_FILE` is unset or blank, no handler is attached and every log call is a cheap no-op.
- Parent directory of `LINUX_INFO_LOG_FILE` is created with `os.makedirs(..., exist_ok=True)` before the `FileHandler` opens the file.
- `setup_logging()` is idempotent and called from `main()` once at startup.
- Custom level `TRACE = 5` (below `DEBUG`) is added to `logging`. `Logger.trace(msg, extra=...)` is patched on.

### Events

| Logger | Level | Message | Fields |
|--------|-------|---------|--------|
| `linux_info_mcp.server` | INFO | `server_start` | `tools`, `tool_count` |
| `linux_info_mcp.server` | INFO | `server_stop` | — |
| `linux_info_mcp.server` | TRACE | `tool_call_in` | `tool`, `arguments` |
| `linux_info_mcp.server` | INFO | `tool_call` | `tool`, `host`, `duration_ms`, `exit_code`, `outcome` (`ok` / `nonzero` / `partial` / `validation_error` / `unknown_tool` / `handler_error`), `host_count` (multi-host only; `host` is `null` then), `error` (on any non-`ok` outcome) |
| `linux_info_mcp.server` | TRACE | `tool_call_out` | `tool`, `result` |
| `linux_info_mcp.ssh` | TRACE | `ssh_call_start` | `host`, `remote_cmd` |
| `linux_info_mcp.ssh` | INFO | `ssh_call` | `host`, `exit_code`, `duration_ms`, `stdout_bytes`, `stderr_bytes`, `truncated`, `stderr_truncated`, `outcome` (`ok` / `nonzero` / `timeout`) |
| `linux_info_mcp.ssh` | TRACE | `ssh_call_io` | `host`, `stdout`, `stderr` |

`duration_ms` is also returned on `SshResult.duration_ms` so callers can act on it without scraping logs.

### Correlation

Every log line emitted during a tool call carries `tool` (the MCP tool name) and `request_id` (a 12-hex-char id, fresh per call). These are injected automatically by a `logging.Filter` reading a `contextvars.ContextVar` set in `_call_tool`. Server-emitted lines and `run_ssh`-emitted lines therefore join on `request_id`, and `ssh_call` directly shows which tool triggered it.

Every log line — including those emitted outside a tool call (e.g. `server_start`) — also carries `pid` (the OS process id). This lets you separate concurrent server processes when multiple Claude Code / Claude Desktop sessions share a single `LINUX_INFO_LOG_FILE`.

Concurrency-safe: `contextvars` propagate across `asyncio` task boundaries; each call sees its own context regardless of interleaving.

### Format

Each line is one JSON object:

```json
{"ts":"2026-05-30T12:34:56.789012+00:00","level":"INFO","logger":"linux_info_mcp.ssh","msg":"ssh_call","host":"h1","exit_code":0,"duration_ms":42.51,"stdout_bytes":1234,"stderr_bytes":0,"truncated":false,"outcome":"ok","pid":12345,"tool":"read_file","request_id":"a1b2c3d4e5f6"}
```

Reserved standard `LogRecord` keys (`name`, `args`, `levelname`, etc.) are stripped from the JSON payload; everything else passed via `extra=` is included verbatim. Exceptions logged via `logger.exception(...)` add a `"exc"` field with the formatted traceback.

### Where logging happens

- `run_ssh` is the central point for SSH-call timing (`duration_ms`) and remote-cmd I/O. Per-tool handlers do NOT log; they delegate to `run_ssh`.
- `_call_tool` in `server.py` is the central point for tool-level timing (covers validation, handler dispatch, and serialization).

## Testing

- Framework: `pytest`.
- Unit tests cover:
  - Each validator: accept legal inputs; reject illegal (injection attempts, bad flags, non-whitelisted predicates, NUL, newline, leading `-` host, oversized length).
  - Remote command builders: snapshot-style assertions on the produced string (e.g., grep pattern starting with `-` is safely placed after `-e`).
  - `run_ssh`: monkeypatch `subprocess.run`; assert argv shape, timeout, byte cap (truncation flag).
  - Server tools: integration via SDK in-memory transport if available, else direct call of tool handlers with mocked `run_ssh`.
- Run command: `uv run pytest -q`.
- CI not in scope, but tests must run from a clean checkout with only `uv sync` + `uv run pytest`.

## Run / Install

- Install: `uv sync` in repo root.
- Dev run: `uv run python server.py` (stdio transport).
- Tests: `uv run pytest -q`.
- MCP client config (Claude Desktop / Claude Code):
  ```json
  {
    "mcpServers": {
      "linux-info": {
        "command": "uv",
        "args": ["run", "--directory", "/abs/path/to/linux-info-mcp", "python", "server.py"],
        "env": {
          "LINUX_INFO_SSH_CMD": "ssh",
          "LINUX_INFO_HOSTS": "",
          "LINUX_INFO_TIMEOUT": "30",
          "LINUX_INFO_MAX_BYTES": "1048576"
        }
      }
    }
  }
  ```

## Dependencies

- `mcp` (official Python SDK)
- `pytest` (dev)
- Python `>=3.11`.
- Build backend: `hatchling` (so `[project.scripts]` entry points install correctly).

No other runtime deps.
