# linux-info-mcp — Specification

MCP server that runs read-only diagnostic commands on remote hosts via SSH. Exposes per-tool wrappers around common Linux inspection commands. 43 tools across 12 modules (files, systemd, journalctl, perf, net, proc, disk, kernel, pkg, sys, time, fs, docker).

## Goals & Non-Goals

**Goals**
- Read-only remote inspection over SSH.
- Safe by construction: no command injection, no flag injection, no `-exec`-style escape hatches.
- Configurable SSH invocation (so `ssh`, `ssh -F file`, `pt ro`, `tshctx ssh`, etc. all work).
- Single-file install via `uv`; runnable from any MCP client (Claude Desktop, Claude Code).

**Non-goals**
- Multi-host fan-out (single host per call).
- Any write/mutate operation on remote host.
- Streaming output (single response, byte-capped).
- Authentication management (delegate to user's SSH agent / config).

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
- `length: int` (required, positive). Hard cap = `floor((LINUX_INFO_MAX_BYTES - 64) * 3 / 4)` so the base64-encoded stream (plus newline/format margin) fits within the stdout cap. Validator rejects above the cap rather than silently clamping.

**Behavior**
- Remote command: `dd if=<path> ibs=1 skip=<offset> count=<length> status=none | base64`.
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
- `mode: str | None` — preset, default `"auxf"`. Whitelist: `aux`, `auxf`, `aux-sort-mem`, `aux-sort-cpu`, `ef`, `efH`, `forest`, `tree`. The handler maps each to a fixed flag string (e.g. `aux-sort-mem` → `aux --sort=-rss`); raw flag passthrough is **not** accepted.
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
- `human: bool | None` — `-H`. Mutually exclusive with `time_iso` and `kernel_time`.
- `time_iso: bool | None` — `--time-format=iso`.
- `kernel_time: bool | None` — `-k`.
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
- Exactly one of `key` / `all` required. Remote command: `sysctl [-a | <key>] [--pattern=<val>]`.

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
- `format: str | None` — whitelist: `default`, `terse`, `human`. `terse` → `-t`. `default` / `human` → omit (default verbose).

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

## Configuration (environment variables)

| Var | Default | Meaning |
|-----|---------|---------|
| `LINUX_INFO_SSH_CMD` | `ssh` | Command + flags. Parsed with `shlex.split` (shell-style: quotes/escapes honored); becomes argv prefix. Example: `ssh -F /home/me/.ssh/config -o ConnectTimeout=5`. |
| `LINUX_INFO_HOSTS` | `` (empty) | Comma-separated allowlist. Empty = any host. Hostnames matched exactly. |
| `LINUX_INFO_TIMEOUT` | `30` | Seconds before subprocess kill. On timeout: `exit_code=124`, `[timeout]` appended to `stderr`. |
| `LINUX_INFO_MAX_BYTES` | `1048576` | 1 MiB cap applied to both stdout and stderr. Stdout truncation sets `truncated: true`. |
| `LINUX_INFO_LOG_FILE` | `` (empty) | Absolute path to JSONL log file. Empty / unset = logging fully disabled. |
| `LINUX_INFO_LOG_LEVEL` | `INFO` | One of `TRACE`, `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Unknown values fall back to `INFO`. Only honored when `LINUX_INFO_LOG_FILE` is set. |

### Grep flag whitelist details
- Exact-match set: `-i`, `-E`, `-v`, `-n`, `-w`, `-F`.
- Context flag: `-C<N>` where `N` is a single digit `1`–`9`.

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
  server.py                  # entrypoint shim
  linux_info_mcp/
    __init__.py
    ssh.py                   # run_ssh + builders for the original 3 tools
    validate.py              # shared validators + whitelists
    server.py                # MCP server: collects ToolSpec lists from tools/* and registers
    tools/
      __init__.py
      files.py               # ToolSpec list: read_file, find_files, read_binary
      systemctl.py           # ToolSpec list: systemctl_status, systemctl_list
      journalctl.py          # ToolSpec list: journalctl
      perf.py                # ToolSpec list: iostat, vmstat, free, df, ps
      net.py                 # ToolSpec list: ss, ip_addr, ip_route, lsof_net
      proc.py                # ToolSpec list: lsof, pgrep, pidof, top
      disk.py                # ToolSpec list: du, lsblk, blkid, smartctl
      kernel.py              # ToolSpec list: dmesg, uname, sysctl
      pkg.py                 # ToolSpec list: dpkg_list, rpm_list, apt_list_installed
      sys.py                 # ToolSpec list: uptime, who, last, lscpu, lsmem, dmidecode
      time.py                # ToolSpec list: chronyc, timedatectl
      fs.py                  # ToolSpec list: mount, findmnt, stat_fs
      docker.py              # ToolSpec list: docker_ps, docker_inspect, docker_images
  tests/
    test_validate.py
    test_ssh.py
    test_server.py
    tools/
      test_systemctl.py
      test_journalctl.py
      test_perf.py
      test_net.py
      test_proc.py
      test_disk.py
      test_kernel.py
      test_pkg.py
      test_sys.py
      test_time.py
      test_fs.py
      test_docker.py
    conftest.py
  pyproject.toml
  README.md
  SPEC.md                    # this file
```

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

- `validate.py`: pure shared validators only — `validate_host`, `validate_path`, `validate_grep_flags`, `validate_grep_pattern`, `validate_find_args`, `validate_offset_length`, `binary_length_cap`, `validate_unit_name`, `validate_lines_int`, `_reject_unsafe_chars` (private). Tool-specific validators may live inside the tool module.
- `ssh.py`: `run_ssh(host, remote_cmd) -> SshResult`, plus the file-tool builders. Each tool module builds its own remote command string (calls `shlex.quote` itself) and uses `run_ssh` for execution.
- `server.py`: imports `TOOLS` from every `tools/*.py`, builds a single dispatch dict, registers MCP tools. Handlers are sync (they call blocking `subprocess.run` via `run_ssh`); `_call_tool` runs each via `await asyncio.to_thread(spec.handler, args)` so concurrent MCP `call_tool` requests truly parallelize instead of serializing on the event loop. ContextVar (`tool`, `request_id`) propagates into the worker thread because `asyncio.to_thread` snapshots and replays the current `contextvars.Context`.

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
| `linux_info_mcp.server` | INFO | `tool_call` | `tool`, `host`, `duration_ms`, `exit_code`, `outcome` (`ok` / `nonzero` / `validation_error` / `unknown_tool` / `handler_error`), `error` (only on `validation_error`) |
| `linux_info_mcp.server` | TRACE | `tool_call_out` | `tool`, `result` |
| `linux_info_mcp.ssh` | TRACE | `ssh_call_start` | `host`, `remote_cmd` |
| `linux_info_mcp.ssh` | INFO | `ssh_call` | `host`, `exit_code`, `duration_ms`, `stdout_bytes`, `stderr_bytes`, `truncated`, `outcome` (`ok` / `nonzero` / `timeout`) |
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
