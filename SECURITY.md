# Security Policy

## Supported Versions

Only the latest commit on `main` is supported. There are no point releases yet; fixes ship forward only.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Use one of:

- GitHub private vulnerability report: <https://github.com/ranglust/linux-info-mcp/security/advisories/new>

Include:

- Affected commit SHA or tag.
- Reproduction (input args, expected behavior, observed behavior).
- Impact assessment if you have one (RCE, command injection, info disclosure, sandbox escape, etc.).

You will get an initial acknowledgment within 5 business days. Coordinated disclosure preferred; please give us at least 30 days before public disclosure for non-critical issues, sooner if a fix has shipped.

## In Scope

- Command injection in any tool handler or builder (anywhere a remote command is constructed).
- Argument validation bypass (NUL/newline rejection, host allowlist, whitelist regexes). Multi-host `hosts` entries pass the same `validate_host` path per entry.
- SSH command argv construction (`shlex.split` of `LINUX_INFO_SSH_CMD`, host quoting).
- Multi-host fan-out: host-count cap bypass (`LINUX_INFO_MAX_HOSTS` / hard max 25, the SSH-storm guard) or ContextVar bleed across per-host worker threads.
- Privilege escalation (`LINUX_INFO_SUDO`): `sudo -n` reaching a binary outside the privilege-prone set, sudo applied via an unconstrainable shape (e.g. `sudo sh -c`), or the prefix being injectable. NOT in scope: an operator's own over-broad sudoers (`NOPASSWD: ALL`) — the privilege boundary is the sudoers file, which the operator owns. The server only emits `sudo -n <binary>` for the documented tool set when opted in.
- Logging-side issues (log injection, secret leakage in logs, ContextVar bleed across requests).
- Truncation/output-cap bypass that could mask injected payloads.
- Any path that lets a caller execute a write/mutate command on a remote host (this server is read-only by construction).

## Out of Scope

- SSH credential management — delegated to the user's `ssh` config and agent. The server never handles credentials.
- An operator's own over-broad sudoers when `LINUX_INFO_SUDO` is enabled (see In Scope). Privilege is the sudoers file's job.
- `privilege_error` detection accuracy — it is a best-effort stderr heuristic; false positives/negatives are not vulnerabilities.
- DoS via expensive but legitimate commands (e.g. `find` over `/`). Use `LINUX_INFO_TIMEOUT` and `LINUX_INFO_MAX_BYTES`.
- Issues requiring an attacker who already controls the MCP client process.
- Issues in upstream dependencies (`mcp` SDK, Python stdlib) — please report those upstream; we will pick up fixes via Dependabot.

## Logging and Secrets

When `LINUX_INFO_LOG_LEVEL=TRACE`, the server writes the **full remote command** plus the **full remote stdout and stderr** of every tool call to the JSONL log file. If the called tool happens to read sensitive data (e.g. `read_file /etc/shadow`, an environment dump, or a private key), that data lands in the log file, persists with whatever umask the file inherits, and is not rotated. Use TRACE only for short, targeted debugging sessions on machines you control, and prefer ephemeral log paths (`$TMPDIR/...`) over long-lived ones.

`tool_call_in` TRACE entries also record the full `arguments` object passed to the tool — keep that in mind if you later add a tool that accepts secret-shaped arguments.

INFO-level logging (the default) records sizes, durations, exit codes, and outcomes only — no payload bytes.

## Hardening Defaults

- All remote commands are constructed as a single `LC_ALL=C`-prefixed string with every interpolated value passed through `shlex.quote`.
- NUL and newline are rejected before quoting on every value that reaches the remote shell.
- Host names are rejected if they contain whitespace, start with `-`, or fail an allowlist set via `LINUX_INFO_HOSTS`.
- Whitelists are exact-match (set / dict membership) or fully anchored `re.fullmatch` regexes.
- Flag-injection-prone values (`--since=`, `--grep=`, etc.) use the equals-form so the value cannot be misparsed as a separate flag.
- `subprocess.run` uses `shell=False` for the local exec; only the remote command is interpreted by a shell, and only over a single shell-quoted string.

If you find a way around any of these, that is in scope.
