# Security Policy

## Supported Versions

Only the latest commit on `main` is supported. There are no point releases yet; fixes ship forward only.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Use one of:

- GitHub private vulnerability report: <https://github.com/ranglust/linux-info-mcp/security/advisories/new>
- Email: ronen.angluster@coinbase.com

Include:

- Affected commit SHA or tag.
- Reproduction (input args, expected behavior, observed behavior).
- Impact assessment if you have one (RCE, command injection, info disclosure, sandbox escape, etc.).

You will get an initial acknowledgment within 5 business days. Coordinated disclosure preferred; please give us at least 30 days before public disclosure for non-critical issues, sooner if a fix has shipped.

## In Scope

- Command injection in any tool handler or builder (anywhere a remote command is constructed).
- Argument validation bypass (NUL/newline rejection, host allowlist, whitelist regexes).
- SSH command argv construction (`shlex.split` of `LINUX_INFO_SSH_CMD`, host quoting).
- Logging-side issues (log injection, secret leakage in logs, ContextVar bleed across requests).
- Truncation/output-cap bypass that could mask injected payloads.
- Any path that lets a caller execute a write/mutate command on a remote host (this server is read-only by construction).

## Out of Scope

- SSH credential management — delegated to the user's `ssh` config and agent. The server never handles credentials.
- DoS via expensive but legitimate commands (e.g. `find` over `/`). Use `LINUX_INFO_TIMEOUT` and `LINUX_INFO_MAX_BYTES`.
- Issues requiring an attacker who already controls the MCP client process.
- Issues in upstream dependencies (`mcp` SDK, Python stdlib) — please report those upstream; we will pick up fixes via Dependabot.

## Hardening Defaults

- All remote commands are constructed as a single `LC_ALL=C`-prefixed string with every interpolated value passed through `shlex.quote`.
- NUL and newline are rejected before quoting on every value that reaches the remote shell.
- Host names are rejected if they contain whitespace, start with `-`, or fail an allowlist set via `LINUX_INFO_HOSTS`.
- Whitelists are exact-match (set / dict membership) or fully anchored `re.fullmatch` regexes.
- Flag-injection-prone values (`--since=`, `--grep=`, etc.) use the equals-form so the value cannot be misparsed as a separate flag.
- `subprocess.run` uses `shell=False` for the local exec; only the remote command is interpreted by a shell, and only over a single shell-quoted string.

If you find a way around any of these, that is in scope.
