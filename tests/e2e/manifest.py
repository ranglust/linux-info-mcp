"""Universal safe args per tool for live snapshot capture (e2e layer 3).

Values chosen to succeed on stock Linux without per-host config. Tools needing
host-specific targets (docker_inspect/_logs, smartctl, dmidecode-without-root)
get best-effort placeholders; absent targets yield an error baseline, which the
compare step still matches as "both error consistently".

Each entry maps tool name -> list of arg-sets (host injected at capture time).
Tools not listed are captured with default args ({}).
"""

from __future__ import annotations

TOOL_ARGS: dict[str, list[dict]] = {
    # files
    "read_file": [{"path": "/etc/hostname"}],
    "read_binary": [{"path": "/etc/hostname", "offset": 0, "length": 16}],
    "find_files": [{"path": "/etc", "name": "*.conf", "maxdepth": 1}],
    # systemd
    "systemctl_status": [{"unit": "systemd-journald.service"}],
    "systemctl_list": [{}],
    "journalctl": [{"lines": 50}],
    # perf
    "df": [{}],
    "ps": [{}],
    # net
    # proc
    "pgrep": [{"pattern": "systemd"}],
    "pidof": [{"program": "systemd"}],
    # disk
    "du": [{"path": "/etc", "summary": True}],
    "smartctl": [{"device": "/dev/sda", "mode": "info"}],
    # kernel
    "dmesg": [{"tail_lines": 50}],
    "uname": [{"mode": "all"}],
    "sysctl": [{"key": "kernel.hostname"}],
    # sys
    "last": [{"lines": 20}],
    "dmidecode": [{"type": "system"}],
    # time
    "chronyc": [{"subcommand": "tracking"}],
    "timedatectl": [{"mode": "status"}],
    # fs
    "stat_fs": [{"path": "/"}],
    # proc
    "proc_limits": [{"pid": 1}],
    # net: ethtool requires iface; eth0 is best-effort (error baseline on hosts
    # without eth0, which is fine — both sides will error consistently).
    "ethtool": [{"iface": "eth0"}],
    # kernel: cgroup_path is relative to /sys/fs/cgroup; system.slice is always
    # present on systemd hosts.
    "cgroup_stats": [{"cgroup_path": "system.slice"}],
    # docker: capture_samples resolves these to the first real container
    # (alphabetical) via docker_ps -q; these placeholders are the fallback when
    # the host has no docker / no containers (error baseline).
    "docker_inspect": [{"targets": ["e2e-nonexistent"]}],
    "docker_logs": [{"container": "e2e-nonexistent", "tail": 50}],
}
