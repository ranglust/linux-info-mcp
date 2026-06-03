"""Reference output parsers for tools that lack native JSON output."""

from __future__ import annotations

_DF_HEADER = ["Filesystem", "1K-blocks", "Used", "Available", "Use%"]


def parse_df(stdout: str) -> list[dict]:
    """Parse default df output (1K-blocks). Raises ValueError on unexpected header."""
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        return []
    if lines[0].split()[:5] != _DF_HEADER:
        raise ValueError(f"unexpected df header: {lines[0]!r}")
    out: list[dict] = []
    for line in lines[1:]:
        parts = line.split(maxsplit=5)  # mount may contain spaces
        if len(parts) < 6:
            continue
        try:
            row = {
                "fs": parts[0],
                "blocks_1k": int(parts[1]),
                "used_1k": int(parts[2]),
                "avail_1k": int(parts[3]),
                "use_pct": int(parts[4].rstrip("%")),
                "mount": parts[5].strip(),
            }
        except ValueError:
            continue
        out.append(row)
    return out


def _parse_mem(vals: list[str]) -> dict | None:
    try:
        if len(vals) >= 7:
            t, u, f, sh, bu, ca, av = (int(x) for x in vals[:7])
            return {
                "total": t,
                "used": u,
                "free": f,
                "shared": sh,
                "buffers": bu,
                "cache": ca,
                "available": av,
            }
        if len(vals) >= 6:
            t, u, f, sh, bc, av = (int(x) for x in vals[:6])
            return {
                "total": t,
                "used": u,
                "free": f,
                "shared": sh,
                "buff_cache": bc,
                "available": av,
            }
        if len(vals) >= 3:
            t, u, f = (int(x) for x in vals[:3])
            return {"total": t, "used": u, "free": f}
    except ValueError:
        return None
    return None


def _parse_swap(vals: list[str]) -> dict | None:
    try:
        if len(vals) >= 3:
            t, u, f = (int(x) for x in vals[:3])
            return {"total": t, "used": u, "free": f}
    except ValueError:
        return None
    return None


def parse_free(stdout: str) -> list[dict]:
    """Parse free (default/-b/-k/-m/-g/-w, single or -s/-c multi-sample).

    Returns one entry per sample: {"mem": {...}, "swap": {...}}. Human (-h) units
    are non-numeric and yield no parsed rows. Garbage never raises.
    """
    samples: list[dict] = []
    cur: dict | None = None
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        label, sep, rest = line.partition(":")
        if not sep:
            continue  # header row or junk (no colon)
        label = label.strip().lower()
        vals = rest.split()
        if label == "mem":
            mem = _parse_mem(vals)
            if mem is None:
                cur = None
                continue
            cur = {"mem": mem}
            samples.append(cur)
        elif label == "swap":
            swap = _parse_swap(vals)
            if swap is None:
                continue
            if cur is None:
                cur = {}
                samples.append(cur)
            cur["swap"] = swap
    return samples
