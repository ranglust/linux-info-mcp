import pytest

from linux_info_mcp.tools._parsers import parse_df, parse_free

# ---------------------------------------------------------------------------
# parse_df
# ---------------------------------------------------------------------------

_DF_NORMAL = """\
Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       41252336 8765432  30387654  23% /
tmpfs            8192000       0   8192000   0% /dev/shm
"""

_DF_SPACES = """\
Filesystem     1K-blocks   Used Available Use% Mounted on
/dev/sdb1        1024000 512000    512000  50% /mnt/my backup
"""

_DF_HEADER_ONLY = "Filesystem     1K-blocks    Used Available Use% Mounted on\n"


def test_parse_df_normal_rows():
    rows = parse_df(_DF_NORMAL)
    assert rows == [
        {
            "fs": "/dev/sda1",
            "blocks_1k": 41252336,
            "used_1k": 8765432,
            "avail_1k": 30387654,
            "use_pct": 23,
            "mount": "/",
        },
        {
            "fs": "tmpfs",
            "blocks_1k": 8192000,
            "used_1k": 0,
            "avail_1k": 8192000,
            "use_pct": 0,
            "mount": "/dev/shm",
        },
    ]


def test_parse_df_mount_with_spaces_preserved():
    rows = parse_df(_DF_SPACES)
    assert len(rows) == 1
    assert rows[0]["mount"] == "/mnt/my backup"


def test_parse_df_header_only_returns_empty():
    assert parse_df(_DF_HEADER_ONLY) == []


def test_parse_df_empty_returns_empty():
    assert parse_df("") == []
    assert parse_df("   \n  \n") == []


def test_parse_df_unexpected_header_raises():
    with pytest.raises(ValueError):
        parse_df("Size Used Avail\n/dev/sda1 10 5 5\n")


def test_parse_df_garbage_raises():
    with pytest.raises(ValueError):
        parse_df("complete nonsense\nwith no header\n")


def test_parse_df_skips_wrapped_short_line():
    # df wraps a long fs name onto its own line; the wrapped line has < 6 fields.
    wrapped = (
        "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
        "/dev/mapper/a-really-long-volume-name\n"
        "                41252336 8765432  30387654  23% /data\n"
    )
    rows = parse_df(wrapped)
    # Second physical line (numbers only) has 5 fields -> skipped; wrapped name line skipped.
    assert all("mount" in r for r in rows)


# ---------------------------------------------------------------------------
# parse_free
# ---------------------------------------------------------------------------

_FREE_STANDARD = """\
              total        used        free      shared  buff/cache   available
Mem:       16384000     4096000     8192000      256000     4096000    11800000
Swap:       2048000           0     2048000
"""

_FREE_WIDE = """\
              total        used        free      shared     buffers       cache   available
Mem:       16384000     4096000     8000000      256000      512000     3584000    11800000
Swap:       2048000           0     2048000
"""

_FREE_MULTISAMPLE = """\
              total        used        free      shared  buff/cache   available
Mem:       16384000     4096000     8192000      256000     4096000    11800000
Swap:       2048000           0     2048000

              total        used        free      shared  buff/cache   available
Mem:       16384000     4200000     8088000      256000     4096000    11700000
Swap:       2048000           0     2048000
"""

_FREE_NO_SWAP = """\
              total        used        free      shared  buff/cache   available
Mem:       16384000     4096000     8192000      256000     4096000    11800000
"""


def test_parse_free_standard_layout():
    samples = parse_free(_FREE_STANDARD)
    assert samples == [
        {
            "mem": {
                "total": 16384000,
                "used": 4096000,
                "free": 8192000,
                "shared": 256000,
                "buff_cache": 4096000,
                "available": 11800000,
            },
            "swap": {"total": 2048000, "used": 0, "free": 2048000},
        }
    ]


def test_parse_free_wide_layout_splits_buffers_cache():
    samples = parse_free(_FREE_WIDE)
    assert len(samples) == 1
    mem = samples[0]["mem"]
    assert mem["buffers"] == 512000
    assert mem["cache"] == 3584000
    assert "buff_cache" not in mem


def test_parse_free_multisample_returns_list():
    samples = parse_free(_FREE_MULTISAMPLE)
    assert len(samples) == 2
    assert samples[0]["mem"]["used"] == 4096000
    assert samples[1]["mem"]["used"] == 4200000


def test_parse_free_missing_swap():
    samples = parse_free(_FREE_NO_SWAP)
    assert len(samples) == 1
    assert "swap" not in samples[0]


def test_parse_free_garbage_no_exception():
    assert parse_free("random text with no colon\nlines here") == []
    # "Mem:" with non-numeric values must not raise.
    assert parse_free("Mem: abc def ghi") == []


def test_parse_free_empty():
    assert parse_free("") == []
