import pytest

from linux_info_mcp.validate import (
    binary_length_cap,
    validate_find_args,
    validate_grep_flags,
    validate_grep_pattern,
    validate_host,
    validate_offset_length,
    validate_path,
)

# host


def test_host_basic():
    assert validate_host("server01.example.com") == "server01.example.com"


def test_host_rejects_empty():
    with pytest.raises(ValueError):
        validate_host("")


def test_host_rejects_leading_dash():
    with pytest.raises(ValueError):
        validate_host("-oProxyCommand=evil")


def test_host_rejects_whitespace():
    with pytest.raises(ValueError):
        validate_host("foo bar")


def test_host_rejects_newline():
    with pytest.raises(ValueError):
        validate_host("foo\nbar")


def test_host_rejects_nul():
    with pytest.raises(ValueError):
        validate_host("foo\x00bar")


def test_host_allowlist_accepts(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_HOSTS", "host1, host2 ,host3")
    assert validate_host("host2") == "host2"


def test_host_allowlist_rejects(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_HOSTS", "host1,host2")
    with pytest.raises(ValueError):
        validate_host("host3")


def test_host_empty_allowlist_allows_anything(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_HOSTS", "")
    assert validate_host("anything") == "anything"


# path


def test_path_basic():
    assert validate_path("/etc/hosts") == "/etc/hosts"


def test_path_rejects_newline():
    with pytest.raises(ValueError):
        validate_path("/etc/hosts\nfoo")


def test_path_rejects_nul():
    with pytest.raises(ValueError):
        validate_path("/etc/h\x00sts")


def test_path_rejects_empty():
    with pytest.raises(ValueError):
        validate_path("")


# grep


def test_grep_pattern_ok():
    assert validate_grep_pattern("foo.*bar") == "foo.*bar"


def test_grep_pattern_rejects_newline():
    with pytest.raises(ValueError):
        validate_grep_pattern("foo\nbar")


def test_grep_pattern_rejects_nul():
    with pytest.raises(ValueError):
        validate_grep_pattern("foo\x00bar")


def test_grep_flags_none():
    assert validate_grep_flags(None) == []


def test_grep_flags_basic_whitelist():
    assert validate_grep_flags(["-i", "-E", "-v", "-n", "-w", "-F"]) == [
        "-i",
        "-E",
        "-v",
        "-n",
        "-w",
        "-F",
    ]


def test_grep_flags_context():
    assert validate_grep_flags(["-C3"]) == ["-C3"]


def test_grep_flags_context_zero_rejected():
    with pytest.raises(ValueError):
        validate_grep_flags(["-C0"])


def test_grep_flags_context_double_digit_rejected():
    with pytest.raises(ValueError):
        validate_grep_flags(["-C10"])


def test_grep_flags_rejects_injection():
    with pytest.raises(ValueError):
        validate_grep_flags(["-e;rm"])


def test_grep_flags_rejects_unknown():
    with pytest.raises(ValueError):
        validate_grep_flags(["--color"])


def test_grep_flags_rejects_non_list():
    with pytest.raises(ValueError):
        validate_grep_flags("-i")


def test_grep_flags_rejects_non_string_entry():
    with pytest.raises(ValueError):
        validate_grep_flags([1])


# find


def test_find_empty():
    assert validate_find_args() == {}


def test_find_type_accepts_whitelist():
    for t in "fdlbcps":
        assert validate_find_args(type=t)["type"] == t


def test_find_type_rejects_other():
    with pytest.raises(ValueError):
        validate_find_args(type="x")


def test_find_type_rejects_compound():
    with pytest.raises(ValueError):
        validate_find_args(type="f -exec rm")


def test_find_depth_ok():
    out = validate_find_args(maxdepth=3, mindepth=0)
    assert out == {"maxdepth": 3, "mindepth": 0}


def test_find_depth_negative():
    with pytest.raises(ValueError):
        validate_find_args(maxdepth=-1)


def test_find_depth_bool_rejected():
    with pytest.raises(ValueError):
        validate_find_args(maxdepth=True)


def test_find_mtime_ok():
    assert validate_find_args(mtime="-7")["mtime"] == "-7"
    assert validate_find_args(mtime="+30")["mtime"] == "+30"
    assert validate_find_args(mtime="0")["mtime"] == "0"


def test_find_mtime_rejects():
    for bad in ("abc", "1d", "1.5", "-", "++1"):
        with pytest.raises(ValueError):
            validate_find_args(mtime=bad)


def test_find_size_ok():
    for s in ("100", "+1k", "-200c", "5M", "+2G"):
        assert validate_find_args(size=s)["size"] == s


def test_find_size_rejects():
    for bad in ("1X", "abc", "1k2", "-", ""):
        with pytest.raises(ValueError):
            validate_find_args(size=bad)


def test_find_name_rejects_newline():
    with pytest.raises(ValueError):
        validate_find_args(name="foo\nbar")


def test_find_name_rejects_nul():
    with pytest.raises(ValueError):
        validate_find_args(iname="foo\x00")


def test_find_path_glob_rejects_newline():
    with pytest.raises(ValueError):
        validate_find_args(path_glob="*\n*")


# offset/length


def test_offset_length_ok():
    assert validate_offset_length(0, 100, 1024) == (0, 100)


def test_offset_negative():
    with pytest.raises(ValueError):
        validate_offset_length(-1, 10, 1024)


def test_length_zero():
    with pytest.raises(ValueError):
        validate_offset_length(0, 0, 1024)


def test_length_negative():
    with pytest.raises(ValueError):
        validate_offset_length(0, -5, 1024)


def test_length_oversized():
    with pytest.raises(ValueError):
        validate_offset_length(0, 2000, 1024)


def test_offset_bool_rejected():
    with pytest.raises(ValueError):
        validate_offset_length(True, 10, 1024)


def test_binary_length_cap_formula():
    # base64(N) = ceil(N/3)*4. Cap leaves 64 bytes margin for newlines/etc.
    assert binary_length_cap(1024) == (1024 - 64) * 3 // 4
    assert binary_length_cap(1024 * 1024) == (1024 * 1024 - 64) * 3 // 4


def test_length_at_cap_accepted():
    cap = binary_length_cap(1024)
    assert validate_offset_length(0, cap, 1024) == (0, cap)


def test_length_above_cap_rejected_even_below_max_bytes():
    cap = binary_length_cap(1024)
    with pytest.raises(ValueError):
        validate_offset_length(0, cap + 1, 1024)


def test_length_at_max_bytes_rejected_when_above_cap():
    # max_bytes=1024 → cap=720. length=1024 > 720, so reject.
    with pytest.raises(ValueError):
        validate_offset_length(0, 1024, 1024)
