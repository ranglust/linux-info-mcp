import pytest

from linux_info_mcp.validate import (
    HARD_MAX_HOSTS,
    binary_length_cap,
    effective_max_hosts,
    parallelism,
    resolve_target_hosts,
    validate_find_args,
    validate_grep_flags,
    validate_grep_pattern,
    validate_host,
    validate_host_list,
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


def test_path_rejects_leading_dash():
    with pytest.raises(ValueError):
        validate_path("-delete")


def test_path_rejects_leading_dash_predicate_form():
    with pytest.raises(ValueError):
        validate_path("-fls")


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


def test_binary_length_cap_property_encoded_size_fits_under_max():
    import base64

    for max_b in (256, 1024, 4096, 1024 * 1024):
        n = binary_length_cap(max_b)
        encoded = base64.b64encode(b"\x00" * n)
        assert len(encoded) <= max_b, (
            f"max_bytes={max_b} cap={n} produced encoded={len(encoded)} > {max_b}"
        )


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


# validate_int_in_range


def test_int_range_in_bounds():
    from linux_info_mcp.validate import validate_int_in_range

    assert validate_int_in_range(5, lo=1, hi=10) == 5
    assert validate_int_in_range(1, lo=1, hi=10) == 1
    assert validate_int_in_range(10, lo=1, hi=10) == 10


def test_int_range_below_lo():
    from linux_info_mcp.validate import validate_int_in_range

    with pytest.raises(ValueError):
        validate_int_in_range(0, lo=1, hi=10)


def test_int_range_above_hi():
    from linux_info_mcp.validate import validate_int_in_range

    with pytest.raises(ValueError):
        validate_int_in_range(11, lo=1, hi=10)


def test_int_range_rejects_bool():
    from linux_info_mcp.validate import validate_int_in_range

    with pytest.raises(ValueError):
        validate_int_in_range(True, lo=0, hi=10)


def test_int_range_rejects_str():
    from linux_info_mcp.validate import validate_int_in_range

    with pytest.raises(ValueError):
        validate_int_in_range("5", lo=0, hi=10)


# validate_unit_name


def test_unit_name_basic():
    from linux_info_mcp.validate import validate_unit_name

    assert validate_unit_name("nginx.service") == "nginx.service"
    assert validate_unit_name("getty@tty1.service") == "getty@tty1.service"


def test_unit_name_rejects_leading_dash():
    from linux_info_mcp.validate import validate_unit_name

    with pytest.raises(ValueError):
        validate_unit_name("-evil")


def test_unit_name_rejects_newline():
    from linux_info_mcp.validate import validate_unit_name

    with pytest.raises(ValueError):
        validate_unit_name("nginx\nrm")


def test_unit_name_rejects_too_long():
    from linux_info_mcp.validate import validate_unit_name

    with pytest.raises(ValueError):
        validate_unit_name("a" * 257)


def test_unit_name_rejects_disallowed_chars():
    from linux_info_mcp.validate import validate_unit_name

    with pytest.raises(ValueError):
        validate_unit_name("nginx;rm")


# reject_unsafe_chars


def test_reject_unsafe_chars_passes_clean():
    from linux_info_mcp.validate import reject_unsafe_chars

    reject_unsafe_chars("hello", "x")
    reject_unsafe_chars("a/b/c.txt", "path")


def test_reject_unsafe_chars_rejects_nul():
    from linux_info_mcp.validate import reject_unsafe_chars

    with pytest.raises(ValueError):
        reject_unsafe_chars("a\x00b", "x")


def test_reject_unsafe_chars_rejects_newline():
    from linux_info_mcp.validate import reject_unsafe_chars

    with pytest.raises(ValueError):
        reject_unsafe_chars("a\nb", "x")


def test_reject_unsafe_chars_rejects_carriage_return():
    from linux_info_mcp.validate import reject_unsafe_chars

    with pytest.raises(ValueError):
        reject_unsafe_chars("a\rb", "x")


# ---------------------------------------------------------------------------
# validate_cgroup_path
# ---------------------------------------------------------------------------


def test_validate_cgroup_path_accepts_normal():
    from linux_info_mcp.validate import validate_cgroup_path

    assert validate_cgroup_path("system.slice/sshd.service") == "system.slice/sshd.service"


def test_validate_cgroup_path_accepts_simple():
    from linux_info_mcp.validate import validate_cgroup_path

    assert validate_cgroup_path("user.slice") == "user.slice"


def test_validate_cgroup_path_rejects_empty():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("")


def test_validate_cgroup_path_rejects_leading_slash():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("/system.slice")


def test_validate_cgroup_path_rejects_dotdot_segment():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("system.slice/../../etc/shadow")


def test_validate_cgroup_path_rejects_bare_dotdot():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("..")


def test_validate_cgroup_path_rejects_nul():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("system.slice\x00")


def test_validate_cgroup_path_rejects_newline():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("system.slice\nfoo")


def test_validate_cgroup_path_rejects_bad_char():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("system.slice/foo;rm -rf /")


def test_validate_cgroup_path_rejects_too_long():
    from linux_info_mcp.validate import validate_cgroup_path

    with pytest.raises(ValueError):
        validate_cgroup_path("a" * 1025)


# multi-host: effective_max_hosts / parallelism


def test_effective_max_hosts_default():
    assert effective_max_hosts() == 10


def test_effective_max_hosts_env_override(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_HOSTS", "7")
    assert effective_max_hosts() == 7


def test_effective_max_hosts_clamped_to_hard_max(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_HOSTS", "1000")
    assert effective_max_hosts() == HARD_MAX_HOSTS == 25


def test_effective_max_hosts_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_HOSTS", "notanint")
    assert effective_max_hosts() == 10


def test_effective_max_hosts_zero_falls_back(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_HOSTS", "0")
    assert effective_max_hosts() == 10


def test_parallelism_default():
    assert parallelism() == 4


def test_parallelism_env_override(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_PARALLELISM", "8")
    assert parallelism() == 8


def test_parallelism_clamped(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_PARALLELISM", "999")
    assert parallelism() == HARD_MAX_HOSTS


def test_parallelism_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_PARALLELISM", "x")
    assert parallelism() == 4


def test_parallelism_zero_falls_back(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_PARALLELISM", "0")
    assert parallelism() == 4


# multi-host: validate_host_list


def test_validate_host_list_basic():
    assert validate_host_list(["h1", "h2"]) == ["h1", "h2"]


def test_validate_host_list_dedupes_preserving_order():
    assert validate_host_list(["h1", "h2", "h1", "h3"]) == ["h1", "h2", "h3"]


def test_validate_host_list_rejects_non_list():
    with pytest.raises(ValueError):
        validate_host_list("h1")


def test_validate_host_list_rejects_empty():
    with pytest.raises(ValueError):
        validate_host_list([])


def test_validate_host_list_rejects_over_limit():
    with pytest.raises(ValueError):
        validate_host_list([f"h{i}" for i in range(11)])


def test_validate_host_list_respects_env_limit(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_HOSTS", "2")
    with pytest.raises(ValueError):
        validate_host_list(["h1", "h2", "h3"])


def test_validate_host_list_hard_max_enforced(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_MAX_HOSTS", "100")
    with pytest.raises(ValueError):
        validate_host_list([f"h{i}" for i in range(26)])


def test_validate_host_list_rejects_injection_host():
    with pytest.raises(ValueError):
        validate_host_list(["h1", "-oProxyCommand=evil"])


def test_validate_host_list_rejects_newline_host():
    with pytest.raises(ValueError):
        validate_host_list(["h1", "h2\nrm -rf /"])


def test_validate_host_list_honors_allowlist(monkeypatch):
    monkeypatch.setenv("LINUX_INFO_HOSTS", "h1,h2")
    with pytest.raises(ValueError):
        validate_host_list(["h1", "h3"])


# multi-host: resolve_target_hosts


def test_resolve_single_host():
    assert resolve_target_hosts({"host": "h1"}) == (["h1"], False)


def test_resolve_multi_hosts():
    assert resolve_target_hosts({"hosts": ["h1", "h2"]}) == (["h1", "h2"], True)


def test_resolve_rejects_both():
    with pytest.raises(ValueError):
        resolve_target_hosts({"host": "h1", "hosts": ["h2"]})


def test_resolve_rejects_neither():
    with pytest.raises(ValueError):
        resolve_target_hosts({"path": "/x"})


def test_resolve_single_validates_host():
    with pytest.raises(ValueError):
        resolve_target_hosts({"host": "-oProxyCommand=evil"})
