import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "LINUX_INFO_HOSTS",
        "LINUX_INFO_SSH_CMD",
        "LINUX_INFO_TIMEOUT",
        "LINUX_INFO_MAX_BYTES",
        "LINUX_INFO_LOG_FILE",
        "LINUX_INFO_LOG_LEVEL",
        "LINUX_INFO_MAX_HOSTS",
        "LINUX_INFO_PARALLELISM",
        "LINUX_INFO_SUDO",
    ):
        monkeypatch.delenv(var, raising=False)
    from linux_info_mcp.log import reset_for_tests

    reset_for_tests()
    yield
    reset_for_tests()
