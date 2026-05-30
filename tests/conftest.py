import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("LINUX_INFO_HOSTS", "LINUX_INFO_SSH_CMD", "LINUX_INFO_TIMEOUT", "LINUX_INFO_MAX_BYTES"):
        monkeypatch.delenv(var, raising=False)
    yield
