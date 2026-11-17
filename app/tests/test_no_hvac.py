"""Guard: the lab talks to Vault only through Vault Proxy over the UNIX socket with the standard library.
No hvac (or any other Vault client library) in the code, the dependencies or the lockfile."""

from __future__ import annotations

import importlib.util
from pathlib import Path

APP = Path(__file__).resolve().parent.parent


def test_hvac_not_installed():
    assert importlib.util.find_spec("hvac") is None


def test_hvac_not_in_dependencies_or_lockfile():
    for name in ("pyproject.toml", "uv.lock"):
        assert "hvac" not in (APP / name).read_text().lower(), name


def test_hvac_not_imported_anywhere():
    for path in (APP / "src").rglob("*.py"):
        assert "hvac" not in path.read_text().lower(), path
