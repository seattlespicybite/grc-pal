"""Shared test settings."""
import pytest


@pytest.fixture(autouse=True)
def _no_update_check(monkeypatch):
    """Tests never call GitHub: the Updates page release list is off unless a test turns it on."""
    monkeypatch.setenv("GRCPAL_UPDATE_CHECK", "off")
