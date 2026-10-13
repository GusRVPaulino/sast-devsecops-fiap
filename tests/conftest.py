"""Fixtures compartilhadas: banco SQLite isolado por teste e IA desligada."""

from __future__ import annotations

import pytest

from sentinela.config import get_settings
from sentinela.storage import db


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELA_DATABASE_URL", f"sqlite:///{tmp_path / 'teste.db'}")
    monkeypatch.setenv("SENTINELA_EXECUTION_MODE", "inline")
    monkeypatch.setenv("SENTINELA_AI_ENABLED", "false")
    get_settings.cache_clear()
    db.reset_caches()
    db.create_all()
    yield
    get_settings.cache_clear()
    db.reset_caches()


@pytest.fixture
def client(database):
    from fastapi.testclient import TestClient

    from sentinela.api.app import app

    return TestClient(app)
