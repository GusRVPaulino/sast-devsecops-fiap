"""Engine e sessões do banco."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from sentinela.config import get_settings
from sentinela.storage.models import Base


@cache
def get_engine(url: str | None = None) -> Engine:
    url = url or get_settings().database_url
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


@cache
def _session_factory(url: str | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(url), expire_on_commit=False)


@contextmanager
def session_scope(url: str | None = None) -> Iterator[Session]:
    session = _session_factory(url)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def create_all(url: str | None = None) -> None:
    """Usado em testes e no modo SQLite de desenvolvimento; produção usa Alembic."""

    Base.metadata.create_all(get_engine(url))


def reset_caches() -> None:
    get_engine.cache_clear()
    _session_factory.cache_clear()
