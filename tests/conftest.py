from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from fluffy import Guard
from fluffy.db import connect, migrate
from fluffy.redact import RedactionFilter, clear_secret_stores, register_secret_store
from fluffy.secrets import MemorySecretStore


@pytest.fixture(autouse=True)
def _clean_redaction_state() -> Iterator[None]:
    """Backstop: keep the module-level store registry and root logger clean.

    ``Guard.close()`` undoes its own installs; this scrub catches anything a
    test registered directly or leaked on failure.
    """
    yield
    clear_secret_stores()
    root = logging.getLogger()
    for f in list(root.filters):
        if isinstance(f, RedactionFilter):
            root.removeFilter(f)
    for handler in root.handlers:
        for f in list(handler.filters):
            if isinstance(f, RedactionFilter):
                handler.removeFilter(f)


@pytest.fixture()
def guard(tmp_path: Path) -> Iterator[Guard]:
    with Guard(db_path=tmp_path / "state.db") as g:
        yield g


@pytest.fixture()
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    """An open, fully migrated state database."""
    c = connect(tmp_path / "state.db")
    migrate(c)
    yield c
    c.close()


@pytest.fixture()
def registered_store() -> MemorySecretStore:
    """An empty in-memory store registered with the global redaction registry."""
    store = MemorySecretStore()
    register_secret_store(store)
    return store
