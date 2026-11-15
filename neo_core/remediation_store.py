"""Persistence for remediation items.

RemediationStore is the interface; SqliteStore is the local backend. A DynamoDB
backend can implement the same four methods without touching callers.
"""
from __future__ import annotations

import sqlite3
from typing import Protocol

from .remediation import RemediationItem, State


class RemediationStore(Protocol):
    def get_by_key(self, key: str) -> RemediationItem | None: ...
    def get(self, item_id: str) -> RemediationItem | None: ...
    def list(self, state: State | None = None) -> list[RemediationItem]: ...
    def save(self, item: RemediationItem, event: str = "") -> None: ...


class SqliteStore:
    def __init__(self, path: str = "neo_remediation.db"):
        # An MCP server may call from a different thread than the one that opened the store.
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS items (
                item_id TEXT PRIMARY KEY,
                key     TEXT UNIQUE NOT NULL,
                state   TEXT NOT NULL,
                body    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS history (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id TEXT NOT NULL,
                at      TEXT NOT NULL,
                state   TEXT NOT NULL,
                event   TEXT NOT NULL
            );
            """
        )

    def _load(self, row) -> RemediationItem | None:
        return RemediationItem.model_validate_json(row[0]) if row else None

    def get_by_key(self, key: str) -> RemediationItem | None:
        return self._load(self._db.execute("SELECT body FROM items WHERE key=?", (key,)).fetchone())

    def get(self, item_id: str) -> RemediationItem | None:
        return self._load(self._db.execute("SELECT body FROM items WHERE item_id=?", (item_id,)).fetchone())

    def list(self, state: State | None = None) -> list[RemediationItem]:
        if state is None:
            rows = self._db.execute("SELECT body FROM items ORDER BY item_id").fetchall()
        else:
            rows = self._db.execute("SELECT body FROM items WHERE state=? ORDER BY item_id",
                                    (state.value,)).fetchall()
        return [RemediationItem.model_validate_json(r[0]) for r in rows]

    def history(self, item_id: str) -> list[tuple[str, str, str]]:
        return self._db.execute(
            "SELECT at, state, event FROM history WHERE item_id=? ORDER BY id", (item_id,)
        ).fetchall()

    def save(self, item: RemediationItem, event: str = "") -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO items(item_id, key, state, body) VALUES(?,?,?,?) "
                "ON CONFLICT(item_id) DO UPDATE SET state=excluded.state, body=excluded.body",
                (item.item_id, item.key, item.state.value, item.model_dump_json()),
            )
            self._db.execute(
                "INSERT INTO history(item_id, at, state, event) VALUES(?,?,?,?)",
                (item.item_id, item.updated_at, item.state.value, event),
            )

    def close(self) -> None:
        self._db.close()
