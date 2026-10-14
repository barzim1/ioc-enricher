"""Prosty cache SQLite z TTL. Oszczędza limity API (VT free: 4 zapytania/min, 500/dzień)."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Callable, Optional


class Cache:
    def __init__(self, path: str, ttl_seconds: int = 24 * 3600,
                 clock: Callable[[], float] = time.time):
        self.ttl = ttl_seconds
        self._clock = clock
        if path != ":memory:":
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
            path = str(Path(path).expanduser())
        self._db = sqlite3.connect(path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS cache ("
            "key TEXT PRIMARY KEY, payload TEXT NOT NULL, stored_at REAL NOT NULL)"
        )
        self._db.commit()

    @staticmethod
    def make_key(provider: str, ioc_type: str, value: str) -> str:
        return f"{provider}|{ioc_type}|{value}"

    def get(self, key: str) -> Optional[dict]:
        row = self._db.execute(
            "SELECT payload, stored_at FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        payload, stored_at = row
        if self._clock() - stored_at > self.ttl:
            self._db.execute("DELETE FROM cache WHERE key = ?", (key,))
            self._db.commit()
            return None
        return json.loads(payload)

    def put(self, key: str, value: dict) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO cache (key, payload, stored_at) VALUES (?, ?, ?)",
            (key, json.dumps(value), self._clock()),
        )
        self._db.commit()

    def purge_expired(self) -> int:
        cur = self._db.execute(
            "DELETE FROM cache WHERE ? - stored_at > ?", (self._clock(), self.ttl)
        )
        self._db.commit()
        return cur.rowcount

    def close(self) -> None:
        self._db.close()
