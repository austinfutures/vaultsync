"""SQLite state store. Holds file metadata, chunk index, peers, and sync log.

Encrypted chunk *bytes* live on disk under <vault>/blobs/; SQLite only stores
metadata and integrity hashes, so the DB stays small and fast.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    file_id       BLOB NOT NULL UNIQUE,
    nonce_prefix  BLOB NOT NULL,
    wrapped_fek   BLOB NOT NULL,
    plaintext_size INTEGER NOT NULL,
    plaintext_sha256 TEXT NOT NULL,
    chunk_count   INTEGER NOT NULL,
    chunk_size    INTEGER NOT NULL,
    owner_fp      TEXT NOT NULL,
    signature     BLOB NOT NULL,
    version       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chunks (
    file_row  INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    idx       INTEGER NOT NULL,
    size      INTEGER NOT NULL,
    sha256    TEXT NOT NULL,
    PRIMARY KEY (file_row, idx)
);

CREATE TABLE IF NOT EXISTS peers (
    fingerprint TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    card_json   TEXT NOT NULL,
    added_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sync_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_fp   TEXT NOT NULL,
    file_id   BLOB NOT NULL,
    chunks_sent INTEGER NOT NULL,
    at        TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class DB:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    @contextmanager
    def tx(self):
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def close(self) -> None:
        self.conn.close()