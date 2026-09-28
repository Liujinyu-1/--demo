from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    winner_count INTEGER NOT NULL CHECK(winner_count > 0),
    status TEXT NOT NULL DEFAULT 'REGISTRATION',
    rule_json TEXT NOT NULL,
    rule_hash TEXT NOT NULL,
    beacon_round INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    closed_at TEXT,
    frozen_at TEXT,
    merkle_root TEXT,
    manifest_hash TEXT,
    beacon_json TEXT,
    seed TEXT,
    drawn_at TEXT
);

CREATE TABLE IF NOT EXISTS participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_db_id INTEGER NOT NULL REFERENCES batches(id),
    lottery_no TEXT NOT NULL,
    name TEXT NOT NULL,
    id_number TEXT NOT NULL,
    contact TEXT NOT NULL,
    salt TEXT NOT NULL,
    commitment TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    registered_at TEXT NOT NULL,
    reviewed_at TEXT,
    leaf_hash TEXT,
    score TEXT,
    rank INTEGER,
    is_winner INTEGER NOT NULL DEFAULT 0,
    UNIQUE(batch_db_id, lottery_no),
    UNIQUE(batch_db_id, id_number)
);

CREATE TABLE IF NOT EXISTS ledger_blocks (
    height INTEGER PRIMARY KEY,
    previous_hash TEXT NOT NULL,
    tx_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    block_hash TEXT NOT NULL UNIQUE,
    batch_id TEXT,
    stage TEXT NOT NULL DEFAULT 'LEGACY',
    data_hash TEXT,
    state_hash TEXT,
    business_previous_hash TEXT
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_database(path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        conn.executescript(SCHEMA)
        # 兼容旧版数据库：新增字段不破坏已经存在的V1哈希链记录。
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(ledger_blocks)")
        }
        migrations = {
            "batch_id": "ALTER TABLE ledger_blocks ADD COLUMN batch_id TEXT",
            "stage": (
                "ALTER TABLE ledger_blocks "
                "ADD COLUMN stage TEXT NOT NULL DEFAULT 'LEGACY'"
            ),
            "data_hash": "ALTER TABLE ledger_blocks ADD COLUMN data_hash TEXT",
            "state_hash": "ALTER TABLE ledger_blocks ADD COLUMN state_hash TEXT",
            "business_previous_hash": (
                "ALTER TABLE ledger_blocks ADD COLUMN business_previous_hash TEXT"
            ),
        }
        for column, statement in migrations.items():
            if column not in columns:
                conn.execute(statement)
