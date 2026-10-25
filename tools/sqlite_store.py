# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Transactional local journal; independent connections serialize reservations."""
import json
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from tools.clock import SimClock, ClockMode
from tools.idempotency import CallClaim, CompletedCall, IdempotencyRecord, IdempotencyInProgress


class SQLiteStore:
    def __init__(self, path, *, clock=None):
        self.path = str(Path(path).resolve())
        self.clock = clock or SimClock(ClockMode.REAL)
        with self.transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS journal (key TEXT PRIMARY KEY, record TEXT NOT NULL, state TEXT NOT NULL, token TEXT, expires REAL, result TEXT, real_ts REAL, sim_ts REAL)')
            db.execute('CREATE TABLE IF NOT EXISTS decisions (key TEXT PRIMARY KEY, document TEXT NOT NULL)')

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _completed(self, row):
        return CompletedCall(IdempotencyRecord(**json.loads(row['record'])), json.loads(row['result']))

    def get(self, key):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM journal WHERE key=? AND state='done'", (key,)).fetchone()
            return self._completed(row) if row else None

    def reserve_once(self, record):
        stamp = self.clock.now()
        with self.transaction() as db:
            return db.execute("INSERT OR IGNORE INTO journal VALUES (?,?,'done',NULL,NULL,'null',?,?)",
                              (record.key, json.dumps(asdict(record)), stamp.real_ts, stamp.sim_ts)).rowcount == 1

    def acquire(self, record):
        with self.transaction() as db:
            stamp = self.clock.now()
            row = db.execute('SELECT * FROM journal WHERE key=?', (record.key,)).fetchone()
            if row and row['state'] == 'done':
                return CallClaim(record, False, existing=self._completed(row))
            if row and row['expires'] > stamp.real_ts:
                return CallClaim(record, False)
            token = uuid.uuid4().hex
            db.execute("INSERT OR REPLACE INTO journal VALUES (?,?,'claimed',?,?,NULL,?,?)",
                       (record.key, json.dumps(asdict(record)), token, stamp.real_ts + 600,
                        stamp.real_ts, stamp.sim_ts))
            return CallClaim(record, True, token)

    def complete(self, claim, completed):
        if not claim.acquired or not claim.token or claim.record != completed.record:
            raise IdempotencyInProgress('claim does not match completion')
        with self.transaction() as db:
            stamp = self.clock.now()
            changed = db.execute("UPDATE journal SET state='done',result=?,real_ts=?,sim_ts=? WHERE key=? AND state='claimed' AND token=? AND expires>?",
                                 (json.dumps(completed.result), stamp.real_ts, stamp.sim_ts,
                                  completed.key, claim.token, stamp.real_ts)).rowcount
            if changed != 1:
                raise IdempotencyInProgress('claim expired or no longer owned')

    def abandon(self, claim):
        if claim.acquired:
            with self.transaction() as db:
                db.execute("DELETE FROM journal WHERE key=? AND state='claimed' AND token=?",
                           (claim.record.key, claim.token))

    def put(self, completed):
        claim = self.acquire(completed.record)
        if claim.existing is not None:
            return
        self.complete(claim, completed)

    def record_suggestion(self, key, document):
        stamp = self.clock.now()
        document = {**document, 'real_ts': stamp.real_ts, 'sim_ts': stamp.sim_ts}
        with self.transaction() as db:
            db.execute('INSERT OR IGNORE INTO decisions VALUES (?,?)', (key, json.dumps(document)))

    def snapshot(self):
        with self.transaction() as db:
            rows = db.execute('SELECT document FROM decisions ORDER BY rowid DESC LIMIT 60').fetchall()
        return {'decisions': [json.loads(row[0]) for row in rows], 'counts': {},
                'scans': [], 'human_queue': []}


class TransactionJournal(SQLiteStore):
    """The journal, inside a transaction someone else opened and will end.

    Every read and write runs on `conn` with no BEGIN, COMMIT or ROLLBACK of
    its own: the owner of the transaction commits the journal together with
    whatever else it wrote, or rolls all of it back. `conn` must have the
    journal's file attached, and exactly one attached file may hold a
    `journal` table, because the statements name it unqualified.
    """

    def __init__(self, conn, *, clock=None):
        self.path = None
        self.clock = clock or SimClock(ClockMode.REAL)
        self._conn = conn

    @contextmanager
    def transaction(self):
        if not self._conn.in_transaction:
            # Outside its transaction a write would autocommit on its own.
            raise RuntimeError("the transaction this journal belongs to has ended")
        cursor = self._conn.cursor()
        cursor.row_factory = sqlite3.Row
        try:
            yield cursor
        finally:
            cursor.close()
