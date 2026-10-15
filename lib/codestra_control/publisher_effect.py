"""Durable fail-closed publication intents; no automatic recovery or retry."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import stat

class IntentLedger:
    def __init__(self, path):
        self.path=Path(path)
        parent=self.path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise ValueError('UNTRUSTED_LEDGER_DIRECTORY')
        fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600) if not self.path.exists() else None
        if fd is not None:os.close(fd)
        self._validate()
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS intents (key TEXT PRIMARY KEY, authority TEXT NOT NULL, state TEXT NOT NULL, receipts TEXT NOT NULL)')
    def _validate(self):
        for path in (self.path,*(Path(str(self.path)+suffix) for suffix in ('-journal','-wal','-shm'))):
            try:info=path.lstat()
            except FileNotFoundError:continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid() or info.st_mode & 0o077:
                raise ValueError('UNTRUSTED_LEDGER_FILE')
    @contextmanager
    def _db(self):
        self._validate()
        db=sqlite3.connect(self.path,timeout=5)
        try:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback();raise
        finally:db.close()
    def reserve(self,key,authority):
        with self._db() as db:
            try:db.execute('INSERT INTO intents VALUES (?,?,?,?)',(key,authority,'RESERVED','[]'))
            except sqlite3.IntegrityError:return False
        return True
    def record(self,key,state,receipts):
        if state not in ('COMPLETE','PARTIAL','UNCERTAIN','REJECTED'):raise ValueError('INVALID_INTENT_STATE')
        with self._db() as db:
            cursor=db.execute('UPDATE intents SET state=?,receipts=? WHERE key=? AND state IN (?,?)',
                              (state,json.dumps(receipts),key,'RESERVED','PARTIAL'))
            if cursor.rowcount!=1:raise ValueError('INTENT_NOT_RESERVED')
