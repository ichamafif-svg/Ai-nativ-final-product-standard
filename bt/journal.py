"""T04 — the durable prefix, and the pins that make it rollback-resistant (ARCHITECTURE.md §8.2, F0-10).

The journal is a SQLite file. Every write is judged by the kernel, checked by the independent checker (T05), then
pinned in a separate pin store BEFORE it is committed: a crash between the two leaves a pin ahead of the journal,
whose exact entry is kept beside the pin and restored by `recover_tail`, never forgotten authority.

The pin store must live in a restoration domain independent of the journal; two files on one restorable volume are
not independent (L-04). One writer per journal (D06): the SQLite write lock orders admission, pin-before-commit and
departure on one host; nothing here is a multi-host consensus.
"""
from __future__ import annotations

import copy
import hashlib
import os
import sqlite3
import threading
from contextlib import closing, contextmanager
from pathlib import Path

from kernel import Kernel, Refused, apply, canon, empty, parse

from .checker import Checker, Disagreement

DIGEST_PREFIX = "sha256:"


class Halted(Exception):
    """A persistent stop: two independent mechanisms disagreed. Only an operator clears it, outside the system."""


def raw_digest(raw: bytes) -> str:
    return DIGEST_PREFIX + hashlib.sha256(raw).hexdigest()


def _sqlite(path: Path, *, create: bool):
    if create:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    elif not path.is_file():
        raise FileNotFoundError(f"{path} must exist: a durable store is never silently recreated")
    db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=30, isolation_level=None)
    db.execute("PRAGMA synchronous=FULL")
    return db


class PinStore:
    """Monotonic pins, the exact entry behind the highest pin, the genesis binding and the halt flag."""

    def __init__(self, path, *, create: bool = False):
        self.path = Path(path).resolve()
        if create:
            with closing(_sqlite(self.path, create=True)) as db:
                db.executescript("CREATE TABLE pins (size INTEGER PRIMARY KEY, head TEXT NOT NULL);"
                                 "CREATE TABLE tail (size INTEGER PRIMARY KEY, raw BLOB NOT NULL);"
                                 "CREATE TABLE domain (genesis TEXT NOT NULL);"
                                 "CREATE TABLE halt (reason TEXT NOT NULL);")
        else:
            _sqlite(self.path, create=False).close()

    def _db(self):
        return _sqlite(self.path, create=False)

    def bind(self, genesis: str) -> None:
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT genesis FROM domain").fetchone()
            if row and row[0] != genesis:
                db.rollback()
                raise ValueError("this pin store belongs to another ledger")
            if not row:
                db.execute("INSERT INTO domain VALUES (?)", (genesis,))
            db.commit()

    def genesis(self):
        with closing(self._db()) as db:
            row = db.execute("SELECT genesis FROM domain").fetchone()
        return row[0] if row else None

    def pin(self):
        with closing(self._db()) as db:
            row = db.execute("SELECT size, head FROM pins ORDER BY size DESC LIMIT 1").fetchone()
        return {"size": row[0], "head": row[1]} if row else None

    def keep_then_pin(self, size: int, raw: bytes) -> None:
        """Keep the exact entry, then pin it. Pins only move forward; a different head at the same size is a fork."""
        head = raw_digest(raw)
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT size, head FROM pins ORDER BY size DESC LIMIT 1").fetchone()
                if row and (size < row[0] or (size == row[0] and head != row[1])):
                    raise ValueError("pin regression or fork")
                db.execute("DELETE FROM tail")
                db.execute("INSERT INTO tail VALUES (?, ?)", (size, raw))
                if not row or size > row[0]:
                    db.execute("INSERT INTO pins VALUES (?, ?)", (size, head))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def tail(self):
        with closing(self._db()) as db:
            row = db.execute("SELECT size, raw FROM tail ORDER BY size DESC LIMIT 1").fetchone()
        return (row[0], bytes(row[1])) if row else None

    def halt(self, reason: str) -> None:
        with closing(self._db()) as db:
            db.execute("INSERT INTO halt VALUES (?)", (str(reason)[:500],))

    def halted(self):
        with closing(self._db()) as db:
            row = db.execute("SELECT reason FROM halt LIMIT 1").fetchone()
        return row[0] if row else None


class Journal:
    """The only path to durable admission. `transact(builder)` judges, checks, pins and commits one entry."""

    def __init__(self, path, kernel: Kernel, pins: PinStore, genesis_pin: str, *, create: bool = False):
        self.path = Path(path).resolve()
        if self.path == pins.path:
            raise ValueError("the pins must be retained apart from the journal")
        if not isinstance(genesis_pin, str) or not genesis_pin.startswith(DIGEST_PREFIX):
            raise ValueError("an externally supplied genesis pin is required")
        self.kernel, self.pins, self.genesis_pin = kernel, pins, genesis_pin
        self.checker = Checker()
        self._lock = threading.RLock()
        self.state, self.heads = empty(), []
        if create:
            with closing(_sqlite(self.path, create=True)) as db:
                db.executescript("CREATE TABLE entries (seq INTEGER PRIMARY KEY, raw BLOB NOT NULL);"
                                 "CREATE TABLE reservations (token TEXT PRIMARY KEY, seq INTEGER NOT NULL);")
        pins.bind(genesis_pin)

    def _db(self):
        return _sqlite(self.path, create=False)

    # ---- judgment with the independent check ----------------------------------------------------------------------
    def _halt(self, reason: str):
        self.pins.halt(reason)
        raise Halted(reason)

    def _judge(self, entry) -> tuple[dict, list]:
        record, delta = self.kernel.decide(self.state, entry)
        law = self.kernel.law_by_digest(record["law"])
        try:
            self.checker.check(self.state, record, copy.deepcopy(delta), entry, law.raw, law.digest)
        except Disagreement as exc:
            self._halt(f"independent check: {exc}")
        return record, delta

    def _sync(self, db, *, check_pin: bool = True) -> None:
        """Absorb unseen rows, rejudged; verify the genesis and the pin. Any doubt stops."""
        reason = self.pins.halted()
        if reason:
            raise Halted(reason)
        n = len(self.heads)
        rows = db.execute("SELECT seq, raw FROM entries WHERE seq >= ? ORDER BY seq", (max(n - 1, 0),)).fetchall()
        if n and (not rows or rows[0][0] != n - 1 or raw_digest(rows[0][1]) != self.heads[-1]):
            self.state, self.heads = empty(), []          # the verified tip changed: replay everything
            rows = db.execute("SELECT seq, raw FROM entries ORDER BY seq").fetchall()
        elif n:
            rows = rows[1:]
        for seq, raw in rows:
            if seq != len(self.heads):
                raise Refused("HIST.CHAIN", "the journal has a gap")
            record, delta = self._judge(parse(bytes(raw)))
            apply(self.state, delta)
            self.heads.append(self.state["head"])
        if self.heads and self.state["domain"] != self.genesis_pin:
            raise Refused("HIST.GENESIS", "the journal is not the externally pinned genesis")
        if check_pin and self.heads:
            pin = self.pins.pin()
            if pin is None or pin["size"] < len(self.heads):
                raise Refused("HIST.PIN", "the journal is ahead of its pin")
            if pin["size"] > len(self.heads):
                raise Refused("HIST.ROLLBACK", "the pin is ahead of the journal: recover the tail or stop")
            if pin["head"] != self.heads[-1]:
                raise Refused("HIST.ROLLBACK", "the journal differs from its pin")

    # ---- reads ------------------------------------------------------------------------------------------------------
    def snapshot(self) -> dict:
        """A detached copy of the verified state; mutating it changes nothing."""
        with self._lock, closing(self._db()) as db:
            db.execute("BEGIN")
            try:
                self._sync(db)
            finally:
                db.rollback()
            return copy.deepcopy(self.state)

    def entries(self) -> list:
        with closing(self._db()) as db:
            return [parse(bytes(raw)) for (raw,) in db.execute("SELECT raw FROM entries ORDER BY seq")]

    # ---- writes -----------------------------------------------------------------------------------------------------
    def transact(self, builder) -> tuple[dict, dict]:
        """Build one entry against the current state, judge it, check it, pin it, commit it. Returns (entry, record)."""
        with self._lock, closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._sync(db)
                entry = builder(copy.deepcopy(self.state))
                record, delta = self._judge(entry)
                raw = canon(entry)
                genesis = self.state["domain"] or next(op[2] for op in delta if op[:2] == ("set", "domain"))
                if genesis != self.genesis_pin:
                    raise Refused("HIST.GENESIS", "the entry is not of the externally pinned genesis")
                db.execute("INSERT INTO entries VALUES (?, ?)", (self.state["size"], raw))
                if record["kind"] == "reservation":
                    try:
                        db.execute("INSERT INTO reservations VALUES (?, ?)", (record["body"]["token"], self.state["size"]))
                    except sqlite3.IntegrityError:
                        self._halt("a token was reserved twice")
                self.pins.keep_then_pin(self.state["size"] + 1, raw)        # pin FIRST, under the write lock
                db.commit()
            except BaseException:
                db.rollback()
                raise
            apply(self.state, delta)
            self.heads.append(self.state["head"])
            return entry, record

    def append(self, entry) -> dict:
        return self.transact(lambda _state: entry)[1]

    @contextmanager
    def effect_gate(self):
        """Hold the write lock: no restriction can be acknowledged between re-judging and the first byte leaving."""
        with self._lock, closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._sync(db)
                yield copy.deepcopy(self.state)
            finally:
                db.rollback()

    def recover_tail(self) -> dict:
        """Restore exactly the entry kept beside a pin that is one ahead of the journal (crash between pin and commit)."""
        with self._lock, closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._sync(db, check_pin=False)
                pin, kept = self.pins.pin(), self.pins.tail()
                size = len(self.heads)
                if pin is None or pin["size"] != size + 1 or kept is None or kept[0] != size + 1 \
                        or raw_digest(kept[1]) != pin["head"]:
                    raise Refused("HIST.PIN", "no kept entry for a pin exactly one ahead")
                entry = parse(kept[1])
                record, delta = self._judge(entry)
                db.execute("INSERT INTO entries VALUES (?, ?)", (size, kept[1]))
                if record["kind"] == "reservation":
                    db.execute("INSERT INTO reservations VALUES (?, ?)", (record["body"]["token"], size))
                db.commit()
            except BaseException:
                db.rollback()
                raise
            apply(self.state, delta)
            self.heads.append(self.state["head"])
            return copy.deepcopy(self.state)
