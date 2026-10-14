"""Where sessions and rate limits live (SESSION-*, ANTI-AUTOMATION). One interface, two stores:

    MemoryStore()                    one process: bounded, least-recently-used entries evicted first (never a reset)
    RedisStore("rediss://…")         several processes or hosts: atomic, expiring, the same keys

Keys are never secrets: a session id is stored by its SHA-256, so reading the store does not give a live session.
`from_env()` picks Redis when STANDARD_STORE_URL is set; in production a memory store with several workers is refused
(sessions and limits would differ from one worker to the next).
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import OrderedDict

MAX_ITEMS = 200_000


class StoreError(RuntimeError):
    pass


class MemoryStore:
    def __init__(self, max_items: int = MAX_ITEMS):
        self.lock, self.items, self.max = threading.RLock(), OrderedDict(), max_items

    def _live(self, key):
        item = self.items.get(key)
        if item is None:
            return None
        value, until = item
        if until is not None and until < time.time():
            del self.items[key]
            return None
        self.items.move_to_end(key)
        return value

    def _put(self, key, value, ttl):
        self.items[key] = (value, None if ttl is None else time.time() + ttl)
        self.items.move_to_end(key)
        while len(self.items) > self.max:
            self.items.popitem(last=False)

    def get(self, key: str):
        with self.lock:
            value = self._live(key)
            return None if value is None else json.loads(value)

    def set(self, key: str, value, ttl: float | None = None) -> None:
        with self.lock:
            self._put(key, json.dumps(value), ttl)

    def delete(self, key: str) -> None:
        with self.lock:
            self.items.pop(key, None)

    def add(self, key: str, member: str, ttl: float | None = None) -> None:
        with self.lock:
            members = set(json.loads(self._live(key) or "[]")) | {member}
            self._put(key, json.dumps(sorted(members)), ttl)

    def members(self, key: str) -> list:
        with self.lock:
            return json.loads(self._live(key) or "[]")

    def discard(self, key: str, member: str) -> None:
        with self.lock:
            members = set(json.loads(self._live(key) or "[]")) - {member}
            if members:
                self._put(key, json.dumps(sorted(members)), None)
            else:
                self.items.pop(key, None)

    def take(self, key: str, per_minute: int) -> bool:
        """One token from a bucket refilled at per_minute; False when empty."""
        with self.lock:
            now = time.time()
            tokens, at = json.loads(self._live(key) or json.dumps([per_minute, now]))
            tokens = min(per_minute, tokens + (now - at) * per_minute / 60)
            ok = tokens >= 1
            self._put(key, json.dumps([tokens - 1 if ok else tokens, now]), 120)
            return ok


_TAKE = """
local v = redis.call('GET', KEYS[1])
local now, rate = tonumber(ARGV[1]), tonumber(ARGV[2])
local tokens, at = rate, now
if v then local d = cjson.decode(v); tokens, at = d[1], d[2] end
tokens = math.min(rate, tokens + (now - at) * rate / 60)
local ok = 0
if tokens >= 1 then tokens = tokens - 1; ok = 1 end
redis.call('SET', KEYS[1], cjson.encode({tokens, now}), 'EX', 120)
return ok
"""


class RedisStore:
    """The same interface on Redis (redis-py). TLS (rediss://) is required outside localhost."""

    def __init__(self, url: str, *, prefix: str = "standard:"):
        import redis
        from urllib.parse import urlsplit
        host = urlsplit(url).hostname or ""
        if not url.startswith("rediss://") and host not in ("localhost", "127.0.0.1", "::1"):
            raise StoreError("a remote store is reached over TLS (rediss://)")
        self.r, self.prefix = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2), prefix
        self._take = self.r.register_script(_TAKE)

    def _k(self, key):
        return self.prefix + key

    def get(self, key):
        v = self.r.get(self._k(key))
        return None if v is None else json.loads(v)

    def set(self, key, value, ttl=None):
        self.r.set(self._k(key), json.dumps(value), ex=None if ttl is None else max(1, int(ttl)))

    def delete(self, key):
        self.r.delete(self._k(key))

    def add(self, key, member, ttl=None):
        self.r.sadd(self._k(key), member)
        if ttl is not None:
            self.r.expire(self._k(key), max(1, int(ttl)), gt=True)

    def members(self, key):
        return sorted(m.decode() for m in self.r.smembers(self._k(key)))

    def discard(self, key, member):
        self.r.srem(self._k(key), member)

    def take(self, key, per_minute):
        return bool(self._take(keys=[self._k(key)], args=[time.time(), per_minute]))


def from_env():
    """A store for one owner (the guard's limits, the session block's sessions): Redis at STANDARD_STORE_URL, shared
    by every worker; else a memory store of its own, refused in production when the server runs several workers."""
    url = os.environ.get("STANDARD_STORE_URL")
    if url:
        return RedisStore(url)
    workers = int(os.environ.get("WEB_CONCURRENCY", "1") or "1")
    if os.environ.get("STANDARD_ENV") == "production" and workers > 1:
        raise StoreError("several workers share no memory: set STANDARD_STORE_URL")
    return MemoryStore()
