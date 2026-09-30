"""Tiny JSON-file cache: one file per query, keyed by a hash of the query."""

import datetime as _dt
import hashlib
import json
import pathlib
import re
from typing import Optional

from . import clock

CACHE_TTL_HOURS = 24  # cached answers older than this are re-queried


class Cache:
    def __init__(self, root: pathlib.Path, enabled: bool = True, refresh: bool = False,
                 ttl_hours: float = CACHE_TTL_HOURS):
        self.root = pathlib.Path(root)
        self.enabled = enabled
        self.refresh = refresh  # True = ignore existing entries but still write new ones
        self.ttl = _dt.timedelta(hours=ttl_hours)
        self.hits = 0
        self.misses = 0
        if enabled:
            self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, namespace: str, key: str) -> pathlib.Path:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", key)[:80]
        digest = hashlib.sha1(key.encode()).hexdigest()[:10]
        d = self.root / namespace
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{safe}_{digest}.json"

    _path = path_for  # backwards-compatible name

    def get(self, namespace: str, key: str) -> Optional[dict]:
        if not self.enabled or self.refresh:
            return None
        p = self.path_for(namespace, key)
        if not p.exists():
            self.misses += 1
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            fetched = _dt.datetime.fromisoformat(data["fetched_at"])
            if clock.utcnow() - fetched > self.ttl:
                self.misses += 1
                return None
            self.hits += 1
            return data
        except (ValueError, KeyError, OSError):
            self.misses += 1
            return None

    def put(self, namespace: str, key: str, payload: dict) -> None:
        if not self.enabled:
            return
        payload = dict(payload)
        payload["fetched_at"] = clock.now_iso()
        payload["query"] = key
        self.path_for(namespace, key).write_text(json.dumps(payload, indent=2), encoding="utf-8")
