"""Remember model answers so rescans are fast and don't resend data.

The key is the whole redacted state, not just the executable: `python3
serve.py` and `python3 train.py` share an exe but not an answer. A miss
costs one request; a wrong hit costs a wrong placement, so only parts that
vary by accident (session numbers, container ids) are normalised away.

The key also covers the question text and which backend/model was asked, so
editing a class description or switching models never reuses old answers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from dataclasses import replace
from pathlib import Path

from iawp.classify.base import Classification, Classifier

DEFAULT_TTL_DAYS = 30

# Parts of a state that differ between two runs of the same workload.
_VOLATILE = [
    (re.compile(r"session-\d+\.scope"), "session-N.scope"),
    (re.compile(r"user-\d+\.slice"), "user-N.slice"),
    (re.compile(r"user@\d+\.service"), "user@N.service"),
    (re.compile(r"[0-9a-f]{32,}"), "<id>"),  # container ids, k8s pod uids
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS answers (
    key        TEXT PRIMARY KEY,
    classifier TEXT NOT NULL,  -- backend and requested model, e.g. local:http://... model=x
    state      TEXT NOT NULL,  -- redacted, normalised state (what the model saw)
    answer     TEXT NOT NULL,  -- JSON: cls, probabilities, enough_info
    model      TEXT NOT NULL,  -- model version that actually answered
    created    REAL NOT NULL
)
"""


def default_path() -> Path:
    if os.geteuid() == 0:
        return Path("/var/cache/iawp/classify.db")
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "iawp" / "classify.db"


def normalise(state: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in state.items():
        for rx, repl in _VOLATILE:
            v = rx.sub(repl, v)
        out[k] = v
    return out


class Cache:
    def __init__(self, path: Path, ttl_days: float = DEFAULT_TTL_DAYS):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fresh = not path.exists()
        self.db = sqlite3.connect(path)
        if fresh:
            os.chmod(path, 0o600)
        self.db.execute(_SCHEMA)
        self.ttl = ttl_days * 86400
        self.path = path

    def get(self, key: str) -> Classification | None:
        row = self.db.execute("SELECT answer, model, created FROM answers WHERE key = ?", (key,)).fetchone()
        if row is None or time.time() - row[2] > self.ttl:
            return None
        a = json.loads(row[0])
        return Classification(a["cls"], a["probabilities"], a["enough_info"], row[1], cached_at=row[2])

    def put(self, key: str, classifier: str, state: dict[str, str], c: Classification) -> None:
        answer = {"cls": c.cls, "probabilities": c.probabilities, "enough_info": c.enough_info}
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO answers VALUES (?, ?, ?, ?, ?, ?)",
                            (key, classifier, json.dumps(state), json.dumps(answer), c.model, time.time()))

    def stats(self) -> list[tuple[str, str, int]]:
        """(classifier, answering model, entries) per group."""
        return self.db.execute(
            "SELECT classifier, model, COUNT(*) FROM answers GROUP BY classifier, model ORDER BY classifier, model"
        ).fetchall()

    def clear(self) -> int:
        with self.db:
            return self.db.execute("DELETE FROM answers").rowcount


class CachedClassifier:
    """Wraps a backend: look up first, ask the model only on a miss."""

    def __init__(self, inner: Classifier, cache: Cache, identity: str, questions: dict):
        self.inner = inner
        self.name = inner.name
        self.cache = cache
        self.identity = identity
        self.questions = json.dumps(questions, sort_keys=True)
        self.hits = self.misses = 0

    def classify(self, state: dict[str, str]) -> Classification:
        state = normalise(state)
        key = hashlib.sha256(
            json.dumps([self.identity, self.questions, state], sort_keys=True).encode()
        ).hexdigest()
        if (hit := self.cache.get(key)) is not None:
            self.hits += 1
            return hit
        self.misses += 1
        result = self.inner.classify(state)
        self.cache.put(key, self.identity, state, result)
        return replace(result, cached_at=None)
