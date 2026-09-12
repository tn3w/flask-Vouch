from __future__ import annotations

import time
from collections import Counter, OrderedDict
from threading import Lock

from flask_vouch.challenges import ChallengeBase
from flask_vouch.policy import CHALLENGE_TTL

MAX_CHALLENGES = 100_000
MAX_RATE_KEYS = 100_000


class ChallengeStore:
    """In-memory challenge store, bounded by TTL and by entry count."""

    def __init__(self, ttl: int = CHALLENGE_TTL, max_size: int = MAX_CHALLENGES):
        self._ttl = ttl
        self._max_size = max_size
        self._data: OrderedDict[str, ChallengeBase] = OrderedDict()
        self._lock = Lock()

    def _prune(self) -> None:
        cutoff = time.time() - self._ttl
        for key in [k for k, v in self._data.items() if v.created_at < cutoff]:
            del self._data[key]
        while len(self._data) >= self._max_size:
            self._data.popitem(last=False)

    def set(self, challenge: ChallengeBase) -> None:
        with self._lock:
            self._prune()
            self._data[challenge.id] = challenge
            self._data.move_to_end(challenge.id)

    def get(self, challenge_id: str) -> ChallengeBase | None:
        with self._lock:
            challenge = self._data.get(challenge_id)
            if challenge and challenge.created_at < time.time() - self._ttl:
                del self._data[challenge_id]
                return None
            return challenge

    def consume(self, challenge_id: str) -> ChallengeBase | None:
        """Claim an unspent challenge, marking it spent in the same lock so two
        concurrent solutions cannot both redeem it."""
        with self._lock:
            challenge = self._data.get(challenge_id)
            if not challenge or challenge.spent:
                return None
            if challenge.created_at < time.time() - self._ttl:
                del self._data[challenge_id]
                return None
            challenge.spent = True
            return challenge


class RateLimiter:
    """Sliding-window counter per key, with LRU eviction so memory stays bounded."""

    def __init__(self, max_keys: int = MAX_RATE_KEYS):
        self._max_keys = max_keys
        self._data: OrderedDict[str, list[float]] = OrderedDict()
        self._lock = Lock()

    def hit(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        cutoff = now - window

        with self._lock:
            hits = [t for t in self._data.pop(key, []) if t > cutoff]
            allowed = len(hits) < limit
            if allowed:
                hits.append(now)

            self._data[key] = hits
            while len(self._data) > self._max_keys:
                self._data.popitem(last=False)

            return allowed


class Metrics:
    """Counts what the bouncer decided, for scraping into whatever you use."""

    def __init__(self):
        self._counts: Counter[str] = Counter()
        self._lock = Lock()

    def count(self, action: str) -> None:
        with self._lock:
            self._counts[action] += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()
