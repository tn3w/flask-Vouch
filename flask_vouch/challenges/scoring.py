import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from threading import Lock


def penalize(state: dict, amount: float, reason: str) -> None:
    state["score"] = max(0.0, state["score"] - amount)
    state["flags"].append(reason)


def run_checks(checks, *args) -> dict:
    state = {"score": 1.0, "flags": []}
    for check in checks:
        check(*args, state)
    return state


def rounded(score: float) -> float:
    return round(score * 10000) / 10000


def sign_token(payload: dict, secret: bytes) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    signature = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    encoded = urlsafe_b64encode(body.encode()).rstrip(b"=").decode()
    return f"{encoded}.{signature}"


def verify_token(token: str, secret: bytes) -> dict | None:
    try:
        encoded, signature = token.split(".", 1)
        body = urlsafe_b64decode(encoded + "==").decode()
        expected = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        return json.loads(body)
    except Exception:
        return None


def score_token(score: float, secret: bytes, ttl: int = 300, **extra) -> str:
    return sign_token({"score": score, "exp": int(time.time() + ttl), **extra}, secret)


class SessionStore:
    """Short-lived probe sessions, evicted once their round window expires."""

    def __init__(self, timeout: int):
        self._timeout = timeout
        self._sessions: dict = {}
        self._lock = Lock()

    def start(self, key: str, session) -> None:
        cutoff = time.monotonic() - self._timeout
        with self._lock:
            for stale in [
                k for k, v in self._sessions.items() if v.started_at < cutoff
            ]:
                del self._sessions[stale]
            self._sessions[key] = session

    def get(self, key: str):
        with self._lock:
            return self._sessions.get(key)

    def drop(self, key: str) -> None:
        with self._lock:
            self._sessions.pop(key, None)
