import functools
import time
from collections import OrderedDict
from threading import Lock

_UNITS = {
    "second": 1,
    "seconds": 1,
    "sec": 1,
    "minute": 60,
    "minutes": 60,
    "min": 60,
    "hour": 3600,
    "hours": 3600,
    "hr": 3600,
    "day": 86400,
    "days": 86400,
}

_RETRY_AFTER = "60"


def _parse_rate(rate: str) -> tuple[int, int]:
    rate = rate.strip().lower()
    for sep in (" per ", "/"):
        if sep in rate:
            count_str, unit = rate.split(sep, 1)
            window = _UNITS.get(unit.strip())
            if window:
                return int(count_str.strip()), window
    raise ValueError(f"Invalid rate: {rate!r}")


def _xff_or(xff: str, fallback: str) -> str:
    first = xff.split(",")[0].strip()
    return first if first else fallback


class _MemoryStore:
    def __init__(self, max_size: int = 10_000):
        self._data: OrderedDict[str, list[float]] = OrderedDict()
        self._max_size = max_size
        self._lock = Lock()

    def hit(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        cutoff = now - window

        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                hits = [t for t in self._data[key] if t > cutoff]
            else:
                hits = []
                if len(self._data) >= self._max_size:
                    self._data.popitem(last=False)

            if len(hits) >= limit:
                self._data[key] = hits
                return False

            hits.append(now)
            self._data[key] = hits
            return True


class _RedisStore:
    def __init__(self, client, prefix: str = "fbrl"):
        from flask_vouch.redis import RedisRateLimiter

        self._limiter = RedisRateLimiter(client, prefix)

    def hit(self, key: str, limit: int, window: int) -> bool:
        return self._limiter.hit(key, limit, window)


class RateLimiter:
    """Standalone rate limiter for Flask with per-route decorators.

    Backends: in-memory LRU (default) or Redis via ``redis_client``.

    Usage — decorator::

        rl = RateLimiter(default="100/minute")

        @rl.limit("10/minute")
        def my_view(): ...

        @rl.exempt
        def health(): ...

    Usage — Flask global::

        rl.init_flask(app, rate="200/minute")
    """

    def __init__(
        self,
        default: str = "100/minute",
        max_size: int = 10_000,
        redis_client=None,
        prefix: str = "fbrl",
    ):
        self._default = _parse_rate(default)
        self._store = (
            _RedisStore(redis_client, prefix)
            if redis_client
            else _MemoryStore(max_size)
        )

    def limit(self, rate: str):
        lim, win = _parse_rate(rate)

        def decorator(func):
            if getattr(func, "_rl_exempt", False):
                return func

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                from flask import Response, request

                xff = request.headers.get("X-Forwarded-For", "")
                ip = _xff_or(xff, request.remote_addr or "")
                if not self._store.hit(f"{func.__qualname__}:{ip}", lim, win):
                    return Response(
                        "Too Many Requests",
                        status=429,
                        headers={"Retry-After": _RETRY_AFTER},
                    )
                return func(*args, **kwargs)

            setattr(wrapper, "_rl_limit", (lim, win))
            return wrapper

        return decorator

    def exempt(self, func):
        func._rl_exempt = True
        return func

    def init_flask(self, app, rate: str | None = None):
        lim, win = _parse_rate(rate) if rate else self._default
        store = self._store

        @app.before_request
        def _check():
            from flask import Response, request

            view = app.view_functions.get(request.endpoint)
            if view and getattr(view, "_rl_exempt", False):
                return None

            xff = request.headers.get("X-Forwarded-For", "")
            ip = _xff_or(xff, request.remote_addr or "")

            if not store.hit(f"{request.endpoint}:{ip}", lim, win):
                return Response(
                    "Too Many Requests",
                    status=429,
                    headers={"Retry-After": _RETRY_AFTER},
                )
            return None
