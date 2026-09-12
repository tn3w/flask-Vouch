from __future__ import annotations

import functools

from flask_vouch.policy import client_ip, parse_trusted
from flask_vouch.stores import RateLimiter as _MemoryStore

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


def _parse_rate(rate: str) -> tuple[int, int]:
    rate = rate.strip().lower()
    for sep in (" per ", "/"):
        if sep in rate:
            count_str, unit = rate.split(sep, 1)
            window = _UNITS.get(unit.strip())
            if window:
                return int(count_str.strip()), window
    raise ValueError(f"Invalid rate: {rate!r}")


def _too_many(window: int):
    from flask import Response

    return Response(
        "Too Many Requests",
        status=429,
        headers={"Retry-After": str(window), "X-Robots-Tag": "noindex, nofollow"},
    )


class _RedisStore:
    def __init__(self, client, prefix: str = "vouch-rl"):
        from flask_vouch.redis import RedisRateLimiter

        self._limiter = RedisRateLimiter(client, prefix)

    def hit(self, key: str, limit: int, window: int) -> bool:
        return self._limiter.hit(key, limit, window)


class RateLimiter:
    """Standalone rate limiter for Flask with per-route decorators.

    Backends: in-memory LRU (default) or Redis via ``redis_client``.

    Decorator usage::

        rl = RateLimiter(default="100/minute")

        @rl.limit("10/minute")
        def my_view(): ...

        @rl.exempt
        def health(): ...

    Flask-global usage::

        rl.exempt("static")
        rl.init_flask(app, rate="200/minute")

    Behind a proxy pass ``trusted_proxies``, otherwise ``X-Forwarded-For`` is
    ignored and everyone behind the proxy shares one budget.
    """

    def __init__(
        self,
        default: str = "100/minute",
        max_size: int = 10_000,
        redis_client=None,
        prefix: str = "vouch-rl",
        trusted_proxies: int | list[str] | None = None,
    ):
        self._default = _parse_rate(default)
        self._exempt_endpoints: set[str] = set()
        self._trusted = parse_trusted(trusted_proxies)
        self._store = (
            _RedisStore(redis_client, prefix)
            if redis_client
            else _MemoryStore(max_size)
        )

    def _client_ip(self) -> str:
        from flask import request

        return client_ip(
            request.remote_addr or "",
            request.headers.get("X-Forwarded-For", ""),
            self._trusted,
        )

    def limit(self, rate: str):
        lim, win = _parse_rate(rate)

        def decorator(func):
            if getattr(func, "_rl_exempt", False):
                return func

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                key = f"{func.__qualname__}:{self._client_ip()}"
                if not self._store.hit(key, lim, win):
                    return _too_many(win)
                return func(*args, **kwargs)

            setattr(wrapper, "_rl_limit", (lim, win))
            return wrapper

        return decorator

    def exempt(self, func):
        """Decorator, or endpoint name, that skips rate limiting.

        ``rl.exempt("static")`` keeps asset requests from consuming the budget.
        """
        if isinstance(func, str):
            self._exempt_endpoints.add(func)
            return func
        func._rl_exempt = True
        return func

    def init_flask(self, app, rate: str | None = None):
        """Apply a per-endpoint budget to every route. Routes carrying their own
        ``@limit`` keep only that one, rather than being counted twice."""
        lim, win = _parse_rate(rate) if rate else self._default
        store = self._store

        @app.before_request
        def _check():
            from flask import request

            if request.endpoint in self._exempt_endpoints:
                return None

            view = app.view_functions.get(request.endpoint)
            if view and (
                getattr(view, "_rl_exempt", False) or hasattr(view, "_rl_limit")
            ):
                return None

            key = f"{request.endpoint}:{self._client_ip()}"
            return None if store.hit(key, lim, win) else _too_many(win)
