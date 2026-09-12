from __future__ import annotations

import logging
import re
import socket
import time
from collections import OrderedDict
from functools import lru_cache
from threading import Lock

log = logging.getLogger("flask_vouch.crawlers")

_KEYWORDS = (
    "bot",
    "crawl",
    "spider",
    "scrape",
    "slurp",
    "archiv",
    "headless",
    "indexer",
    "preview",
    "fetch",
    "monitor",
    "uptime",
    "feed",
    "check",
    "validator",
    "scan",
    "probe",
    "rank",
    "analyz",
    "synthetic",
    "sitemap",
    "favicon",
    "resolver",
    "sleuth",
    "ghost",
    "page speed",
    "search console",
    "-publisher",
    "-agent",
    "www.",
)

_REAL_BROWSERS = (
    "opera/",
    "lynx/",
    "links ",
    "links/",
    "elinks/",
    "w3m/",
    "konqueror/",
    "icab/",
    "netsurf",
    "seamonkey/",
    "iceweasel/",
)

_REAL_COMPAT = (
    "msie",
    "konqueror",
    "avant",
    "maxthon",
    "sleipnir",
    "acoo",
    "slcc",
    ".net clr",
    "presto",
)


def _bare_compatible(low: str) -> bool:
    start = low.find("(compatible;")
    if start == -1:
        return False
    end = low.find(")", start)
    return end != -1 and not any(token in low[start:end] for token in _REAL_COMPAT)


@lru_cache(maxsize=2048)
def is_crawler(user_agent: str) -> bool:
    low = user_agent.lower()

    if any(keyword in low for keyword in _KEYWORDS):
        return True
    if "http://" in user_agent or "https://" in user_agent:
        return True
    if not user_agent.startswith("Mozilla/") and not any(
        browser in low for browser in _REAL_BROWSERS
    ):
        return True
    return _bare_compatible(low)


@lru_cache(maxsize=2048)
def crawler_name(user_agent: str) -> str | None:
    if user_agent.startswith("Mozilla/"):
        compat = user_agent.find("(compatible;")
        if compat == -1:
            return None
        start = compat + len("(compatible;")
        while start < len(user_agent) and user_agent[start] == " ":
            start += 1
        end = start
        while end < len(user_agent) and user_agent[end] not in " /;)":
            end += 1
        return user_agent[start:end] or None

    head = user_agent.split(None, 1)[0] if user_agent else ""
    return head.split("/", 1)[0] or None


VERIFY_CACHE_TTL = 3600
MAX_VERIFY_CACHE = 10_000

OPERATOR_DOMAINS: dict[str, tuple[str, ...]] = {
    "googlebot": (".googlebot.com", ".google.com"),
    "google-inspectiontool": (".googlebot.com", ".google.com"),
    "storebot-google": (".googlebot.com", ".google.com"),
    "apis-google": (".google.com",),
    "feedfetcher-google": (".google.com",),
    "bingbot": (".search.msn.com",),
    "bingpreview": (".search.msn.com",),
    "applebot": (".applebot.apple.com",),
    "duckduckbot": (".duckduckgo.com",),
    "duckassistbot": (".duckduckgo.com",),
    "yandexbot": (".yandex.com", ".yandex.ru", ".yandex.net"),
    "yandeximages": (".yandex.com", ".yandex.ru", ".yandex.net"),
    "baiduspider": (".baidu.com", ".baidu.jp"),
    "petalbot": (".petalsearch.com", ".aspiegel.com"),
    "yisouspider": (".yisou.com",),
    "sogou": (".sogou.com",),
    "naver": (".naver.com",),
}

_OPERATOR_RE = re.compile("|".join(sorted(OPERATOR_DOMAINS, key=len, reverse=True)))


class _VerifyCache:
    """Bounded lookup cache: verification results expire and evict oldest first."""

    def __init__(self, ttl: int = VERIFY_CACHE_TTL, max_size: int = MAX_VERIFY_CACHE):
        self._ttl = ttl
        self._max_size = max_size
        self._data: OrderedDict[str, tuple[float, bool]] = OrderedDict()
        self._lock = Lock()

    def get(self, key: str) -> bool | None:
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            if entry[0] < time.time() - self._ttl:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return entry[1]

    def set(self, key: str, value: bool) -> None:
        with self._lock:
            self._data[key] = (time.time(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._max_size:
                self._data.popitem(last=False)


_verify_cache = _VerifyCache()


def bot_operator(user_agent: str) -> str | None:
    """Name of the crawler operator a user agent claims to be, if it claims one."""
    match = _OPERATOR_RE.search(user_agent.lower())
    return match.group(0) if match else None


def _reverse_name(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except OSError:
        return None


def _resolves_to(hostname: str, ip: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return False
    return any(info[4][0] == ip for info in infos)


def _confirm(operator: str, ip: str) -> bool:
    hostname = _reverse_name(ip)
    if not hostname or not hostname.endswith(OPERATOR_DOMAINS[operator]):
        return False
    return _resolves_to(hostname, ip)


def verify_operator(operator: str, ip: str) -> bool:
    """Forward-confirmed reverse DNS: the PTR name must belong to the operator
    and must itself resolve back to the same address. Results are cached."""
    if operator not in OPERATOR_DOMAINS:
        return False

    key = f"{operator}:{ip}"
    cached = _verify_cache.get(key)
    if cached is not None:
        return cached

    confirmed = _confirm(operator, ip)
    _verify_cache.set(key, confirmed)
    if not confirmed:
        log.info("unverified bot claim: operator=%s ip=%s", operator, ip)
    return confirmed


def is_verified_bot(user_agent: str, ip: str) -> bool:
    """True when the user agent claims a known crawler and the address proves it."""
    operator = bot_operator(user_agent)
    return bool(operator) and verify_operator(operator, ip)
