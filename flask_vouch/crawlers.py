from __future__ import annotations

from functools import lru_cache

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
