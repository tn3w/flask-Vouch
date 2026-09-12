"""Flask middleware: policy filtering plus a proof-of-work and attestation gate."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import time
from collections import OrderedDict
from functools import lru_cache
from pathlib import Path
from threading import Lock

import flask

from .motion import score_motion
from .navigator import score_navigator

TEMPLATE = Path(__file__).parent / "challenge.html"

MIN_SECRET_BYTES = 16
MAX_BODY_BYTES = 512_000
MAX_ENTRIES = 100_000

MAX_DIFFICULTY = 24
DIFFICULTY_STEP = 4
MAX_DIFFICULTY_BONUS = 5
CHALLENGE_THRESHOLD = 5
NAVIGATOR_MIN = 0.6
TRUSTED_MIN = 0.85

DEFAULTS = {
    "secret": None,
    "cookie_name": "_vouch",
    "cookie_ttl": 604_800,
    "challenge_ttl": 1800,
    "verify_path": "/.vouch/verify",
    "difficulty": 17,
    "interactive": True,
    "exclude": (),
    "trusted_proxies": None,
    "rate_window": 300,
    "max_challenges": 15,
    "max_verify_attempts": 10,
}

RULES = [
    {"name": "cloudflare-workers", "action": "deny", "headers": {"CF-Worker": ".*"}},
    {
        "name": "known-bad",
        "action": "deny",
        "user_agent": "(?i:MJ12bot|AhrefsBot|SemrushBot|DotBot|BLEXBot|DataForSeoBot"
        "|Bytedance|SerpstatBot|MegaIndex|Seekport|ZoominfoBot|magpie-crawler"
        "|Barkrowler|LinkpadBot|spbot|VelenPublicWebCrawler)",
    },
    {
        "name": "vuln-scanners",
        "action": "deny",
        "user_agent": "(?i:Nmap|Nikto|sqlmap|ZmEu|masscan|WPScan|Acunetix|Nessus"
        "|dirbuster|nuclei|gobuster|feroxbuster|wfuzz|ffuf|httpx|Qualys|OpenVAS"
        "|zgrab|CensysInspect|InternetMeasurement|l9scan|Expanse)",
    },
    {
        "name": "wp-scanners",
        "action": "deny",
        "path": r"(?i:wp-login|wp-admin|xmlrpc\.php|wp-config)",
    },
    {
        "name": "cms-probes",
        "action": "deny",
        "path": r"(?i:/phpmyadmin|/pma/|/adminer|/administrator/|/typo3/"
        r"|/wp-content/(?:uploads|plugins)/.*\.php|/wp-json/wp/v2/users)",
    },
    {
        "name": "framework-leak-probes",
        "action": "deny",
        "path": r"(?i:/actuator(?:/|$)|/_profiler/|/server-status|/server-info"
        r"|/\.vscode/|/\.idea/|/config\.(?:json|yml|yaml)$|/composer\.(?:json|lock)$"
        r"|/package-lock\.json$|/\.npmrc$|/credentials$)",
    },
    {
        "name": "dotfile-probes",
        "action": "deny",
        "path": r"/\.(env|git|svn|hg|bzr|htaccess|htpasswd|DS_Store|aws|ssh"
        r"|bash_history|netrc)",
    },
    {
        "name": "shell-probes",
        "action": "deny",
        "path": r"(?i:\.(php|cgi|asp|aspx|jsp)$|/cgi-bin/|/shell|/cmd)",
    },
    {"name": "traversal-attempts", "action": "deny", "path": r"(\.\./|%2e%2e|%252e)"},
    {
        "name": "injection-attempts",
        "action": "deny",
        "path": r"(?i:union(?:\s|%20|\+)+select|/etc/passwd|\bjava\.lang\.|\$\{jndi:"
        r"|<script|%3cscript|/bin/(?:sh|bash))",
    },
    {"name": "well-known", "action": "allow", "path": r"^/\.well-known/"},
    {"name": "favicon", "action": "allow", "path": r"^/favicon\.ico$"},
    {"name": "robots-txt", "action": "allow", "path": r"^/robots\.txt$"},
    {
        "name": "site-metadata",
        "action": "allow",
        "path": r"^/(sitemap(?:[\w-]*)?\.xml|sitemap_index\.xml|ads\.txt|app-ads\.txt"
        r"|humans\.txt|apple-app-site-association|manifest\.json|browserconfig\.xml)$",
    },
    {
        "name": "health-checks",
        "action": "allow",
        "path": r"^/(healthz?|readyz?|livez?|ping|status)$",
    },
    {
        "name": "verified-search-engines",
        "action": "allow",
        "verified_bot": True,
        "user_agent": "(?i:Googlebot|Google-InspectionTool|Storebot-Google|APIs-Google"
        "|FeedFetcher-Google|Bingbot|BingPreview|DuckDuckBot|DuckAssistBot|Baiduspider"
        "|YandexBot|YandexImages|Applebot|PetalBot|YisouSpider|Sogou|Naver)",
    },
    {
        "name": "search-engine-impostors",
        "action": "deny",
        "user_agent": "(?i:Googlebot|Google-InspectionTool|Storebot-Google|APIs-Google"
        "|FeedFetcher-Google|Bingbot|BingPreview|DuckDuckBot|DuckAssistBot|Baiduspider"
        "|YandexBot|YandexImages|Applebot|PetalBot|YisouSpider|Sogou|Naver)",
    },
    {
        "name": "feed-readers",
        "action": "allow",
        "user_agent": "(?i:Feedly|NewsBlur|Miniflux|FreshRSS|Inoreader|Feedbin"
        "|Tiny Tiny RSS)",
    },
    {
        "name": "monitoring",
        "action": "allow",
        "user_agent": "(?i:UptimeRobot|Pingdom|StatusCake|Better Uptime|Checkly)",
    },
    {
        "name": "link-previews",
        "action": "allow",
        "user_agent": "(?i:Slackbot|Discordbot|Twitterbot|facebookexternalhit"
        "|LinkedInBot|WhatsApp|TelegramBot)",
    },
    {
        "name": "archive-org",
        "action": "allow",
        "user_agent": r"(?i:archive\.org_bot|Wayback)",
    },
    {
        "name": "ai-bots",
        "action": "challenge",
        "difficulty": 21,
        "user_agent": "(?i:GPTBot|ChatGPT|Claude-Web|ClaudeBot|Anthropic|CCBot"
        "|Google-Extended|Bytespider|Diffbot|Cohere-ai|PerplexityBot|YouBot|Amazonbot"
        "|Meta-ExternalAgent|Applebot-Extended|Timpibot|ImagesiftBot|OAI-SearchBot)",
    },
    {
        "name": "headless-browsers",
        "action": "challenge",
        "difficulty": 19,
        "user_agent": "(?i:HeadlessChrome|PhantomJS|Playwright|Puppeteer|Selenium"
        "|electron|cypress|Nightmare|SlimerJS)",
    },
    {
        "name": "aggressive-scrapers",
        "action": "challenge",
        "difficulty": 19,
        "user_agent": r"(?i:Scrapy|colly|HttpClient|python-requests|aiohttp|httpx"
        r"|urllib|Go-http-client|Java/|libwww-perl|mechanize|node-fetch|axios|okhttp"
        r"|Guzzle|reqwest|got\s|undici)",
    },
    {"name": "empty-ua", "action": "challenge", "user_agent": "^$"},
    {"name": "bogon-origin", "action": "challenge", "bogon": True},
    {"name": "unverified-crawler", "action": "challenge", "crawler": True},
    {
        "name": "curl-wget",
        "action": "weigh",
        "weight": 3,
        "user_agent": "(?i:^curl/|^Wget/|^HTTPie/|^fetch/)",
    },
    {"name": "missing-accept", "action": "weigh", "weight": 3, "missing": ["Accept"]},
    {
        "name": "missing-accept-language",
        "action": "weigh",
        "weight": 2,
        "missing": ["Accept-Language"],
    },
    {
        "name": "missing-accept-encoding",
        "action": "weigh",
        "weight": 2,
        "missing": ["Accept-Encoding"],
    },
    {
        "name": "missing-sec-fetch",
        "action": "weigh",
        "weight": 3,
        "user_agent": "(?i:Chrome/|Firefox/|Safari/)",
        "missing": ["Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-Dest"],
    },
    {
        "name": "chrome-without-client-hints",
        "action": "weigh",
        "weight": 3,
        "user_agent": "(?i:Chrome/(?:9[0-9]|[1-9][0-9]{2}))",
        "missing": ["Sec-CH-UA"],
    },
    {
        "name": "connection-close",
        "action": "weigh",
        "weight": 2,
        "headers": {"Connection": "(?i:^close$)"},
    },
    {
        "name": "wildcard-accept-only",
        "action": "weigh",
        "weight": 2,
        "headers": {"Accept": r"^\*/\*$"},
    },
    {
        "name": "automation-headers",
        "action": "weigh",
        "weight": 4,
        "headers": {"X-Requested-With": "(?i:scrapy|selenium|webdriver|puppeteer)"},
    },
    {"name": "generic-browser", "action": "challenge", "user_agent": "Mozilla"},
]

CRAWLER_KEYWORDS = (
    "bot", "crawl", "spider", "scrape", "slurp", "archiv", "headless", "indexer",
    "preview", "fetch", "monitor", "uptime", "feed", "check", "validator", "scan",
    "probe", "rank", "analyz", "synthetic", "sitemap", "favicon", "resolver", "sleuth",
    "ghost", "page speed", "search console", "-publisher", "-agent", "www.",
)

REAL_BROWSERS = (
    "opera/", "lynx/", "links ", "links/", "elinks/", "w3m/", "konqueror/", "icab/",
    "netsurf", "seamonkey/", "iceweasel/",
)

REAL_COMPAT = (
    "msie", "konqueror", "avant", "maxthon", "sleipnir", "acoo", "slcc", ".net clr",
    "presto",
)

OPERATOR_DOMAINS = {
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

OPERATOR_PATTERN = re.compile("|".join(sorted(OPERATOR_DOMAINS, key=len, reverse=True)))

CHALLENGE_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Robots-Tag": "noindex, nofollow",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; img-src data:; connect-src 'self'",
}


def _bare_compatible(lowered: str) -> bool:
    start = lowered.find("(compatible;")
    if start == -1:
        return False
    end = lowered.find(")", start)
    return end != -1 and not any(token in lowered[start:end] for token in REAL_COMPAT)


@lru_cache(maxsize=2048)
def is_crawler(user_agent: str) -> bool:
    lowered = user_agent.lower()
    if any(keyword in lowered for keyword in CRAWLER_KEYWORDS):
        return True
    if "http://" in user_agent or "https://" in user_agent:
        return True
    if not user_agent.startswith("Mozilla/"):
        return not any(browser in lowered for browser in REAL_BROWSERS)
    return _bare_compatible(lowered)


def _forward_confirmed(operator: str, ip: str) -> bool:
    try:
        hostname = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
        if not hostname.endswith(OPERATOR_DOMAINS[operator]):
            return False
        return any(info[4][0] == ip for info in socket.getaddrinfo(hostname, None))
    except OSError:
        return False


@lru_cache(maxsize=4096)
def is_verified_bot(user_agent: str, ip: str) -> bool:
    """True when a claimed crawler passes forward-confirmed reverse DNS."""
    match = OPERATOR_PATTERN.search(user_agent.lower())
    return bool(match) and _forward_confirmed(match.group(0), ip)


def is_bogon(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return True


def _in_networks(address: str, networks: list) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed in network for network in networks)


def client_ip(peer: str, forwarded: str, trusted) -> str:
    """Trust ``X-Forwarded-For`` only for the configured hops or proxy networks."""
    if not trusted or not forwarded:
        return peer

    chain = [part.strip() for part in forwarded.split(",") if part.strip()] + [peer]
    if isinstance(trusted, int):
        return chain[max(0, len(chain) - 1 - trusted)]

    for candidate in reversed(chain):
        if not _in_networks(candidate, trusted):
            return candidate
    return chain[0]


class Rule:
    def __init__(self, spec: dict):
        self.action = spec["action"]
        self.weight = spec.get("weight", 0)
        self.difficulty = spec.get("difficulty", 0)
        self.crawler = spec.get("crawler", False)
        self.verified_bot = spec.get("verified_bot", False)
        self.bogon = spec.get("bogon", False)
        self.missing = [name.lower() for name in spec.get("missing", ())]
        self.user_agent = _compiled(spec.get("user_agent"))
        self.path = _compiled(spec.get("path"))
        self.headers = {
            key.lower(): re.compile(value)
            for key, value in spec.get("headers", {}).items()
        }

    def matches(self, context: dict) -> bool:
        if self.bogon and not is_bogon(context["ip"]):
            return False
        if self.crawler and not is_crawler(context["user_agent"]):
            return False
        if self.verified_bot:
            if not is_verified_bot(context["user_agent"], context["ip"]):
                return False
        if self.user_agent and not self.user_agent.search(context["user_agent"]):
            return False
        if self.path and not self.path.search(context["path"]):
            return False
        if any(context["headers"].get(key) for key in self.missing):
            return False
        return all(
            key in context["headers"] and pattern.search(context["headers"][key])
            for key, pattern in self.headers.items()
        )


def _compiled(pattern):
    return re.compile(pattern) if pattern else None


def evaluate(rules: list, context: dict, difficulty: int) -> tuple:
    """First allow or deny wins; weighed signals raise the difficulty."""
    weight = 0
    challenge = 0

    for rule in rules:
        if not rule.matches(context):
            continue
        if rule.action in ("allow", "deny"):
            return rule.action, 0
        if rule.action == "challenge" and not challenge:
            challenge = rule.difficulty or difficulty
        weight += rule.weight

    bonus = min(MAX_DIFFICULTY_BONUS, weight // DIFFICULTY_STEP)
    if not challenge and weight >= CHALLENGE_THRESHOLD:
        challenge = difficulty
    if not challenge:
        return "allow", 0
    return "challenge", min(MAX_DIFFICULTY, challenge + bonus)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def seal(claims: dict, secret: bytes) -> str:
    body = _b64encode(json.dumps(claims, separators=(",", ":")).encode())
    signature = hmac.new(secret, body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64encode(signature)}"


def unseal(token: str, secret: bytes) -> dict | None:
    body, _, signature = token.partition(".")
    expected = hmac.new(secret, body.encode(), hashlib.sha256).digest()
    try:
        if not hmac.compare_digest(expected, _b64decode(signature)):
            return None
        claims = json.loads(_b64decode(body))
    except (ValueError, TypeError):
        return None

    if not isinstance(claims, dict) or claims.get("exp", 0) < time.time():
        return None
    return claims


class ChallengeStore:
    """Single-use challenges, bounded by age and by entry count."""

    def __init__(self, ttl: int):
        self._ttl = ttl
        self._data: OrderedDict = OrderedDict()
        self._lock = Lock()

    def add(self, challenge: dict) -> None:
        with self._lock:
            cutoff = time.time() - self._ttl
            for key in [k for k, v in self._data.items() if v["created"] < cutoff]:
                del self._data[key]
            while len(self._data) >= MAX_ENTRIES:
                self._data.popitem(last=False)
            self._data[challenge["id"]] = challenge

    def consume(self, challenge_id: str) -> dict | None:
        with self._lock:
            challenge = self._data.pop(challenge_id, None)
        if not challenge or challenge["created"] < time.time() - self._ttl:
            return None
        return challenge


class RateLimiter:
    """Sliding window per key, evicting the least recently used keys."""

    def __init__(self):
        self._data: OrderedDict = OrderedDict()
        self._lock = Lock()

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        with self._lock:
            hits = [stamp for stamp in self._data.pop(key, []) if stamp > now - window]
            allowed = len(hits) < limit
            if allowed:
                hits.append(now)
            self._data[key] = hits
            while len(self._data) > MAX_ENTRIES:
                self._data.popitem(last=False)
            return allowed


def leading_zero_bits(digest: bytes) -> int:
    for index, byte in enumerate(digest):
        if byte:
            return index * 8 + (8 - byte.bit_length())
    return len(digest) * 8


def solves_proof_of_work(data: str, nonce, difficulty: int) -> bool:
    if not isinstance(nonce, int) or isinstance(nonce, bool) or not 0 <= nonce < 2**53:
        return False
    digest = hashlib.sha256(f"{data}{nonce}".encode()).digest()
    return leading_zero_bits(digest) >= difficulty


def safe_redirect(target) -> str:
    if not isinstance(target, str) or not target.startswith("/"):
        return "/"
    unsafe = target.startswith(("//", "/\\")) or "\n" in target or "\r" in target
    return "/" if unsafe else target


@lru_cache(maxsize=1)
def _template() -> str:
    return TEMPLATE.read_text()


def _payload_literal(payload: dict) -> str:
    return (
        json.dumps(payload)
        .replace("'", "\\u0027")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def _json_error(message: str, status: int):
    response = flask.jsonify({"ok": False, "error": message})
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


class Vouch:
    """Challenge unknown clients before they reach the app.

    Usage::

        app = Flask(__name__)
        Vouch(app, secret="a-long-random-secret", trusted_proxies=1)
    """

    def __init__(self, app=None, **options):
        self.options = {**DEFAULTS, **options}
        self.rules = [Rule(spec) for spec in RULES]
        self.limiter = RateLimiter()
        self.store = ChallengeStore(self.options["challenge_ttl"])
        self.secret = b""
        self.exclude = [re.compile(pattern) for pattern in self.options["exclude"]]
        if app is not None:
            self.init_app(app)

    def init_app(self, app: flask.Flask) -> None:
        secret = self.options["secret"] or app.config.get("SECRET_KEY") or ""
        self.secret = secret.encode() if isinstance(secret, str) else secret
        if len(self.secret) < MIN_SECRET_BYTES:
            raise ValueError(f"secret must be at least {MIN_SECRET_BYTES} bytes")

        trusted = self.options["trusted_proxies"]
        if trusted is not None and not isinstance(trusted, int):
            self.options["trusted_proxies"] = [
                ipaddress.ip_network(network, strict=False) for network in trusted
            ]

        app.before_request(self._before_request)
        app.extensions["vouch"] = self

    def _context(self) -> dict:
        request = flask.request
        return {
            "path": request.path,
            "user_agent": request.user_agent.string,
            "headers": {key.lower(): value for key, value in request.headers.items()},
            "ip": client_ip(
                request.remote_addr or "",
                request.headers.get("X-Forwarded-For", ""),
                self.options["trusted_proxies"],
            ),
        }

    def _hash_ip(self, ip: str) -> str:
        return hmac.new(self.secret, ip.encode(), hashlib.sha256).hexdigest()[:16]

    def _rate_ok(self, scope: str, ip: str, limit: int) -> bool:
        key = f"{scope}:{self._hash_ip(ip)}"
        return self.limiter.allow(key, limit, self.options["rate_window"])

    def _before_request(self):
        request = flask.request
        if request.path == self.options["verify_path"]:
            if request.method != "POST":
                return flask.Response("Method Not Allowed", status=405)
            return self._verify()

        if any(pattern.search(request.path) for pattern in self.exclude):
            return None

        cookie = request.cookies.get(self.options["cookie_name"])
        claims = unseal(cookie, self.secret) if cookie else None
        if claims:
            flask.g.vouch = claims
            return None

        context = self._context()
        action, difficulty = evaluate(self.rules, context, self.options["difficulty"])
        if action == "allow":
            return None
        if action == "deny":
            return flask.Response("Forbidden", status=403)
        return self._issue(context, difficulty)

    def _issue(self, context: dict, difficulty: int):
        if not self._rate_ok("issue", context["ip"], self.options["max_challenges"]):
            return flask.Response("Too Many Requests", status=429)

        challenge = {
            "id": secrets.token_urlsafe(24),
            "data": secrets.token_hex(32),
            "difficulty": difficulty,
            "ip_hash": self._hash_ip(context["ip"]),
            "created": time.time(),
        }
        self.store.add(challenge)
        page = self._render(challenge, flask.request.full_path.rstrip("?"))
        return flask.Response(page, status=200, headers=CHALLENGE_HEADERS)

    def _render(self, challenge: dict, redirect: str) -> str:
        payload = {
            "id": challenge["id"],
            "data": challenge["data"],
            "difficulty": challenge["difficulty"],
            "verifyPath": self.options["verify_path"],
            "redirect": safe_redirect(redirect),
            "interactive": bool(self.options["interactive"]),
        }
        return _template().replace("{{CHALLENGE}}", _payload_literal(payload))

    def _verify(self):
        request = flask.request
        if (request.content_length or 0) > MAX_BODY_BYTES:
            return _json_error("Payload too large", 413)

        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return _json_error("Bad request", 400)

        context = self._context()
        attempts = self.options["max_verify_attempts"]
        if not self._rate_ok("verify", context["ip"], attempts):
            return _json_error("Too many attempts", 429)

        challenge = self.store.consume(str(body.get("id", "")))
        if not challenge:
            return _json_error("Challenge expired", 403)
        if not hmac.compare_digest(challenge["ip_hash"], self._hash_ip(context["ip"])):
            return _json_error("Challenge expired", 403)

        reason, claims = self._judge(challenge, body, context)
        if reason:
            return _json_error(reason, 403)
        return self._grant(claims, safe_redirect(body.get("redirect")))

    def _judge(self, challenge: dict, body: dict, context: dict) -> tuple:
        if not solves_proof_of_work(
            challenge["data"], body.get("nonce"), challenge["difficulty"]
        ):
            return "Invalid proof of work", {}

        navigator = score_navigator(body.get("signals"), context["headers"])
        harder = max(0, challenge["difficulty"] - self.options["difficulty"]) * 0.03
        if navigator["score"] < min(TRUSTED_MIN, NAVIGATOR_MIN + harder):
            return "Browser check failed", {}

        motion = score_motion(body.get("motion"))
        if motion["verdict"] == "bot":
            return "Interaction check failed", {}
        if motion["verdict"] != "human" and navigator["score"] < TRUSTED_MIN:
            return "Interaction check failed", {}

        return "", {"nav": navigator["score"], "mot": motion["score"]}

    def _grant(self, claims: dict, redirect: str):
        now = int(time.time())
        sealed = seal(
            {**claims, "exp": now + self.options["cookie_ttl"]}, self.secret
        )
        response = flask.jsonify({"ok": True, "redirect": redirect})
        response.headers["Cache-Control"] = "no-store"
        response.set_cookie(
            self.options["cookie_name"],
            sealed,
            max_age=self.options["cookie_ttl"],
            path="/",
            httponly=True,
            samesite="Lax",
            secure=flask.request.is_secure,
        )
        return response
