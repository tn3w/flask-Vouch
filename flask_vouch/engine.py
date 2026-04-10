import base64
import hashlib
import hmac
import html as _html
import ipaddress
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, TypedDict, Unpack

if TYPE_CHECKING:
    from flask_vouch.blocklist import IPBlocklist

try:
    import re2 as _regex  # type: ignore[reportMissingImports]
except ImportError:
    import re as _regex

_match_bot_signal = _regex.compile(
    r"(?i)bot\b|crawl|spider|scrape|fetch|scan\b|index"
    r"|preview|slurp|archiv|headless"
    r"|\+https?://|@[\w.-]+\.\w{2,}\b"
).search

_match_browser_sign = _regex.compile(
    r"(?i)mozilla/|webkit|gecko|trident|presto|khtml"
    r"|opera[\s/]|links\s|lynx/"
    r"|\((?:windows|macintosh|x11|linux)"
).search

_match_bare_compat = _regex.compile(
    r"(?i)\(compatible;"
    r"(?![^)]*(?:windows|mac|linux|msie|konqueror))"
    r"[^)]*\)"
).search

_match_url = _regex.compile(r"(?:^|[+;]|\s-\s)https?://[^\s);,]+").search
_extract_url = _regex.compile(r"https?://[^\s);,]+").search

_match_known_tool = _regex.compile(
    r"(?i)lighthouse|playwright|selenium|wget[\s/]"
    r"|nikto|sqlmap|nmap\b|pingdom|httrack"
    r"|google[\s-](?:favicon|ads|safety|extended)"
    r"|\bby\s+\S+\.(?:com|org|net)\b"
    r"|^[\w.-]+\.(?:com|net|org|io|ai)[/\s]"
    r"|;\s*\w+-agent[);]"
).search

_search_compatible_name = _regex.compile(
    r"(?i)\(compatible;\s*([A-Za-z][\w.-]*)(?:/[\w.-]+)?"
).search
_search_prefix_name = _regex.compile(
    r"^([A-Z][\w.-]*(?: [A-Z][\w.-]*)*)(?=(?:/[\w.-]+)?(?:\s|$| - ))"
).search
_find_name = _regex.compile(r"([A-Z][\w.-]*(?: [A-Z][\w.-]*)*)(?:/[\w.-]+)?").findall
_strip_comments = _regex.compile(r"\([^)]*\)").sub
_strip_browser_bits = _regex.compile(
    r"\b(?:Mozilla/\S+|AppleWebKit/\S+|KHTML,?|like|Gecko|"
    r"Chrome/\S+|Chromium/\S+|Safari/\S+|Version/\S+|Firefox/\S+|"
    r"Ubuntu|Mobile)\b"
).sub


@lru_cache(maxsize=2048)
def is_crawler(user_agent: str) -> bool:
    return bool(
        _match_bot_signal(user_agent)
        or not _match_browser_sign(user_agent)
        or _match_bare_compat(user_agent)
        or _match_known_tool(user_agent)
        or _match_url(user_agent)
    )


@lru_cache(maxsize=2048)
def crawler_name(user_agent: str) -> str | None:
    match = _search_compatible_name(user_agent)
    if match:
        return match.group(1)
    if not user_agent.startswith("Mozilla/5.0"):
        match = _search_prefix_name(user_agent)
        if match:
            return match.group(1)
        parts = user_agent.split()
        return parts[0].split("/", 1)[0] if parts else None
    names = _find_name(_strip_browser_bits(" ", _strip_comments(" ", user_agent)))
    return names[-1] if names else None

from flask_vouch.challenges import ChallengeBase, ChallengeHandler, SHA256Balloon

Challenge = ChallengeBase

COOKIE_NAME = "_tollbooth"
VERIFY_PATH = "/.tollbooth/verify"
CHALLENGE_TTL = 1800
COOKIE_TTL = 604_800

DEFAULT_DIFFICULTY = 10
CHALLENGE_THRESHOLD = 5
MAX_STORE_SIZE = 100_000

RATE_LIMIT_WINDOW = 300
MAX_CHALLENGE_FAILURES = 3
MAX_CHALLENGE_REQUESTS = 10

TOKEN_RATE_WINDOW = 60
TOKEN_RATE_LIMIT = 120
TOKEN_TOTAL_LIMIT = 3000

CSRF_TTL = 1800

BRANDING = True
ACCENT_COLOR = "#44ff88"


class Request(TypedDict):
    method: str
    path: str
    query: str
    user_agent: str
    remote_addr: str
    headers: dict[str, str]
    cookies: dict[str, str]
    form: dict[str, str]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4))


_JWT_HEADER = _b64url_encode(b'{"alg":"HS256","typ":"JWT"}')


def _meta_encrypt(data: dict, secret: bytes) -> str:
    plaintext = json.dumps(data, separators=(",", ":")).encode()
    key = hmac.new(secret, b"tbmeta", hashlib.sha256).digest()
    n = len(plaintext)
    keystream = b"".join(
        hmac.new(key, i.to_bytes(4, "big"), hashlib.sha256).digest()
        for i in range(-(-n // 32))
    )[:n]
    return _b64url_encode(bytes(a ^ b for a, b in zip(plaintext, keystream)))


def _meta_decrypt(s: str, secret: bytes) -> dict | None:
    try:
        ct = _b64url_decode(s)
        key = hmac.new(secret, b"tbmeta", hashlib.sha256).digest()
        n = len(ct)
        keystream = b"".join(
            hmac.new(key, i.to_bytes(4, "big"), hashlib.sha256).digest()
            for i in range(-(-n // 32))
        )[:n]
        return json.loads(bytes(a ^ b for a, b in zip(ct, keystream)))
    except Exception:
        return None


def jwt_encode(claims: dict, secret: bytes) -> str:
    payload = _b64url_encode(json.dumps(claims).encode())
    signing = f"{_JWT_HEADER}.{payload}"
    sig = hmac.new(secret, signing.encode(), hashlib.sha256).digest()

    return f"{signing}.{_b64url_encode(sig)}"


def jwt_decode(token: str, secret: bytes) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid token")

    if parts[0] != _JWT_HEADER:
        raise ValueError("unsupported algorithm")

    signing = f"{parts[0]}.{parts[1]}"
    expected = hmac.new(
        secret,
        signing.encode(),
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(expected, _b64url_decode(parts[2])):
        raise ValueError("invalid signature")

    claims = json.loads(_b64url_decode(parts[1]))
    if claims.get("exp", 0) < time.time():
        raise ValueError("token expired")

    return claims


class Store:
    def __init__(
        self,
        challenge_ttl: int = CHALLENGE_TTL,
        max_size: int = MAX_STORE_SIZE,
    ):
        self._ttl = challenge_ttl
        self._max_size = max_size
        self._data: dict[str, ChallengeBase] = {}
        self._lock = Lock()

    def _cleanup(self):
        cutoff = time.time() - self._ttl
        for k in [k for k, v in self._data.items() if v.created_at < cutoff]:
            del self._data[k]

    def _evict_oldest(self):
        excess = len(self._data) - self._max_size + 1
        if excess <= 0:
            return
        oldest = sorted(
            self._data,
            key=lambda k: self._data[k].created_at,
        )[:excess]
        for k in oldest:
            del self._data[k]

    def set(self, challenge: ChallengeBase):
        with self._lock:
            self._cleanup()
            self._evict_oldest()
            self._data[challenge.id] = challenge

    def get(self, cid: str) -> ChallengeBase | None:
        with self._lock:
            self._cleanup()
            return self._data.get(cid)


class RateLimiter:
    def __init__(self):
        self._data: dict[str, list[float]] = {}
        self._lock = Lock()

    def hit(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        cutoff = now - window
        with self._lock:
            hits = [t for t in self._data.get(key, []) if t > cutoff]
            if len(hits) >= limit:
                self._data[key] = hits
                return False
            hits.append(now)
            self._data[key] = hits
            return True


class TokenTracker:
    def __init__(self):
        self._lock = Lock()
        self._windows: dict[str, list[float]] = {}
        self._totals: dict[str, int] = {}

    def hit(
        self,
        cid: str,
        rate_limit: int,
        rate_window: int,
        total_limit: int,
    ) -> bool:
        now = time.time()
        with self._lock:
            if total_limit > 0:
                count = self._totals.get(cid, 0) + 1
                if count > total_limit:
                    return False
                self._totals[cid] = count

            if rate_limit > 0:
                cutoff = now - rate_window
                hits = [t for t in self._windows.get(cid, []) if t > cutoff]
                if len(hits) >= rate_limit:
                    return False
                hits.append(now)
                self._windows[cid] = hits

        return True


@dataclass
class Rule:
    name: str
    action: str = "weigh"
    user_agent: str | None = None
    path: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    remote_addresses: list[str] = field(default_factory=list)
    difficulty: int = 0
    weight: int = 0
    blocklist: bool = False
    crawler: bool = False
    bogon_ip: bool = False

    def __post_init__(self):
        self.action = self.action.lower()

        self._ua_re = re.compile(self.user_agent) if self.user_agent else None
        self._path_re = re.compile(self.path) if self.path else None
        self._header_res = {k: re.compile(v) for k, v in self.headers.items()}
        self._networks = [
            ipaddress.ip_network(a, strict=False) for a in self.remote_addresses
        ]

    def matches(self, request: Request, blocklist=None) -> bool:
        if self.blocklist and not _in_blocklist(blocklist, request["remote_addr"]):
            return False

        if self.bogon_ip and not _is_bogon_ip(request["remote_addr"]):
            return False

        if self.crawler and not is_crawler(request["user_agent"]):
            return False

        if self._ua_re and not self._ua_re.search(request["user_agent"]):
            return False

        if self._path_re and not self._path_re.search(request["path"]):
            return False

        if any(
            not p.search(request["headers"].get(k, ""))
            for k, p in self._header_res.items()
        ):
            return False

        if not self._networks:
            return True

        try:
            addr = ipaddress.ip_address(request["remote_addr"])
        except ValueError:
            return False

        return any(addr in n for n in self._networks)


@dataclass
class Policy:
    rules: list[Rule]
    challenge_threshold: int = CHALLENGE_THRESHOLD
    default_difficulty: int = DEFAULT_DIFFICULTY
    challenge_handler: ChallengeHandler = field(default_factory=SHA256Balloon)
    cookie_name: str = COOKIE_NAME
    verify_path: str = VERIFY_PATH
    challenge_ttl: int = CHALLENGE_TTL
    cookie_ttl: int = COOKIE_TTL
    branding: bool = BRANDING
    accent_color: str = ACCENT_COLOR
    max_challenge_failures: int = MAX_CHALLENGE_FAILURES
    max_challenge_requests: int = MAX_CHALLENGE_REQUESTS
    rate_limit_window: int = RATE_LIMIT_WINDOW
    token_rate_limit: int = TOKEN_RATE_LIMIT
    token_rate_window: int = TOKEN_RATE_WINDOW
    token_total_limit: int = TOKEN_TOTAL_LIMIT

    def evaluate(
        self,
        request: Request,
        blocklist=None,
    ) -> tuple[str, int, "Rule | None"]:
        weight = 0

        for rule in self.rules:
            if not rule.matches(request, blocklist):
                continue
            if rule.action == "allow":
                return "allow", 0, None
            if rule.action == "deny":
                return "deny", 0, rule
            if rule.action == "challenge":
                return "challenge", rule.difficulty or self.default_difficulty, rule
            weight += rule.weight

        if weight >= self.challenge_threshold:
            return "challenge", self.default_difficulty, None

        return "allow", 0, None


def load_policy(config=None, rules=None) -> Policy:
    base = Path(__file__).parent

    cfg_path = Path(config) if config else (base / "config.json")
    cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}

    rules_path = Path(rules) if rules else base / "rules.json"
    rule_list = json.loads(rules_path.read_text())

    return Policy(
        rules=[Rule(**r) for r in rule_list],
        **cfg,
    )


def _in_blocklist(blocklist, ip: str) -> bool:
    if not blocklist:
        return False
    if isinstance(blocklist, list):
        return any(bl.contains(ip) for bl in blocklist)
    return blocklist.contains(ip)


def _is_bogon_ip(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return True


def _blocklist_match(blocklist, ip: str) -> str | None:
    if not blocklist:
        return None
    items = blocklist if isinstance(blocklist, list) else [blocklist]
    for bl in items:
        match = bl.match_range(ip)
        if match:
            return match
    return None


def _safe_redirect(redirect: str) -> str:
    if (
        not redirect.startswith("/")
        or redirect.startswith("//")
        or redirect.startswith("/\\")
        or "\n" in redirect
        or "\r" in redirect
    ):
        return "/"
    return redirect


_BASE_CSP = (
    "default-src 'none'; "
    "script-src 'unsafe-inline'; "
    "worker-src blob:; "
    "style-src 'unsafe-inline'; "
    "img-src data: 'self'; "
    "connect-src 'self'"
)

_BASE_CHALLENGE_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def _challenge_headers(handler) -> dict[str, str]:
    extra = handler.extra_csp
    csp = f"{_BASE_CSP}; {extra}" if extra else _BASE_CSP
    return {**_BASE_CHALLENGE_HEADERS, "Content-Security-Policy": csp}


class EngineKwargs(TypedDict, total=False):
    policy: "Policy | None"
    rules: "list[Rule]"
    default_rules: bool
    config_file: str | None
    rules_file: str | None
    blocklist: "IPBlocklist | list[IPBlocklist] | None"
    challenge_threshold: int
    default_difficulty: int
    challenge_handler: ChallengeHandler
    cookie_name: str
    verify_path: str
    challenge_ttl: int
    cookie_ttl: int
    branding: bool
    accent_color: str
    max_challenge_failures: int
    max_challenge_requests: int
    rate_limit_window: int
    token_rate_limit: int
    token_rate_window: int
    token_total_limit: int


class Engine:
    def __init__(self, secret, **kwargs: Unpack[EngineKwargs]):
        policy = kwargs.pop("policy", None)
        extra_rules = kwargs.pop("rules", None)
        include_defaults = kwargs.pop("default_rules", True)
        config_file = kwargs.pop("config_file", None)
        rules_file = kwargs.pop("rules_file", None)
        self.blocklist = kwargs.pop("blocklist", None)

        self.secret = secret.encode() if isinstance(secret, str) else secret
        self.policy = policy or load_policy(config_file, rules_file)

        for key, val in kwargs.items():
            setattr(self.policy, key, val)

        if extra_rules is not None:
            self.policy.rules = (
                extra_rules + self.policy.rules if include_defaults else extra_rules
            )

        handler = self.policy.challenge_handler
        if hasattr(handler, "secret"):
            setattr(handler, "secret", self.secret)

        self.store = Store(self.policy.challenge_ttl)
        self._rate_limiter = RateLimiter()
        self._token_tracker = TokenTracker()

    def _hmac(self, data: bytes) -> bytes:
        return hmac.new(self.secret, data, hashlib.sha256).digest()

    def _hash_ip(self, ip: str) -> str:
        return self._hmac(ip.encode()).hex()[:16]

    def generate_csrf_token(
        self,
        challenge_id: str,
        request: Request,
    ) -> str:
        now = int(time.time())
        payload = f"{challenge_id}:{now}:{self._hash_ip(request['remote_addr'])}"
        sig = self._hmac(f"csrf:{payload}".encode())
        return _b64url_encode(f"{payload}:{_b64url_encode(sig)}".encode())

    def validate_csrf_token(
        self,
        token: str,
        challenge_id: str,
        request: Request,
    ) -> bool:
        try:
            decoded = _b64url_decode(token).decode()
            parts = decoded.rsplit(":", 1)
            if len(parts) != 2:
                return False

            payload, sig_b64 = parts
            expected = self._hmac(f"csrf:{payload}".encode())
            if not hmac.compare_digest(_b64url_decode(sig_b64), expected):
                return False

            fields = payload.split(":")
            if len(fields) != 3:
                return False

            token_cid, token_time, token_ip = fields
            if token_cid != challenge_id:
                return False

            if not hmac.compare_digest(token_ip, self._hash_ip(request["remote_addr"])):
                return False

            issued = int(token_time)
            if time.time() - issued > CSRF_TTL:
                return False

            return True
        except (ValueError, UnicodeDecodeError):
            return False

    def generate_client_id(self, request: Request) -> str:
        parts = [
            request["remote_addr"],
            request["user_agent"],
            request["headers"].get("Accept-Language", ""),
            request["headers"].get("Accept-Encoding", ""),
            request["headers"].get(
                "Sec-Ch-Ua", request["headers"].get("sec-ch-ua", "")
            ),
            request["headers"].get(
                "Sec-Ch-Ua-Platform",
                request["headers"].get("sec-ch-ua-platform", ""),
            ),
        ]
        tls_version = request["headers"].get(
            "X-Tls-Version",
            request["headers"].get("x-tls-version", ""),
        )
        tls_cipher = request["headers"].get(
            "X-Tls-Cipher",
            request["headers"].get("x-tls-cipher", ""),
        )
        parts.extend([tls_version, tls_cipher])
        raw = "|".join(parts)
        return self._hmac(f"client_id:{raw}".encode()).hex()[:32]

    def check_cookie(
        self,
        cookie_value: str,
        request: Request,
    ) -> dict | None:
        try:
            claims = jwt_decode(cookie_value, self.secret)
            if not hmac.compare_digest(
                str(claims.get("ip", "")),
                self._hash_ip(request["remote_addr"]),
            ):
                return None
            meta_enc = claims.pop("_m", None)
            if meta_enc:
                meta = _meta_decrypt(meta_enc, self.secret)
                if meta:
                    claims.update(meta)
            return claims
        except (ValueError, KeyError):
            return None

    def check_token_limit(self, cid: str) -> bool:
        p = self.policy
        if p.token_rate_limit == 0 and p.token_total_limit == 0:
            return True
        return self._token_tracker.hit(
            cid, p.token_rate_limit, p.token_rate_window, p.token_total_limit
        )

    def issue_challenge(
        self,
        difficulty: int,
        request: Request,
    ) -> ChallengeBase:
        handler = self.policy.challenge_handler
        effective = handler.to_difficulty(difficulty)
        challenge = ChallengeBase(
            id=secrets.token_urlsafe(24),
            random_data=handler.generate_random_data(effective),
            difficulty=effective,
            ip_hash=self._hash_ip(request["remote_addr"]),
            created_at=time.time(),
            challenge_type=handler.challenge_type,
        )
        self.store.set(challenge)
        return challenge

    def validate_challenge(
        self,
        challenge_id,
        nonce,
        request,
        csrf_token=None,
    ) -> str | None:
        if csrf_token and not self.validate_csrf_token(
            csrf_token, challenge_id, request
        ):
            return None

        challenge = self.store.get(challenge_id)
        if not challenge or challenge.spent:
            return None

        if challenge.challenge_type != self.policy.challenge_handler.challenge_type:
            return None

        if not hmac.compare_digest(
            challenge.ip_hash,
            self._hash_ip(request["remote_addr"]),
        ):
            return None

        try:
            nonce_val = self.policy.challenge_handler.nonce_from_form(str(nonce))
        except (ValueError, TypeError):
            return None

        if not self.policy.challenge_handler.verify(
            challenge.random_data, nonce_val, challenge.difficulty
        ):
            return None

        challenge.spent = True
        self.store.set(challenge)

        now = time.time()
        extra = self.policy.challenge_handler.jwt_extra(
            challenge.random_data, nonce_val
        )
        claims: dict = {
            "iat": int(now),
            "exp": int(now + self.policy.cookie_ttl),
            "ip": self._hash_ip(request["remote_addr"]),
            "cid": challenge_id,
            "fid": self.generate_client_id(request),
        }
        meta = {**(extra or {}), "remote_addr": request["remote_addr"]}
        claims["_m"] = _meta_encrypt(meta, self.secret)
        return jwt_encode(claims, self.secret)

    _BRANDING = (
        '<div class="branding">'
        "Protected by "
        '<a href="https://github.com/libcaptcha/'
        'tollbooth" target="_blank">tollbooth</a>'
        " · "
        '<a href="https://github.com/libcaptcha" '
        'target="_blank">libcaptcha</a>'
        "</div>"
    )

    def render_challenge(
        self,
        challenge: ChallengeBase,
        redirect_to: str,
        request: Request,
        error: str = "",
    ) -> str:
        handler = self.policy.challenge_handler
        payload_dict = handler.render_payload(
            challenge, self.policy.verify_path, redirect_to
        )
        csrf_token = self.generate_csrf_token(challenge.id, request)
        payload_dict["csrfToken"] = csrf_token
        payload = json.dumps(payload_dict)
        branding = self._BRANDING if self.policy.branding else ""

        safe = (
            payload.replace("'", "\\u0027")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )

        html = (
            handler.template.replace("{{CHALLENGE_DATA}}", safe)
            .replace("{{BRANDING}}", branding)
            .replace("{{ERROR}}", error)
            .replace("{{ACCENT_COLOR}}", self.policy.accent_color)
        )
        for key, value in payload_dict.items():
            safe_value = (
                str(value) if key == "captchaEmbed" else _html.escape(str(value))
            )
            html = html.replace(f"{{{{{key}}}}}", safe_value)
        return html

    def process(
        self,
        request: Request,
    ) -> tuple[str, int, dict[str, str], str]:
        cookie = request["cookies"].get(self.policy.cookie_name)
        if cookie:
            claims = self.check_cookie(cookie, request)
            if claims and self.check_token_limit(claims["cid"]):
                return "pass", 0, {}, ""

        action, difficulty, _ = self.policy.evaluate(
            request,
            self.blocklist,
        )

        if action == "allow":
            return "pass", 0, {}, ""
        if action == "deny":
            return (
                "deny",
                403,
                {"Content-Type": "text/plain"},
                "Forbidden",
            )

        ip_hash = self._hash_ip(request["remote_addr"])
        if not self._rate_limiter.hit(
            f"gen:{ip_hash}",
            self.policy.max_challenge_requests,
            self.policy.rate_limit_window,
        ):
            return "deny", 403, {"Content-Type": "text/plain"}, "Too Many Requests"

        challenge = self.issue_challenge(difficulty, request)
        body = self.render_challenge(challenge, request["path"], request)
        return "challenge", 200, _challenge_headers(self.policy.challenge_handler), body

    def handle_verify(
        self,
        request: Request,
    ) -> tuple[int, dict[str, str], str]:
        form = request["form"]
        nonce = form.get("nonce") or ",".join(
            filter(None, [form.get("nonce.x", ""), form.get("nonce.y", "")])
        )
        csrf_token = form.get("csrf_token", "")
        token = self.validate_challenge(form.get("id", ""), nonce, request, csrf_token)

        if not token:
            ip_hash = self._hash_ip(request["remote_addr"])
            if not self._rate_limiter.hit(
                f"fail:{ip_hash}",
                self.policy.max_challenge_failures,
                self.policy.rate_limit_window,
            ):
                return 403, {"Content-Type": "text/plain"}, "Too Many Requests"

            if self.policy.challenge_handler.retry_on_failure:
                redirect = _safe_redirect(form.get("redirect", "/"))
                challenge = self.issue_challenge(
                    self.policy.default_difficulty, request
                )
                body = self.render_challenge(
                    challenge,
                    redirect,
                    request,
                    error='<p class="error">Incorrect \u2014 try again.</p>',
                )
                return 200, _challenge_headers(self.policy.challenge_handler), body
            return 403, {"Content-Type": "text/plain"}, "Invalid"

        redirect = _safe_redirect(form.get("redirect", "/"))

        cookie = (
            f"{self.policy.cookie_name}={token}; "
            f"Path=/; HttpOnly; SameSite=Strict; "
            f"Secure; Max-Age={self.policy.cookie_ttl}"
        )

        return (
            302,
            {
                "Location": redirect,
                "Set-Cookie": cookie,
            },
            "",
        )
