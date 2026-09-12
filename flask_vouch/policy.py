from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Optional, TypedDict, Union

from flask_vouch.challenges import ChallengeHandler, SHA256Balloon
from flask_vouch.crawlers import is_crawler, is_verified_bot

if TYPE_CHECKING:
    from flask_vouch.netset import NetSet

    # 3.9: alias evaluated, not stringified
    Blocklist = Optional[Union["NetSet", List["NetSet"]]]
else:
    Blocklist = Any

COOKIE_NAME = "_vouch"
VERIFY_PATH = "/.vouch/verify"
CHALLENGE_TTL = 1800
COOKIE_TTL = 604_800

DEFAULT_DIFFICULTY = 10
CHALLENGE_THRESHOLD = 5
DENY_THRESHOLD = 0
DIFFICULTY_STEP = 4
MAX_DIFFICULTY_BONUS = 6
VERIFY_BOTS = True

RATE_LIMIT_WINDOW = 300
MAX_CHALLENGE_FAILURES = 3
MAX_CHALLENGE_REQUESTS = 10

BRANDING = True
ACCENT_COLOR = "#44ff88"
COOKIE_SECURE = True
COOKIE_SAMESITE = "Lax"
COOKIE_DOMAIN = None
COOKIE_REFRESH = True
BIND_IP = False

RULES_FILE = Path(__file__).parent / "rules.json"


class _RequestBase(TypedDict):
    method: str
    path: str
    query: str
    user_agent: str
    remote_addr: str
    headers: dict[str, str]
    cookies: dict[str, str]
    form: dict[str, str]
    secure: bool


class Request(_RequestBase, total=False):
    json: Any
    _claims: Any
    _refresh: str


def in_blocklist(blocklist: Blocklist, ip: str) -> bool:
    return any(item.contains(ip) for item in _as_list(blocklist))


def blocklist_match(blocklist: Blocklist, ip: str) -> str | None:
    for item in _as_list(blocklist):
        match = item.match_range(ip)
        if match:
            return match
    return None


def _as_list(blocklist: Blocklist) -> list:
    if not blocklist:
        return []
    return blocklist if isinstance(blocklist, list) else [blocklist]


def is_bogon_ip(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return True


NETWORK_TYPES = (ipaddress.IPv4Network, ipaddress.IPv6Network)


def _networks(values: list) -> list:
    return [
        (
            value
            if isinstance(value, NETWORK_TYPES)
            else ipaddress.ip_network(value, False)
        )
        for value in values
    ]


def parse_trusted(trusted: int | list | str | None) -> int | list | None:
    """Normalize ``trusted_proxies`` into a hop count or a list of networks."""
    if trusted is None or isinstance(trusted, int):
        return trusted
    return _networks([trusted] if isinstance(trusted, str) else trusted)


def _in_networks(address: str, networks: list) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed in network for network in networks)


def client_ip(peer: str, forwarded: str, trusted: int | list | None) -> str:
    """Resolve the client address, trusting ``X-Forwarded-For`` only as configured.

    ``trusted`` is the number of proxies in front of the app, or the networks
    those proxies use. Without it the header is ignored, since anyone can set it.
    """
    if not trusted or not forwarded:
        return peer

    chain = [part.strip() for part in forwarded.split(",") if part.strip()] + [peer]

    if isinstance(trusted, int):
        return chain[max(0, len(chain) - 1 - trusted)]

    networks = trusted if isinstance(trusted[0], NETWORK_TYPES) else _networks(trusted)
    for candidate in reversed(chain):
        if not _in_networks(candidate, networks):
            return candidate
    return chain[0]


@dataclass
class Rule:
    name: str
    action: str = "weigh"
    user_agent: str | None = None
    path: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    missing_headers: list[str] = field(default_factory=list)
    remote_addresses: list[str] = field(default_factory=list)
    difficulty: int = 0
    weight: int = 0
    blocklist: bool = False
    crawler: bool = False
    bogon_ip: bool = False
    verified_bot: bool = False

    def __post_init__(self):
        self.action = self.action.lower()

        self._user_agent_re = re.compile(self.user_agent) if self.user_agent else None
        self._path_re = re.compile(self.path) if self.path else None
        self._header_res = {k: re.compile(v) for k, v in self.headers.items()}
        self._networks = [
            ipaddress.ip_network(address, strict=False)
            for address in self.remote_addresses
        ]

    def matches(
        self,
        request: Request,
        blocklist: Blocklist = None,
        verify_bots: bool = True,
    ) -> bool:
        if self.blocklist and not in_blocklist(blocklist, request["remote_addr"]):
            return False

        if self.bogon_ip and not is_bogon_ip(request["remote_addr"]):
            return False

        if self.crawler and not is_crawler(request["user_agent"]):
            return False

        if (
            self.verified_bot
            and verify_bots
            and not is_verified_bot(request["user_agent"], request["remote_addr"])
        ):
            return False

        if self._user_agent_re and not self._user_agent_re.search(
            request["user_agent"]
        ):
            return False

        if self._path_re and not self._path_re.search(request["path"]):
            return False

        if any(
            key not in request["headers"] or not pattern.search(request["headers"][key])
            for key, pattern in self._header_res.items()
        ):
            return False

        if any(request["headers"].get(key) for key in self.missing_headers):
            return False

        if not self._networks:
            return True

        try:
            address = ipaddress.ip_address(request["remote_addr"])
        except ValueError:
            return False

        return any(address in network for network in self._networks)


@dataclass
class Policy:
    rules: list[Rule]
    challenge_threshold: int = CHALLENGE_THRESHOLD
    deny_threshold: int = DENY_THRESHOLD
    difficulty_step: int = DIFFICULTY_STEP
    max_difficulty_bonus: int = MAX_DIFFICULTY_BONUS
    verify_bots: bool = VERIFY_BOTS
    default_difficulty: int = DEFAULT_DIFFICULTY
    challenge_handler: ChallengeHandler = field(default_factory=SHA256Balloon)
    cookie_name: str = COOKIE_NAME
    verify_path: str = VERIFY_PATH
    challenge_ttl: int = CHALLENGE_TTL
    cookie_ttl: int = COOKIE_TTL
    branding: bool = BRANDING
    accent_color: str = ACCENT_COLOR
    template_dir: str | Path | None = None
    cookie_secure: bool = COOKIE_SECURE
    cookie_samesite: str = COOKIE_SAMESITE
    cookie_domain: str | None = COOKIE_DOMAIN
    cookie_refresh: bool = COOKIE_REFRESH
    bind_ip: bool = BIND_IP
    max_challenge_failures: int = MAX_CHALLENGE_FAILURES
    max_challenge_requests: int = MAX_CHALLENGE_REQUESTS
    rate_limit_window: int = RATE_LIMIT_WINDOW

    def difficulty_bonus(self, weight: int) -> int:
        """Extra difficulty earned by piling up ``weigh`` signals."""
        if self.difficulty_step <= 0:
            return 0
        return min(self.max_difficulty_bonus, weight // self.difficulty_step)

    def evaluate(
        self,
        request: Request,
        blocklist: Blocklist = None,
    ) -> tuple[str, int, "Rule | None"]:
        """First ``allow`` or ``deny`` wins outright. A ``challenge`` rule is held
        while the remaining ``weigh`` rules run, so accumulated signals can raise
        its difficulty or push the request over ``deny_threshold``."""
        weight = 0
        challenge: tuple[int, Rule] | None = None

        for rule in self.rules:
            if not rule.matches(request, blocklist, self.verify_bots):
                continue
            if rule.action == "allow":
                return "allow", 0, rule
            if rule.action == "deny":
                return "deny", 0, rule
            if rule.action == "challenge" and not challenge:
                challenge = (rule.difficulty or self.default_difficulty, rule)
            weight += rule.weight

        if self.deny_threshold and weight >= self.deny_threshold:
            return "deny", 0, challenge[1] if challenge else None

        if challenge:
            difficulty, rule = challenge
            return "challenge", difficulty + self.difficulty_bonus(weight), rule

        if weight >= self.challenge_threshold:
            bonus = self.difficulty_bonus(weight)
            return "challenge", self.default_difficulty + bonus, None

        return "allow", 0, None


def load_policy(
    config: str | Path | None = None,
    rules: str | Path | None = None,
) -> Policy:
    settings = json.loads(Path(config).read_text()) if config else {}
    rule_list = json.loads(Path(rules or RULES_FILE).read_text())
    return Policy(rules=[Rule(**rule) for rule in rule_list], **settings)
