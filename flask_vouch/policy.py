from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Optional, TypedDict, Union

from flask_vouch.challenges import ChallengeHandler, SHA256Balloon
from flask_vouch.crawlers import is_crawler

if TYPE_CHECKING:
    from flask_vouch.netset import NetSet

    # 3.9: alias evaluated, not stringified
    Blocklist = Optional[Union["NetSet", List["NetSet"]]]
else:
    Blocklist = Any

COOKIE_NAME = "_tollbooth"
VERIFY_PATH = "/.tollbooth/verify"
CHALLENGE_TTL = 1800
COOKIE_TTL = 604_800

DEFAULT_DIFFICULTY = 10
CHALLENGE_THRESHOLD = 5

RATE_LIMIT_WINDOW = 300
MAX_CHALLENGE_FAILURES = 3
MAX_CHALLENGE_REQUESTS = 10

BRANDING = True
ACCENT_COLOR = "#44ff88"
COOKIE_SECURE = True
COOKIE_SAMESITE = "Lax"
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

        self._user_agent_re = re.compile(self.user_agent) if self.user_agent else None
        self._path_re = re.compile(self.path) if self.path else None
        self._header_res = {k: re.compile(v) for k, v in self.headers.items()}
        self._networks = [
            ipaddress.ip_network(address, strict=False)
            for address in self.remote_addresses
        ]

    def matches(self, request: Request, blocklist: Blocklist = None) -> bool:
        if self.blocklist and not in_blocklist(blocklist, request["remote_addr"]):
            return False

        if self.bogon_ip and not is_bogon_ip(request["remote_addr"]):
            return False

        if self.crawler and not is_crawler(request["user_agent"]):
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
    bind_ip: bool = BIND_IP
    max_challenge_failures: int = MAX_CHALLENGE_FAILURES
    max_challenge_requests: int = MAX_CHALLENGE_REQUESTS
    rate_limit_window: int = RATE_LIMIT_WINDOW

    def evaluate(
        self,
        request: Request,
        blocklist: Blocklist = None,
    ) -> tuple[str, int, "Rule | None"]:
        weight = 0

        for rule in self.rules:
            if not rule.matches(request, blocklist):
                continue
            if rule.action == "allow":
                return "allow", 0, rule
            if rule.action == "deny":
                return "deny", 0, rule
            if rule.action == "challenge":
                return "challenge", rule.difficulty or self.default_difficulty, rule
            weight += rule.weight

        if weight >= self.challenge_threshold:
            return "challenge", self.default_difficulty, None

        return "allow", 0, None


def load_policy(
    config: str | Path | None = None,
    rules: str | Path | None = None,
) -> Policy:
    settings = json.loads(Path(config).read_text()) if config else {}
    rule_list = json.loads(Path(rules or RULES_FILE).read_text())
    return Policy(rules=[Rule(**rule) for rule in rule_list], **settings)
