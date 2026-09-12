from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

from flask_vouch.challenges import ChallengeBase, ChallengeHandler
from flask_vouch.policy import Blocklist, Policy, Request, Rule, load_policy
from flask_vouch.rendering import render_challenge
from flask_vouch.stores import ChallengeStore, RateLimiter
from flask_vouch.tokens import jwt_decode, jwt_encode

if TYPE_CHECKING:
    from typing_extensions import Unpack

log = logging.getLogger("flask_vouch")

MIN_SECRET_BYTES = 16


class ChallengeError(RuntimeError):
    """A challenge handler failed to produce or check a challenge."""


class EngineKwargs(TypedDict, total=False):
    policy: "Policy | None"
    rules: "list[Rule]"
    default_rules: bool
    config_file: str | None
    rules_file: str | None
    blocklist: Blocklist
    challenge_threshold: int
    deny_threshold: int
    difficulty_step: int
    max_difficulty_bonus: int
    verify_bots: bool
    default_difficulty: int
    challenge_handler: ChallengeHandler
    cookie_name: str
    verify_path: str
    challenge_ttl: int
    cookie_ttl: int
    branding: bool
    accent_color: str
    template_dir: str | Path | None
    cookie_secure: bool
    cookie_samesite: str
    cookie_domain: str | None
    cookie_refresh: bool
    bind_ip: bool
    max_challenge_failures: int
    max_challenge_requests: int
    rate_limit_window: int


class Engine:
    """Framework-agnostic core: policy evaluation, challenges, access cookies."""

    def __init__(self, secret: str | bytes, **kwargs: Unpack[EngineKwargs]):
        policy = kwargs.pop("policy", None)
        extra_rules = kwargs.pop("rules", None)
        include_defaults = kwargs.pop("default_rules", True)
        config_file = kwargs.pop("config_file", None)
        rules_file = kwargs.pop("rules_file", None)
        self.blocklist = kwargs.pop("blocklist", None)

        self.secret = _check_secret(secret)
        self.policy = policy or load_policy(config_file, rules_file)

        for key, value in kwargs.items():
            setattr(self.policy, key, value)

        if extra_rules is not None:
            self.policy.rules = (
                extra_rules + self.policy.rules if include_defaults else extra_rules
            )

        handler = self.policy.challenge_handler
        if hasattr(handler, "secret"):
            setattr(handler, "secret", self.secret)

        self.store = ChallengeStore(self.policy.challenge_ttl)
        self.rate_limiter = RateLimiter()

    def _hmac(self, data: bytes) -> bytes:
        return hmac.new(self.secret, data, hashlib.sha256).digest()

    def hash_ip(self, ip: str) -> str:
        return self._hmac(ip.encode()).hex()[:16]

    def allow(self, scope: str, request: Request, limit: int) -> bool:
        key = f"{scope}:{self.hash_ip(request['remote_addr'])}"
        allowed = self.rate_limiter.hit(key, limit, self.policy.rate_limit_window)
        if not allowed:
            log.info("rate limit hit: scope=%s path=%s", scope, request["path"])
        return allowed

    def check_cookie(self, cookie_value: str, request: Request) -> dict | None:
        try:
            claims = jwt_decode(cookie_value, self.secret)
        except (ValueError, KeyError):
            return None

        if self.policy.bind_ip and not hmac.compare_digest(
            str(claims.get("ip", "")), self.hash_ip(request["remote_addr"])
        ):
            return None

        return claims

    def issue_challenge(self, difficulty: int, request: Request) -> ChallengeBase:
        handler = self.policy.challenge_handler
        effective = handler.to_difficulty(difficulty)

        try:
            random_data = handler.generate_random_data(effective)
        except Exception as error:
            log.exception("challenge generation failed")
            raise ChallengeError(str(error)) from error

        challenge = ChallengeBase(
            id=secrets.token_urlsafe(24),
            random_data=random_data,
            difficulty=effective,
            ip_hash=self.hash_ip(request["remote_addr"]),
            created_at=time.time(),
            challenge_type=handler.challenge_type,
        )
        self.store.set(challenge)
        return challenge

    def validate_challenge(
        self, challenge_id: str, nonce, request: Request
    ) -> str | None:
        handler = self.policy.challenge_handler
        challenge = self.store.consume(challenge_id)

        if not challenge:
            return None

        if challenge.challenge_type != handler.challenge_type:
            return None

        if not hmac.compare_digest(
            challenge.ip_hash, self.hash_ip(request["remote_addr"])
        ):
            return None

        try:
            answer = handler.nonce_from_form(str(nonce))
            if not handler.verify(challenge.random_data, answer, challenge.difficulty):
                return None
            extra = handler.jwt_extra(challenge.random_data, answer)
        except (ValueError, TypeError):
            return None
        except Exception as error:
            log.exception("challenge verification failed")
            raise ChallengeError(str(error)) from error

        return self.issue_cookie(request, challenge_id, extra)

    def issue_cookie(self, request: Request, challenge_id: str, extra: dict) -> str:
        now = int(time.time())
        claims = {
            **extra,
            "iat": now,
            "exp": now + self.policy.cookie_ttl,
            "cid": challenge_id,
        }
        if self.policy.bind_ip:
            claims["ip"] = self.hash_ip(request["remote_addr"])
        return jwt_encode(claims, self.secret)

    def stale_cookie(self, claims: dict) -> bool:
        """True once a valid cookie is past half its life and worth reissuing."""
        if not self.policy.cookie_refresh:
            return False
        return time.time() - claims.get("iat", 0) > self.policy.cookie_ttl / 2

    def renew_cookie(self, request: Request, claims: dict) -> str:
        extra = {
            key: value
            for key, value in claims.items()
            if key not in ("iat", "exp", "ip", "cid")
        }
        return self.issue_cookie(request, str(claims.get("cid", "")), extra)

    def render_challenge(
        self,
        challenge: ChallengeBase,
        redirect: str,
        error: str = "",
    ) -> str:
        policy = self.policy
        try:
            return render_challenge(
                policy.challenge_handler,
                challenge,
                policy.verify_path,
                redirect,
                accent_color=policy.accent_color,
                branding=policy.branding,
                error=error,
                template_dir=policy.template_dir,
            )
        except Exception as error_:
            log.exception("challenge rendering failed")
            raise ChallengeError(str(error_)) from error_


def _check_secret(secret: str | bytes | None) -> bytes:
    if not secret:
        raise ValueError("A secret is required (pass secret= or set SECRET_KEY)")

    value = secret.encode() if isinstance(secret, str) else secret
    if len(value) < MIN_SECRET_BYTES:
        raise ValueError(f"secret must be at least {MIN_SECRET_BYTES} bytes")

    return value
