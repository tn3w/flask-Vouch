from __future__ import annotations

import ipaddress
import json
import logging
import re
import types
from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING

import flask

from flask_vouch.crawlers import crawler_name, is_crawler
from flask_vouch.engine import ChallengeError, Engine, EngineKwargs
from flask_vouch.policy import Request, blocklist_match
from flask_vouch.rendering import RETRY_ERROR_HTML, challenge_headers, safe_redirect

if TYPE_CHECKING:
    from typing_extensions import Unpack

log = logging.getLogger("flask_vouch")

_PREFIX = "VOUCH_"

_NETWORK_TYPES = (ipaddress.IPv4Network, ipaddress.IPv6Network)

_JSON_CT = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
}


class VouchKwargs(EngineKwargs, total=False):
    secret: str | None
    engine: Engine | None
    exclude: list[str] | None
    json_mode: bool | Callable[[Request], bool]
    trusted_proxies: int | list[str] | None


def _config_kwargs(app_config) -> dict:
    return {
        key[len(_PREFIX) :].lower(): value
        for key, value in app_config.items()
        if key.startswith(_PREFIX)
    }


def _networks(values: list) -> list:
    return [
        (
            value
            if isinstance(value, _NETWORK_TYPES)
            else ipaddress.ip_network(value, False)
        )
        for value in values
    ]


def _parse_trusted(trusted: int | list | str | None) -> int | list | None:
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

    networks = trusted if isinstance(trusted[0], _NETWORK_TYPES) else _networks(trusted)
    for candidate in reversed(chain):
        if not _in_networks(candidate, networks):
            return candidate
    return chain[0]


def _to_request(trusted_proxies: int | list | None = None) -> Request:
    r = flask.request
    return {
        "method": r.method,
        "path": r.path,
        "query": r.query_string.decode(),
        "user_agent": r.user_agent.string,
        "remote_addr": client_ip(
            r.remote_addr or "",
            r.headers.get("X-Forwarded-For", ""),
            trusted_proxies,
        ),
        "headers": dict(r.headers),
        "cookies": dict(r.cookies),
        "form": dict(r.form),
        "json": r.get_json(silent=True) if r.is_json else None,
        "secure": r.is_secure,
    }


class _Response:
    def __init__(
        self, status: int, headers: dict, body: str, cookie: dict | None = None
    ):
        self.status = status
        self.headers = headers
        self.body = body
        self.cookie = cookie


def _to_response(result: _Response) -> flask.Response:
    response = flask.Response(
        result.body,
        status=result.status,
        headers=result.headers,
    )
    if result.cookie:
        response.set_cookie(**result.cookie)
    return response


def _make_claims(user_agent: str, **overrides) -> types.SimpleNamespace:
    crawling = is_crawler(user_agent)
    return types.SimpleNamespace(
        **{
            "score": None,
            "matched_rule": None,
            "blocklist_match": None,
            "is_crawler": crawling,
            "crawler_name": crawler_name(user_agent) if crawling else None,
            **overrides,
        }
    )


def _error(use_json: bool, status: int, message: str) -> _Response:
    if use_json:
        return _Response(status, dict(_JSON_CT), json.dumps({"error": message.lower()}))
    return _Response(status, {"Content-Type": "text/plain"}, message)


class Vouch:
    """Flask middleware that issues bot challenges and grants signed access cookies.

    Usage::

        app = Flask(__name__)
        vouch = Vouch(app, secret="change-me")

    Application factory::

        vouch = Vouch(secret="change-me")
        vouch.init_app(app)

    Config via ``app.config`` with ``VOUCH_`` prefix::

        app.config["VOUCH_COOKIE_NAME"] = "_b"
        app.config["VOUCH_COOKIE_TTL"] = 3600

    Behind a reverse proxy, say how many hops to trust so ``X-Forwarded-For``
    cannot be spoofed::

        vouch = Vouch(app, secret="change-me", trusted_proxies=1)
    """

    def __init__(self, app: flask.Flask | None = None, **kwargs: Unpack[VouchKwargs]):
        self._kwargs = dict(kwargs)
        self._excludes: list[re.Pattern] = []
        self._json_mode: bool | Callable[[Request], bool] = False
        self._trusted_proxies: int | list | None = None
        self._exempt_endpoints: set[str] = set()
        self._engine: Engine | None = None

        if kwargs.get("secret") or kwargs.get("engine"):
            self._configure(dict(kwargs))

        if app is not None:
            self.init_app(app)

    def _configure(self, options: dict) -> None:
        self._excludes = [re.compile(p) for p in (options.pop("exclude", None) or [])]
        self._json_mode = options.pop("json_mode", False)
        self._trusted_proxies = _parse_trusted(options.pop("trusted_proxies", None))
        engine = options.pop("engine", None)
        secret = options.pop("secret", None)
        self._engine = engine or Engine(secret, **options)

    @property
    def engine(self) -> Engine:
        if not self._engine:
            raise RuntimeError("Call init_app() first or pass secret= at construction")
        return self._engine

    def init_app(self, app: flask.Flask) -> None:
        if not self._engine:
            merged = {**_config_kwargs(app.config), **self._kwargs}
            merged.setdefault("secret", app.config.get("SECRET_KEY"))
            self._configure(merged)

        app.before_request(self._check)
        app.extensions["vouch"] = self

    @property
    def verify_path(self) -> str:
        return self.engine.policy.verify_path

    def is_excluded(self, path: str) -> bool:
        return any(pattern.search(path) for pattern in self._excludes)

    def is_verify(self, method: str, path: str) -> bool:
        return method == "POST" and path == self.verify_path

    def _is_json(self, request: Request) -> bool:
        if callable(self._json_mode):
            return self._json_mode(request)
        return self._json_mode

    def _challenge(
        self, difficulty: int, request: Request, use_json: bool
    ) -> _Response:
        policy = self.engine.policy
        if not self.engine.allow("gen", request, policy.max_challenge_requests):
            return _error(use_json, 429, "Too Many Requests")

        challenge = self.engine.issue_challenge(difficulty, request)
        path = request["path"]

        if use_json:
            payload = policy.challenge_handler.render_payload(
                challenge, self.verify_path, path
            )
            return _Response(200, dict(_JSON_CT), json.dumps({"challenge": payload}))

        body = self.engine.render_challenge(challenge, path)
        return _Response(200, challenge_headers(policy.challenge_handler), body)

    def _handle_poll(self, body: dict) -> _Response:
        handler = self.engine.policy.challenge_handler
        return _Response(
            200, dict(_JSON_CT), json.dumps(handler.handle_http_poll(body, self.engine))
        )

    def _handle_verify(self, request: Request) -> _Response:
        form = request["form"]
        nonce = form.get("nonce") or ",".join(
            filter(None, [form.get("nonce.x", ""), form.get("nonce.y", "")])
        )
        token = self.engine.validate_challenge(form.get("id", ""), nonce, request)
        use_json = self._is_json(request)
        redirect = safe_redirect(form.get("redirect", "/"))
        policy = self.engine.policy

        if not token:
            return self._verify_failed(request, redirect, use_json)

        if use_json:
            return _Response(200, dict(_JSON_CT), json.dumps({"token": token}))

        cookie = {
            "key": policy.cookie_name,
            "value": token,
            "max_age": policy.cookie_ttl,
            "path": "/",
            "httponly": True,
            "samesite": policy.cookie_samesite,
            "secure": policy.cookie_secure and request.get("secure", False),
        }
        return _Response(302, {"Location": redirect}, "", cookie=cookie)

    def _verify_failed(
        self, request: Request, redirect: str, use_json: bool
    ) -> _Response:
        policy = self.engine.policy
        if not self.engine.allow("fail", request, policy.max_challenge_failures):
            return _error(use_json, 429, "Too Many Requests")

        if use_json:
            return _error(True, 403, "Invalid")

        if not policy.challenge_handler.retry_on_failure:
            return _error(False, 403, "Invalid")

        challenge = self.engine.issue_challenge(policy.default_difficulty, request)
        body = self.engine.render_challenge(challenge, redirect, error=RETRY_ERROR_HTML)
        return _Response(403, challenge_headers(policy.challenge_handler), body)

    def _verified_claims(self, request: Request) -> bool:
        cookie = request["cookies"].get(self.engine.policy.cookie_name)
        if not cookie:
            return False

        claims = self.engine.check_cookie(cookie, request)
        if not claims:
            return False

        request["_claims"] = _make_claims(request["user_agent"], **claims)
        return True

    def _allow_claims(self, request: Request, matched_rule) -> None:
        matched_blocklist = (
            blocklist_match(self.engine.blocklist, request["remote_addr"])
            if matched_rule and matched_rule.blocklist
            else None
        )
        request["_claims"] = _make_claims(
            request["user_agent"],
            matched_rule=matched_rule.name if matched_rule else None,
            blocklist_match=matched_blocklist,
        )

    def process_request(
        self,
        request: Request,
        force: str | None = None,
        deny_challenges: bool = False,
    ) -> _Response | None:
        if self.is_excluded(request["path"]):
            return None

        try:
            return self._route(request, force, deny_challenges)
        except ChallengeError:
            return _error(self._is_json(request), 503, "Challenge Unavailable")

    def _route(
        self,
        request: Request,
        force: str | None,
        deny_challenges: bool,
    ) -> _Response | None:
        if self.is_verify(request["method"], request["path"]):
            return self._verify_route(request)

        if self._verified_claims(request):
            return None

        if force:
            action, difficulty, matched_rule = force, 0, None
        else:
            action, difficulty, matched_rule = self.engine.policy.evaluate(
                request, self.engine.blocklist
            )

        if action == "allow":
            self._allow_claims(request, matched_rule)
            return None

        use_json = self._is_json(request)
        if action == "deny" or deny_challenges:
            return _error(use_json, 403, "Forbidden")

        difficulty = difficulty or self.engine.policy.default_difficulty
        return self._challenge(difficulty, request, use_json)

    def _verify_route(self, request: Request) -> _Response:
        handler = self.engine.policy.challenge_handler
        body = request.get("json")
        if body is not None:
            if handler.supports_http_poll:
                return self._handle_poll(body)
            return _error(True, 400, "Bad Request")

        cookie = request["cookies"].get(self.engine.policy.cookie_name)
        if cookie and self.engine.check_cookie(cookie, request):
            return _error(self._is_json(request), 403, "Forbidden")
        return self._handle_verify(request)

    def _apply(self, request: Request, **kwargs):
        result = self.process_request(request, **kwargs)
        if result:
            return _to_response(result)
        flask.g.vouch = request.get("_claims")
        return None

    def _check(self):
        endpoint = flask.request.endpoint
        if endpoint in self._exempt_endpoints:
            return None

        view = flask.current_app.view_functions.get(endpoint) if endpoint else None
        if view and getattr(view, "_vouch_exempt", False):
            return None

        return self._apply(_to_request(self._trusted_proxies))

    def _guard(self, **kwargs):
        def decorator(view):
            @wraps(view)
            def wrapper(*args, **view_kwargs):
                result = self._apply(_to_request(self._trusted_proxies), **kwargs)
                return result if result else view(*args, **view_kwargs)

            setattr(wrapper, "_vouch_exempt", True)
            return wrapper

        return decorator

    def exempt(self, view):
        """Decorator, or endpoint name, that skips the bouncer check.

        ``vouch.exempt("static")`` covers Flask's static files;
        ``vouch.exempt("admin.static")`` covers a blueprint's.
        """
        if isinstance(view, str):
            self._exempt_endpoints.add(view)
            return view
        setattr(view, "_vouch_exempt", True)
        return view

    def protect(self, view):
        """Decorator: always run bouncer check on this route (overrides global allow)."""
        return self._guard()(view)

    def challenge(self, view):
        """Decorator: always issue a challenge on this route regardless of policy."""
        return self._guard(force="challenge")(view)

    def block(self, view):
        """Decorator: deny anything the policy would challenge or deny; pass allows."""
        return self._guard(deny_challenges=True)(view)

    def mount_verify(self, app: flask.Flask) -> None:
        """Manually register the verify endpoint on a given app."""

        @app.route(self.verify_path, methods=["POST"])
        def _verify():
            return self._apply(_to_request(self._trusted_proxies)) or ("", 200)
