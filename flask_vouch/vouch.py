import json
import re
import types
from collections.abc import Callable
from functools import wraps
from typing import Unpack

import flask

from flask_vouch.engine import (
    Engine,
    EngineKwargs,
    Request,
    _blocklist_match,
    _challenge_headers,
    _safe_redirect,
)
from flask_vouch.engine import crawler_name as _crawler_name
from flask_vouch.engine import is_crawler as _is_crawler

_PREFIX = "VOUCH_"

_JSON_CT = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
}

_RETRY_ERROR = '<p class="error">Incorrect, try again.</p>'


class VouchKwargs(EngineKwargs, total=False):
    secret: str | None
    engine: Engine | None
    exclude: list[str] | None
    json_mode: bool | Callable[[Request], bool]


def _config_kwargs(app_config):
    return {
        key[len(_PREFIX) :].lower(): value
        for key, value in app_config.items()
        if key.startswith(_PREFIX)
    }


def _to_request() -> Request:
    r = flask.request
    forwarded = r.headers.get("X-Forwarded-For", "")
    return {
        "method": r.method,
        "path": r.path,
        "query": r.query_string.decode(),
        "user_agent": r.user_agent.string,
        "remote_addr": (
            forwarded.split(",")[0].strip() if forwarded else (r.remote_addr or "")
        ),
        "headers": dict(r.headers),
        "cookies": dict(r.cookies),
        "form": dict(r.form),
        "json": r.get_json(silent=True) if r.is_json else None,
        "secure": r.is_secure,
    }


def _to_response(result: _Response) -> flask.Response:
    response = flask.Response(
        result.body,
        status=result.status,
        headers=result.headers,
    )
    if result.cookie:
        response.set_cookie(**result.cookie)
    return response


def _make_claims(user_agent: str, client_id: str, **overrides) -> types.SimpleNamespace:
    crawling = _is_crawler(user_agent)
    return types.SimpleNamespace(
        **{
            "score": None,
            "matched_rule": None,
            "blocklist_match": None,
            "is_crawler": crawling,
            "crawler_name": _crawler_name(user_agent) if crawling else None,
            "client_id": client_id,
            **overrides,
        }
    )


class _Response:
    def __init__(
        self, status: int, headers: dict, body: str, cookie: dict | None = None
    ):
        self.status = status
        self.headers = headers
        self.body = body
        self.cookie = cookie


def _error(use_json: bool, status: int, message: str) -> _Response:
    if use_json:
        body = json.dumps({"error": message.lower()})
        return _Response(status, dict(_JSON_CT), body)
    return _Response(status, {"Content-Type": "text/plain"}, message)


class Vouch:
    """Flask middleware that issues bot challenges and grants signed access cookies.

    Usage::

        app = Flask(__name__)
        bouncer = Vouch(app, secret="change-me")

    Application factory::

        bouncer = Vouch(secret="change-me")
        bouncer.init_app(app)

    Config via ``app.config`` with ``VOUCH_`` prefix::

        app.config["VOUCH_COOKIE_NAME"] = "_b"
        app.config["VOUCH_COOKIE_TTL"] = 3600
    """

    def __init__(self, app=None, **kwargs: Unpack[VouchKwargs]):
        self._kwargs = kwargs
        self._excludes: list = []
        self._json_mode: bool | Callable[[Request], bool] = kwargs.get("json_mode", False)
        self._exempt_endpoints: set[str] = set()
        self._engine: Engine | None = None

        if kwargs.get("secret") or kwargs.get("engine"):
            self._configure(dict(kwargs))

        if app is not None:
            self.init_app(app)

    def _configure(self, options: dict) -> None:
        options = dict(options)
        self._excludes = [re.compile(p) for p in (options.pop("exclude", None) or [])]
        self._json_mode = options.pop("json_mode", False)
        engine = options.pop("engine", None)
        secret = options.pop("secret", None)
        self._engine = engine or Engine(secret=secret, **options)

    @property
    def engine(self) -> Engine:
        assert self._engine, "Call init_app() first or pass secret= at construction"
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
        return any(p.search(path) for p in self._excludes)

    def is_verify(self, method: str, path: str) -> bool:
        return method == "POST" and path == self.verify_path

    def _is_json(self, request: Request) -> bool:
        if callable(self._json_mode):
            return self._json_mode(request)
        return self._json_mode

    def _rate_limited(self, request: Request, scope: str, limit: int) -> bool:
        ip_hash = self.engine._hash_ip(request["remote_addr"])
        return not self.engine._rate_limiter.hit(
            f"{scope}:{ip_hash}", limit, self.engine.policy.rate_limit_window
        )

    def _retry_challenge(self, request: Request, redirect: str) -> _Response:
        challenge = self.engine.issue_challenge(
            self.engine.policy.default_difficulty, request
        )
        body = self.engine.render_challenge(
            challenge, redirect, request, error=_RETRY_ERROR
        )
        headers = _challenge_headers(self.engine.policy.challenge_handler)
        return _Response(429, headers, body)

    def _challenge(self, difficulty: int, request: Request, use_json: bool) -> _Response:
        policy = self.engine.policy
        if self._rate_limited(request, "gen", policy.max_challenge_requests):
            return _error(use_json, 403, "Too Many Requests")

        challenge = self.engine.issue_challenge(difficulty, request)
        path = request["path"]

        if use_json:
            payload = policy.challenge_handler.render_payload(
                challenge, self.verify_path, path
            )
            payload["csrfToken"] = self.engine.generate_csrf_token(
                challenge.id, request
            )
            body = json.dumps({"challenge": payload})
            return _Response(200, dict(_JSON_CT), body)

        body = self.engine.render_challenge(challenge, path, request)
        return _Response(200, _challenge_headers(policy.challenge_handler), body)

    def _handle_poll(self, body: dict) -> _Response:
        handler = self.engine.policy.challenge_handler
        result = handler.handle_http_poll(body, self.engine)
        return _Response(200, dict(_JSON_CT), json.dumps(result))

    def _handle_verify(self, request: Request) -> _Response:
        form = request["form"]
        nonce = form.get("nonce") or ",".join(
            filter(None, [form.get("nonce.x", ""), form.get("nonce.y", "")])
        )
        token = self.engine.validate_challenge(
            form.get("id", ""), nonce, request, form.get("csrf_token", "")
        )
        use_json = self._is_json(request)
        redirect = _safe_redirect(form.get("redirect", "/"))
        policy = self.engine.policy

        if not token:
            if self._rate_limited(request, "fail", policy.max_challenge_failures):
                return _error(use_json, 403, "Too Many Requests")
            if use_json:
                return _error(True, 403, "Invalid")
            if policy.challenge_handler.retry_on_failure:
                return self._retry_challenge(request, redirect)
            return _error(False, 403, "Invalid")

        if use_json:
            return _Response(200, dict(_JSON_CT), json.dumps({"token": token}))

        cookie = {
            "key": policy.cookie_name,
            "value": token,
            "max_age": policy.cookie_ttl,
            "path": "/",
            "httponly": True,
            "samesite": "Strict",
            "secure": policy.cookie_secure and request.get("secure", False),
        }
        return _Response(302, {"Location": redirect}, "", cookie=cookie)

    def _verified_claims(self, request: Request) -> bool:
        cookie = request["cookies"].get(self.engine.policy.cookie_name)
        if not cookie:
            return False
        claims = self.engine.check_cookie(cookie, request)
        if not claims or not self.engine.check_token_limit(claims["cid"]):
            return False
        client_id = self.engine.generate_client_id(request)
        request["_claims"] = _make_claims(request["user_agent"], client_id, **claims)
        return True

    def process_request(
        self, request: Request, force: str | None = None, deny_challenges: bool = False
    ) -> _Response | None:
        if self.is_excluded(request["path"]):
            return None

        if self.is_verify(request["method"], request["path"]):
            return self._verify_route(request)

        if self._verified_claims(request):
            return None

        if force:
            action, difficulty, matched_rule = force, None, None
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
            return _Response(400, dict(_JSON_CT), '{"error":"bad request"}')

        cookie = request["cookies"].get(self.engine.policy.cookie_name)
        if cookie and self.engine.check_cookie(cookie, request):
            return _error(self._is_json(request), 403, "Forbidden")
        return self._handle_verify(request)

    def _allow_claims(self, request: Request, matched_rule) -> None:
        blocklist_match = (
            _blocklist_match(self.engine.blocklist, request["remote_addr"])
            if matched_rule and matched_rule.blocklist
            else None
        )
        request["_claims"] = _make_claims(
            request["user_agent"],
            self.engine.generate_client_id(request),
            matched_rule=matched_rule.name if matched_rule else None,
            blocklist_match=blocklist_match,
        )

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

        return self._apply(_to_request())

    def _guard(self, **kwargs):
        def decorator(view):
            @wraps(view)
            def wrapper(*args, **view_kwargs):
                result = self._apply(_to_request(), **kwargs)
                return result if result else view(*args, **view_kwargs)

            wrapper._vouch_exempt = True  # type: ignore[attr-defined]
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
        view._vouch_exempt = True
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
            return self._apply(_to_request()) or ("", 200)
