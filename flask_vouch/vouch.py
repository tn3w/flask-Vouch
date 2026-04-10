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
    Policy,
    Rule,
    _blocklist_match,
    _challenge_headers,
    _safe_redirect,
    crawler_name as _crawler_name,
    is_crawler as _is_crawler,
)

_PREFIX = "VOUCH_"

_JSON_CT = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
}


class VouchKwargs(EngineKwargs, total=False):
    secret: str | None
    engine: Engine | None
    exclude: list[str] | None
    json_mode: bool | Callable[[dict], bool]


def _config_kwargs(app_config):
    return {
        key[len(_PREFIX) :].lower(): value
        for key, value in app_config.items()
        if key.startswith(_PREFIX)
    }


def _to_request():
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
    }


def _to_response(result):
    return flask.Response(
        result.body,
        status=result.status,
        headers=result.headers,
    )


def _crawler_fields(user_agent: str) -> tuple[bool, str | None]:
    crawling = _is_crawler(user_agent)
    return crawling, (_crawler_name(user_agent) if crawling else None)


class _Response:
    def __init__(self, status: int, headers: dict, body: str):
        self.status = status
        self.headers = headers
        self.body = body


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
        exclude = kwargs.pop("exclude", None) if isinstance(kwargs, dict) else None
        json_mode = (
            kwargs.pop("json_mode", False) if isinstance(kwargs, dict) else False
        )
        self._excludes = [re.compile(p) for p in (exclude or [])]
        self._json_mode = json_mode
        self._engine: Engine | None = None

        secret = kwargs.get("secret")
        engine = kwargs.get("engine")
        if secret or engine:
            self._engine = engine or Engine(
                secret=secret,
                **{
                    k: v
                    for k, v in kwargs.items()
                    if k not in ("secret", "engine", "exclude", "json_mode")
                },
            )

        if app is not None:
            self.init_app(app)

    @property
    def engine(self) -> Engine:
        assert self._engine, "Call init_app() first or pass secret= at construction"
        return self._engine

    def init_app(self, app: flask.Flask) -> None:
        if not self._engine:
            merged = {**_config_kwargs(app.config), **self._kwargs}
            if "secret" not in merged and "engine" not in merged:
                merged.setdefault("secret", app.config.get("SECRET_KEY"))
            exclude = merged.pop("exclude", None)
            json_mode = merged.pop("json_mode", False)
            engine = merged.pop("engine", None)
            secret = merged.pop("secret", None)
            self._excludes = [re.compile(p) for p in (exclude or [])]
            self._json_mode = json_mode
            self._engine = engine or Engine(secret=secret, **merged)

        app.before_request(self._check)
        app.extensions["vouch"] = self

    @property
    def verify_path(self) -> str:
        return self.engine.policy.verify_path

    def is_excluded(self, path: str) -> bool:
        return any(p.search(path) for p in self._excludes)

    def is_verify(self, method: str, path: str) -> bool:
        return method == "POST" and path == self.verify_path

    def _is_json(self, request) -> bool:
        if callable(self._json_mode):
            return self._json_mode(request)
        return self._json_mode

    def _deny(self, use_json: bool) -> _Response:
        if use_json:
            return _Response(403, dict(_JSON_CT), '{"error":"forbidden"}')
        return _Response(403, {"Content-Type": "text/plain"}, "Forbidden")

    def _challenge(self, difficulty: int, request: dict, use_json: bool) -> _Response:
        ip_hash = self.engine._hash_ip(request["remote_addr"])
        if not self.engine._rate_limiter.hit(
            f"gen:{ip_hash}",
            self.engine.policy.max_challenge_requests,
            self.engine.policy.rate_limit_window,
        ):
            if use_json:
                return _Response(403, dict(_JSON_CT), '{"error":"too many requests"}')
            return _Response(403, {"Content-Type": "text/plain"}, "Too Many Requests")

        challenge = self.engine.issue_challenge(difficulty, request)
        path = request["path"]

        if use_json:
            handler = self.engine.policy.challenge_handler
            payload = handler.render_payload(challenge, self.verify_path, path)
            csrf_token = self.engine.generate_csrf_token(challenge.id, request)
            payload["csrfToken"] = csrf_token
            body = json.dumps({"challenge": payload})
            return _Response(200, dict(_JSON_CT), body)

        body = self.engine.render_challenge(challenge, path, request)
        return _Response(
            200, _challenge_headers(self.engine.policy.challenge_handler), body
        )

    def _handle_verify(self, request: dict) -> _Response:
        form = request["form"]
        nonce = form.get("nonce") or ",".join(
            filter(None, [form.get("nonce.x", ""), form.get("nonce.y", "")])
        )
        csrf_token = form.get("csrf_token", "")
        token = self.engine.validate_challenge(
            form.get("id", ""), nonce, request, csrf_token
        )
        use_json = self._is_json(request)

        if not token:
            ip_hash = self.engine._hash_ip(request["remote_addr"])
            if not self.engine._rate_limiter.hit(
                f"fail:{ip_hash}",
                self.engine.policy.max_challenge_failures,
                self.engine.policy.rate_limit_window,
            ):
                if use_json:
                    return _Response(
                        403, dict(_JSON_CT), '{"error":"too many requests"}'
                    )
                return _Response(
                    403, {"Content-Type": "text/plain"}, "Too Many Requests"
                )

            if use_json:
                return _Response(403, dict(_JSON_CT), '{"error":"invalid"}')
            if self.engine.policy.challenge_handler.retry_on_failure:
                redirect = _safe_redirect(form.get("redirect", "/"))
                challenge = self.engine.issue_challenge(
                    self.engine.policy.default_difficulty, request
                )
                body = self.engine.render_challenge(
                    challenge,
                    redirect,
                    request,
                    error='<p class="error">Incorrect \u2014 try again.</p>',
                )
                return _Response(
                    429, _challenge_headers(self.engine.policy.challenge_handler), body
                )
            return _Response(403, {"Content-Type": "text/plain"}, "Invalid")

        if use_json:
            return _Response(200, dict(_JSON_CT), json.dumps({"token": token}))

        redirect = _safe_redirect(form.get("redirect", "/"))
        p = self.engine.policy
        cookie_val = (
            f"{p.cookie_name}={token}; "
            f"Path=/; HttpOnly; SameSite=Strict; "
            f"Secure; Max-Age={p.cookie_ttl}"
        )
        return _Response(302, {"Location": redirect, "Set-Cookie": cookie_val}, "")

    def process_request(self, request: dict) -> _Response | None:
        if self.is_excluded(request["path"]):
            return None

        if self.is_verify(request["method"], request["path"]):
            cookie = request["cookies"].get(self.engine.policy.cookie_name)
            if cookie and self.engine.check_cookie(cookie, request):
                return self._deny(self._is_json(request))
            return self._handle_verify(request)

        cookie = request["cookies"].get(self.engine.policy.cookie_name)
        if cookie:
            claims = self.engine.check_cookie(cookie, request)
            if claims and self.engine.check_token_limit(claims["cid"]):
                is_crawler, crawler_name = _crawler_fields(request["user_agent"])
                client_id = self.engine.generate_client_id(request)
                request["_claims"] = types.SimpleNamespace(
                    score=None,
                    matched_rule=None,
                    blocklist_match=None,
                    is_crawler=is_crawler,
                    crawler_name=crawler_name,
                    client_id=client_id,
                    **claims,
                )
                return None

        action, difficulty, matched_rule = self.engine.policy.evaluate(
            request, self.engine.blocklist
        )

        if action == "allow":
            is_crawler, crawler_name = _crawler_fields(request["user_agent"])
            bl_match = (
                _blocklist_match(self.engine.blocklist, request["remote_addr"])
                if matched_rule and matched_rule.blocklist
                else None
            )
            client_id = self.engine.generate_client_id(request)
            request["_claims"] = types.SimpleNamespace(
                score=None,
                matched_rule=matched_rule.name if matched_rule else None,
                blocklist_match=bl_match,
                is_crawler=is_crawler,
                crawler_name=crawler_name,
                client_id=client_id,
            )
            return None

        use_json = self._is_json(request)
        if action == "deny":
            return self._deny(use_json)
        return self._challenge(difficulty, request, use_json)

    def _check(self):
        endpoint = flask.request.endpoint
        view = flask.current_app.view_functions.get(endpoint) if endpoint else None
        if view and getattr(view, "_vouch_exempt", False):
            return None

        req = _to_request()
        result = self.process_request(req)
        if result:
            return _to_response(result)
        flask.g.vouch = req.get("_claims")
        return None

    def exempt(self, view):
        """Decorator: skip bouncer check for this route."""
        view._vouch_exempt = True
        return view

    def protect(self, view):
        """Decorator: always run bouncer check on this route (overrides global allow)."""

        @wraps(view)
        def wrapper(*args, **kwargs):
            req = _to_request()
            result = self.process_request(req)
            if result:
                return _to_response(result)
            flask.g.vouch = req.get("_claims")
            return view(*args, **kwargs)

        return wrapper

    def challenge(self, view):
        """Decorator: always issue a challenge on this route regardless of policy."""

        @wraps(view)
        def wrapper(*args, **kwargs):
            req = _to_request()
            override = Vouch(engine=self.engine)
            override._engine = Engine(
                secret=self.engine.secret,
                policy=Policy(
                    rules=[Rule(name="always_challenge", action="challenge")],
                    challenge_handler=self.engine.policy.challenge_handler,
                    cookie_name=self.engine.policy.cookie_name,
                    verify_path=self.engine.policy.verify_path,
                    cookie_ttl=self.engine.policy.cookie_ttl,
                    challenge_ttl=self.engine.policy.challenge_ttl,
                ),
            )
            override._engine.store = self.engine.store
            override._engine._rate_limiter = self.engine._rate_limiter
            result = override.process_request(req)
            if result:
                return _to_response(result)
            flask.g.vouch = req.get("_claims")
            return view(*args, **kwargs)

        return wrapper

    def block(self, view):
        """Decorator: deny anything the policy would challenge or deny; pass allows."""
        view._vouch_block = True

        @wraps(view)
        def wrapper(*args, **kwargs):
            req = _to_request()
            use_json = self._is_json(req)
            cookie = req["cookies"].get(self.engine.policy.cookie_name)
            if cookie and self.engine.check_cookie(cookie, req):
                flask.g.vouch = req.get("_claims")
                return view(*args, **kwargs)
            action, _, _ = self.engine.policy.evaluate(req, self.engine.blocklist)
            if action != "allow":
                return _to_response(self._deny(use_json))
            flask.g.vouch = None
            return view(*args, **kwargs)

        return wrapper

    def mount_verify(self, app: flask.Flask) -> None:
        """Manually register the verify endpoint on a given app."""

        @app.route(self.verify_path, methods=["POST"])
        def _verify():
            req = _to_request()
            result = self.process_request(req)
            if result:
                return _to_response(result)
            return "", 200
