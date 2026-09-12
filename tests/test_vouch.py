from __future__ import annotations

import json
import re
import time
from typing import Any

import flask
import pytest

from flask_vouch import (
    Engine,
    Policy,
    Rule,
    Vouch,
    __version__,
    jwt_decode,
    jwt_encode,
    load_policy,
)
from flask_vouch.challenges import ChallengeBase
from flask_vouch.challenges.base import count_leading_zero_bits as _count_lzb
from flask_vouch.challenges.sha256_balloon import _balloon
from flask_vouch.policy import CHALLENGE_TTL, COOKIE_NAME, Request
from flask_vouch.stores import ChallengeStore

SECRET = "test-secret-key-32-bytes-long!!!"


def make_request(
    method="GET",
    path="/",
    user_agent="Mozilla/5.0",
    remote_addr="1.2.3.4",
    headers=None,
    cookies=None,
    form=None,
):
    return {
        "method": method,
        "user_agent": user_agent,
        "path": path,
        "query": "",
        "remote_addr": remote_addr,
        "headers": headers or {},
        "cookies": cookies or {},
        "form": form or {},
    }


def challenge_policy():
    return Policy(rules=[Rule(name="all", action="challenge", difficulty=1)])


def deny_policy():
    return Policy(rules=[Rule(name="bad", action="deny", user_agent="BadBot")])


def solve(engine, remote_addr="1.2.3.4"):
    from flask_vouch.challenges import SHA256Balloon

    request = make_request(remote_addr=remote_addr)
    challenge = engine.issue_challenge(1, request)
    handler = engine.policy.challenge_handler
    assert isinstance(handler, SHA256Balloon)
    for nonce in range(200_000):
        result = _balloon(
            challenge.random_data,
            nonce,
            handler.space_cost,
            handler.time_cost,
            handler.delta,
        )
        if _count_lzb(result) >= 1:
            return challenge.id, str(nonce)
    raise RuntimeError("unsolvable")


def extract_challenge(html):
    if isinstance(html, bytes):
        html = html.decode()
    match = re.search(r"JSON\.parse\('(.+?)'\)", html)
    return json.loads(match.group(1)) if match else None


def solve_pow(challenge):
    for nonce in range(500_000):
        result = _balloon(
            challenge["data"],
            nonce,
            challenge["spaceCost"],
            challenge["timeCost"],
            challenge["delta"],
        )
        if _count_lzb(result) >= challenge["difficulty"]:
            return str(nonce)
    raise RuntimeError("unsolvable")


# --- JWT ---


class TestJWT:
    def test_encode_decode(self):
        secret = b"secret-key-32-bytes-long!!!!!!!!"
        claims: dict[str, Any] = {"sub": "test", "exp": int(time.time()) + 3600}
        token = jwt_encode(claims, secret)
        decoded = jwt_decode(token, secret)
        assert decoded["sub"] == "test"

    def test_expired_token(self):
        secret = b"secret-key-32-bytes-long!!!!!!!!"
        token = jwt_encode({"exp": int(time.time()) - 1}, secret)
        with pytest.raises(ValueError, match="expired"):
            jwt_decode(token, secret)

    def test_invalid_signature(self):
        secret = b"secret-key-32-bytes-long!!!!!!!!"
        token = jwt_encode({"exp": int(time.time()) + 3600}, secret)
        with pytest.raises(ValueError, match="signature"):
            jwt_decode(token, b"wrong-key-32-bytes!!!!!!!!!!!!!!!")

    def test_malformed_token(self):
        with pytest.raises(ValueError, match="invalid"):
            jwt_decode("not.a.valid.token", b"key")

    def test_tampered_payload(self):
        secret = b"secret-key-32-bytes-long!!!!!!!!"
        token = jwt_encode({"exp": int(time.time()) + 3600}, secret)
        parts = token.split(".")
        parts[1] = parts[1][::-1]
        with pytest.raises(ValueError):
            jwt_decode(".".join(parts), secret)


# --- Store ---


class TestStore:
    def test_set_and_get(self):
        store = ChallengeStore()
        c = ChallengeBase(
            id="abc",
            random_data="ff",
            difficulty=1,
            ip_hash="x",
            created_at=time.time(),
        )
        store.set(c)
        assert store.get("abc") is c

    def test_missing_key(self):
        assert ChallengeStore().get("nope") is None

    def test_expiry(self):
        store = ChallengeStore()
        c = ChallengeBase(
            id="old",
            random_data="ff",
            difficulty=1,
            ip_hash="x",
            created_at=time.time() - CHALLENGE_TTL - 1,
        )
        store.set(c)
        assert store.get("old") is None


# --- Rule ---


class TestRule:
    def test_user_agent_match(self):
        rule = Rule(name="t", user_agent="(?i:scrapy)")
        assert rule.matches(make_request(user_agent="Scrapy/2.0"))
        assert not rule.matches(make_request(user_agent="Mozilla/5.0"))

    def test_path_match(self):
        rule = Rule(name="t", path="/admin")
        assert rule.matches(make_request(path="/admin"))
        assert not rule.matches(make_request(path="/"))

    def test_cidr_match(self):
        rule = Rule(name="t", remote_addresses=["10.0.0.0/8"])
        assert rule.matches(make_request(remote_addr="10.1.2.3"))
        assert not rule.matches(make_request(remote_addr="192.168.1.1"))

    def test_invalid_ip(self):
        rule = Rule(name="t", remote_addresses=["10.0.0.0/8"])
        assert not rule.matches(make_request(remote_addr="not-an-ip"))

    def test_no_criteria_matches_all(self):
        assert Rule(name="t").matches(make_request())


# --- Policy ---


class TestPolicy:
    def test_allow_rule(self):
        policy = Policy(
            rules=[Rule(name="bot", action="allow", user_agent="Googlebot")]
        )
        action, _, _ = policy.evaluate(make_request(user_agent="Googlebot/2.1"))
        assert action == "allow"

    def test_deny_rule(self):
        policy = Policy(rules=[Rule(name="bad", action="deny", user_agent="AhrefsBot")])
        action, _, _ = policy.evaluate(make_request(user_agent="AhrefsBot/7.0"))
        assert action == "deny"

    def test_challenge_rule(self):
        policy = Policy(
            rules=[
                Rule(name="s", action="challenge", difficulty=8, user_agent="Scrapy")
            ]
        )
        action, diff, _ = policy.evaluate(make_request(user_agent="Scrapy/2.0"))
        assert action == "challenge"
        assert diff == 8

    def test_weight_accumulation(self):
        policy = Policy(
            rules=[
                Rule(name="w1", action="weigh", weight=3, user_agent="curl"),
                Rule(name="w2", action="weigh", weight=3, headers={"Accept": "^$"}),
            ],
            challenge_threshold=5,
        )
        action, _, _ = policy.evaluate(
            make_request(user_agent="curl/7", headers={"Accept": ""})
        )
        assert action == "challenge"

    def test_no_match_allows(self):
        policy = Policy(rules=[Rule(name="s", action="deny", user_agent="SomeBot")])
        action, _, _ = policy.evaluate(make_request(user_agent="Mozilla/5.0"))
        assert action == "allow"

    def test_load_default_policy(self):
        policy = load_policy()
        assert len(policy.rules) > 0
        assert policy.challenge_threshold == 5


# --- Engine ---


class TestEngine:
    def make_engine(self, **kwargs):
        policy = kwargs.pop("policy", Policy(rules=[]))
        return Engine(secret=SECRET, policy=policy, **kwargs)

    def make_bouncer(self, **kwargs):
        return Vouch(engine=self.make_engine(**kwargs))

    def test_process_allows_normal(self):
        assert self.make_bouncer().process_request(make_request()) is None

    def test_process_denies_bad_bot(self):
        bouncer = self.make_bouncer(
            policy=Policy(rules=[Rule(name="bad", action="deny", user_agent="BadBot")])
        )
        result = bouncer.process_request(make_request(user_agent="BadBot/1.0"))
        assert result.status == 403
        assert result.body == "Forbidden"

    def test_process_challenges_scraper(self):
        bouncer = self.make_bouncer(
            policy=Policy(
                rules=[
                    Rule(
                        name="s", action="challenge", difficulty=2, user_agent="Scrapy"
                    )
                ]
            )
        )
        result = bouncer.process_request(make_request(user_agent="Scrapy/2.0"))
        assert result.status == 200
        assert "challenge" in result.body.lower()
        assert result.headers["Cache-Control"] == "no-store"

    def test_issue_and_validate_challenge(self):
        engine = self.make_engine()
        request = make_request()
        cid, nonce = solve(engine)
        token = engine.validate_challenge(cid, nonce, request)
        assert token is not None
        assert len(token.split(".")) == 3

    def test_challenge_single_use(self):
        engine = self.make_engine()
        request = make_request()
        cid, nonce = solve(engine)
        engine.validate_challenge(cid, nonce, request)
        assert engine.validate_challenge(cid, nonce, request) is None

    def test_challenge_ip_binding(self):
        engine = self.make_engine()
        cid, nonce = solve(engine, remote_addr="1.2.3.4")
        token = engine.validate_challenge(
            cid, nonce, make_request(remote_addr="5.6.7.8")
        )
        assert token is None

    def test_cookie_round_trip(self):
        engine = self.make_engine()
        request = make_request()
        cid, nonce = solve(engine)
        token = engine.validate_challenge(cid, nonce, request)
        assert token is not None
        assert engine.check_cookie(token, request)

    def test_cookie_wrong_ip(self):
        engine = self.make_engine(policy=challenge_policy())
        engine.policy.bind_ip = True
        cid, nonce = solve(engine, remote_addr="1.2.3.4")
        token = engine.validate_challenge(
            cid, nonce, make_request(remote_addr="1.2.3.4")
        )
        assert token is not None
        assert not engine.check_cookie(token, make_request(remote_addr="9.9.9.9"))

    def test_cookie_invalid(self):
        assert not self.make_engine().check_cookie("garbage", make_request())

    def test_render_challenge_contains_data(self):
        engine = self.make_engine()
        req = make_request()
        challenge = engine.issue_challenge(4, req)
        html = engine.render_challenge(challenge, "/")
        assert challenge.id in html
        assert challenge.random_data in html


# --- Vouch (process_request) ---


class TestBouncerBase:
    def make_bouncer(self, **kwargs):
        policy = kwargs.pop("policy", Policy(rules=[]))
        return Vouch(secret=SECRET, policy=policy, **kwargs)

    def test_allows_normal(self):
        bouncer = self.make_bouncer()
        assert bouncer.process_request(make_request()) is None

    def test_denies(self):
        bouncer = self.make_bouncer(policy=deny_policy())
        result = bouncer.process_request(make_request(user_agent="BadBot"))
        assert result is not None
        assert result.status == 403
        assert result.body == "Forbidden"

    def test_challenges_html(self):
        bouncer = self.make_bouncer(policy=challenge_policy())
        result = bouncer.process_request(make_request())
        assert result is not None
        assert result.status == 200
        assert "challenge" in result.body.lower()

    def test_exclude(self):
        bouncer = self.make_bouncer(policy=challenge_policy(), exclude=[r"^/health"])
        assert bouncer.process_request(make_request(path="/health")) is None
        result = bouncer.process_request(make_request(path="/api"))
        assert result is not None and result.status == 200

    def test_cookie_bypass(self):
        bouncer = self.make_bouncer(policy=challenge_policy())
        cid, nonce = solve(bouncer.engine)
        result = bouncer.process_request(
            make_request(
                method="POST",
                path=bouncer.verify_path,
                form={"id": cid, "nonce": nonce, "redirect": "/"},
            )
        )
        assert result is not None and result.status == 302
        cookie_val = result.cookie["value"]
        assert (
            bouncer.process_request(make_request(cookies={COOKIE_NAME: cookie_val}))
            is None
        )

    def test_json_challenge(self):
        bouncer = self.make_bouncer(policy=challenge_policy(), json_mode=True)
        result = bouncer.process_request(make_request())
        assert result is not None and result.status == 200
        data = json.loads(result.body)
        assert "id" in data["challenge"]
        assert result.headers["Content-Type"] == "application/json"

    def test_json_deny(self):
        bouncer = self.make_bouncer(policy=deny_policy(), json_mode=True)
        result = bouncer.process_request(make_request(user_agent="BadBot"))
        assert result is not None and result.status == 403
        assert json.loads(result.body)["error"] == "forbidden"

    def test_html_verify_success(self):
        bouncer = self.make_bouncer()
        cid, nonce = solve(bouncer.engine)
        result = bouncer.process_request(
            make_request(
                method="POST",
                path=bouncer.verify_path,
                form={"id": cid, "nonce": nonce, "redirect": "/ok"},
            )
        )
        assert result is not None and result.status == 302
        assert result.headers["Location"] == "/ok"
        assert result.cookie["key"] == COOKIE_NAME

    def test_html_verify_failure(self):
        bouncer = self.make_bouncer()
        result = bouncer.process_request(
            make_request(
                method="POST",
                path=bouncer.verify_path,
                form={"id": "fake", "nonce": "0"},
            )
        )
        assert result is not None and result.status == 403
        assert result.body == "Invalid"

    def test_verify_blocked_with_valid_clearance(self):
        bouncer = self.make_bouncer()
        cid, nonce = solve(bouncer.engine)
        first = bouncer.process_request(
            make_request(
                method="POST",
                path=bouncer.verify_path,
                form={"id": cid, "nonce": nonce, "redirect": "/ok"},
            )
        )
        assert first is not None and first.status == 302
        token = first.cookie["value"]
        result = bouncer.process_request(
            make_request(
                method="POST",
                path=bouncer.verify_path,
                cookies={COOKIE_NAME: token},
                form={"id": "any", "nonce": "0"},
            )
        )
        assert result is not None and result.status == 403

    def test_redirect_sanitization(self):
        bouncer = self.make_bouncer()
        cid, nonce = solve(bouncer.engine)
        for bad in ["//evil.com", "https://evil.com", "javascript:alert(1)"]:
            stored = bouncer.engine.store.get(cid)
            assert stored is not None
            stored.spent = False
            result = bouncer.process_request(
                make_request(
                    method="POST",
                    path=bouncer.verify_path,
                    form={"id": cid, "nonce": nonce, "redirect": bad},
                )
            )
            assert result is not None
            assert result.headers["Location"] == "/"

    def test_is_verify(self):
        bouncer = self.make_bouncer()
        assert bouncer.is_verify("POST", bouncer.verify_path)
        assert not bouncer.is_verify("GET", bouncer.verify_path)
        assert not bouncer.is_verify("POST", "/other")

    def test_is_excluded(self):
        bouncer = self.make_bouncer(exclude=[r"^/static/", r"^/health$"])
        assert bouncer.is_excluded("/static/foo.js")
        assert bouncer.is_excluded("/health")
        assert not bouncer.is_excluded("/api")


# --- Flask integration ---


class TestFlask:
    def make_app(self, **kwargs):
        policy = kwargs.pop("policy", Policy(rules=[]))
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        bouncer = Vouch(app, secret=SECRET, policy=policy, **kwargs)

        @app.route("/")
        def index():
            return "OK"

        @app.route("/public")
        @bouncer.exempt
        def public():
            return "public"

        return app, bouncer

    def test_allows_normal(self):
        app, _ = self.make_app()
        with app.test_client() as c:
            assert c.get("/").status_code == 200

    def test_challenges(self):
        app, _ = self.make_app(policy=challenge_policy())
        with app.test_client() as c:
            assert c.get("/").status_code == 200

    def test_exempt_skips(self):
        app, _ = self.make_app(policy=challenge_policy())
        with app.test_client() as c:
            resp = c.get("/public")
            assert resp.status_code == 200
            assert resp.data == b"public"

    def make_static_app(self, tmp_path):
        (tmp_path / "app.css").write_text("body{}")
        app = flask.Flask(
            __name__, static_folder=str(tmp_path), static_url_path="/static"
        )
        app.config["TESTING"] = True
        blueprint = flask.Blueprint(
            "admin",
            __name__,
            static_folder=str(tmp_path),
            static_url_path="/static",
            url_prefix="/admin",
        )
        app.register_blueprint(blueprint)
        return app, Vouch(app, secret=SECRET, policy=challenge_policy())

    def test_exempt_endpoint_name(self, tmp_path):
        app, bouncer = self.make_static_app(tmp_path)
        bouncer.exempt("static")
        with app.test_client() as c:
            assert c.get("/static/app.css").data == b"body{}"
            assert c.get("/admin/static/app.css").data != b"body{}"

    def test_exempt_blueprint_static(self, tmp_path):
        app, bouncer = self.make_static_app(tmp_path)
        bouncer.exempt("admin.static")
        with app.test_client() as c:
            assert c.get("/admin/static/app.css").data == b"body{}"

    def test_exempt_endpoint_before_init_app(self, tmp_path):
        (tmp_path / "app.css").write_text("body{}")
        app = flask.Flask(
            __name__, static_folder=str(tmp_path), static_url_path="/static"
        )
        app.config["TESTING"] = True
        bouncer = Vouch(secret=SECRET, policy=challenge_policy())
        bouncer.exempt("static")
        bouncer.init_app(app)
        with app.test_client() as c:
            assert c.get("/static/app.css").data == b"body{}"

    def test_denies_bad_bot(self):
        app, _ = self.make_app(policy=deny_policy())
        with app.test_client() as c:
            resp = c.get("/", headers={"User-Agent": "BadBot"})
            assert resp.status_code == 403

    def test_verify_flow(self):
        app, bouncer = self.make_app(policy=challenge_policy())
        with app.test_client() as c:
            resp = c.get("/")
            assert resp.status_code == 200
            challenge = extract_challenge(resp.data)
            assert challenge is not None
            nonce = solve_pow(challenge)
            resp = c.post(
                bouncer.verify_path,
                data={"id": challenge["id"], "nonce": nonce, "redirect": "/"},
            )
            assert resp.status_code == 302

    def test_init_app_deferred(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        bouncer = Vouch(secret=SECRET, policy=Policy(rules=[]))

        @app.route("/")
        def index():
            return "OK"

        bouncer.init_app(app)
        assert "vouch" in app.extensions
        with app.test_client() as c:
            assert c.get("/").status_code == 200

    def test_protect_method(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        bouncer = Vouch(secret=SECRET, policy=challenge_policy())

        @app.route("/guarded")
        @bouncer.protect
        def guarded():
            return "guarded"

        with app.test_client() as c:
            assert c.get("/guarded").status_code == 200

    def test_block_method_passes_non_crawler(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        bouncer = Vouch(secret=SECRET, policy=Policy(rules=[]))

        @app.route("/sensitive")
        @bouncer.block
        def sensitive():
            return "ok"

        with app.test_client() as c:
            resp = c.get(
                "/sensitive",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            assert resp.status_code == 200


# --- Weighted escalation ---


class TestWeightEscalation:
    def policy(self, **kwargs):
        return Policy(
            rules=[
                Rule(name="c", action="challenge", user_agent="Mozilla"),
                Rule(name="w1", action="weigh", weight=4, headers={"X-A": ".*"}),
                Rule(name="w2", action="weigh", weight=4, headers={"X-B": ".*"}),
            ],
            **kwargs,
        )

    def test_weigh_rules_run_after_a_challenge_rule(self):
        action, difficulty, rule = self.policy().evaluate(
            make_request(headers={"X-A": "1", "X-B": "1"})
        )
        assert (action, difficulty, rule.name) == ("challenge", 12, "c")

    def test_no_signals_keeps_base_difficulty(self):
        action, difficulty, _ = self.policy().evaluate(make_request())
        assert (action, difficulty) == ("challenge", 10)

    def test_bonus_is_capped(self):
        policy = self.policy(max_difficulty_bonus=1)
        _, difficulty, _ = policy.evaluate(
            make_request(headers={"X-A": "1", "X-B": "1"})
        )
        assert difficulty == 11

    def test_deny_threshold_overrides_challenge(self):
        policy = self.policy(deny_threshold=8)
        action, _, _ = policy.evaluate(make_request(headers={"X-A": "1", "X-B": "1"}))
        assert action == "deny"

    def test_deny_threshold_off_by_default(self):
        assert Policy(rules=[]).deny_threshold == 0

    def test_difficulty_step_zero_disables_bonus(self):
        policy = self.policy(difficulty_step=0)
        _, difficulty, _ = policy.evaluate(
            make_request(headers={"X-A": "1", "X-B": "1"})
        )
        assert difficulty == 10


# --- missing_headers ---


class TestMissingHeaders:
    def rule(self):
        return Rule(name="m", missing_headers=["Accept", "Accept-Language"])

    def test_matches_when_all_absent(self):
        assert self.rule().matches(make_request(headers={}))

    def test_matches_when_present_but_empty(self):
        assert self.rule().matches(make_request(headers={"Accept": ""}))

    def test_no_match_when_one_present(self):
        assert not self.rule().matches(make_request(headers={"Accept": "text/html"}))


# --- Verified bots ---


class TestVerifiedBots:
    def request(self, user_agent="Googlebot/2.1"):
        return make_request(user_agent=user_agent)

    def test_operator_read_from_user_agent(self):
        from flask_vouch import bot_operator

        assert bot_operator("Mozilla/5.0 (compatible; Googlebot/2.1)") == "googlebot"
        assert bot_operator("Mozilla/5.0 (compatible; Bingbot/2.0)") == "bingbot"
        assert bot_operator("Mozilla/5.0") is None

    def test_unknown_operator_never_verifies(self):
        from flask_vouch import verify_operator

        assert not verify_operator("nosuchbot", "1.2.3.4")

    def test_rule_rejects_unverifiable_claim(self, monkeypatch):
        import flask_vouch.policy as policy_module

        monkeypatch.setattr(policy_module, "is_verified_bot", lambda ua, ip: False)
        assert not Rule(name="v", verified_bot=True).matches(self.request())

    def test_rule_accepts_verified_claim(self, monkeypatch):
        import flask_vouch.policy as policy_module

        monkeypatch.setattr(policy_module, "is_verified_bot", lambda ua, ip: True)
        assert Rule(name="v", verified_bot=True).matches(self.request())

    def test_verify_bots_off_falls_back_to_user_agent(self, monkeypatch):
        import flask_vouch.policy as policy_module

        monkeypatch.setattr(policy_module, "is_verified_bot", lambda ua, ip: False)
        rule = Rule(name="v", verified_bot=True)
        assert rule.matches(self.request(), verify_bots=False)

    def test_verification_result_is_cached(self, monkeypatch):
        import flask_vouch.crawlers as crawlers

        calls = []
        monkeypatch.setattr(crawlers, "_verify_cache", crawlers._VerifyCache())
        monkeypatch.setattr(
            crawlers, "_confirm", lambda op, ip: calls.append(ip) or True
        )
        assert crawlers.verify_operator("googlebot", "9.9.9.9")
        assert crawlers.verify_operator("googlebot", "9.9.9.9")
        assert len(calls) == 1


# --- Response hardening, refresh, metrics ---


class TestHardening:
    def app(self, **kwargs):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        bouncer = Vouch(app, secret=SECRET, **kwargs)

        @app.route("/")
        def index():
            return "ok"

        return app, bouncer

    def test_challenge_page_is_not_indexable(self):
        app, _ = self.app()
        resp = app.test_client().get("/", headers={"User-Agent": "curl/8.0"})
        assert resp.headers["X-Robots-Tag"] == "noindex, nofollow"
        assert resp.headers["Referrer-Policy"] == "no-referrer"

    def test_rate_limited_response_carries_retry_after(self):
        app, bouncer = self.app(max_challenge_requests=1)
        client = app.test_client()
        client.get("/", headers={"User-Agent": "curl/8.0"})
        resp = client.get("/", headers={"User-Agent": "curl/8.0"})
        assert resp.status_code == 429
        assert resp.headers["Retry-After"] == str(
            bouncer.engine.policy.rate_limit_window
        )

    def test_forbidden_response_is_not_indexable(self):
        app, _ = self.app(policy=Policy(rules=[Rule(name="d", action="deny")]))
        resp = app.test_client().get("/")
        assert resp.status_code == 403
        assert resp.headers["X-Robots-Tag"] == "noindex, nofollow"

    def stale_cookie(self, engine, age):
        request = make_request()
        claims = jwt_decode(engine.issue_cookie(request, "cid", {}), engine.secret)
        claims["iat"] = int(time.time()) - age
        return jwt_encode(claims, engine.secret)

    def test_old_cookie_is_reissued(self):
        app, bouncer = self.app()
        engine = bouncer.engine
        client = app.test_client()
        client.set_cookie(
            COOKIE_NAME, self.stale_cookie(engine, engine.policy.cookie_ttl - 10)
        )
        resp = client.get("/")
        assert resp.status_code == 200
        assert COOKIE_NAME in resp.headers.get("Set-Cookie", "")

    def test_fresh_cookie_is_left_alone(self):
        app, bouncer = self.app()
        client = app.test_client()
        client.set_cookie(COOKIE_NAME, self.stale_cookie(bouncer.engine, 0))
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Set-Cookie" not in resp.headers

    def test_refresh_can_be_turned_off(self):
        app, bouncer = self.app(cookie_refresh=False)
        engine = bouncer.engine
        client = app.test_client()
        client.set_cookie(
            COOKIE_NAME, self.stale_cookie(engine, engine.policy.cookie_ttl - 10)
        )
        assert "Set-Cookie" not in client.get("/").headers

    def test_cookie_domain_is_applied(self):
        app, _ = self.app(cookie_domain=".example.com")
        resp = app.test_client().get("/", headers={"User-Agent": "curl/8.0"})
        assert resp.status_code == 200

    def test_metrics_count_decisions(self):
        app, bouncer = self.app()
        app.test_client().get("/", headers={"User-Agent": "curl/8.0"})
        assert bouncer.metrics.snapshot()["challenge"] == 1
        bouncer.metrics.reset()
        assert bouncer.metrics.snapshot() == {}

    def test_on_decision_hook_receives_rule(self):
        seen: list[Any] = []
        app, _ = self.app(
            policy=Policy(rules=[Rule(name="d", action="deny")]),
            on_decision=lambda action, request, rule: seen.append((action, rule.name)),
        )
        app.test_client().get("/")
        assert seen == [("deny", "d")]


# --- Challenges are one-shot ---


class TestChallengeConsumption:
    def engine(self):
        from flask_vouch.challenges import SHA256

        return Engine(
            secret=SECRET, policy=Policy(rules=[], challenge_handler=SHA256())
        )

    def solved(self, engine, request):
        challenge = engine.issue_challenge(0, request)
        handler = engine.policy.challenge_handler
        nonce = next(
            n
            for n in range(200_000)
            if handler.verify(challenge.random_data, n, challenge.difficulty)
        )
        return challenge, str(nonce)

    def test_solution_redeems_once(self):
        engine = self.engine()
        request = make_request()
        challenge, nonce = self.solved(engine, request)
        assert engine.validate_challenge(challenge.id, nonce, request)
        assert engine.validate_challenge(challenge.id, nonce, request) is None

    def test_concurrent_redemptions_yield_one_cookie(self):
        from concurrent.futures import ThreadPoolExecutor

        engine = self.engine()
        request = make_request()
        challenge, nonce = self.solved(engine, request)

        with ThreadPoolExecutor(16) as pool:
            tokens = list(
                pool.map(
                    lambda _: engine.validate_challenge(challenge.id, nonce, request),
                    range(16),
                )
            )
        assert sum(token is not None for token in tokens) == 1

    def test_wrong_answer_burns_the_challenge(self):
        engine = self.engine()
        request = make_request()
        challenge = engine.issue_challenge(0, request)
        assert engine.validate_challenge(challenge.id, "0", request) is None
        assert engine.store.consume(challenge.id) is None


# --- Extras hardening ---


class TestExtrasHardening:
    def app(self, **kwargs):
        from flask_vouch.extras import RateLimiter

        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        limiter = RateLimiter(**kwargs)
        return app, limiter

    def test_forwarded_for_is_ignored_without_trusted_proxies(self):
        app, limiter = self.app(default="2/minute")
        limiter.init_flask(app)
        app.route("/")(lambda: "ok")
        client = app.test_client()
        codes = [
            client.get("/", headers={"X-Forwarded-For": f"9.9.9.{n}"}).status_code
            for n in range(4)
        ]
        assert codes == [200, 200, 429, 429]

    def test_forwarded_for_honoured_when_trusted(self):
        app, limiter = self.app(default="2/minute", trusted_proxies=1)
        limiter.init_flask(app)
        app.route("/")(lambda: "ok")
        client = app.test_client()
        codes = [
            client.get("/", headers={"X-Forwarded-For": f"9.9.9.{n}"}).status_code
            for n in range(4)
        ]
        assert codes == [200] * 4

    def test_retry_after_matches_the_window(self):
        app, limiter = self.app(default="1/day")
        limiter.init_flask(app)
        app.route("/")(lambda: "ok")
        client = app.test_client()
        client.get("/")
        assert client.get("/").headers["Retry-After"] == "86400"

    def test_route_limit_replaces_the_global_budget(self):
        app, limiter = self.app(default="2/minute")

        @app.route("/x")
        @limiter.limit("10/minute")
        def x():
            return "ok"

        limiter.init_flask(app)
        client = app.test_client()
        assert [client.get("/x").status_code for _ in range(5)] == [200] * 5

    def test_error_handler_styles_vouch_refusals(self):
        from flask_vouch.extras import ErrorHandler

        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        vouch = Vouch(app, secret=SECRET, policy=Policy(rules=[Rule("d", "deny")]))
        ErrorHandler(vouch=vouch).init_flask(app)
        app.route("/")(lambda: "ok")

        resp = app.test_client().get("/")
        assert resp.status_code == 403
        assert resp.headers["Content-Type"] == "text/html; charset=utf-8"
        assert b"Forbidden" in resp.data and len(resp.data) > 200

    def test_error_handler_escapes_and_substitutes_once(self):
        from flask_vouch.extras import ErrorHandler

        handler = ErrorHandler(template="<p>{{detail}}</p>")
        assert handler.render(404, detail="<b>x</b>") == "<p>&lt;b&gt;x&lt;/b&gt;</p>"
        assert handler.render(404, detail="{{title}}") == "<p>{{title}}</p>"


# --- Altcha ---


class TestAltcha:
    def solve(self, altcha, hardness=1):
        import hashlib
        from base64 import b64encode

        challenge = altcha.create_challenge(hardness)
        number = next(
            n
            for n in range(200_000)
            if hashlib.sha256((challenge["salt"] + str(n)).encode()).hexdigest()
            == challenge["challenge"]
        )
        return b64encode(json.dumps({**challenge, "number": number}).encode()).decode()

    def altcha(self, **kwargs):
        from flask_vouch.extras.third_party_captcha import _Altcha

        return _Altcha(b"k" * 32, **kwargs)

    def test_valid_solution_passes(self):
        altcha = self.altcha()
        assert altcha.verify_challenge(self.solve(altcha))

    def test_replay_is_rejected(self):
        altcha = self.altcha()
        payload = self.solve(altcha)
        assert altcha.verify_challenge(payload)
        assert not altcha.verify_challenge(payload)

    def test_expired_solution_is_rejected(self):
        altcha = self.altcha(ttl=-1)
        assert not altcha.verify_challenge(self.solve(altcha))

    def test_forged_signature_is_rejected(self):
        from base64 import b64decode, b64encode

        altcha = self.altcha()
        data = json.loads(b64decode(self.solve(altcha)))
        data["signature"] = "0" * 64
        forged = b64encode(json.dumps(data).encode()).decode()
        assert not altcha.verify_challenge(forged)

    def test_garbage_is_rejected(self):
        assert not self.altcha().verify_challenge("not-base64-json")
