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
from flask_vouch.challenges.base import count_leading_zero_bits as _count_lzb
from flask_vouch.challenges.sha256_balloon import _balloon
from flask_vouch.engine import CHALLENGE_TTL, COOKIE_NAME, Challenge, Store

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


def test_version():
    assert __version__ == "1.0.0"


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
        store = Store()
        c = Challenge(
            id="abc",
            random_data="ff",
            difficulty=1,
            ip_hash="x",
            created_at=time.time(),
        )
        store.set(c)
        assert store.get("abc") is c

    def test_missing_key(self):
        assert Store().get("nope") is None

    def test_expiry(self):
        store = Store()
        c = Challenge(
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

    def test_process_allows_normal(self):
        action, _, _, _ = self.make_engine().process(make_request())
        assert action == "pass"

    def test_process_denies_bad_bot(self):
        engine = self.make_engine(
            policy=Policy(rules=[Rule(name="bad", action="deny", user_agent="BadBot")])
        )
        action, status, _, body = engine.process(make_request(user_agent="BadBot/1.0"))
        assert action == "deny"
        assert status == 403
        assert body == "Forbidden"

    def test_process_challenges_scraper(self):
        engine = self.make_engine(
            policy=Policy(
                rules=[
                    Rule(
                        name="s", action="challenge", difficulty=2, user_agent="Scrapy"
                    )
                ]
            )
        )
        action, status, headers, body = engine.process(
            make_request(user_agent="Scrapy/2.0")
        )
        assert action == "challenge"
        assert status == 200
        assert "challenge" in body.lower()
        assert headers["Cache-Control"] == "no-store"

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
        engine = self.make_engine()
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
        html = engine.render_challenge(challenge, "/", req)
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
        cookie_val = result.headers["Set-Cookie"].split("=", 1)[1].split(";")[0]
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
        assert COOKIE_NAME in result.headers["Set-Cookie"]

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
        token = first.headers["Set-Cookie"].split("=", 1)[1].split(";")[0]
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
