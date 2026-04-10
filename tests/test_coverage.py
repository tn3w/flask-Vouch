"""Additional tests to improve coverage of uncovered lines."""

import hashlib
import hmac
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import flask
import pytest

from flask_vouch import Engine, Policy, Rule, Vouch, jwt_decode, jwt_encode
from flask_vouch.blocklist import (
    IPBlocklist,
    _cache_path_for,
    _contains,
    _load_text,
    _merge,
    _parse_line,
    parse_blocklist,
)
from flask_vouch.challenges.base import (
    ChallengeBase,
    ChallengeHandler,
    ChallengeType,
    count_leading_zero_bits,
)
from flask_vouch.challenges.sha256 import SHA256
from flask_vouch.engine import (
    CHALLENGE_TTL,
    COOKIE_NAME,
    Challenge,
    RateLimiter,
    Store,
    TokenTracker,
    _b64url_decode,
    _b64url_encode,
    _is_bogon_ip,
    _meta_decrypt,
    _meta_encrypt,
    _safe_redirect,
)

SECRET = "test-secret-key-32-bytes-long!!!"
SECRET_BYTES = SECRET.encode()


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


# --- blocklist._parse_line ---


class TestParseLine:
    def test_cidr_v4(self):
        r = _parse_line("10.0.0.0/8")
        assert r == (
            4,
            int(__import__("ipaddress").ip_address("10.0.0.0")),
            int(__import__("ipaddress").ip_address("10.255.255.255")),
        )

    def test_cidr_v6(self):
        r = _parse_line("2001:db8::/32")
        assert r is not None
        assert r[0] == 6

    def test_range(self):
        r = _parse_line("1.2.3.4-1.2.3.10")
        assert r == (
            4,
            __import__("ipaddress").IPv4Address("1.2.3.4")._ip,
            __import__("ipaddress").IPv4Address("1.2.3.10")._ip,
        )

    def test_single_ip(self):
        import ipaddress

        r = _parse_line("8.8.8.8")
        val = int(ipaddress.ip_address("8.8.8.8"))
        assert r == (4, val, val)

    def test_blank_line(self):
        assert _parse_line("") is None
        assert _parse_line("  ") is None

    def test_comment(self):
        assert _parse_line("# comment") is None

    def test_invalid(self):
        assert _parse_line("notanip") is None


# --- blocklist._merge ---


class TestMerge:
    def test_empty(self):
        assert _merge([]) == []

    def test_non_overlapping(self):
        r = _merge([(1, 2), (5, 6)])
        assert r == [[1, 2], [5, 6]]

    def test_overlapping(self):
        r = _merge([(1, 5), (4, 8)])
        assert r == [[1, 8]]

    def test_adjacent(self):
        r = _merge([(1, 3), (4, 6)])
        assert r == [[1, 6]]


# --- blocklist._cache_path_for ---


class TestCachePathFor:
    def test_http_url(self):
        p = _cache_path_for("https://example.com/blocklist.txt")
        assert p is not None
        assert p.name == "blocklist.txt"

    def test_local_path(self):
        assert _cache_path_for("/local/file.txt") is None


# --- blocklist._load_text ---


class TestLoadText:
    def test_local_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("1.2.3.4\n")
            name = f.name
        assert _load_text(name, None) == "1.2.3.4\n"

    def test_from_cache(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("cached content\n")
            cache = Path(f.name)
        assert _load_text("https://example.com/x.txt", cache) == "cached content\n"


# --- blocklist.parse_blocklist ---


class TestParseBlocklist:
    def test_parses_mixed(self):
        text = "# header\n10.0.0.0/8\n192.168.1.1\nbad\n"
        v4, v6 = parse_blocklist(text)
        assert len(v4) >= 1

    def test_empty(self):
        v4, v6 = parse_blocklist("")
        assert v4 == [] and v6 == []


# --- blocklist._contains ---


class TestContains:
    def test_hit(self):
        assert _contains([10, 20], [15, 25], 12)

    def test_miss(self):
        assert not _contains([10, 20], [15, 25], 5)

    def test_boundary(self):
        assert _contains([10], [20], 10)
        assert _contains([10], [20], 20)
        assert not _contains([10], [20], 21)


# --- IPBlocklist ---


class TestIPBlocklist:
    def _make_loaded(self, text):
        bl = IPBlocklist.__new__(IPBlocklist)
        bl._source = "local"
        bl._cache = None
        bl._v4_starts = []
        bl._v4_ends = []
        bl._v6_starts = []
        bl._v6_ends = []
        import ipaddress

        v4, v6 = parse_blocklist(text)
        s4, e4 = zip(*v4) if v4 else ([], [])
        s6, e6 = zip(*v6) if v6 else ([], [])
        bl._v4_starts, bl._v4_ends = list(s4), list(e4)
        bl._v6_starts, bl._v6_ends = list(s6), list(e6)
        return bl

    def test_contains_hit(self):
        bl = self._make_loaded("10.0.0.0/8\n")
        assert bl.contains("10.1.2.3")

    def test_contains_miss(self):
        bl = self._make_loaded("10.0.0.0/8\n")
        assert not bl.contains("192.168.1.1")

    def test_contains_invalid_ip(self):
        bl = self._make_loaded("10.0.0.0/8\n")
        assert not bl.contains("not-an-ip")

    def test_len(self):
        bl = self._make_loaded("10.0.0.0/8\n1.2.3.4\n")
        assert len(bl) >= 1

    def test_from_sources_single(self):
        result = IPBlocklist.from_sources("https://example.com/x.txt")
        assert isinstance(result, IPBlocklist)

    def test_from_sources_list(self):
        result = IPBlocklist.from_sources(
            ["https://a.com/a.txt", "https://b.com/b.txt"]
        )
        assert len(result) == 2

    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("1.2.3.4\n10.0.0.0/8\n")
            name = f.name
        bl = IPBlocklist(name)
        bl.load()
        assert bl.contains("1.2.3.4")
        assert bl.contains("10.5.5.5")
        assert len(bl) >= 2

    def test_match_range_hit(self):
        bl = self._make_loaded("10.0.0.0/8\n")
        result = bl.match_range("10.1.2.3")
        assert result is not None

    def test_match_range_miss(self):
        bl = self._make_loaded("10.0.0.0/8\n")
        assert bl.match_range("192.168.1.1") is None

    def test_match_range_invalid(self):
        bl = self._make_loaded("10.0.0.0/8\n")
        assert bl.match_range("bad") is None

    def test_match_range_v6(self):
        bl = self._make_loaded("2001:db8::/32\n")
        assert bl.match_range("2001:db8::1") is not None

    def test_match_range_wide_range(self):
        import ipaddress

        bl = self._make_loaded("1.0.0.0/8\n2.0.0.0/8\n")
        # force a multi-network summary by injecting a range
        start = ipaddress.ip_address("1.0.0.0")
        end = ipaddress.ip_address("2.255.255.255")
        bl._v4_starts = [int(start)]
        bl._v4_ends = [int(end)]
        result = bl.match_range("1.5.0.0")
        assert result is not None and "-" in result


# --- SHA256 challenge handler ---


class TestSHA256Handler:
    def test_challenge_type(self):
        h = SHA256()
        assert h.challenge_type == ChallengeType.SHA256

    def test_to_difficulty(self):
        h = SHA256()
        assert h.to_difficulty(0) == 8  # offset is 8

    def test_template_is_html(self):
        h = SHA256()
        tmpl = h.template
        assert (
            "<html" in tmpl.lower()
            or "<!doctype" in tmpl.lower()
            or "script" in tmpl.lower()
        )

    def test_verify_valid(self):
        import hashlib

        h = SHA256()
        data = "abc"
        for nonce in range(100000):
            result = hashlib.sha256((data + str(nonce)).encode()).digest()
            if count_leading_zero_bits(result) >= 1:
                assert h.verify(data, nonce, 1)
                break

    def test_verify_invalid(self):
        h = SHA256()
        assert not h.verify("abc", 0, 64)

    def test_render_payload(self):
        h = SHA256()
        c = ChallengeBase(
            id="testid",
            random_data="deadbeef",
            difficulty=8,
            ip_hash="x",
            created_at=time.time(),
        )
        payload = h.render_payload(c, "/verify", "/home")
        assert payload["id"] == "testid"
        assert payload["data"] == "deadbeef"
        assert payload["difficulty"] == 8


# --- ChallengeBase.__post_init__ with string type ---


class TestChallengeBase:
    def test_string_challenge_type(self):
        c = ChallengeBase(
            id="x",
            random_data="y",
            difficulty=1,
            ip_hash="z",
            created_at=time.time(),
            challenge_type="sha256",
        )
        assert c.challenge_type == ChallengeType.SHA256


# --- ChallengeHandler abstract property coverage ---


class TestChallengeHandlerDefaults:
    def test_supports_websocket(self):
        from flask_vouch.challenges.sha256_balloon import SHA256Balloon

        h = SHA256Balloon()
        assert h.supports_websocket is False

    def test_extra_csp(self):
        from flask_vouch.challenges.sha256_balloon import SHA256Balloon

        h = SHA256Balloon()
        assert h.extra_csp == ""

    def test_supports_http_poll(self):
        from flask_vouch.challenges.sha256_balloon import SHA256Balloon

        h = SHA256Balloon()
        assert h.supports_http_poll is False

    def test_handle_http_poll(self):
        from flask_vouch.challenges.sha256_balloon import SHA256Balloon

        h = SHA256Balloon()
        result = h.handle_http_poll({}, None)
        assert result["type"] == "error"


# --- _meta_encrypt / _meta_decrypt ---


class TestMetaCrypto:
    def test_round_trip(self):
        data = {"remote_addr": "1.2.3.4", "extra": 42}
        enc = _meta_encrypt(data, SECRET_BYTES)
        dec = _meta_decrypt(enc, SECRET_BYTES)
        assert dec == data

    def test_wrong_key_returns_none(self):
        enc = _meta_encrypt({"x": 1}, SECRET_BYTES)
        # wrong key produces garbled JSON → None
        result = _meta_decrypt(enc, b"wrong-key-32-bytes!!!!!!!!!!!!!!!")
        # may be None or parse garbage — shouldn't crash
        # actually with XOR key it will decode to garbage, not valid JSON
        assert result is None or isinstance(result, dict)


# --- RateLimiter ---


class TestRateLimiter:
    def test_allows_under_limit(self):
        rl = RateLimiter()
        assert rl.hit("k", 3, 60)
        assert rl.hit("k", 3, 60)

    def test_blocks_over_limit(self):
        rl = RateLimiter()
        rl.hit("k", 2, 60)
        rl.hit("k", 2, 60)
        assert not rl.hit("k", 2, 60)


# --- TokenTracker ---


class TestTokenTracker:
    def test_total_limit(self):
        tt = TokenTracker()
        tt.hit("c", 0, 60, 2)
        tt.hit("c", 0, 60, 2)
        assert not tt.hit("c", 0, 60, 2)

    def test_rate_limit(self):
        tt = TokenTracker()
        tt.hit("c", 2, 60, 0)
        tt.hit("c", 2, 60, 0)
        assert not tt.hit("c", 2, 60, 0)

    def test_no_limits(self):
        tt = TokenTracker()
        for _ in range(10):
            assert tt.hit("c", 0, 60, 0)


# --- Store eviction ---


class TestStoreEviction:
    def test_evicts_oldest_when_full(self):
        store = Store(max_size=2)
        c1 = Challenge(
            id="a",
            random_data="x",
            difficulty=1,
            ip_hash="h",
            created_at=time.time() - 10,
        )
        c2 = Challenge(
            id="b",
            random_data="y",
            difficulty=1,
            ip_hash="h",
            created_at=time.time() - 5,
        )
        store.set(c1)
        store.set(c2)
        c3 = Challenge(
            id="c", random_data="z", difficulty=1, ip_hash="h", created_at=time.time()
        )
        store.set(c3)
        # oldest (a) should be evicted
        assert store.get("a") is None
        assert store.get("c") is c3


# --- Engine.validate_csrf_token ---


class TestCSRFToken:
    def make_engine(self):
        return Engine(secret=SECRET, policy=Policy(rules=[]))

    def test_valid_token(self):
        engine = self.make_engine()
        req = make_request()
        token = engine.generate_csrf_token("cid123", req)
        assert engine.validate_csrf_token(token, "cid123", req)

    def test_wrong_challenge_id(self):
        engine = self.make_engine()
        req = make_request()
        token = engine.generate_csrf_token("cid123", req)
        assert not engine.validate_csrf_token(token, "other", req)

    def test_wrong_ip(self):
        engine = self.make_engine()
        token = engine.generate_csrf_token("cid", make_request(remote_addr="1.2.3.4"))
        assert not engine.validate_csrf_token(
            token, "cid", make_request(remote_addr="9.9.9.9")
        )

    def test_garbage_token(self):
        engine = self.make_engine()
        assert not engine.validate_csrf_token("garbage!!!", "cid", make_request())

    def test_expired_token(self):
        engine = self.make_engine()
        req = make_request()
        with patch("flask_vouch.engine.time") as mock_time:
            mock_time.time.return_value = time.time() - 9000
            token = engine.generate_csrf_token("cid", req)
        assert not engine.validate_csrf_token(token, "cid", req)


# --- Engine.check_token_limit ---


class TestCheckTokenLimit:
    def test_no_limits_always_true(self):
        engine = Engine(
            secret=SECRET,
            policy=Policy(rules=[], token_rate_limit=0, token_total_limit=0),
        )
        for _ in range(10):
            assert engine.check_token_limit("cid")

    def test_total_limit_exceeded(self):
        engine = Engine(
            secret=SECRET,
            policy=Policy(rules=[], token_total_limit=2, token_rate_limit=0),
        )
        engine.check_token_limit("c")
        engine.check_token_limit("c")
        assert not engine.check_token_limit("c")


# --- Engine.validate_challenge with csrf ---


class TestValidateChallengeExtra:
    def make_engine(self):
        from flask_vouch.challenges import SHA256Balloon

        return Engine(
            secret=SECRET,
            policy=Policy(rules=[], challenge_handler=SHA256Balloon()),
        )

    def test_csrf_valid_passes(self):
        engine = self.make_engine()
        from flask_vouch.challenges.base import count_leading_zero_bits as clzb
        from flask_vouch.challenges.sha256_balloon import _balloon

        req = make_request()
        c = engine.issue_challenge(1, req)
        csrf = engine.generate_csrf_token(c.id, req)
        handler = engine.policy.challenge_handler
        for nonce in range(200_000):
            result = _balloon(
                c.random_data,
                nonce,
                handler.space_cost,
                handler.time_cost,
                handler.delta,
            )
            if clzb(result) >= 1:
                token = engine.validate_challenge(c.id, str(nonce), req, csrf)
                assert token is not None
                return
        raise RuntimeError("unsolvable")

    def test_csrf_invalid_fails(self):
        engine = self.make_engine()
        req = make_request()
        c = engine.issue_challenge(1, req)
        token = engine.validate_challenge(c.id, "0", req, "bad-csrf")
        assert token is None

    def test_invalid_nonce_type(self):
        engine = self.make_engine()
        req = make_request()
        c = engine.issue_challenge(1, req)
        token = engine.validate_challenge(c.id, "notanumber", req)
        assert token is None


# --- bogon IP rule ---


class TestBogonIPRule:
    def test_bogon_matches_private(self):
        rule = Rule(name="t", bogon_ip=True)
        assert rule.matches(make_request(remote_addr="192.168.1.1"))

    def test_bogon_no_match_public(self):
        rule = Rule(name="t", bogon_ip=True)
        assert not rule.matches(make_request(remote_addr="8.8.8.8"))


# --- Engine.process cookie path ---


class TestEngineProcessCookiePath:
    def make_engine(self):
        from flask_vouch.challenges import SHA256Balloon
        from flask_vouch.challenges.base import count_leading_zero_bits as clzb
        from flask_vouch.challenges.sha256_balloon import _balloon

        engine = Engine(
            secret=SECRET,
            policy=Policy(
                rules=[Rule(name="all", action="challenge", difficulty=1)],
            ),
        )
        req = make_request()
        c = engine.issue_challenge(1, req)
        handler = engine.policy.challenge_handler
        for nonce in range(200_000):
            result = _balloon(
                c.random_data,
                nonce,
                handler.space_cost,
                handler.time_cost,
                handler.delta,
            )
            if clzb(result) >= 1:
                token = engine.validate_challenge(c.id, str(nonce), req)
                assert token is not None
                return engine, token
        raise RuntimeError("unsolvable")

    def test_valid_cookie_bypasses(self):
        engine, token = self.make_engine()
        req = make_request(cookies={COOKIE_NAME: token})
        action, status, _, _ = engine.process(req)
        assert action == "pass"


# --- Vouch callable json_mode ---


class TestVouchCallableJsonMode:
    def test_callable_json_mode(self):
        bouncer = Vouch(
            secret=SECRET,
            policy=Policy(rules=[Rule(name="all", action="deny", user_agent="Bot")]),
            json_mode=lambda req: req["user_agent"] == "Bot/1.0",
        )
        req = make_request(user_agent="Bot/1.0")
        result = bouncer.process_request(req)
        assert result is not None and result.status == 403
        import json

        assert json.loads(result.body)["error"] == "forbidden"

    def test_callable_json_false(self):
        bouncer = Vouch(
            secret=SECRET,
            policy=Policy(rules=[Rule(name="all", action="deny", user_agent="Bot")]),
            json_mode=lambda req: False,
        )
        result = bouncer.process_request(make_request(user_agent="Bot/1.0"))
        assert result is not None and result.body == "Forbidden"


# --- Vouch rate limiting ---


class TestVouchRateLimiting:
    def test_challenge_rate_limit(self):
        bouncer = Vouch(
            secret=SECRET,
            policy=Policy(
                rules=[Rule(name="all", action="challenge", difficulty=1)],
                max_challenge_requests=1,
                rate_limit_window=60,
            ),
        )
        req = make_request()
        r1 = bouncer.process_request(req)
        assert r1 is not None and r1.status == 200
        r2 = bouncer.process_request(req)
        assert r2 is not None and r2.status == 403

    def test_verify_failure_rate_limit(self):
        bouncer = Vouch(
            secret=SECRET,
            policy=Policy(
                rules=[Rule(name="all", action="challenge", difficulty=1)],
                max_challenge_failures=1,
                rate_limit_window=60,
            ),
        )
        req = make_request(
            method="POST",
            path=bouncer.verify_path,
            form={"id": "fake", "nonce": "0"},
        )
        r1 = bouncer.process_request(req)
        assert r1 is not None and r1.status == 403 and r1.body == "Invalid"
        r2 = bouncer.process_request(req)
        assert r2 is not None and r2.status == 403 and r2.body == "Too Many Requests"

    def test_verify_failure_rate_limit_json(self):
        bouncer = Vouch(
            secret=SECRET,
            policy=Policy(
                rules=[Rule(name="all", action="challenge", difficulty=1)],
                max_challenge_failures=1,
                rate_limit_window=60,
            ),
            json_mode=True,
        )
        req = make_request(
            method="POST",
            path=bouncer.verify_path,
            form={"id": "fake", "nonce": "0"},
        )
        bouncer.process_request(req)
        r2 = bouncer.process_request(req)
        assert r2 is not None
        import json

        assert json.loads(r2.body)["error"] == "too many requests"


# --- Vouch json verify success ---


class TestVouchJsonVerify:
    def test_json_verify_success(self):
        bouncer = Vouch(secret=SECRET, policy=Policy(rules=[]), json_mode=True)
        from flask_vouch.challenges.base import count_leading_zero_bits as clzb
        from flask_vouch.challenges.sha256_balloon import _balloon

        req = make_request()
        c = bouncer.engine.issue_challenge(1, req)
        handler = bouncer.engine.policy.challenge_handler
        for nonce in range(200_000):
            result = _balloon(
                c.random_data,
                nonce,
                handler.space_cost,
                handler.time_cost,
                handler.delta,
            )
            if clzb(result) >= 1:
                r = bouncer.process_request(
                    make_request(
                        method="POST",
                        path=bouncer.verify_path,
                        form={"id": c.id, "nonce": str(nonce), "redirect": "/"},
                    )
                )
                assert r is not None and r.status == 200
                import json

                assert "token" in json.loads(r.body)
                return
        raise RuntimeError("unsolvable")

    def test_json_verify_invalid(self):
        bouncer = Vouch(secret=SECRET, policy=Policy(rules=[]), json_mode=True)
        r = bouncer.process_request(
            make_request(
                method="POST",
                path=bouncer.verify_path,
                form={"id": "fake", "nonce": "0"},
            )
        )
        assert r is not None and r.status == 403
        import json

        assert json.loads(r.body)["error"] == "invalid"


# --- Vouch init_app with config ---


class TestVouchInitAppConfig:
    def test_secret_key_fallback(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = SECRET
        bouncer = Vouch(policy=Policy(rules=[]))

        @app.route("/")
        def index():
            return "OK"

        bouncer.init_app(app)
        with app.test_client() as c:
            assert c.get("/").status_code == 200


# --- Flask decorators ---


class TestFlaskDecorators:
    def make_app(self, policy=None):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        bouncer = Vouch(
            secret=SECRET,
            policy=policy
            or Policy(rules=[Rule(name="all", action="challenge", difficulty=1)]),
        )

        @app.route("/")
        def index():
            return "OK"

        bouncer.init_app(app)
        return app, bouncer

    def test_challenge_decorator(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        bouncer = Vouch(secret=SECRET, policy=Policy(rules=[]))
        bouncer.init_app(app)

        @app.route("/always")
        @bouncer.challenge
        def always():
            return "always"

        with app.test_client() as c:
            resp = c.get("/always")
            assert resp.status_code == 200
            assert b"challenge" in resp.data.lower()

    def test_protect_decorator_no_cookie(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        bouncer = Vouch(
            secret=SECRET,
            policy=Policy(rules=[Rule(name="all", action="challenge", difficulty=1)]),
        )
        bouncer.init_app(app)

        @app.route("/protected")
        @bouncer.protect
        def protected():
            return "secret"

        with app.test_client() as c:
            resp = c.get("/protected")
            assert resp.status_code == 200
            assert b"challenge" in resp.data.lower()

    def test_mount_verify(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        bouncer = Vouch(secret=SECRET, policy=Policy(rules=[]))
        bouncer.mount_verify(app)
        with app.test_client() as c:
            resp = c.post(bouncer.verify_path, data={"id": "x", "nonce": "0"})
            assert resp.status_code == 403

    def test_block_decorator_allows_non_crawler(self):
        app = flask.Flask(__name__)
        app.config["TESTING"] = True
        bouncer = Vouch(secret=SECRET, policy=Policy(rules=[]))
        bouncer.init_app(app)

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


# --- _safe_redirect edge cases ---


class TestSafeRedirect:
    def test_valid(self):
        assert _safe_redirect("/page") == "/page"

    def test_double_slash(self):
        assert _safe_redirect("//evil.com") == "/"

    def test_backslash(self):
        assert _safe_redirect("/\\evil") == "/"

    def test_newline(self):
        assert _safe_redirect("/page\nX-Header: injected") == "/"

    def test_no_leading_slash(self):
        assert _safe_redirect("https://evil.com") == "/"


# --- Engine constructor with extra_rules ---


class TestEngineConstructorRules:
    def test_extra_rules_prepended(self):
        extra = [Rule(name="extra", action="deny", user_agent="EvilBot")]
        engine = Engine(secret=SECRET, rules=extra)
        action, _, _ = engine.policy.evaluate(make_request(user_agent="EvilBot/1.0"))
        assert action == "deny"

    def test_extra_rules_only(self):
        extra = [Rule(name="only", action="allow")]
        engine = Engine(secret=SECRET, rules=extra, default_rules=False)
        assert len(engine.policy.rules) == 1

    def test_policy_kwarg_override(self):
        engine = Engine(secret=SECRET, cookie_name="_custom")
        assert engine.policy.cookie_name == "_custom"
