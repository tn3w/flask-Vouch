"""Additional tests to improve coverage of uncovered lines."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import flask

from flask_vouch import Engine, Policy, Rule, Vouch
from flask_vouch.challenges.base import (
    ChallengeBase,
    ChallengeType,
    count_leading_zero_bits,
)
from flask_vouch.challenges.sha256 import SHA256
from flask_vouch.crawlers import crawler_name, is_crawler
from flask_vouch.netset import (
    NetSet,
    _cache_path_for,
    _contains,
    _load_text,
    _merge,
    _parse_line,
    parse_netset,
)
from flask_vouch.policy import COOKIE_NAME, blocklist_match, load_policy
from flask_vouch.rendering import challenge_headers, resolve_template, safe_redirect
from flask_vouch.stores import ChallengeStore, RateLimiter
from flask_vouch.tokens import b64url_encode
from flask_vouch.vouch import _to_request, client_ip

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

    def test_http_fetch_writes_cache(self, tmp_path):
        cache = tmp_path / "remote.txt"

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"5.6.7.8\n"

        with patch("flask_vouch.netset.urlopen", return_value=Response()):
            assert _load_text("https://example.com/x.txt", cache) == "5.6.7.8\n"

        assert cache.read_text() == "5.6.7.8\n"


# --- blocklist.parse_netset ---


class TestParseBlocklist:
    def test_parses_mixed(self):
        text = "# header\n10.0.0.0/8\n192.168.1.1\nbad\n"
        v4, v6 = parse_netset(text)
        assert len(v4) >= 1

    def test_empty(self):
        v4, v6 = parse_netset("")
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


# --- NetSet ---


class TestNetSet:
    def _make_loaded(self, text):
        bl = NetSet.__new__(NetSet)
        bl._source = "local"
        bl._cache = None
        bl._v4_starts = []
        bl._v4_ends = []
        bl._v6_starts = []
        bl._v6_ends = []
        import ipaddress

        v4, v6 = parse_netset(text)
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
        result = NetSet.from_sources("https://example.com/x.txt")
        assert isinstance(result, NetSet)

    def test_from_sources_list(self):
        result = NetSet.from_sources(["https://a.com/a.txt", "https://b.com/b.txt"])
        assert len(result) == 2

    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("1.2.3.4\n10.0.0.0/8\n")
            name = f.name
        bl = NetSet(name)
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

    def test_load_force_bypasses_cache(self, tmp_path):
        source = tmp_path / "source.txt"
        source.write_text("1.2.3.4\n")
        cache = tmp_path / "cache.txt"
        cache.write_text("10.0.0.0/8\n")

        bl = NetSet(str(source))
        bl._cache = cache
        bl.load(force=True)

        assert bl.contains("1.2.3.4")
        assert not bl.contains("10.1.2.3")

    def test_start_updates_refreshes_cache(self, tmp_path):
        source = tmp_path / "blocklist.txt"
        source.write_text("1.2.3.4\n")
        cache = tmp_path / "cache.txt"
        cache.write_text("10.0.0.0/8\n")

        bl = NetSet(str(source))
        bl._cache = cache

        class StopLoop(Exception):
            pass

        class FakeEvent:
            def __init__(self):
                self.calls = 0

            def wait(self, interval):
                self.calls += 1
                if self.calls > 1:
                    raise StopLoop

        class FakeThread:
            def __init__(self, target, daemon):
                self.target = target
                self.daemon = daemon
                self.started = False

            def start(self):
                self.started = True
                try:
                    self.target()
                except StopLoop:
                    pass

        with patch("flask_vouch.netset.threading.Event", return_value=FakeEvent()):
            with patch("flask_vouch.netset.threading.Thread", FakeThread):
                thread = bl.start_updates(interval=1)

        assert isinstance(thread, FakeThread)
        assert thread.started
        assert bl.contains("1.2.3.4")
        assert not cache.exists()

    def test_contains_v6_hit(self):
        bl = self._make_loaded("2001:db8::/32\n")
        assert bl.contains("2001:db8::1234")


# --- SHA256 challenge handler ---


class TestSHA256Handler:
    def test_challenge_type(self):
        h = SHA256()
        assert h.challenge_type == ChallengeType.SHA256

    def test_to_difficulty(self):
        h = SHA256()
        assert h.to_difficulty(0) == 8  # offset is 8

    def test_template_is_html(self):
        from flask_vouch.rendering import resolve_template

        tmpl = resolve_template(SHA256())
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

    def test_window_expires(self):
        rl = RateLimiter()
        with patch("flask_vouch.engine.time.time", side_effect=[100.0, 101.0, 170.0]):
            assert rl.hit("k", 2, 60)
            assert rl.hit("k", 2, 60)
            assert rl.hit("k", 2, 60)

    def test_exempt_endpoint_skips_limit(self, tmp_path):
        from flask_vouch.extras.rate_limiter import RateLimiter as FlaskRateLimiter

        (tmp_path / "app.css").write_text("body{}")
        app = flask.Flask(
            __name__, static_folder=str(tmp_path), static_url_path="/static"
        )
        limiter = FlaskRateLimiter()
        limiter.exempt("static")
        limiter.init_flask(app, rate="1/minute")

        @app.route("/")
        def index():
            return "OK"

        with app.test_client() as c:
            for _ in range(3):
                assert c.get("/static/app.css").status_code == 200
            assert c.get("/").status_code == 200
            assert c.get("/").status_code == 429


# --- Store eviction ---


class TestStoreEviction:
    def test_evicts_oldest_when_full(self):
        store = ChallengeStore(max_size=2)
        c1 = ChallengeBase(
            id="a",
            random_data="x",
            difficulty=1,
            ip_hash="h",
            created_at=time.time() - 10,
        )
        c2 = ChallengeBase(
            id="b",
            random_data="y",
            difficulty=1,
            ip_hash="h",
            created_at=time.time() - 5,
        )
        store.set(c1)
        store.set(c2)
        c3 = ChallengeBase(
            id="c", random_data="z", difficulty=1, ip_hash="h", created_at=time.time()
        )
        store.set(c3)
        # oldest (a) should be evicted
        assert store.get("a") is None
        assert store.get("c") is c3


# --- Engine.validate_challenge ---


class TestValidateChallengeExtra:
    def make_engine(self):
        from flask_vouch.challenges import SHA256Balloon

        return Engine(
            secret=SECRET,
            policy=Policy(rules=[], challenge_handler=SHA256Balloon()),
        )

    def test_solution_issues_cookie(self):
        engine = self.make_engine()
        from flask_vouch.challenges.base import count_leading_zero_bits as clzb
        from flask_vouch.challenges.sha256_balloon import _balloon

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
                assert engine.validate_challenge(c.id, str(nonce), req) is not None
                return
        raise RuntimeError("unsolvable")

    def test_invalid_nonce_type(self):
        engine = self.make_engine()
        req = make_request()
        c = engine.issue_challenge(1, req)
        token = engine.validate_challenge(c.id, "notanumber", req)
        assert token is None

    def test_wrong_challenge_type_fails(self):
        engine = self.make_engine()
        req = make_request()
        c = engine.issue_challenge(1, req)
        c.challenge_type = "sha256"
        engine.store.set(c)
        assert engine.validate_challenge(c.id, "0", req) is None


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
        assert Vouch(engine=engine).process_request(req) is None

    def test_invalid_cookie_falls_back_to_policy(self):
        engine = Engine(
            secret=SECRET,
            policy=Policy(rules=[Rule(name="all", action="deny", user_agent="Bot")]),
        )
        req = make_request(
            user_agent="Bot/1.0", cookies={COOKIE_NAME: "bad.token.value"}
        )
        result = Vouch(engine=engine).process_request(req)
        assert result.status == 403
        assert result.body == "Forbidden"


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
        assert r2 is not None and r2.status == 429

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
        assert r2 is not None and r2.status == 429 and r2.body == "Too Many Requests"

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
        assert safe_redirect("/page") == "/page"

    def test_double_slash(self):
        assert safe_redirect("//evil.com") == "/"

    def test_backslash(self):
        assert safe_redirect("/\\evil") == "/"

    def test_newline(self):
        assert safe_redirect("/page\nX-Header: injected") == "/"

    def test_no_leading_slash(self):
        assert safe_redirect("https://evil.com") == "/"


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


class TestEngineHelpers:
    def test_crawler_name_compatible(self):
        assert (
            crawler_name("Mozilla/5.0 (compatible; TestBot/1.0; +https://example.com)")
            == "TestBot"
        )

    def test_crawler_name_prefix(self):
        assert crawler_name("Example Bot/1.0 - https://example.com") == "Example"

    def test_crawler_name_fallback_first_token(self):
        assert crawler_name("bot/1.0") == "bot"

    def test_crawler_name_browser_tail_name(self):
        assert (
            crawler_name(
                "Mozilla/5.0 (compatible; Googlebot/2.1; +https://www.google.com/bot.html)"
            )
            == "Googlebot"
        )

    def test_is_crawler_false_for_normal_browser(self):
        assert not is_crawler(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36"
        )

    def test_blocklist_match_list(self):
        a = NetSet.__new__(NetSet)
        b = NetSet.__new__(NetSet)
        a.match_range = lambda ip: None
        b.match_range = lambda ip: "10.0.0.0/8"
        assert blocklist_match([a, b], "10.1.2.3") == "10.0.0.0/8"

    def test_blocklist_match_none(self):
        assert blocklist_match(None, "1.2.3.4") is None

    def test_challenge_headers_extra_csp(self):
        class Handler:
            extra_csp = "frame-src https://example.com"

        headers = challenge_headers(Handler())
        assert "frame-src https://example.com" in headers["Content-Security-Policy"]

    def test_load_policy_applies_config_file(self, tmp_path):
        rules = tmp_path / "rules.json"
        rules.write_text('[{"name":"ok","action":"allow"}]')
        config = tmp_path / "config.json"
        config.write_text('{"default_difficulty": 3}')
        policy = load_policy(config=config, rules=rules)
        assert policy.rules[0].action == "allow"
        assert policy.default_difficulty == 3

    def test_load_policy_missing_config_raises(self, tmp_path):
        import pytest

        with pytest.raises(FileNotFoundError):
            load_policy(config=tmp_path / "missing.json")

    def test_engine_sets_handler_secret(self):
        class SecretHandler(SHA256):
            secret = None

        engine = Engine(
            secret=SECRET, policy=Policy(rules=[], challenge_handler=SecretHandler())
        )
        assert engine.policy.challenge_handler.secret == SECRET.encode()


class TestRuleExtraPaths:
    def test_blocklist_rule_requires_hit(self):
        class StubBlocklist:
            def contains(self, ip):
                return ip == "10.1.2.3"

        rule = Rule(name="blocked", blocklist=True)
        assert rule.matches(make_request(remote_addr="10.1.2.3"), StubBlocklist())
        assert not rule.matches(make_request(remote_addr="8.8.8.8"), StubBlocklist())

    def test_crawler_rule_requires_crawler(self):
        rule = Rule(name="crawler", crawler=True)
        assert rule.matches(make_request(user_agent="Scrapy/2.0"))
        assert not rule.matches(make_request())

    def test_header_rule_missing_header_fails(self):
        rule = Rule(name="hdr", headers={"X-Test": "^ok$"})
        assert not rule.matches(make_request(headers={}))


class TestEngineVerifyBranches:
    def make_engine(self, **policy_kwargs):
        return Engine(
            secret=SECRET,
            policy=Policy(rules=[], challenge_handler=SHA256(), **policy_kwargs),
        )

    def test_handle_verify_uses_nonce_coordinates(self):
        class CoordinateHandler(SHA256):
            def to_difficulty(self, base: int) -> int:
                return base

            def nonce_from_form(self, raw: str) -> str:
                return raw

            def verify(
                self, random_data: str, nonce: int | str, difficulty: int
            ) -> bool:
                return nonce == "0,0"

        engine = Engine(
            secret=SECRET,
            policy=Policy(rules=[], challenge_handler=CoordinateHandler()),
        )
        req = make_request()
        challenge = engine.issue_challenge(0, req)

        result = Vouch(engine=engine).process_request(
            make_request(
                method="POST",
                path=engine.policy.verify_path,
                form={
                    "id": challenge.id,
                    "nonce.x": "0",
                    "nonce.y": "0",
                    "redirect": "/done",
                },
            )
        )

        assert result.status == 302
        assert result.headers["Location"] == "/done"

    def test_handle_verify_retry_usessafe_redirect(self):
        class RetryHandler(SHA256):
            @property
            def retry_on_failure(self) -> bool:
                return True

        engine = Engine(
            secret=SECRET,
            policy=Policy(rules=[], challenge_handler=RetryHandler()),
        )
        result = Vouch(engine=engine).process_request(
            make_request(
                method="POST",
                path=engine.policy.verify_path,
                form={"id": "missing", "nonce": "bad", "redirect": "//evil.com"},
            )
        )

        assert result.status == 403
        assert "Content-Security-Policy" in result.headers
        assert '"redirect": "/"' in result.body


# --- Trusted proxies ---


class TestClientIP:
    def test_header_ignored_without_trust(self):
        assert client_ip("10.0.0.1", "1.2.3.4", None) == "10.0.0.1"

    def test_no_header_uses_peer(self):
        assert client_ip("10.0.0.1", "", 1) == "10.0.0.1"

    def test_hop_count_picks_last_written_entry(self):
        assert client_ip("10.0.0.1", "1.2.3.4, 10.0.0.9", 1) == "10.0.0.9"
        assert client_ip("10.0.0.1", "1.2.3.4, 10.0.0.9", 2) == "1.2.3.4"

    def test_spoofed_prefix_is_skipped(self):
        assert client_ip("10.0.0.1", "evil, 1.2.3.4", 1) == "1.2.3.4"

    def test_trusted_networks(self):
        assert client_ip("10.0.0.1", "1.2.3.4, 10.0.0.9", ["10.0.0.0/8"]) == "1.2.3.4"

    def test_trusted_networks_all_trusted(self):
        assert client_ip("10.0.0.1", "10.0.0.2", ["10.0.0.0/8"]) == "10.0.0.2"

    def test_invalid_entry_is_not_trusted(self):
        assert client_ip("10.0.0.1", "not-an-ip", ["10.0.0.0/8"]) == "not-an-ip"

    def test_flask_request_uses_trusted_proxies(self):
        app = flask.Flask(__name__)
        with app.test_request_context("/", headers={"X-Forwarded-For": "8.8.8.8"}):
            assert _to_request(1)["remote_addr"] == "8.8.8.8"
            assert _to_request(None)["remote_addr"] != "8.8.8.8"


# --- Secret validation ---


class TestSecret:
    def test_missing_secret(self):
        import pytest

        with pytest.raises(ValueError):
            Engine(None)

    def test_short_secret(self):
        import pytest

        with pytest.raises(ValueError):
            Engine("too-short")

    def test_bytes_secret(self):
        assert Engine(SECRET_BYTES, policy=Policy(rules=[])).secret == SECRET_BYTES

    def test_engine_property_without_configuration(self):
        import pytest

        with pytest.raises(RuntimeError):
            Vouch().engine


# --- Custom templates ---


class TestCustomTemplates:
    def make_challenge(self, handler):
        return ChallengeBase(
            id="abc",
            random_data="ff",
            difficulty=1,
            ip_hash="x",
            created_at=time.time(),
            challenge_type=handler.challenge_type,
        )

    def test_inline_template_wins(self):
        handler = SHA256(template="<b>{{id}}</b>")
        assert resolve_template(handler) == "<b>{{id}}</b>"

    def test_path_template_is_read(self, tmp_path):
        page = tmp_path / "page.html"
        page.write_text("<i>custom</i>")
        assert resolve_template(SHA256(template=page)) == "<i>custom</i>"

    def test_template_dir_override(self, tmp_path):
        (tmp_path / "sha256.html").write_text("<u>dir</u>")
        assert resolve_template(SHA256(), tmp_path) == "<u>dir</u>"

    def test_template_dir_falls_back_to_bundled(self, tmp_path):
        assert "<!DOCTYPE" in resolve_template(SHA256(), tmp_path).upper()

    def test_rendered_page_uses_override(self):
        handler = SHA256(template="<b>{{id}}</b> {{ACCENT_COLOR}} {{BRANDING}}")
        engine = Engine(
            secret=SECRET, policy=Policy(rules=[], challenge_handler=handler)
        )
        html = engine.render_challenge(self.make_challenge(handler), "/")
        assert html.startswith("<b>abc</b> #44ff88 ")
        assert "flask-Vouch" in html


# --- Handler failures surface as 503 ---


class TestChallengeErrors:
    def make_vouch(self, handler):
        return Vouch(
            secret=SECRET,
            policy=Policy(
                rules=[Rule(name="all", action="challenge")],
                challenge_handler=handler,
            ),
        )

    def test_generation_failure(self):
        class Broken(SHA256):
            def generate_random_data(self, difficulty: int = 0) -> str:
                raise RuntimeError("boom")

        result = self.make_vouch(Broken()).process_request(make_request())
        assert result is not None and result.status == 503

    def test_render_failure(self):
        class Broken(SHA256):
            def render_payload(self, challenge, verify_path, redirect):
                raise RuntimeError("boom")

        result = self.make_vouch(Broken()).process_request(make_request())
        assert result is not None and result.status == 503

    def test_verification_failure(self):
        class Broken(SHA256):
            def verify(self, random_data, nonce, difficulty):
                raise RuntimeError("boom")

        vouch = self.make_vouch(Broken())
        challenge = vouch.engine.issue_challenge(1, make_request())
        result = vouch.process_request(
            make_request(
                method="POST",
                path=vouch.verify_path,
                form={"id": challenge.id, "nonce": "1"},
            )
        )
        assert result is not None and result.status == 503


# --- Cookie binding ---


class TestCookieBinding:
    def solve(self, engine, request):
        challenge = engine.issue_challenge(0, request)
        for nonce in range(200_000):
            token = engine.validate_challenge(challenge.id, str(nonce), request)
            if token:
                return token
        raise RuntimeError("unsolvable")

    def make_engine(self, **kwargs):
        return Engine(
            secret=SECRET,
            policy=Policy(rules=[], challenge_handler=SHA256(), **kwargs),
        )

    def test_roaming_allowed_by_default(self):
        engine = self.make_engine()
        token = self.solve(engine, make_request())
        assert engine.check_cookie(token, make_request(remote_addr="9.9.9.9"))

    def test_bind_ip_rejects_other_address(self):
        engine = self.make_engine(bind_ip=True)
        token = self.solve(engine, make_request())
        assert engine.check_cookie(token, make_request()) is not None
        assert engine.check_cookie(token, make_request(remote_addr="9.9.9.9")) is None


# --- Package metadata ---


class TestVersion:
    def test_version_matches_distribution(self):
        from importlib.metadata import version

        import flask_vouch

        assert flask_vouch.__version__ == version("flask-Vouch")
