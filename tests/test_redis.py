from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from flask_vouch.challenges import SHA256, ChallengeBase, ChallengeType
from flask_vouch.netset import NetSet, parse_netset
from flask_vouch.policy import Policy, Rule

redis = pytest.importorskip("redis")

SECRET = "test-secret-key-32-bytes-long!!!"
NETSET_TEXT = """
# comment
10.0.0.0/24
192.168.5.10
172.16.0.5-172.16.0.9
2001:db8::/126
"""


@pytest.fixture
def client():
    server = redis.Redis(port=6399)
    try:
        server.ping()
    except redis.exceptions.RedisError:
        pytest.skip("no redis on port 6399")
    server.flushall()
    return server


def request(**overrides):
    return {
        "method": "GET",
        "path": "/",
        "query": "",
        "user_agent": "x",
        "remote_addr": "1.2.3.4",
        "headers": {},
        "cookies": {},
        "form": {},
        "secure": True,
        **overrides,
    }


class TestRedisRateLimiter:
    def limiter(self, client):
        from flask_vouch.redis import RedisRateLimiter

        return RedisRateLimiter(client, prefix="t")

    def test_allows_up_to_the_limit(self, client):
        limiter = self.limiter(client)
        assert [limiter.hit("k", 3, 60) for _ in range(5)] == [True] * 3 + [False] * 2

    def test_window_expiry_is_set_once(self, client):
        limiter = self.limiter(client)
        limiter.hit("k", 3, 60)
        limiter.hit("k", 3, 60)
        assert 0 < client.ttl("t:rl:k") <= 60

    def test_concurrent_hits_respect_the_limit(self, client):
        limiter = self.limiter(client)
        with ThreadPoolExecutor(32) as pool:
            granted = sum(pool.map(lambda _: limiter.hit("r", 10, 60), range(200)))
        assert granted == 10


class TestRedisChallengeStore:
    def store(self, client):
        from flask_vouch.redis import RedisChallengeStore

        return RedisChallengeStore(client, prefix="t", ttl=60)

    def challenge(self):
        return ChallengeBase(
            id="c1",
            random_data="d",
            difficulty=1,
            ip_hash="h",
            created_at=time.time(),
            challenge_type=ChallengeType.SHA256,
        )

    def test_round_trip(self, client):
        store = self.store(client)
        store.set(self.challenge())
        stored = store.get("c1")
        assert stored and stored.challenge_type is ChallengeType.SHA256

    def test_consume_is_one_shot(self, client):
        store = self.store(client)
        store.set(self.challenge())
        assert store.consume("c1") is not None
        assert store.consume("c1") is None

    def test_consume_of_unknown_id(self, client):
        assert self.store(client).consume("nope") is None

    def test_concurrent_consumes_yield_one_winner(self, client):
        store = self.store(client)
        store.set(self.challenge())
        with ThreadPoolExecutor(32) as pool:
            wins = sum(
                x is not None
                for x in pool.map(lambda _: store.consume("c1"), range(64))
            )
        assert wins == 1


class TestRedisNetSet:
    def loaded(self, client, monkeypatch):
        import flask_vouch.redis as module

        monkeypatch.setattr(module, "_load_text", lambda source, cache: NETSET_TEXT)
        netset = module.RedisNetSet(client, prefix="t")
        netset.load("ignored")
        return netset

    def memory(self):
        netset = NetSet.__new__(NetSet)
        netset._source, netset._cache = "x", None
        netset._loaded, netset._warned = True, True
        v4, v6 = parse_netset(NETSET_TEXT)
        netset._v4_starts = [s for s, _ in v4]
        netset._v4_ends = [e for _, e in v4]
        netset._v6_starts = [s for s, _ in v6]
        netset._v6_ends = [e for _, e in v6]
        return netset

    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("10.0.0.0", True),
            ("10.0.0.255", True),
            ("10.0.1.0", False),
            ("9.255.255.255", False),
            ("192.168.5.10", True),
            ("192.168.5.11", False),
            ("172.16.0.5", True),
            ("172.16.0.9", True),
            ("172.16.0.10", False),
            ("2001:db8::", True),
            ("2001:db8::3", True),
            ("2001:db8::4", False),
            ("not-an-ip", False),
        ],
    )
    def test_membership(self, client, monkeypatch, ip, expected):
        assert self.loaded(client, monkeypatch).contains(ip) is expected

    def test_matches_the_in_memory_netset(self, client, monkeypatch):
        import ipaddress
        import random

        remote = self.loaded(client, monkeypatch)
        local = self.memory()
        random.seed(7)
        sample = [
            str(ipaddress.IPv4Address(random.getrandbits(32))) for _ in range(500)
        ]
        assert all(remote.contains(ip) == local.contains(ip) for ip in sample)

    def test_length_counts_both_families(self, client, monkeypatch):
        assert len(self.loaded(client, monkeypatch)) == 4


class TestRedisEngine:
    def engine(self, client, **kwargs):
        from flask_vouch.redis import RedisEngine

        kwargs.setdefault("policy", Policy(rules=[], challenge_handler=SHA256()))
        return RedisEngine(client, secret=SECRET, auto_sync=False, **kwargs)

    def test_path_config_is_serializable(self, client, tmp_path):
        engine = self.engine(client, template_dir=tmp_path)
        assert client.get("vouch:config")
        assert engine.policy.template_dir == tmp_path

    def test_second_worker_adopts_the_shared_rules(self, client):
        first = self.engine(
            client, policy=Policy(rules=[Rule(name="keep", action="deny")])
        )
        second = self.engine(client)
        first.sync()
        assert [r.name for r in second.policy.rules] == ["keep"]
        assert [r.name for r in first.policy.rules] == ["keep"]

    def test_worker_started_after_an_update_sees_it(self, client):
        first = self.engine(client)
        first.update_rules([Rule(name="live", action="challenge")])
        assert [r.name for r in self.engine(client).policy.rules] == ["live"]

    def test_policy_updates_propagate(self, client):
        first = self.engine(client)
        second = self.engine(client)
        first.update_policy(default_difficulty=17)
        second.sync()
        assert second.policy.default_difficulty == 17

    def test_solution_redeems_once_across_workers(self, client):
        engine = self.engine(client)
        req = request()
        challenge = engine.issue_challenge(0, req)
        handler = engine.policy.challenge_handler
        nonce = str(
            next(
                n
                for n in range(200_000)
                if handler.verify(challenge.random_data, n, challenge.difficulty)
            )
        )
        with ThreadPoolExecutor(16) as pool:
            tokens = list(
                pool.map(
                    lambda _: engine.validate_challenge(challenge.id, nonce, req),
                    range(16),
                )
            )
        issued = [t for t in tokens if t]
        assert len(issued) == 1
        assert engine.check_cookie(issued[0], req) is not None
