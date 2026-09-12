from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
from dataclasses import asdict, fields

from flask_vouch.challenges import ChallengeBase
from flask_vouch.challenges.datasets import DatasetStore, set_default_store
from flask_vouch.engine import Engine
from flask_vouch.netset import NETSET_URL, _load_text, parse_netset
from flask_vouch.policy import CHALLENGE_TTL, Policy, Rule

log = logging.getLogger("flask_vouch.redis")


class RedisChallengeStore:
    def __init__(self, client, prefix="vouch", ttl=CHALLENGE_TTL):
        self._r = client
        self._prefix = prefix
        self._ttl = ttl

    def _key(self, cid):
        return f"{self._prefix}:c:{cid}"

    def consume(self, cid):
        """Redeem a challenge exactly once. ``GETDEL`` reads and removes it in a
        single atomic command, so only one worker can ever see it (Redis 6.2+)."""
        raw = self._r.getdel(self._key(cid))
        if not raw:
            return None
        challenge = ChallengeBase(**json.loads(raw))
        challenge.spent = True
        return challenge

    def set(self, challenge):
        elapsed = time.time() - challenge.created_at
        remaining = max(1, int(self._ttl - elapsed))
        self._r.set(
            self._key(challenge.id),
            json.dumps(asdict(challenge)),
            ex=remaining,
        )

    def get(self, cid):
        raw = self._r.get(self._key(cid))
        if not raw:
            return None
        return ChallengeBase(**json.loads(raw))


class RedisEngine(Engine):
    def __init__(
        self,
        client,
        *,
        secret=None,
        prefix="vouch",
        auto_sync=True,
        **kwargs,
    ):
        self._r = client
        self._prefix = prefix
        self._channel = f"{prefix}:sync"

        secret = self._resolve_secret(secret)
        super().__init__(secret, **kwargs)
        self._init_config()

        self.store = RedisChallengeStore(client, prefix, self.policy.challenge_ttl)
        self.rate_limiter = RedisRateLimiter(client, prefix)

        set_default_store(DatasetStore(client, prefix))

        self._listener = None
        if auto_sync:
            self._start_listener()

    def _rkey(self, name):
        return f"{self._prefix}:{name}"

    def _resolve_secret(self, secret):
        key = self._rkey("secret")
        if secret:
            val = secret.encode() if isinstance(secret, str) else secret
            self._r.set(key, val)
            return val

        stored = self._r.get(key)
        if stored:
            return stored if isinstance(stored, bytes) else stored.encode()
        raise ValueError("No secret provided and none found in Redis")

    def _config_json(self):
        cfg = {
            f.name: getattr(self.policy, f.name)
            for f in fields(Policy)
            if f.name not in ("rules", "challenge_handler")
        }
        return json.dumps(cfg, default=str)

    def _rules_json(self):
        return json.dumps([asdict(r) for r in self.policy.rules])

    def _init_config(self):
        """The first worker seeds the shared policy; every later one adopts what
        is already there, so starting a worker cannot wipe a live ruleset."""
        if self._r.set(self._rkey("config"), self._config_json(), nx=True):
            self._r.set(self._rkey("rules"), self._rules_json())
            return
        self._pull_config()

    def _push_config(self):
        self._r.set(self._rkey("config"), self._config_json())
        self._r.set(self._rkey("rules"), self._rules_json())

    def _pull_config(self):
        raw_cfg = self._r.get(self._rkey("config"))
        raw_rules = self._r.get(self._rkey("rules"))
        if not raw_cfg or not raw_rules:
            return

        for k, v in json.loads(raw_cfg).items():
            setattr(self.policy, k, v)

        self.policy.rules = [Rule(**r) for r in json.loads(raw_rules)]

    def sync(self):
        stored = self._r.get(self._rkey("secret"))
        if stored:
            self.secret = stored if isinstance(stored, bytes) else stored.encode()
        self._pull_config()

    def update_secret(self, secret):
        self.secret = secret.encode() if isinstance(secret, str) else secret
        self._r.set(self._rkey("secret"), self.secret)
        self._r.publish(self._channel, "secret")

    def update_policy(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self.policy, k, v)
        self._push_config()
        self._r.publish(self._channel, "config")

    def update_rules(self, rules):
        self.policy.rules = rules
        self._push_config()
        self._r.publish(self._channel, "rules")

    def _start_listener(self):
        def listen():
            ps = self._r.pubsub()
            ps.subscribe(self._channel)
            for msg in ps.listen():
                if msg["type"] == "message":
                    self.sync()

        thread = threading.Thread(
            target=listen,
            daemon=True,
        )
        thread.start()
        self._listener = thread


_LUA_RATE_HIT = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
return n <= tonumber(ARGV[1]) and 1 or 0
"""


class RedisRateLimiter:
    def __init__(self, client, prefix="vouch"):
        self._prefix = prefix
        self._hit = client.register_script(_LUA_RATE_HIT)

    def hit(self, key: str, limit: int, window: int) -> bool:
        rkey = f"{self._prefix}:rl:{key}"
        return bool(self._hit(keys=[rkey], args=[limit, window]))


_RANGE_SEPARATOR = "~"

# Members are "<start>~<end>", so the greatest member at or below the address
# carries its own end and no second lookup is needed. The \255 suffix on the max
# keeps a member whose start equals the address inside the range.
_LUA_IP_CHECK = r"""
local hit = redis.call(
    'ZREVRANGEBYLEX', KEYS[1],
    '[' .. ARGV[1] .. '\255', '-', 'LIMIT', 0, 1
)
if #hit == 0 then return 0 end
return ARGV[1] <= string.sub(hit[1], #ARGV[1] + 2) and 1 or 0
"""


class RedisNetSet:
    def __init__(self, client, prefix="vouch"):
        self._r = client
        self._prefix = prefix
        self._check = client.register_script(_LUA_IP_CHECK)

    def _key(self, version):
        return f"{self._prefix}:bl:{'v4' if version == 4 else 'v6'}"

    def _hex(self, val, version):
        width = 8 if version == 4 else 32
        return f"{val:0{width}x}"

    def load(self, source=NETSET_URL):
        text = _load_text(source, None)
        v4, v6 = parse_netset(text)

        for version, ranges in [(4, v4), (6, v6)]:
            key = self._key(version)
            self._r.delete(key)
            pipe = self._r.pipeline(transaction=False)
            for i, (start, end) in enumerate(ranges):
                member = (
                    f"{self._hex(start, version)}"
                    f"{_RANGE_SEPARATOR}"
                    f"{self._hex(end, version)}"
                )
                pipe.zadd(key, {member: 0})
                if i % 5000 == 4999:
                    pipe.execute()
            pipe.execute()

    def contains(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        hex_ip = self._hex(int(addr), addr.version)
        return bool(self._check(keys=[self._key(addr.version)], args=[hex_ip]))

    def start_updates(self, interval=86400, source=NETSET_URL):
        lock_key = f"{self._prefix}:bl:lock"

        def run():
            while True:
                threading.Event().wait(interval)
                if not self._r.set(lock_key, "1", nx=True, ex=interval):
                    continue
                try:
                    self.load(source)
                    log.info("Blocklist updated: %d entries", len(self))
                except Exception:
                    self._r.delete(lock_key)
                    log.warning("Blocklist update failed", exc_info=True)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def __len__(self):
        return self._r.zcard(self._key(4)) + self._r.zcard(self._key(6))
