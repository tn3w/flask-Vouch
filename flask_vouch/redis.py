import ipaddress
import json
import logging
import threading
import time
from dataclasses import asdict, fields

from flask_vouch.blocklist import BLOCKLIST_URL, _load_text, parse_blocklist
from flask_vouch.challenges.datasets import DatasetStore, set_default_store
from flask_vouch.engine import (
    CHALLENGE_TTL,
    COOKIE_TTL,
    Challenge,
    Engine,
    Policy,
    Rule,
)

log = logging.getLogger("flask_vouch.redis")


class RedisStore:
    def __init__(self, client, prefix="tollbooth", ttl=CHALLENGE_TTL):
        self._r = client
        self._prefix = prefix
        self._ttl = ttl

    def _key(self, cid):
        return f"{self._prefix}:c:{cid}"

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
        return Challenge(**json.loads(raw))


class RedisEngine(Engine):
    def __init__(
        self,
        client,
        *,
        secret=None,
        prefix="tollbooth",
        auto_sync=True,
        **kwargs,
    ):
        self._r = client
        self._prefix = prefix
        self._channel = f"{prefix}:sync"

        secret = self._resolve_secret(secret)
        super().__init__(secret, **kwargs)
        self._push_config()

        self.store = RedisStore(client, prefix, self.policy.challenge_ttl)
        self._rate_limiter = RedisRateLimiter(client, prefix)
        self._token_tracker = RedisTokenTracker(client, prefix, self.policy.cookie_ttl)

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

    def _push_config(self):
        cfg = {
            f.name: getattr(self.policy, f.name)
            for f in fields(Policy)
            if f.name not in ("rules", "challenge_handler")
        }
        self._r.set(self._rkey("config"), json.dumps(cfg))
        self._r.set(
            self._rkey("rules"),
            json.dumps([asdict(r) for r in self.policy.rules]),
        )

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
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
if cur >= tonumber(ARGV[1]) then return 0 end
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
return 1
"""


class RedisRateLimiter:
    def __init__(self, client, prefix="tollbooth"):
        self._prefix = prefix
        self._hit = client.register_script(_LUA_RATE_HIT)

    def hit(self, key: str, limit: int, window: int) -> bool:
        rkey = f"{self._prefix}:rl:{key}"
        return bool(self._hit(keys=[rkey], args=[limit, window]))


_LUA_TOKEN_HIT = """
local total_limit = tonumber(ARGV[1])
local rate_limit = tonumber(ARGV[2])
local rate_window = tonumber(ARGV[3])
local total_ttl = tonumber(ARGV[4])
if total_limit > 0 then
    local total = tonumber(redis.call('INCR', KEYS[1]))
    if total == 1 and total_ttl > 0 then
        redis.call('EXPIRE', KEYS[1], total_ttl)
    end
    if total > total_limit then return 0 end
end
if rate_limit > 0 then
    local cur = tonumber(redis.call('GET', KEYS[2]) or '0')
    if cur >= rate_limit then return 0 end
    local n = redis.call('INCR', KEYS[2])
    if n == 1 then redis.call('EXPIRE', KEYS[2], rate_window) end
end
return 1
"""


class RedisTokenTracker:
    def __init__(self, client, prefix="tollbooth", cookie_ttl=COOKIE_TTL):
        self._prefix = prefix
        self._cookie_ttl = cookie_ttl
        self._hit = client.register_script(_LUA_TOKEN_HIT)

    def hit(
        self,
        cid: str,
        rate_limit: int,
        rate_window: int,
        total_limit: int,
    ) -> bool:
        total_key = f"{self._prefix}:tk:{cid}"
        rate_key = f"{self._prefix}:tkr:{cid}"
        return bool(
            self._hit(
                keys=[total_key, rate_key],
                args=[total_limit, rate_limit, rate_window, self._cookie_ttl],
            )
        )


_LUA_IP_CHECK = """
local ip = ARGV[1]
local r = redis.call(
    'ZREVRANGEBYLEX', KEYS[1],
    '[' .. ip, '-', 'LIMIT', 0, 1
)
if #r == 0 then return 0 end
local e = redis.call('HGET', KEYS[2], r[1])
if e and ip <= e then return 1 end
return 0
"""


class RedisIPBlocklist:
    def __init__(self, client, prefix="tollbooth"):
        self._r = client
        self._prefix = prefix
        self._check = client.register_script(_LUA_IP_CHECK)

    def _keys(self, version):
        v = "v4" if version == 4 else "v6"
        return (
            f"{self._prefix}:bl:{v}:z",
            f"{self._prefix}:bl:{v}:h",
        )

    def _hex(self, val, version):
        width = 8 if version == 4 else 32
        return f"{val:0{width}x}"

    def load(self, source=BLOCKLIST_URL):
        text = _load_text(source, None)
        v4, v6 = parse_blocklist(text)

        for version, ranges in [(4, v4), (6, v6)]:
            zkey, hkey = self._keys(version)
            self._r.delete(zkey, hkey)
            pipe = self._r.pipeline(transaction=False)
            for i, (start, end) in enumerate(ranges):
                s = self._hex(start, version)
                e = self._hex(end, version)
                pipe.zadd(zkey, {s: 0})
                pipe.hset(hkey, s, e)
                if i % 5000 == 4999:
                    pipe.execute()
            pipe.execute()

    def contains(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        zkey, hkey = self._keys(addr.version)
        hex_ip = self._hex(int(addr), addr.version)
        return bool(
            self._check(keys=[zkey, hkey], args=[hex_ip]),
        )

    def start_updates(self, interval=86400, source=BLOCKLIST_URL):
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
        v4z, _ = self._keys(4)
        v6z, _ = self._keys(6)
        return self._r.zcard(v4z) + self._r.zcard(v6z)
