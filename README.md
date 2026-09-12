<div align="center">

# 𐌅𐌋𐌀𐌔𐌊-ᕓꝊ𐌵𐌂𐋅

Bot-challenge middleware for Flask. Intercepts unrecognized visitors, issues proof-of-work or CAPTCHA challenges, and grants HMAC-signed JWT access cookies to solvers.

[![PyPI](https://img.shields.io/pypi/v/flask-Vouch?style=flat-square)](https://pypi.org/project/flask-Vouch/)
[![Python](https://img.shields.io/pypi/pyversions/flask-Vouch?style=flat-square)](https://pypi.org/project/flask-Vouch/)
[![License](https://img.shields.io/github/license/tn3w/flask-Vouch?style=flat-square)](https://github.com/tn3w/flask-Vouch/blob/main/LICENSE)
[![Issues](https://img.shields.io/github/issues/tn3w/flask-Vouch?style=flat-square)](https://github.com/tn3w/flask-Vouch/issues)
[![Stars](https://img.shields.io/github/stars/tn3w/flask-Vouch?style=flat-square)](https://github.com/tn3w/flask-Vouch/stargazers)
[![Downloads](https://static.pepy.tech/personalized-badge/flask-Vouch?period=month&units=international_system&left_color=grey&right_color=blue&left_text=downloads/month&style=flat-square)](https://pepy.tech/project/flask-Vouch)

</div>

```python
from flask import Flask
from flask_vouch import Vouch

app = Flask(__name__)
vouch = Vouch(app, secret="change-me")
```

Bots get a browser challenge page. Humans solve it once, get a cookie, browse freely.

## Install

```bash
pip install flask-Vouch
```

Python 3.9 or newer, Flask 2.0 or newer.

Optional extras:

```bash
pip install flask-Vouch[image]      # image-based captchas (Pillow, numpy)
pip install flask-Vouch[audio]      # audio captcha (numpy, scipy)
```

## How it works

1. Every suspicious unauthenticated request matching the configured rules is redirected to a challenge page.
2. A proof-of-work challenge (SHA-256 Balloon by default) is issued.
3. The browser solves it in JavaScript and POSTs to `/.tollbooth/verify`.
4. A valid solution sets a signed JWT cookie subsequent requests pass through.

Behind a proxy, set `trusted_proxies` so the client address (used for rate limits
and challenge binding) is read from `X-Forwarded-For` only where that header is
actually trustworthy, see [Behind a proxy](#behind-a-proxy).

## Quick start

```python
from flask import Flask
from flask_vouch import Vouch

app = Flask(__name__)
vouch = Vouch(app, secret="change-me")

@app.route("/")
def index():
    return "You passed the challenge!"

@app.route("/internal")
@vouch.exempt
def internal():
    return "ok"
```

Application factory:

```python
vouch = Vouch(secret="change-me")

def create_app():
    app = Flask(__name__)
    vouch.init_app(app)
    return app
```

`SECRET_KEY` fallback if no `secret=` is passed, `app.config["SECRET_KEY"]` is used automatically:

```python
app.config["SECRET_KEY"] = "change-me"
vouch = Vouch()
vouch.init_app(app)
```

## Configuration

Pass as kwargs or via `app.config` with the `VOUCH_` prefix:

| Parameter                | Default              | Description                                           |
| ------------------------ | -------------------- | ----------------------------------------------------- |
| `secret`                 | `SECRET_KEY`         | HMAC/JWT signing key, 16 bytes minimum                |
| `policy`                 | default rules        | `Policy` instance                                     |
| `exclude`                | `[]`                 | Path regexes to skip entirely                         |
| `json_mode`              | `False`              | Return JSON challenge instead of HTML                 |
| `trusted_proxies`        | `None`               | Proxy hop count, or the networks they use             |
| `cookie_name`            | `_tollbooth`         | Access cookie name                                    |
| `cookie_ttl`             | `604800`             | Cookie lifetime in seconds (7 days)                   |
| `cookie_secure`          | `True`               | `Secure` flag; only set over HTTPS                    |
| `cookie_samesite`        | `Lax`                | `SameSite` flag                                       |
| `bind_ip`                | `False`              | Tie the cookie to the solver's IP                     |
| `verify_path`            | `/.tollbooth/verify` | Challenge verification endpoint                       |
| `challenge_handler`      | `SHA256Balloon`      | Challenge implementation                              |
| `template_dir`           | `None`               | Directory of challenge pages overriding the built-ins |
| `default_difficulty`     | `10`                 | Difficulty when a rule sets none                      |
| `challenge_threshold`    | `5`                  | Weight at which `weigh` rules trigger a challenge     |
| `challenge_ttl`          | `1800`               | Seconds an unsolved challenge stays valid             |
| `max_challenge_requests` | `10`                 | Challenges per IP per window                          |
| `max_challenge_failures` | `3`                  | Failed solutions per IP per window                    |
| `rate_limit_window`      | `300`                | Seconds both limits are measured over                 |
| `branding`               | `True`               | Show the footer credit on challenge pages             |
| `accent_color`           | `#44ff88`            | Challenge page accent                                 |
| `blocklist`              | `None`               | `NetSet` instance or list of them                     |

```python
app.config["VOUCH_COOKIE_NAME"] = "_v"
app.config["VOUCH_COOKIE_TTL"] = 3600
```

`bind_ip` is off by default: a cookie keeps working when a phone switches
towers or a laptop changes network. Turn it on when session theft matters more
than those re-challenges. The challenge itself is always IP-bound, so a solution
cannot be farmed out to another address.

### Behind a proxy

`X-Forwarded-For` is ignored unless `trusted_proxies` says how far to trust it,
otherwise anyone could set the header and sidestep the per-IP limits.

```python
vouch = Vouch(app, secret="s", trusted_proxies=1)                 # one proxy hop
vouch = Vouch(app, secret="s", trusted_proxies=["10.0.0.0/8"])    # proxy networks
```

With a hop count the address written by your own proxy is used; anything a
client prepended to the header is skipped. With networks the chain is walked
from the right until an address outside them is found.

## Route decorators

| Decorator          | Behavior                                                  |
| ------------------ | --------------------------------------------------------- |
| `@vouch.exempt`    | Skip challenge entirely for this route                    |
| `@vouch.protect`   | Always run challenge check (overrides global allow)       |
| `@vouch.challenge` | Always issue a challenge regardless of policy             |
| `@vouch.block`     | Deny detected crawlers outright; challenge or pass others |

`exempt` also takes an endpoint name, `vouch.exempt("static")` for static files,
`vouch.exempt("admin.static")` for a blueprint's.

## Request claims

Anything that passes the bouncer gets `flask.g.vouch`:

```python
@app.route("/")
def index():
    claims = flask.g.vouch
    if claims.is_crawler:
        return f"hello {claims.crawler_name}"
    return "hello"
```

| Field             | Meaning                                                           |
| ----------------- | ----------------------------------------------------------------- |
| `is_crawler`      | User agent looks like a crawler                                   |
| `crawler_name`    | Crawler name when one could be read, else `None`                  |
| `matched_rule`    | Name of the rule that allowed the request, `None` if none matched |
| `blocklist_match` | Matching blocklist range, when the rule matched on `blocklist`    |
| `score`           | Attestation score, for handlers that produce one                  |
| `cid`             | Id of the solved challenge, on cookie-carrying requests           |

## Custom rules

```python
from flask_vouch import Vouch, Policy, Rule

policy = Policy(
    rules=[
        Rule(name="allow-google", action="allow", user_agent="Googlebot"),
        Rule(name="block-scrapers", action="deny", user_agent="AhrefsBot|SemrushBot"),
        Rule(name="challenge-curl", action="challenge", difficulty=8, user_agent="curl"),
    ]
)

vouch = Vouch(app, secret="s", policy=policy)
```

Load the built-in ruleset from `rules.json`:

```python
from flask_vouch import load_policy

vouch = Vouch(app, secret="s", policy=load_policy())
```

Rule fields:

| Field              | Type          | Description                               |
| ------------------ | ------------- | ----------------------------------------- |
| `name`             | `str`         | Identifier                                |
| `action`           | `str`         | `allow` · `deny` · `challenge` · `weigh`  |
| `user_agent`       | `str` (regex) | Match on User-Agent header                |
| `path`             | `str` (regex) | Match on request path                     |
| `headers`          | `dict`        | Match on arbitrary headers (regex values) |
| `remote_addresses` | `list[str]`   | CIDR ranges to match                      |
| `difficulty`       | `int`         | Challenge difficulty (default: policy)    |
| `weight`           | `int`         | Score added when `action=weigh`           |
| `blocklist`        | `bool`        | Match IPs in the loaded netset            |
| `bogon_ip`         | `bool`        | Match non-global / bogon IPs              |
| `crawler`          | `bool`        | Match detected crawler user agents        |

## Challenge types

```python
from flask_vouch import (
    SHA256Balloon,              # default, proof of work    (SHA-256 balloon hashing)
    SHA256,                     # lightweight SHA-256 PoW
    ChainCaptcha,               # no-interaction iterated-SHA-256 PoW
    CharacterCaptcha,           # text CAPTCHA
    ImageCaptcha,               # image CAPTCHA             (requires [image])
    RotationCaptcha,            # rotation CAPTCHA          (requires [image])
    CupCaptcha,                 # cup fill CAPTCHA          (requires [image])
    SlidingCaptcha,             # sliding puzzle            (requires [image])
    CircleCaptcha,              # circle select CAPTCHA     (requires [image])
    TraceCaptcha,               # curve-trace CAPTCHA       (pure Python, kinematics)
    ImageGridCaptcha,           # image grid CAPTCHA        (requires [image])
    AudioCaptcha,               # audio CAPTCHA             (requires [audio])
    NavigatorAttestation,       # browser signal attestation
    QuirkProbe,                 # browser-engine quirk verification
    ThirdPartyCaptchaChallenge, # embed external CAPTCHAs
)

vouch = Vouch(app, secret="s", challenge_handler=CharacterCaptcha())
```

### Custom challenge pages

Every challenge ships a page; replace it per handler or per directory. A `Path`
is read from disk, a `str` is the page itself:

```python
from pathlib import Path

vouch = Vouch(app, secret="s", challenge_handler=SHA256(template=Path("wall.html")))
vouch = Vouch(app, secret="s", template_dir="templates/vouch")
```

`template_dir` is looked up by challenge type, so `templates/vouch/sha256.html`
replaces the SHA-256 page and any type without a file there keeps the built-in
one. A handler's own `template` wins over the directory. Files are read once and
cached, restart to pick up edits.

Copy a bundled page from `flask_vouch/challenges/templates/` as a starting point.
Every placeholder below is replaced where it appears, a page only needs the ones
it uses:

| Placeholder          | Contents                                                               |
| -------------------- | ---------------------------------------------------------------------- |
| `{{CHALLENGE_DATA}}` | Whole payload as JSON, escaped for embedding in `<script>`             |
| `{{<payload key>}}`  | One key of `render_payload`, HTML-escaped (`{{id}}`, `{{image}}`, ...) |
| `{{ACCENT_COLOR}}`   | `accent_color` from the policy                                         |
| `{{BRANDING}}`       | Footer credit, empty when `branding=False`                             |
| `{{ERROR}}`          | Retry message after a wrong answer, empty otherwise                    |

Proof-of-work and attestation pages take the JSON blob because their scripts need
it; the CAPTCHA pages read individual keys. `{{ERROR}}` only ever gets filled on
handlers whose `retry_on_failure` is true, which is every CAPTCHA.

The page must POST `id`, `nonce` and `redirect` to `verifyPath`. Two-coordinate
answers may post `nonce.x` and `nonce.y` instead of `nonce`.

### Custom handlers

Subclass `ChallengeHandler`, only `challenge_type`, `verify` and `render_payload`
are required. `to_difficulty` applies the type's offset from `DIFFICULTY_OFFSETS`,
and the page is read from `challenges/templates/<challenge-type>.html` unless a
`template` is set.

```python
from flask_vouch.challenges import ChallengeHandler, ChallengeType

class MyChallenge(ChallengeHandler):
    @property
    def challenge_type(self):
        return ChallengeType.SHA256

    def verify(self, random_data, nonce, difficulty):
        return str(nonce) == random_data[:4]

    def render_payload(self, challenge, verify_path, redirect):
        return {"id": challenge.id, "verifyPath": verify_path, "redirect": redirect}
```

CAPTCHAs that must hand the browser a page while keeping the answer server-side
subclass `SignedTokenHandler`: `issue_token(solution)` returns the encrypted,
HMAC-signed, expiring string stored as the challenge's `random_data`, and
`read_token(token)` returns the solution back (raising once `token_ttl` passes).
Handlers that render media additionally keep it in a `RenderCache` between
`generate_random_data` and `render_payload`.

A handler raising during generation, rendering or verification is logged on the
`flask_vouch` logger and answered with `503`, the rest of the site keeps serving.

## IP netset

A netset is a newline-delimited list of IPs, CIDR ranges, or `start-end`
ranges (`#` comments ignored) the [FireHOL ipset/netset] format. `NetSet`
loads one from a file path or URL, merges overlapping ranges, and answers
membership in O(log n).

```python
from flask_vouch import Vouch, NetSet

ns = NetSet()        # defaults to bundled blocklist.netset URL
ns.load()
ns.start_updates()   # auto-refresh daily in a daemon thread

vouch = Vouch(app, secret="s", blocklist=ns)
```

Custom source(s) path or URL:

```python
ns = NetSet("https://example.com/bad-ips.netset")
many = NetSet.from_sources(["a.netset", "b.netset"])

vouch = Vouch(app, secret="s", blocklist=[ns1, ns2])
```

[FireHOL ipset/netset]: https://github.com/firehol/blocklist-ipsets

## Redis backend

Challenges, rate limits and CAPTCHA datasets live in memory per process. For
multi-process / multi-worker deployments move them to Redis, which also shares
the secret and lets policy changes propagate to every worker:

```python
import redis
from flask_vouch.redis import RedisEngine
from flask_vouch import Vouch

r = redis.Redis()
engine = RedisEngine(r, secret="s")
vouch = Vouch(app, engine=engine)
```

`RedisNetSet` keeps a blocklist in Redis the same way, with one worker
refreshing it under a lock.

## Production checklist

- Set a `secret` of at least 16 bytes and keep it stable across restarts and
  workers, a new secret invalidates every issued cookie.
- Set `trusted_proxies` when running behind a proxy, otherwise per-IP limits are
  measured against the proxy address.
- Use the [Redis backend](#redis-backend) for more than one worker so challenges
  and rate limits are shared rather than per process.
- Serve over HTTPS, `cookie_secure` only sets the `Secure` flag on secure requests.
- `vouch.exempt("static")` keeps assets out of the bouncer, and health checks out
  of it with `exclude=[r"^/health"]`.
- Challenge pages need inline scripts, so keep the shipped
  `Content-Security-Policy` (the response carries its own) intact at the proxy.
- Watch the `flask_vouch` logger: it reports rate-limit hits at `INFO` and
  handler failures with a traceback.

## Package layout

| Module         | Contents                                                   |
| -------------- | ---------------------------------------------------------- |
| `vouch.py`     | Flask glue: `Vouch`, decorators, request/response mapping  |
| `engine.py`    | `Engine`: challenges, cookies, rate-limit checks           |
| `policy.py`    | `Request`, `Rule`, `Policy`, `load_policy`, defaults       |
| `rendering.py` | Template resolution, challenge page rendering, CSP headers |
| `stores.py`    | In-memory `ChallengeStore` and `RateLimiter`               |
| `tokens.py`    | HS256 JWT encode/decode                                    |
| `crawlers.py`  | User-agent crawler detection                               |
| `netset.py`    | `NetSet` IP blocklists                                     |
| `redis.py`     | Redis-backed store, rate limiter, netset and engine        |
| `challenges/`  | Challenge handlers, their pages and datasets               |
| `extras/`      | `ErrorHandler`, `RateLimiter`, `ThirdPartyCaptcha`         |

## Extras

### ErrorHandler

```python
from flask_vouch.extras import ErrorHandler

eh = ErrorHandler(bouncer=vouch)
eh.init_flask(app)
```

### RateLimiter

```python
from flask_vouch.extras import RateLimiter

rl = RateLimiter(default="100/minute")
rl.exempt("static")
rl.init_flask(app)

@app.route("/login")
@rl.limit("5/minute")
def login(): ...
```

`init_flask` buckets per endpoint, so every asset on a page shares one `static`
budget, exempt it unless you want asset-heavy browsing to hit 429.

### ThirdPartyCaptcha

Puts an external CAPTCHA on your own forms, separate from the bouncer. Pass the
keys per provider, `init_flask` then exposes each widget to Jinja:

```python
from flask_vouch.extras import ThirdPartyCaptcha

tpc = ThirdPartyCaptcha(
    turnstile_site_key="...", turnstile_secret="...",
    language="en",   # "auto" follows the browser
    theme="dark",    # "auto" follows the color scheme
)
tpc.init_flask(app)

@app.route("/submit", methods=["POST"])
def submit():
    if not tpc.is_turnstile_valid():
        abort(403)
    ...
```

Drop a widget into a template by name, it renders as HTML and brings its own
hidden field:

```html
<form method="post" action="/submit">
    <input name="email" type="email" required />
    {{ turnstile }}
    <button type="submit">Sign up</button>
</form>
```

Every provider takes `<name>_site_key` and `<name>_secret` and is checked with
`is_<name>_valid()`: `recaptcha`, `hcaptcha`, `turnstile`, `friendly`,
`captchafox`, `mtcaptcha`, `arkose`, `geetest`. Only the ones you passed keys for
appear; a validator returns `False` when the token is missing, stale or the
secret is unset.

Altcha is self-hosted proof of work, so it has no site key and `altcha_secret` is
optional, `init_flask` derives one from `SECRET_KEY` (or the Vouch secret). It
comes in five difficulties, `{{ altcha1 }}` to `{{ altcha5 }}`, with
`{{ altcha }}` at level 2.

Outside Jinja:

```python
embed = tpc.get_embed("turnstile")
embed = tpc.get_embed("altcha", hardness=4)
embed = tpc.get_embed("recaptcha", site_key="...")
```

## Development

```bash
pip install -e ".[image,audio]" pytest pytest-cov black isort basedpyright
pytest                 # suite runs on Python 3.9 - 3.14
basedpyright           # type check, targets the oldest supported version
isort . && black .
npx prtfm
```

## License

[Apache-2.0](https://github.com/tn3w/flask-Vouch/blob/main/LICENSE)
