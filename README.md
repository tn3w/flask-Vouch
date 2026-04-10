<div align="center">

# 𐌅𐌋𐌀𐌔𐌊-ᕓꝊ𐌵𐌂𐋅

Bot-challenge middleware for Flask — intercepts unrecognized visitors, issues proof-of-work or CAPTCHA challenges, and grants HMAC-signed JWT access cookies to solvers.

[![PyPI](https://img.shields.io/pypi/v/flask-Vouch?style=flat-square)](https://pypi.org/project/flask-Vouch/)
[![Python](https://img.shields.io/pypi/pyversions/flask-Vouch?style=flat-square)](https://pypi.org/project/flask-Vouch/)
[![License](https://img.shields.io/github/license/tn3w/flask-Vouch?style=flat-square)](https://github.com/tn3w/flask-Vouch/blob/main/LICENSE)
[![Issues](https://img.shields.io/github/issues/tn3w/flask-Vouch?style=flat-square)](https://github.com/tn3w/flask-Vouch/issues)
[![Stars](https://img.shields.io/github/stars/tn3w/flask-Vouch?style=flat-square)](https://github.com/tn3w/flask-Vouch/stargazers)
[![Downloads](https://img.shields.io/pypi/dm/flask-Vouch?style=flat-square)](https://pypi.org/project/flask-Vouch/)

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

Optional extras:

```bash
pip install flask-Vouch[image]   # image-based captchas (Pillow)
pip install flask-Vouch[audio]   # audio captcha (numpy, scipy)
```

## How it works

1. Every request without a valid signed cookie is intercepted.
2. A proof-of-work challenge (SHA-256 Balloon by default) is issued.
3. The browser solves it in JavaScript and POSTs to `/.tollbooth/verify`.
4. A valid solution sets a signed JWT cookie — subsequent requests pass through.

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

`SECRET_KEY` fallback — if no `secret=` is passed, `app.config["SECRET_KEY"]` is used automatically:

```python
app.config["SECRET_KEY"] = "change-me"
vouch = Vouch()
vouch.init_app(app)
```

## Configuration

Pass as kwargs or via `app.config` with the `VOUCH_` prefix:

| Parameter           | Default              | Description                            |
| ------------------- | -------------------- | -------------------------------------- |
| `secret`            | `SECRET_KEY`         | HMAC/JWT signing key                   |
| `policy`            | default rules        | `Policy` instance                      |
| `exclude`           | `[]`                 | Path regexes to skip entirely          |
| `json_mode`         | `False`              | Return JSON challenge instead of HTML  |
| `cookie_name`       | `_tollbooth`         | Access cookie name                     |
| `cookie_ttl`        | `604800`             | Cookie lifetime in seconds (7 days)    |
| `verify_path`       | `/.tollbooth/verify` | Challenge verification endpoint        |
| `challenge_handler` | `SHA256Balloon`      | Challenge implementation               |
| `blocklist`         | `None`               | `IPBlocklist` instance or list of them |

```python
app.config["VOUCH_COOKIE_NAME"] = "_v"
app.config["VOUCH_COOKIE_TTL"] = 3600
```

## Route decorators

| Decorator          | Behavior                                                  |
| ------------------ | --------------------------------------------------------- |
| `@vouch.exempt`    | Skip challenge entirely for this route                    |
| `@vouch.protect`   | Always run challenge check (overrides global allow)       |
| `@vouch.challenge` | Always issue a challenge regardless of policy             |
| `@vouch.block`     | Deny detected crawlers outright; challenge or pass others |

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
| `blocklist`        | `bool`        | Match IPs in the loaded blocklist         |
| `bogon_ip`         | `bool`        | Match non-global / bogon IPs              |
| `crawler`          | `bool`        | Match detected crawler user agents        |

## Challenge types

```python
from flask_vouch import (
    SHA256Balloon,              # default — proof of work (balloon hashing)
    SHA256,                     # lightweight SHA-256 PoW
    CharacterCaptcha,           # text CAPTCHA
    ImageCaptcha,               # image CAPTCHA          (requires Pillow)
    RotationCaptcha,            # rotation CAPTCHA        (requires Pillow)
    SlidingCaptcha,             # sliding puzzle          (requires Pillow)
    CircleCaptcha,              # circle select CAPTCHA   (requires Pillow)
    ImageGridCaptcha,           # image grid CAPTCHA      (requires Pillow)
    AudioCaptcha,               # audio CAPTCHA           (requires numpy, scipy)
    NavigatorAttestation,       # browser signal attestation
    ThirdPartyCaptchaChallenge, # embed external CAPTCHAs
)

vouch = Vouch(app, secret="s", challenge_handler=CharacterCaptcha())
```

## IP blocklist

```python
from flask_vouch import Vouch, IPBlocklist

bl = IPBlocklist()   # defaults to bundled blocklist URL
bl.load()
bl.start_updates()   # auto-refresh daily in a daemon thread

vouch = Vouch(app, secret="s", blocklist=bl)
```

Multiple blocklists:

```python
vouch = Vouch(app, secret="s", blocklist=[bl1, bl2])
```

## Redis backend

For multi-process / multi-worker deployments:

```python
import redis
from flask_vouch.redis import RedisEngine
from flask_vouch import Vouch

r = redis.Redis()
engine = RedisEngine(r, secret="s")
vouch = Vouch(app, engine=engine)
```

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
rl.init_flask(app)

@app.route("/login")
@rl.limit("5/minute")
def login(): ...
```

### ThirdPartyCaptcha

```python
from flask_vouch.extras import ThirdPartyCaptcha

tpc = ThirdPartyCaptcha(turnstile_site_key="...", turnstile_secret="...")
tpc.init_flask(app)

@app.route("/submit", methods=["POST"])
def submit():
    if not tpc.is_turnstile_valid():
        abort(403)
    ...
```

## Formatting

```bash
pip install black isort
isort . && black .
npx prtfm
```

## License

[Apache-2.0](https://github.com/tn3w/flask-Vouch/blob/main/LICENSE)
