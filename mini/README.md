# mini

An gate for a Flask app in three files. Unknown clients get one page that
proves work, attests its browser, and hands over how the pointer moved. Pass once, get a
signed cookie, never see it again.

```
vouch.py        middleware: rules, proof of work, cookie, verify endpoint
navigator.py    scores browser signals for automation and spoofing
motion.py       scores pointer movement
challenge.html  the page: miner, collector, signal probes
```

## Use

```python
from flask import Flask
from mini.vouch import Vouch

app = Flask(__name__)
app.config["SECRET_KEY"] = "at-least-16-bytes-of-secret"

Vouch(app, trusted_proxies=1, exclude=[r"^/static/"])
```

Demo app: `python -m mini.app`, then http://127.0.0.1:5000.

Nothing else to wire up. `before_request` handles every route and the verify endpoint;
once a request passes, `flask.g.vouch` holds the claims (`nav`, `mot`, `exp`).

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `secret` | `SECRET_KEY` | HMAC key, 16 bytes or more |
| `interactive` | `True` | show the "I am human" button; `False` watches passively |
| `difficulty` | `17` | proof-of-work leading zero bits (~0.3 s in a browser) |
| `cookie_name` | `_vouch` | name of the pass cookie |
| `cookie_ttl` | `604800` | how long a pass lasts, seconds |
| `challenge_ttl` | `1800` | how long an issued challenge stays redeemable |
| `verify_path` | `/.vouch/verify` | where the page posts its answer |
| `exclude` | `()` | regexes for paths that skip the gate |
| `trusted_proxies` | `None` | hop count, or CIDRs, before `X-Forwarded-For` is believed |
| `max_challenges` | `15` | challenge pages per IP per window |
| `max_verify_attempts` | `10` | verify posts per IP per window |
| `rate_window` | `300` | window for both limits, seconds |

`VOUCH_`-prefixed `app.config` keys are not read; pass options to the constructor.

## Who gets challenged

`RULES` runs in order. The first `allow` or `deny` wins; a `challenge` rule is held while
`weigh` rules accumulate, and enough weight raises the difficulty or challenges on its own.

- **deny**: scanner and probe user agents, CMS/dotfile/traversal/injection paths,
  Cloudflare Workers, search-engine impostors (claims Googlebot, DNS says otherwise)
- **allow**: `/robots.txt`, `/.well-known/`, sitemaps, health checks, feed readers,
  link previews, uptime monitors, and crawlers that pass forward-confirmed reverse DNS
- **challenge**: AI crawlers (harder), headless browsers, HTTP libraries, empty or
  crawler-shaped user agents, bogon source addresses, and anything claiming to be a browser
- **weigh**: curl/wget, missing `Accept*`, missing `Sec-Fetch-*` or `Sec-CH-UA` from a
  browser that should send them, `Connection: close`, `*/*` only, automation headers

## The challenge

One page, three answers, posted together:

1. **Proof of work.** `sha256(data + nonce)` with `difficulty` leading zero bits, mined in
   one Web Worker per core (falling back to the page itself where workers are blocked)
   and checked server-side in one hash. Off-thread mining keeps the pointer timestamps
   the motion model reads undistorted. Costs the client, not the server.
2. **Navigator attestation.** Automation globals and patched natives, `navigator`
   consistency (vendor, productSub, languages, plugins), engine fingerprint against the
   claimed browser, WebGL renderer, canvas tampering, fonts, media queries, client hints,
   CSS support versus the claimed Chrome version, CDP console side-effects. The reported
   user agent must match the request header.
3. **Motion attestation.** Mouse, touch, keystroke, scroll and click timings collected
   while the page is open, scored on the model from `motion-attestation`.

`interactive: True` shows a checkbox the visitor clicks, which is what produces a real
approach path; the click turns it into a spinner and the progress bar stays hidden.
`interactive: False` shows the progress bar instead and submits on its own once it has
watched enough movement (or after 9 s).

A pass needs all three: valid proof of work, navigator score over the threshold (0.6, rising
with difficulty), and a motion verdict of `human`, or a `suspicious` verdict paired with a
navigator score of 0.85 or better, which is what carries visitors who barely move.

Challenges are single-use, bound to a hashed IP, and rate limited per IP.

## Motion model

Five categories, penalties subtracted from 1.0:

| Category | Max | What it reads |
| --- | --- | --- |
| `kinematics` | 0.70 | six band-measured path features: braking into the target, micro-structure, turn distribution, turns while fast, straightness, speed spread |
| `evidence` | 0.60 | too few events to judge, never a pass |
| `contract` | 0.60 | impossible transcripts: clocks running backward, keys released before pressed |
| `mouse` | 0.35 | trace texture: curvature entropy, micro-tremor, velocity variance, straight-window index, constant acceleration, teleports, coordinate precision, event-clock quantization |
| `dispatch` | 0.30 | injected input: zero-duration clicks, pixel-perfect centers, uniform key dwell, zero-time press/release pairs, clicks with no press |

Any of `contract`, `kinematics`, `mouse`, `dispatch` reaching 80% of its cap caps the whole
score at 0.45, so one conclusive channel is not averaged away. Verdicts: `human` at 0.5,
`suspicious` at 0.3, `bot` below.

Measured against the `motion-attestation` corpus (27 real captures, 14 path generators
replayed as multi-stroke sessions):

- 25/27 humans read `human`; the other two contain almost no interaction and read
  `suspicious`, which still passes on a trusted navigator score
- 11/14 generators read `suspicious` or `bot`
- `overshoot`, `bellVelocity` and `syntheticHuman` still read `human`; kinematically
  faithful mimics are not separable on geometry, which is what the upstream model says too.
  They are left to the navigator layer and the proof of work.
- CDP-dispatched clicks and `element.click()` with no pointer trace read `bot` outright

## Limits

Signals are self-reported, so a determined client can forge a plausible payload; the cost
is that it must also mine the proof of work for every request and match the header
cross-checks. State is in-process, so challenge single-use and rate limits are per worker.
The cookie is an HMAC-sealed JSON blob, not a JWT, and carries no identity.
