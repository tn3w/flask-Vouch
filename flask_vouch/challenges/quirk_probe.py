import hashlib
import hmac
import json
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from .base import ChallengeBase, ChallengeHandler, ChallengeType


def _fail(state: dict, amount: float, reason: str) -> None:
    state["score"] = max(0.0, state["score"] - amount)
    state["flags"].append(reason)


def _check_consistency(report: dict, state: dict) -> None:
    text = report.get("textMetrics") or {}
    measure = text.get("measure")
    bbox = text.get("bbox")
    offset = text.get("offset")
    computed = text.get("computed")

    values = [v for v in (measure, bbox, offset, computed) if isinstance(v, (int, float))]
    if len(values) < 3:
        _fail(state, 0.4, "consistency:missing text APIs")
        return
    if any(v <= 0 for v in values):
        _fail(state, 0.4, "consistency:zero-width text")
        return

    spread = (max(values) - min(values)) / max(values)
    if spread > 0.15:
        _fail(state, 0.3, "consistency:text APIs disagree")

    reflow = report.get("reflow") or {}
    narrow = reflow.get("narrow")
    wide = reflow.get("wide")
    if not (isinstance(narrow, (int, float)) and isinstance(wide, (int, float))):
        _fail(state, 0.3, "consistency:no reflow data")
    elif wide <= narrow:
        _fail(state, 0.3, "consistency:layout did not reflow")


def _check_render(report: dict, state: dict) -> None:
    render = report.get("render") or {}
    if not render.get("supported"):
        _fail(state, 0.5, "render:canvas unsupported")
        return

    if not render.get("antialiased"):
        _fail(state, 0.3, "render:no antialiased edges")

    if not render.get("alphaBlended"):
        _fail(state, 0.2, "render:no alpha blending")

    if render.get("blank"):
        _fail(state, 0.5, "render:blank readback")

    distinct = render.get("distinctColors", 0)
    if distinct < 4:
        _fail(state, 0.3, "render:too few distinct colors")

    if not render.get("seedMatched"):
        _fail(state, 0.3, "render:recipe shapes missing")


def _check_compositor(report: dict, state: dict) -> None:
    comp = report.get("compositor") or {}
    if not comp.get("rafFired"):
        _fail(state, 0.25, "compositor:rAF never fired")
        return
    interval = comp.get("interval")
    if isinstance(interval, (int, float)) and (interval <= 0 or interval > 100):
        _fail(state, 0.15, "compositor:implausible frame interval")
    if not comp.get("microtaskOrder"):
        _fail(state, 0.1, "compositor:wrong microtask order")


_CHECKS = [_check_consistency, _check_render, _check_compositor]


def validate_report(report: dict) -> dict:
    state = {"score": 1.0, "flags": []}
    for check in _CHECKS:
        check(report, state)
    score = round(state["score"] * 10000) / 10000
    return {"score": score, "flags": state["flags"]}


def build_recipe(salt: str) -> dict:
    digest = hashlib.sha256(salt.encode()).digest()
    shapes = []
    for i in range(4):
        offset = i * 5
        shapes.append(
            {
                "x": digest[offset] % 180,
                "y": digest[offset + 1] % 60,
                "radius": 8 + digest[offset + 2] % 24,
                "hue": (digest[offset + 3] * 360) // 256,
                "alpha": 0.4 + (digest[offset + 4] % 60) / 100,
            }
        )
    glyph = "AbgyQ%@".encode()[digest[19] % 7]
    return {"shapes": shapes, "glyphCode": glyph, "checksum": digest[:4].hex()}


def _b64(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_token(payload: dict, secret: bytes) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    return f"{_b64(body.encode())}.{sig}"


def _verify_token(token: str, secret: bytes) -> dict | None:
    try:
        dot = token.index(".")
        body_b64, sig = token[:dot], token[dot + 1 :]
        body = urlsafe_b64decode(body_b64 + "==").decode()
        expected = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        return json.loads(body)
    except Exception:
        return None


@dataclass
class _Session:
    id: str
    salt: str
    nonce: str
    started_at: float = field(default_factory=time.monotonic)


class QuirkProbe(ChallengeHandler):
    SESSION_TIMEOUT = 45

    def __init__(self) -> None:
        self._sessions: dict[str, _Session] = {}
        self._lock = Lock()

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.QUIRK_PROBE

    def to_difficulty(self, base: int) -> int:
        return base

    @property
    def template(self) -> str:
        return (Path(__file__).parent / "templates" / "quirk_probe.html").read_text()

    def generate_random_data(self, difficulty: int = 0) -> str:
        return secrets.token_hex(32)

    def nonce_from_form(self, raw: str) -> str:
        return raw

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        payload = _verify_token(str(nonce), random_data.encode())
        if not payload or time.time() > payload.get("exp", 0):
            return False
        threshold = min(0.85, max(0.55, 0.55 + (difficulty - 5) * 0.02))
        return payload.get("score", 0) >= threshold

    def jwt_extra(self, random_data: str, nonce: int | str) -> dict:
        payload = _verify_token(str(nonce), random_data.encode())
        return {"score": payload["score"]} if payload else {}

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        return {"id": challenge.id, "verifyPath": verify_path, "redirect": redirect}

    @property
    def supports_http_poll(self) -> bool:
        return True

    def handle_http_poll(self, body: dict, engine) -> dict:
        challenge_id = body.get("id", "")

        if body.get("init"):
            challenge = engine.store.get(challenge_id)
            if (
                not challenge
                or challenge.spent
                or challenge.challenge_type != ChallengeType.QUIRK_PROBE
            ):
                return {"type": "error", "reason": "invalid challenge"}
            session = _Session(
                id=challenge_id,
                salt=challenge.random_data,
                nonce=secrets.token_hex(16),
            )
            with self._lock:
                self._evict()
                self._sessions[challenge_id] = session
            return {
                "type": "recipe",
                "nonce": session.nonce,
                "recipe": build_recipe(session.salt),
            }

        with self._lock:
            session = self._sessions.get(challenge_id)
        if not session or body.get("nonce") != session.nonce:
            return {"type": "error", "reason": "no session"}

        challenge = engine.store.get(challenge_id)
        if not challenge:
            return {"type": "error", "reason": "invalid challenge"}

        with self._lock:
            self._sessions.pop(challenge_id, None)

        result = validate_report(body.get("report") or {})
        token = _sign_token(
            {"score": result["score"], "exp": int(time.time() + 300)},
            challenge.random_data.encode(),
        )
        return {"type": "result", "token": token}

    def _evict(self) -> None:
        cutoff = time.monotonic() - self.SESSION_TIMEOUT
        for key in [k for k, v in self._sessions.items() if v.started_at < cutoff]:
            del self._sessions[key]
