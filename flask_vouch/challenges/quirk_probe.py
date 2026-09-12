import hashlib
import secrets
import time
from dataclasses import dataclass, field

from .base import ChallengeBase, ChallengeHandler, ChallengeType
from .scoring import (
    SessionStore,
)
from .scoring import penalize as _fail
from .scoring import (
    rounded,
    run_checks,
    score_token,
    verify_token,
)


def _check_consistency(report: dict, state: dict) -> None:
    text = report.get("textMetrics") or {}
    measure = text.get("measure")
    bbox = text.get("bbox")
    offset = text.get("offset")
    computed = text.get("computed")

    values = [
        v for v in (measure, bbox, offset, computed) if isinstance(v, (int, float))
    ]
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
    state = run_checks(_CHECKS, report)
    return {"score": rounded(state["score"]), "flags": state["flags"]}


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


@dataclass
class _Session:
    id: str
    salt: str
    nonce: str
    started_at: float = field(default_factory=time.monotonic)


class QuirkProbe(ChallengeHandler):
    SESSION_TIMEOUT = 45
    MIN_SCORE = 0.55

    def __init__(self) -> None:
        self._sessions = SessionStore(self.SESSION_TIMEOUT)

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.QUIRK_PROBE

    def generate_random_data(self, difficulty: int = 0) -> str:
        return secrets.token_hex(32)

    def nonce_from_form(self, raw: str) -> str:
        return raw

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        payload = verify_token(str(nonce), random_data.encode())
        if not payload or time.time() > payload.get("exp", 0):
            return False
        threshold = min(
            0.85, max(self.MIN_SCORE, self.MIN_SCORE + (difficulty - 5) * 0.02)
        )
        return payload.get("score", 0) >= threshold

    def jwt_extra(self, random_data: str, nonce: int | str) -> dict:
        payload = verify_token(str(nonce), random_data.encode())
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
            self._sessions.start(challenge_id, session)
            return {
                "type": "recipe",
                "nonce": session.nonce,
                "recipe": build_recipe(session.salt),
            }

        session = self._sessions.get(challenge_id)
        if not session or body.get("nonce") != session.nonce:
            return {"type": "error", "reason": "no session"}

        challenge = engine.store.get(challenge_id)
        if not challenge:
            return {"type": "error", "reason": "invalid challenge"}

        self._sessions.drop(challenge_id)

        result = validate_report(body.get("report") or {})
        token = score_token(result["score"], challenge.random_data.encode())
        return {"type": "result", "token": token}
