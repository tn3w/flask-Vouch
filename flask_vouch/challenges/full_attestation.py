"""Proof of work, navigator attestation and motion attestation on one page."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from .base import (
    ChallengeBase,
    ChallengeHandler,
    ChallengeType,
    count_leading_zero_bits,
)
from .motion import (
    ATTESTATION_TTL,
    SESSION_TIMEOUT,
    _Session,
    challenge_binding,
    open_challenge,
    read_attestation,
    score_motion,
)
from .navigator_attestation import validate_signals
from .scoring import SessionStore, sign_token


@dataclass
class FullAttestation(ChallengeHandler):
    """Everything the browser can be asked for at once: it mines a proof of work,
    attests its own internals, and hands over how the pointer moved.

    A pass needs all three: a valid proof, a navigator score over the threshold,
    and a motion verdict of ``human``, or ``suspicious`` movement carried by a
    navigator score of ``trusted_navigator`` or better, which is what clears
    visitors who barely move the pointer.
    """

    interactive: bool = True
    watch_seconds: int = 6
    min_navigator: float = 0.6
    trusted_navigator: float = 0.85
    min_motion: float = 0.5
    base_difficulty: int = 18
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    template: str | Path | None = None

    def __post_init__(self) -> None:
        self._sessions = SessionStore(SESSION_TIMEOUT)

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.FULL_ATTESTATION

    def generate_random_data(self, difficulty: int = 0) -> str:
        return secrets.token_hex(32)

    def navigator_threshold(self, difficulty: int) -> float:
        harder = max(0, difficulty - self.base_difficulty) * 0.02
        return min(0.85, self.min_navigator + harder)

    def solves_proof(self, random_data: str, proof: str, difficulty: int) -> bool:
        if not proof.isdigit() or len(proof) > 20:
            return False
        digest = hashlib.sha256((random_data + proof).encode()).digest()
        return count_leading_zero_bits(digest) >= difficulty

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        proof, _, token = str(nonce).partition(".")
        if not self.solves_proof(random_data, proof, difficulty):
            return False

        payload = read_attestation(token, self.secret, random_data)
        if not payload:
            return False

        navigator = payload.get("score", 0)
        if navigator < self.navigator_threshold(difficulty):
            return False
        if payload.get("motion", 0) < self.min_motion:
            return False
        if payload.get("verdict") == "human":
            return True
        return navigator >= self.trusted_navigator

    def jwt_extra(self, random_data: str, nonce: int | str) -> dict:
        _, _, token = str(nonce).partition(".")
        payload = read_attestation(token, self.secret, random_data)
        if not payload:
            return {}
        return {"score": payload["score"], "motion": payload["motion"]}

    def nonce_from_form(self, raw: str) -> str:
        return raw.strip()

    @property
    def retry_on_failure(self) -> bool:
        return True

    @property
    def supports_http_poll(self) -> bool:
        return True

    def render_payload(
        self, challenge: ChallengeBase, verify_path: str, redirect: str
    ) -> dict:
        return {
            "id": challenge.id,
            "data": challenge.random_data,
            "difficulty": challenge.difficulty,
            "verifyPath": verify_path,
            "redirect": redirect,
            "interactive": self.interactive,
            "watchSeconds": self.watch_seconds,
        }

    def handle_http_poll(self, body: dict, engine) -> dict:
        challenge_id = str(body.get("id", ""))
        challenge = open_challenge(engine, challenge_id, self.challenge_type)
        if not challenge:
            return {"type": "error", "reason": "invalid challenge"}

        if body.get("init"):
            session = _Session(nonce=secrets.token_hex(16))
            self._sessions.start(challenge_id, session)
            return {
                "type": "challenge",
                "nonce": session.nonce,
                "watchSeconds": self.watch_seconds,
            }

        session = self._sessions.get(challenge_id)
        if not session or body.get("nonce") != session.nonce:
            return {"type": "error", "reason": "no session"}

        self._sessions.drop(challenge_id)
        return self._attest(body, challenge.random_data)

    def _attest(self, body: dict, random_data: str) -> dict:
        navigator = validate_signals(body.get("signals") or {})
        motion = score_motion(body.get("motion"))
        token = sign_token(
            {
                "score": navigator["score"],
                "motion": motion["score"],
                "verdict": motion["verdict"],
                "cid": challenge_binding(random_data),
                "exp": int(time.time() + ATTESTATION_TTL),
            },
            self.secret,
        )
        return {
            "type": "result",
            "token": token,
            "verdict": motion["verdict"],
            "flags": navigator["flags"][:6],
        }
