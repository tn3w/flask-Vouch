import hashlib
from dataclasses import dataclass
from pathlib import Path

from .base import (
    DIFFICULTY_OFFSETS,
    ChallengeBase,
    ChallengeHandler,
    ChallengeType,
    count_leading_zero_bits,
)


def _chain(prefix: str, nonce: int, iterations: int) -> bytes:
    digest = hashlib.sha256((prefix + str(nonce)).encode()).digest()
    for _ in range(iterations - 1):
        digest = hashlib.sha256(digest).digest()
    return digest


@dataclass
class ChainCaptcha(ChallengeHandler):
    iterations: int = 1000

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.CHAIN_CAPTCHA

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

    @property
    def template(self) -> str:
        return (Path(__file__).parent / "templates" / "chain_captcha.html").read_text()

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        result = _chain(random_data, int(nonce), self.iterations)
        return count_leading_zero_bits(result) >= difficulty

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        return {
            "id": challenge.id,
            "data": challenge.random_data,
            "difficulty": challenge.difficulty,
            "iterations": self.iterations,
            "verifyPath": verify_path,
            "redirect": redirect,
        }
