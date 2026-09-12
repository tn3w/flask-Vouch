from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .base import (
    ChallengeBase,
    ChallengeHandler,
    ChallengeType,
    count_leading_zero_bits,
)


@dataclass
class SHA256(ChallengeHandler):
    template: str | Path | None = None

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.SHA256

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        result = hashlib.sha256((random_data + str(nonce)).encode()).digest()
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
            "verifyPath": verify_path,
            "redirect": redirect,
        }
