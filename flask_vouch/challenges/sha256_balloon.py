import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from .base import (
    DIFFICULTY_OFFSETS,
    ChallengeBase,
    ChallengeHandler,
    ChallengeType,
    count_leading_zero_bits,
)


def _balloon(
    prefix: str, nonce: int, space_cost: int, time_cost: int, delta: int
) -> bytes:
    data = (prefix + str(nonce)).encode()
    buf = bytearray(space_cost * 32)
    counter = 0

    def sha(ctr, *parts):
        return hashlib.sha256(struct.pack("<I", ctr) + b"".join(parts)).digest()

    def get(i):
        return bytes(buf[i * 32 : (i + 1) * 32])

    def put(i, val):
        buf[i * 32 : (i + 1) * 32] = val

    put(0, sha(counter, data))
    counter += 1

    for i in range(1, space_cost):
        put(i, sha(counter, get(i - 1)))
        counter += 1

    for t in range(time_cost):
        for i in range(space_cost):
            prev = (i - 1) % space_cost
            put(i, sha(counter, get(prev), get(i)))
            counter += 1

            for j in range(delta):
                param = struct.pack("<IIII", counter, t, i, j)
                counter += 1
                other = (
                    int.from_bytes(hashlib.sha256(param).digest()[:4], "big")
                    % space_cost
                )
                put(i, sha(counter, get(i), get(other)))
                counter += 1

    return get(space_cost - 1)


@dataclass
class SHA256Balloon(ChallengeHandler):
    space_cost: int = 1024
    time_cost: int = 1
    delta: int = 3

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.SHA256_BALLOON

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

    @property
    def template(self) -> str:
        return (Path(__file__).parent / "templates" / "sha256_balloon.html").read_text()

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        result = _balloon(
            random_data, int(nonce), self.space_cost, self.time_cost, self.delta
        )
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
            "spaceCost": self.space_cost,
            "timeCost": self.time_cost,
            "delta": self.delta,
            "verifyPath": verify_path,
            "redirect": redirect,
        }
