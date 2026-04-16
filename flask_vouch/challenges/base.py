import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class ChallengeType(str, Enum):
    SHA256_BALLOON = "sha256-balloon"
    SHA256 = "sha256"
    CHARACTER_CAPTCHA = "character-captcha"
    NAVIGATOR_ATTESTATION = "navigator-attestation"
    SLIDING_CAPTCHA = "sliding-captcha"
    CIRCLE_CAPTCHA = "circle-captcha"
    THIRD_PARTY_CAPTCHA = "third-party-captcha"
    IMAGE_CAPTCHA = "image-captcha"
    IMAGE_GRID_CAPTCHA = "image-grid-captcha"
    AUDIO_CAPTCHA = "audio-captcha"
    ROTATION_CAPTCHA = "rotation-captcha"
    TRACE_CAPTCHA = "trace-captcha"


DIFFICULTY_OFFSETS: dict[ChallengeType, int] = {
    ChallengeType.SHA256_BALLOON: 0,
    ChallengeType.SHA256: 8,
    ChallengeType.CHARACTER_CAPTCHA: -4,
    ChallengeType.NAVIGATOR_ATTESTATION: 0,
    ChallengeType.SLIDING_CAPTCHA: -4,
    ChallengeType.CIRCLE_CAPTCHA: -4,
    ChallengeType.THIRD_PARTY_CAPTCHA: 0,
    ChallengeType.IMAGE_CAPTCHA: -4,
    ChallengeType.IMAGE_GRID_CAPTCHA: -4,
    ChallengeType.AUDIO_CAPTCHA: -4,
    ChallengeType.ROTATION_CAPTCHA: -4,
    ChallengeType.TRACE_CAPTCHA: -4,
}


def count_leading_zero_bits(data: bytes) -> int:
    for i, byte in enumerate(data):
        if byte:
            return i * 8 + (8 - byte.bit_length())
    return len(data) * 8


@dataclass
class ChallengeBase:
    id: str
    random_data: str
    difficulty: int
    ip_hash: str
    created_at: float
    challenge_type: ChallengeType = ChallengeType.SHA256_BALLOON
    spent: bool = False

    def __post_init__(self):
        if isinstance(self.challenge_type, str):
            self.challenge_type = ChallengeType(self.challenge_type)


class ChallengeHandler(ABC):
    @property
    @abstractmethod
    def challenge_type(self) -> ChallengeType: ...

    @abstractmethod
    def to_difficulty(self, base: int) -> int: ...

    @property
    @abstractmethod
    def template(self) -> str: ...

    @abstractmethod
    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool: ...

    @abstractmethod
    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict: ...

    def generate_random_data(self, difficulty: int = 0) -> str:
        return secrets.token_hex(64)

    def nonce_from_form(self, raw: str) -> int | str:
        return int(raw)

    @property
    def retry_on_failure(self) -> bool:
        return False

    def jwt_extra(self, random_data: str, nonce: int | str) -> dict:
        return {}

    @property
    def supports_websocket(self) -> bool:
        return False

    async def handle_websocket(self, _scope, _receive, _send, _engine) -> None:
        pass

    @property
    def extra_csp(self) -> str:
        return ""

    @property
    def supports_http_poll(self) -> bool:
        return False

    def handle_http_poll(self, _body: dict, _engine) -> dict:
        return {"type": "error", "reason": "not supported"}
