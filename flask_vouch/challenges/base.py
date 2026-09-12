from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from threading import Lock

TEMPLATES_DIR = Path(__file__).parent / "templates"
TOKEN_TTL = 1800
RENDER_CACHE_SIZE = 64


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
    CUP_CAPTCHA = "cup-captcha"
    CHAIN_CAPTCHA = "chain-captcha"
    QUIRK_PROBE = "quirk-probe"


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
    ChallengeType.CUP_CAPTCHA: -4,
    ChallengeType.CHAIN_CAPTCHA: 0,
    ChallengeType.QUIRK_PROBE: 0,
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
    """Base for every challenge.

    Handlers set ``template`` to override the bundled page: a ``Path`` is read
    from disk, a ``str`` is used as the page itself.
    """

    template: str | Path | None = None

    @property
    @abstractmethod
    def challenge_type(self) -> ChallengeType: ...

    @abstractmethod
    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool: ...

    @abstractmethod
    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict: ...

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

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
    def extra_csp(self) -> str:
        return ""

    @property
    def supports_http_poll(self) -> bool:
        return False

    def handle_http_poll(self, _body: dict, _engine) -> dict:
        return {"type": "error", "reason": "not supported"}


@dataclass
class SignedTokenHandler(ChallengeHandler):
    """Handler whose solution travels inside an encrypted, signed, expiring token."""

    token_ttl: int = TOKEN_TTL
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    template: str | Path | None = None

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()

    def _keystream(self, iv: str, length: int) -> bytes:
        key = hmac.new(self.secret, iv.encode(), hashlib.sha256).digest()
        return (key * (length // len(key) + 1))[:length]

    def issue_token(self, solution: str, suffix: str = "") -> str:
        iv = secrets.token_hex(16)
        plaintext = solution.encode()
        ciphertext = bytes(
            a ^ b for a, b in zip(plaintext, self._keystream(iv, len(plaintext)))
        ).hex()
        payload = f"{iv}:{ciphertext}:{int(time.time())}:{secrets.token_hex(8)}"
        return f"{payload}:{self._sign(payload)}{suffix}"

    def read_token(self, token: str) -> str:
        iv, ciphertext, issued_at, nonce, signature = token.split(":")[:5]
        payload = f"{iv}:{ciphertext}:{issued_at}:{nonce}"

        if not hmac.compare_digest(self._sign(payload), signature):
            raise ValueError("invalid signature")

        if time.time() - int(issued_at) > self.token_ttl:
            raise ValueError("token expired")

        data = bytes.fromhex(ciphertext)
        return bytes(
            a ^ b for a, b in zip(data, self._keystream(iv, len(data)))
        ).decode()

    @property
    def retry_on_failure(self) -> bool:
        return True

    def nonce_from_form(self, raw: str) -> int | str:
        return raw.strip()


class RenderCache:
    """Holds the rendered media for a challenge until its page is built."""

    def __init__(self, max_size: int = RENDER_CACHE_SIZE):
        self._max_size = max_size
        self._data: dict[str, tuple[float, dict]] = {}
        self._lock = Lock()

    def put(self, key: str, value: dict) -> None:
        with self._lock:
            while len(self._data) >= self._max_size:
                del self._data[min(self._data, key=lambda k: self._data[k][0])]
            self._data[key] = (time.time(), value)

    def pop(self, key: str) -> dict | None:
        with self._lock:
            entry = self._data.pop(key, None)
        return entry[1] if entry else None
