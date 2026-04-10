import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from .base import DIFFICULTY_OFFSETS, ChallengeBase, ChallengeHandler, ChallengeType
from .datasets import get_default_store
from .media import distort_image

_TOKEN_TTL = 1800
_RENDER_CACHE_SIZE = 64


def _img_data_url(data: bytes) -> str:
    return f"data:image/png;base64,{base64.b64encode(data).decode()}"


@dataclass
class ImageGridCaptcha(ChallengeHandler):
    dataset: str = "ai_dogs"
    token_ttl: int = _TOKEN_TTL
    secret: bytes = field(
        default_factory=lambda: secrets.token_bytes(32),
    )

    def __post_init__(self):
        self._cache: dict[str, dict] = {}
        self._cache_lock = Lock()

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.IMAGE_GRID_CAPTCHA

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

    @property
    def template(self) -> str:
        return (
            Path(__file__).parent / "templates" / "image_grid_captcha.html"
        ).read_text()

    def _sign(self, payload: str) -> str:
        return hmac.new(
            self.secret,
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _encrypt(self, plaintext: str, iv: str) -> str:
        key = hmac.new(
            self.secret,
            iv.encode(),
            hashlib.sha256,
        ).digest()
        stream = key * (len(plaintext) // len(key) + 1)
        return bytes(a ^ b for a, b in zip(plaintext.encode(), stream)).hex()

    def _decrypt_token(self, token: str) -> tuple[str, str]:
        parts = token.split(":")
        iv, ct_hex, ts, nonce, sig = parts[:5]
        category = ":".join(parts[5:])
        payload = f"{iv}:{ct_hex}:{ts}:{nonce}"

        if not hmac.compare_digest(self._sign(payload), sig):
            raise ValueError("invalid signature")

        if time.time() - int(ts) > self.token_ttl:
            raise ValueError("token expired")

        key = hmac.new(
            self.secret,
            iv.encode(),
            hashlib.sha256,
        ).digest()
        ct = bytes.fromhex(ct_hex)
        stream = key * (len(ct) // len(key) + 1)
        indices = bytes(a ^ b for a, b in zip(ct, stream)).decode()
        return indices, category

    def _evict_cache(self):
        while len(self._cache) > _RENDER_CACHE_SIZE:
            oldest = min(
                self._cache,
                key=lambda k: self._cache[k]["ts"],
            )
            del self._cache[oldest]

    def generate_random_data(self, difficulty: int = 0) -> str:
        store = get_default_store()
        images, correct_indices, category = store.get_images(
            count=9,
            correct_range=(2, 4),
            dataset=self.dataset,
            preview=False,
        )
        if not images:
            raise RuntimeError(f"failed to load dataset '{self.dataset}'")

        hardness = max(1, min(difficulty, 5))

        grid = [
            _img_data_url(
                distort_image(
                    img,
                    size=100,
                    hardness=hardness,
                ),
            )
            for img in images
        ]

        iv = secrets.token_hex(16)
        ct = self._encrypt(correct_indices, iv)
        ts = str(int(time.time()))
        nonce = secrets.token_hex(8)
        payload = f"{iv}:{ct}:{ts}:{nonce}"
        signed = f"{payload}:{self._sign(payload)}:{category}"

        with self._cache_lock:
            self._evict_cache()
            self._cache[signed] = {
                "grid": grid,
                "category": category,
                "ts": time.time(),
            }

        return signed

    @property
    def retry_on_failure(self) -> bool:
        return True

    def nonce_from_form(self, raw: str) -> str:
        digits = sorted(set(raw.replace(",", "")))
        return "".join(digits)

    def verify(
        self,
        random_data: str,
        nonce: int | str,
        difficulty: int,
    ) -> bool:
        try:
            correct, _ = self._decrypt_token(random_data)
            expected = "".join(sorted(correct))
            given = "".join(sorted(str(nonce)))
            return given == expected
        except Exception:
            return False

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        with self._cache_lock:
            cached = self._cache.pop(
                challenge.random_data,
                None,
            )

        if not cached:
            raise RuntimeError("image cache expired")

        result = {
            "id": challenge.id,
            "category": cached["category"],
            "verifyPath": verify_path,
            "redirect": redirect,
        }
        for i, url in enumerate(cached["grid"]):
            result[f"grid_{i}"] = url

        return result
