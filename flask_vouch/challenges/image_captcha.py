import base64
from dataclasses import dataclass, field

from .base import ChallengeBase, ChallengeType, RenderCache, SignedTokenHandler
from .datasets import get_default_store
from .media import distort_image, distort_images


def _img_data_url(data: bytes) -> str:
    return f"data:image/jpeg;base64,{base64.b64encode(data).decode()}"


@dataclass
class _ImageCaptchaBase(SignedTokenHandler):
    dataset: str = "ai_dogs"
    cache: RenderCache = field(default_factory=RenderCache)

    def _load_images(self, count: int, correct_range, preview: bool):
        images, correct_indices, category = get_default_store().get_images(
            count=count,
            correct_range=correct_range,
            dataset=self.dataset,
            preview=preview,
        )
        if not images:
            raise RuntimeError(f"failed to load dataset '{self.dataset}'")
        return images, correct_indices, category

    def _cached(self, challenge: ChallengeBase) -> dict:
        cached = self.cache.pop(challenge.random_data)
        if not cached:
            raise RuntimeError("image cache expired")
        return cached

    @staticmethod
    def _with_grid(payload: dict, grid: list[str]) -> dict:
        return {**payload, **{f"grid_{i}": url for i, url in enumerate(grid)}}


@dataclass
class ImageCaptcha(_ImageCaptchaBase):
    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.IMAGE_CAPTCHA

    def generate_random_data(self, difficulty: int = 0) -> str:
        images, correct_indices, _ = self._load_images(6, (1, 1), preview=True)
        hardness = max(1, min(difficulty, 5))

        token = self.issue_token(correct_indices)
        self.cache.put(
            token,
            {
                "preview": _img_data_url(
                    distort_image(images[0], size=200, hardness=hardness)
                ),
                "grid": [
                    _img_data_url(d)
                    for d in distort_images(images[1:], size=100, hardness=hardness)
                ],
            },
        )
        return token

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        try:
            return str(nonce) == self.read_token(random_data)
        except Exception:
            return False

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        cached = self._cached(challenge)
        return self._with_grid(
            {
                "id": challenge.id,
                "preview": cached["preview"],
                "verifyPath": verify_path,
                "redirect": redirect,
            },
            cached["grid"],
        )


@dataclass
class ImageGridCaptcha(_ImageCaptchaBase):
    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.IMAGE_GRID_CAPTCHA

    def generate_random_data(self, difficulty: int = 0) -> str:
        images, correct_indices, category = self._load_images(9, (2, 4), preview=False)
        hardness = max(1, min(difficulty, 5))

        token = self.issue_token(correct_indices, suffix=f":{category}")
        self.cache.put(
            token,
            {
                "category": category,
                "grid": [
                    _img_data_url(d)
                    for d in distort_images(images, size=100, hardness=hardness)
                ],
            },
        )
        return token

    def nonce_from_form(self, raw: str) -> str:
        return "".join(sorted(set(raw.replace(",", ""))))

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        try:
            correct = self.read_token(random_data)
        except Exception:
            return False
        return "".join(sorted(str(nonce))) == "".join(sorted(correct))

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        cached = self._cached(challenge)
        return self._with_grid(
            {
                "id": challenge.id,
                "category": cached["category"],
                "verifyPath": verify_path,
                "redirect": redirect,
            },
            cached["grid"],
        )
