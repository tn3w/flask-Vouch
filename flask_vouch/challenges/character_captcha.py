import base64
import hashlib
import hmac
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import cast

from .base import DIFFICULTY_OFFSETS, ChallengeBase, ChallengeHandler, ChallengeType

_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

_PLATFORM_DIRS: dict[str, list[Path]] = {
    "win32": [
        Path(os.getenv("WINDIR", r"C:\Windows")) / "Fonts",
        Path(os.getenv("LOCALAPPDATA", "")) / "Microsoft/Windows/Fonts",
    ],
    "darwin": [
        Path("/Library/Fonts"),
        Path("/System/Library/Fonts"),
    ],
    "linux": [
        Path("/usr/share/fonts"),
        Path("/usr/local/share/fonts"),
    ],
}

_FONT_DIRS = _PLATFORM_DIRS.get(sys.platform, []) + [
    Path.home() / ".local/share/fonts",
    Path.home() / ".fonts",
]


_LATIN_FONT_FAMILIES = {
    "adwaita",
    "arial",
    "cantarell",
    "cascadia",
    "comic",
    "courier",
    "dejavu",
    "fantasque",
    "fira",
    "freemono",
    "freesans",
    "freeserif",
    "hack",
    "helvetica",
    "inter",
    "jetbrains",
    "lato",
    "liberation",
    "meslo",
    "montserrat",
    "nimbus",
    "opensans",
    "oswald",
    "overpass",
    "raleway",
    "roboto",
    "source",
    "terminus",
    "times",
    "ubuntu",
    "unifont",
    "vera",
}


def _is_latin_font(path: Path) -> bool:
    stem = path.stem.lower()
    return any(kw in stem for kw in _LATIN_FONT_FAMILIES)


_fonts_cache: list[str] | None = None


def _find_fonts() -> list[str]:
    global _fonts_cache
    if _fonts_cache is not None:
        return _fonts_cache
    _fonts_cache = [
        str(f)
        for d in _FONT_DIRS
        if d.exists()
        for f in d.rglob("*")
        if f.suffix.lower() in {".ttf", ".otf"} and _is_latin_font(f)
    ]
    return _fonts_cache


_TOKEN_TTL = 1800


@dataclass
class CharacterCaptcha(ChallengeHandler):
    backgrounds_path: str | None = None
    token_ttl: int = _TOKEN_TTL
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.CHARACTER_CAPTCHA

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

    @property
    def template(self) -> str:
        return (
            Path(__file__).parent / "templates" / "character_captcha.html"
        ).read_text()

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()

    def _encrypt(self, plaintext: str, iv: str) -> str:
        key = hmac.new(self.secret, iv.encode(), hashlib.sha256).digest()
        return bytes(a ^ b for a, b in zip(plaintext.encode(), key)).hex()

    def _decrypt_token(self, random_data: str) -> str:
        iv, ct_hex, ts, nonce, sig = random_data.split(":")
        payload = f"{iv}:{ct_hex}:{ts}:{nonce}"
        if not hmac.compare_digest(self._sign(payload), sig):
            raise ValueError("invalid signature")
        if time.time() - int(ts) > self.token_ttl:
            raise ValueError("token expired")
        key = hmac.new(self.secret, iv.encode(), hashlib.sha256).digest()
        return bytes(a ^ b for a, b in zip(bytes.fromhex(ct_hex), key)).decode()

    def generate_random_data(self, difficulty: int = 0) -> str:
        solution = "".join(secrets.choice(_CHARS) for _ in range(max(1, difficulty)))
        iv = secrets.token_hex(16)
        ct = self._encrypt(solution, iv)
        ts = str(int(time.time()))
        nonce = secrets.token_hex(8)
        payload = f"{iv}:{ct}:{ts}:{nonce}"
        return f"{payload}:{self._sign(payload)}"

    @property
    def retry_on_failure(self) -> bool:
        return True

    def nonce_from_form(self, raw: str) -> str:
        return raw.strip().upper()

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        try:
            return self._decrypt_token(random_data).upper() == str(nonce).upper()
        except Exception:
            return False

    def _load_background(self, width: int, height: int):
        from PIL import Image

        if self.backgrounds_path:
            bgs = [
                f
                for f in Path(self.backgrounds_path).iterdir()
                if f.suffix.lower() in (".jpg", ".jpeg")
            ]
            if bgs:
                return (
                    Image.open(secrets.choice(bgs))
                    .convert("RGB")
                    .resize((width, height))
                )
        return Image.new("RGB", (width, height), (80, 80, 80))

    @staticmethod
    def _contrasting_color(
        bg_sample: tuple[int, ...],
    ) -> tuple[int, int, int]:
        luminance = 0.299 * bg_sample[0] + 0.587 * bg_sample[1] + 0.114 * bg_sample[2]
        lo, hi = (160, 255) if luminance < 128 else (0, 90)
        r = secrets.randbelow(hi - lo) + lo
        return (r, secrets.randbelow(hi - lo) + lo, secrets.randbelow(hi - lo) + lo)

    def _render_image(self, solution: str) -> bytes:
        try:
            from PIL import Image, ImageDraw, ImageFont
        except ImportError as e:
            raise ImportError(
                "Pillow is required for CharacterCaptcha: "
                "pip install flask-vouch[image]"
            ) from e

        fonts = _find_fonts()
        img_width = len(solution) * 75 + 20
        img_height = 130
        captcha = self._load_background(img_width, img_height)
        draw = ImageDraw.Draw(captcha)

        x = 10
        for char in solution:
            font_path = secrets.choice(fonts) if fonts else None
            size = secrets.randbelow(21) + 65
            try:
                font = (
                    ImageFont.truetype(font_path, size)
                    if font_path
                    else ImageFont.load_default()
                )
            except Exception:
                font = ImageFont.load_default()

            bbox = draw.textbbox((0, 0), char, font=font)
            char_w = max(bbox[2] - bbox[0] + 20, 1)
            char_h = max(bbox[3] - bbox[1] + 20, 1)

            bg_region = captcha.crop(
                (
                    min(x, img_width - 1),
                    max(img_height // 2 - size // 2, 0),
                    min(x + char_w, img_width),
                    min(img_height // 2 + size // 2, img_height),
                )
            )
            avg_bg = cast(
                tuple[int, int, int],
                bg_region.convert("RGB").resize((1, 1)).getpixel((0, 0)),
            )
            color = self._contrasting_color(avg_bg)

            rotation = secrets.randbelow(41) - 20
            char_img = Image.new("RGBA", (int(char_w), int(char_h)), (0, 0, 0, 0))
            char_draw = ImageDraw.Draw(char_img)
            char_draw.text((10, 10), char, font=font, fill=(*color, 255))
            char_img = char_img.rotate(rotation, expand=True)

            y = (img_height - char_img.height) // 2
            y += secrets.randbelow(21) - 10
            y = max(0, min(y, img_height - char_img.height))
            captcha.paste(char_img, (x, y), char_img)

            x += secrets.randbelow(16) + 60

        for _ in range(8):
            x1 = secrets.randbelow(img_width)
            y1 = secrets.randbelow(img_height)
            x2 = secrets.randbelow(img_width)
            y2 = secrets.randbelow(img_height)
            lc = (
                secrets.randbelow(256),
                secrets.randbelow(256),
                secrets.randbelow(256),
            )
            draw.line([(x1, y1), (x2, y2)], fill=lc, width=2)

        for _ in range(500):
            nx = secrets.randbelow(img_width)
            ny = secrets.randbelow(img_height)
            draw.point(
                (nx, ny),
                fill=(
                    secrets.randbelow(256),
                    secrets.randbelow(256),
                    secrets.randbelow(256),
                ),
            )

        buf = BytesIO()
        captcha.save(buf, format="PNG")
        return buf.getvalue()

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        solution = self._decrypt_token(challenge.random_data)
        image_b64 = base64.b64encode(self._render_image(solution)).decode()
        return {
            "id": challenge.id,
            "image": image_b64,
            "verifyPath": verify_path,
            "redirect": redirect,
        }
