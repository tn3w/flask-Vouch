from __future__ import annotations

import base64
import math
import secrets
from dataclasses import dataclass
from io import BytesIO

from .base import ChallengeBase, ChallengeType, SignedTokenHandler
from .media import cube, draw_wireframes, pyramid, rand_color

_IMG_W, _IMG_H = 400, 200
_PIECE_BASE = 55
_BUMP_R = 10
_PIECE_TOTAL = _PIECE_BASE + 2 * _BUMP_R
_BASE_TOLERANCE = 15


_CUBE = cube(30)
_PYRAMID = pyramid(40, 30)


def _draw_background(draw, w: int, h: int) -> None:
    for _ in range(14):
        freq = secrets.randbelow(40) / 1000 + 0.01
        phase = secrets.randbelow(628) / 100
        amp = secrets.randbelow(25) + 8
        base_y = secrets.randbelow(h)
        pts = [
            (x, int(base_y + amp * math.sin(freq * x + phase))) for x in range(0, w, 3)
        ]
        draw.line(pts, fill=rand_color(40, 140), width=1)

    cx, cy = w // 2, h // 2
    max_r = int(math.hypot(cx, cy)) + 10
    for i in range(1, 8):
        r = i * max_r // 7
        draw.ellipse(
            [cx - r, cy - r, cx + r, cy + r],
            outline=rand_color(30, 80),
            width=1,
        )

    draw_wireframes(
        draw,
        [(*_CUBE, w // 4, h // 2), (*_PYRAMID, 3 * w // 4, h // 2)],
        (50, 130),
    )

    for _ in range(400):
        draw.point(
            (secrets.randbelow(w), secrets.randbelow(h)),
            fill=rand_color(0, 256),
        )

    for _ in range(12):
        draw.line(
            [
                (secrets.randbelow(w), secrets.randbelow(h)),
                (secrets.randbelow(w), secrets.randbelow(h)),
            ],
            fill=rand_color(30, 130),
            width=1,
        )


def _draw_piece_mask(
    draw,
    bx: int,
    by: int,
    base: int,
    bump_r: int,
) -> None:
    draw.rectangle([bx, by, bx + base, by + base], fill=255)

    sides = [
        (bx + base, by + base // 2),
        (bx, by + base // 2),
        (bx + base // 2, by),
        (bx + base // 2, by + base),
    ]
    pattern = [secrets.randbelow(2) for _ in range(4)]
    while sum(pattern) < 2:
        pattern[secrets.randbelow(4)] = 1

    for (cx, cy), outward in zip(sides, pattern):
        draw.ellipse(
            [cx - bump_r, cy - bump_r, cx + bump_r, cy + bump_r],
            fill=255 if outward else 0,
        )


@dataclass
class SlidingCaptcha(SignedTokenHandler):

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.SLIDING_CAPTCHA

    def generate_random_data(self, difficulty: int = 0) -> str:
        x = secrets.randbelow(_IMG_W - 2 * _PIECE_TOTAL) + _PIECE_TOTAL
        y = secrets.randbelow(_IMG_H - _PIECE_TOTAL - _BUMP_R) + _BUMP_R
        return self.issue_token(f"{x},{y}")

    def nonce_from_form(self, raw: str) -> int:
        try:
            return max(0, int(raw.strip()))
        except ValueError:
            return 0

    def verify(
        self,
        random_data: str,
        nonce: int | str,
        difficulty: int,
    ) -> bool:
        try:
            solution = self.read_token(random_data)
            sol_x = int(solution.split(",")[0])
            tolerance = max(5, _BASE_TOLERANCE - difficulty)
            return abs(int(nonce) - sol_x) <= tolerance
        except Exception:
            return False

    def _render_images(
        self,
        solution: str,
    ) -> tuple[bytes, bytes, int]:
        try:
            from PIL import Image, ImageChops, ImageDraw, ImageFilter
        except ImportError as e:
            raise ImportError(
                "Pillow is required for SlidingCaptcha: "
                "pip install flask-vouch[image]"
            ) from e

        sol_x, sol_y = map(int, solution.split(","))
        bx, by = sol_x + _BUMP_R, sol_y + _BUMP_R

        bg = Image.new("RGB", (_IMG_W, _IMG_H), (25, 20, 20))
        _draw_background(ImageDraw.Draw(bg), _IMG_W, _IMG_H)

        mask = Image.new("L", (_IMG_W, _IMG_H), 0)
        _draw_piece_mask(ImageDraw.Draw(mask), bx, by, _PIECE_BASE, _BUMP_R)

        bb = (sol_x, sol_y, sol_x + _PIECE_TOTAL, sol_y + _PIECE_TOTAL)
        piece_rgb = bg.crop(bb)
        piece_alpha = mask.crop(bb)
        piece = Image.merge("RGBA", (*piece_rgb.split(), piece_alpha))

        inner_a = piece_alpha.filter(ImageFilter.MinFilter(3))
        border_a = ImageChops.subtract(piece_alpha, inner_a)
        piece = Image.composite(
            Image.new("RGBA", piece.size, (220, 220, 220, 220)),
            piece,
            border_a,
        )

        dark = Image.new("RGB", bg.size, (0, 0, 0))
        bg = Image.composite(dark, bg, mask.point(lambda p: int(p * 0.55)))

        inner_m = mask.filter(ImageFilter.MinFilter(3))
        border_m = ImageChops.subtract(mask, inner_m)
        bg = Image.composite(
            Image.new("RGB", bg.size, (90, 90, 90)),
            bg,
            border_m,
        )

        bg_buf, piece_buf = BytesIO(), BytesIO()
        bg.save(bg_buf, format="PNG")
        piece.save(piece_buf, format="PNG")
        return bg_buf.getvalue(), piece_buf.getvalue(), sol_y

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        solution = self.read_token(challenge.random_data)
        bg_bytes, piece_bytes, piece_y = self._render_images(solution)
        return {
            "id": challenge.id,
            "background": base64.b64encode(bg_bytes).decode(),
            "piece": base64.b64encode(piece_bytes).decode(),
            "pieceY": piece_y,
            "pieceW": _PIECE_TOTAL,
            "pieceH": _PIECE_TOTAL,
            "sliderMax": _IMG_W - _PIECE_TOTAL,
            "verifyPath": verify_path,
            "redirect": redirect,
        }
