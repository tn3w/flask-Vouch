import base64
import math
import secrets
from dataclasses import dataclass
from io import BytesIO

from .base import ChallengeBase, ChallengeType, SignedTokenHandler
from .media import cube, draw_wireframes, pyramid, rand_color

_IMG_W, _IMG_H = 400, 290
_MIN_R, _MAX_R = 16, 36
_CLICK_TOLERANCE = 15


_CUBE = cube(20)
_PYRAMID = pyramid(28, 20)


def _draw_obfuscation(draw, w: int, h: int) -> None:
    for _ in range(10):
        freq = secrets.randbelow(40) / 1000 + 0.01
        phase = secrets.randbelow(628) / 100
        amp = secrets.randbelow(20) + 6
        base_y = secrets.randbelow(h)
        pts = [
            (x, int(base_y + amp * math.sin(freq * x + phase))) for x in range(0, w, 3)
        ]
        draw.line(pts, fill=rand_color(35, 90), width=1)

    for _ in range(8):
        draw.line(
            [
                (secrets.randbelow(w), secrets.randbelow(h)),
                (secrets.randbelow(w), secrets.randbelow(h)),
            ],
            fill=rand_color(30, 80),
            width=1,
        )

    draw_wireframes(
        draw,
        [
            (*_CUBE, w // 5, h // 2),
            (*_PYRAMID, 4 * w // 5, h // 2),
            (*_CUBE, w // 2, h // 4),
        ],
        (35, 80),
    )

    for _ in range(600):
        draw.point(
            (secrets.randbelow(w), secrets.randbelow(h)),
            fill=rand_color(0, 70),
        )


def _overlaps(cx, cy, cr, placed):
    return any(math.hypot(cx - ox, cy - oy) < cr + or_ + 18 for ox, oy, or_ in placed)


def _render_image(
    cx: int,
    cy: int,
    r: int,
    num_circles: int,
    gap_size: int,
) -> bytes:
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (_IMG_W, _IMG_H), (20, 18, 18))
    draw = ImageDraw.Draw(img)
    _draw_obfuscation(draw, _IMG_W, _IMG_H)

    placed = [(cx, cy, r)]
    for _ in range(num_circles - 1):
        for _ in range(150):
            nr = secrets.randbelow(_MAX_R - _MIN_R) + _MIN_R
            nx = secrets.randbelow(_IMG_W - 2 * nr - 20) + nr + 10
            ny = secrets.randbelow(_IMG_H - 2 * nr - 20) + nr + 10
            if not _overlaps(nx, ny, nr, placed):
                placed.append((nx, ny, nr))
                break

    for ocx, ocy, ocr in placed[1:]:
        w = secrets.randbelow(3) + 2
        draw.arc(
            [ocx - ocr, ocy - ocr, ocx + ocr, ocy + ocr],
            0,
            360,
            fill=rand_color(110, 210),
            width=w,
        )

    gap_start = secrets.randbelow(360)
    gap_end = (gap_start + gap_size) % 360
    w = secrets.randbelow(3) + 2
    color = rand_color(110, 210)
    bbox = [cx - r, cy - r, cx + r, cy + r]
    if gap_end > gap_start:
        if gap_start > 0:
            draw.arc(bbox, 0, gap_start, fill=color, width=w)
        draw.arc(bbox, gap_end, 360, fill=color, width=w)
    else:
        draw.arc(bbox, gap_end, gap_start, fill=color, width=w)

    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@dataclass
class CircleCaptcha(SignedTokenHandler):

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.CIRCLE_CAPTCHA

    def generate_random_data(self, difficulty: int = 0) -> str:
        r = secrets.randbelow(_MAX_R - _MIN_R) + _MIN_R
        margin = r + 10
        cx = secrets.randbelow(_IMG_W - 2 * margin) + margin
        cy = secrets.randbelow(_IMG_H - 2 * margin) + margin
        return self.issue_token(f"{cx},{cy},{r}")

    def verify(
        self,
        random_data: str,
        nonce: int | str,
        difficulty: int,
    ) -> bool:
        try:
            solution = self.read_token(random_data)
            cx, cy, r = map(int, solution.split(","))
            click_x, click_y = map(int, str(nonce).split(","))
            tolerance = r + _CLICK_TOLERANCE
            return (click_x - cx) ** 2 + (click_y - cy) ** 2 <= tolerance**2
        except Exception:
            return False

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        solution = self.read_token(challenge.random_data)
        cx, cy, r = map(int, solution.split(","))
        difficulty = challenge.difficulty
        num_circles = 14 + difficulty // 3
        gap_size = max(25, 50 - difficulty * 2)
        image = _render_image(cx, cy, r, num_circles, gap_size)
        return {
            "id": challenge.id,
            "image": base64.b64encode(image).decode(),
            "verifyPath": verify_path,
            "redirect": redirect,
        }
