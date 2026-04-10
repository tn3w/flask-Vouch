import base64
import hashlib
import hmac
import math
import secrets
import time
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

from .base import DIFFICULTY_OFFSETS, ChallengeBase, ChallengeHandler, ChallengeType

_TOKEN_TTL = 1800
_IMG_W, _IMG_H = 400, 290
_MIN_R, _MAX_R = 16, 36
_CLICK_TOLERANCE = 15


def _rand_color(lo: int, hi: int) -> tuple[int, int, int]:
    d = hi - lo
    return (
        secrets.randbelow(d) + lo,
        secrets.randbelow(d) + lo,
        secrets.randbelow(d) + lo,
    )


def _rot3(x, y, z, rx, ry, rz):
    cy, sy = math.cos(ry), math.sin(ry)
    x, z = cy * x + sy * z, -sy * x + cy * z
    cx, sx = math.cos(rx), math.sin(rx)
    y, z = cx * y - sx * z, sx * y + cx * z
    cz, sz = math.cos(rz), math.sin(rz)
    return cz * x - sz * y, sz * x + cz * y, z


def _proj(x, y, z, f=300):
    d = z + f
    return (x * f / d, y * f / d) if d else (0.0, 0.0)


def _draw_wireframe(draw, verts, edges, rx, ry, rz, ox, oy, color):
    pts = [_proj(*_rot3(v[0], v[1], v[2], rx, ry, rz)) for v in verts]
    for a, b in edges:
        draw.line(
            [
                (int(pts[a][0] + ox), int(pts[a][1] + oy)),
                (int(pts[b][0] + ox), int(pts[b][1] + oy)),
            ],
            fill=color,
            width=1,
        )


_CUBE_V = [(x * 20, y * 20, z * 20) for x in (-1, 1) for y in (-1, 1) for z in (-1, 1)]
_CUBE_E = [
    (i, j)
    for i in range(8)
    for j in range(i + 1, 8)
    if sum(1 for k in range(3) if _CUBE_V[i][k] != _CUBE_V[j][k]) == 1
]

_PYR_V = [(-28, 20, -28), (28, 20, -28), (28, 20, 28), (-28, 20, 28), (0, -28, 0)]
_PYR_E = [(0, 1), (1, 2), (2, 3), (3, 0), (0, 4), (1, 4), (2, 4), (3, 4)]


def _draw_obfuscation(draw, w: int, h: int) -> None:
    for _ in range(10):
        freq = secrets.randbelow(40) / 1000 + 0.01
        phase = secrets.randbelow(628) / 100
        amp = secrets.randbelow(20) + 6
        base_y = secrets.randbelow(h)
        pts = [
            (x, int(base_y + amp * math.sin(freq * x + phase))) for x in range(0, w, 3)
        ]
        draw.line(pts, fill=_rand_color(35, 90), width=1)

    for _ in range(8):
        draw.line(
            [
                (secrets.randbelow(w), secrets.randbelow(h)),
                (secrets.randbelow(w), secrets.randbelow(h)),
            ],
            fill=_rand_color(30, 80),
            width=1,
        )

    for verts, edges, ox, oy in [
        (_CUBE_V, _CUBE_E, w // 5, h // 2),
        (_PYR_V, _PYR_E, 4 * w // 5, h // 2),
        (_CUBE_V, _CUBE_E, w // 2, h // 4),
    ]:
        rx, ry, rz = (math.radians(secrets.randbelow(360)) for _ in range(3))
        _draw_wireframe(draw, verts, edges, rx, ry, rz, ox, oy, _rand_color(35, 80))

    for _ in range(600):
        draw.point(
            (secrets.randbelow(w), secrets.randbelow(h)),
            fill=_rand_color(0, 70),
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
            fill=_rand_color(110, 210),
            width=w,
        )

    gap_start = secrets.randbelow(360)
    gap_end = (gap_start + gap_size) % 360
    w = secrets.randbelow(3) + 2
    color = _rand_color(110, 210)
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
class CircleCaptcha(ChallengeHandler):
    token_ttl: int = _TOKEN_TTL
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.CIRCLE_CAPTCHA

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

    @property
    def template(self) -> str:
        return (Path(__file__).parent / "templates" / "circle_captcha.html").read_text()

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()

    def _encrypt(self, plaintext: str, iv: str) -> str:
        key = hmac.new(self.secret, iv.encode(), hashlib.sha256).digest()
        return bytes(a ^ b for a, b in zip(plaintext.encode(), key)).hex()

    def _decrypt_token(self, token: str) -> str:
        iv, ct_hex, ts, nonce, sig = token.split(":")
        payload = f"{iv}:{ct_hex}:{ts}:{nonce}"
        if not hmac.compare_digest(self._sign(payload), sig):
            raise ValueError("invalid signature")
        if time.time() - int(ts) > self.token_ttl:
            raise ValueError("token expired")
        key = hmac.new(self.secret, iv.encode(), hashlib.sha256).digest()
        return bytes(a ^ b for a, b in zip(bytes.fromhex(ct_hex), key)).decode()

    def generate_random_data(self, difficulty: int = 0) -> str:
        r = secrets.randbelow(_MAX_R - _MIN_R) + _MIN_R
        margin = r + 10
        cx = secrets.randbelow(_IMG_W - 2 * margin) + margin
        cy = secrets.randbelow(_IMG_H - 2 * margin) + margin
        iv = secrets.token_hex(16)
        ct = self._encrypt(f"{cx},{cy},{r}", iv)
        ts = str(int(time.time()))
        nonce = secrets.token_hex(8)
        payload = f"{iv}:{ct}:{ts}:{nonce}"
        return f"{payload}:{self._sign(payload)}"

    @property
    def retry_on_failure(self) -> bool:
        return True

    def nonce_from_form(self, raw: str) -> str:
        return raw.strip()

    def verify(
        self,
        random_data: str,
        nonce: int | str,
        difficulty: int,
    ) -> bool:
        try:
            solution = self._decrypt_token(random_data)
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
        solution = self._decrypt_token(challenge.random_data)
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
