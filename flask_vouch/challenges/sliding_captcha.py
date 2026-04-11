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
_IMG_W, _IMG_H = 400, 200
_PIECE_BASE = 55
_BUMP_R = 10
_PIECE_TOTAL = _PIECE_BASE + 2 * _BUMP_R
_BASE_TOLERANCE = 15


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


_CUBE_V = [(x * 30, y * 30, z * 30) for x in (-1, 1) for y in (-1, 1) for z in (-1, 1)]
_CUBE_E = [
    (i, j)
    for i in range(8)
    for j in range(i + 1, 8)
    if sum(1 for k in range(3) if _CUBE_V[i][k] != _CUBE_V[j][k]) == 1
]

_PYR_V = [
    (-40, 30, -40),
    (40, 30, -40),
    (40, 30, 40),
    (-40, 30, 40),
    (0, -40, 0),
]
_PYR_E = [
    (0, 1),
    (1, 2),
    (2, 3),
    (3, 0),
    (0, 4),
    (1, 4),
    (2, 4),
    (3, 4),
]


def _draw_background(draw, w: int, h: int) -> None:
    for _ in range(14):
        freq = secrets.randbelow(40) / 1000 + 0.01
        phase = secrets.randbelow(628) / 100
        amp = secrets.randbelow(25) + 8
        base_y = secrets.randbelow(h)
        pts = [
            (x, int(base_y + amp * math.sin(freq * x + phase))) for x in range(0, w, 3)
        ]
        draw.line(pts, fill=_rand_color(40, 140), width=1)

    cx, cy = w // 2, h // 2
    max_r = int(math.hypot(cx, cy)) + 10
    for i in range(1, 8):
        r = i * max_r // 7
        draw.ellipse(
            [cx - r, cy - r, cx + r, cy + r],
            outline=_rand_color(30, 80),
            width=1,
        )

    for verts, edges, ox, oy in [
        (_CUBE_V, _CUBE_E, w // 4, h // 2),
        (_PYR_V, _PYR_E, 3 * w // 4, h // 2),
    ]:
        rx, ry, rz = (math.radians(secrets.randbelow(360)) for _ in range(3))
        _draw_wireframe(
            draw,
            verts,
            edges,
            rx,
            ry,
            rz,
            ox,
            oy,
            _rand_color(50, 130),
        )

    for _ in range(400):
        draw.point(
            (secrets.randbelow(w), secrets.randbelow(h)),
            fill=_rand_color(0, 256),
        )

    for _ in range(12):
        draw.line(
            [
                (secrets.randbelow(w), secrets.randbelow(h)),
                (secrets.randbelow(w), secrets.randbelow(h)),
            ],
            fill=_rand_color(30, 130),
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
class SlidingCaptcha(ChallengeHandler):
    token_ttl: int = _TOKEN_TTL
    secret: bytes = field(
        default_factory=lambda: secrets.token_bytes(32),
    )

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.SLIDING_CAPTCHA

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

    @property
    def template(self) -> str:
        return (
            Path(__file__).parent / "templates" / "sliding_captcha.html"
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
        return bytes(a ^ b for a, b in zip(plaintext.encode(), key)).hex()

    def _decrypt_token(self, token: str) -> str:
        iv, ct_hex, ts, nonce, sig = token.split(":")
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
        return bytes(a ^ b for a, b in zip(bytes.fromhex(ct_hex), key)).decode()

    def generate_random_data(self, difficulty: int = 0) -> str:
        x = (
            secrets.randbelow(
                _IMG_W - 2 * _PIECE_TOTAL,
            )
            + _PIECE_TOTAL
        )
        y = (
            secrets.randbelow(
                _IMG_H - _PIECE_TOTAL - _BUMP_R,
            )
            + _BUMP_R
        )
        iv = secrets.token_hex(16)
        ct = self._encrypt(f"{x},{y}", iv)
        ts = str(int(time.time()))
        nonce = secrets.token_hex(8)
        payload = f"{iv}:{ct}:{ts}:{nonce}"
        return f"{payload}:{self._sign(payload)}"

    @property
    def retry_on_failure(self) -> bool:
        return True

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
            solution = self._decrypt_token(random_data)
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
        _draw_piece_mask(
            ImageDraw.Draw(mask),
            bx,
            by,
            _PIECE_BASE,
            _BUMP_R,
        )

        bb = (
            sol_x,
            sol_y,
            sol_x + _PIECE_TOTAL,
            sol_y + _PIECE_TOTAL,
        )
        piece_rgb = bg.crop(bb)
        piece_alpha = mask.crop(bb)
        piece = Image.merge(
            "RGBA",
            (*piece_rgb.split(), piece_alpha),
        )

        inner_a = piece_alpha.filter(ImageFilter.MinFilter(3))
        border_a = ImageChops.subtract(piece_alpha, inner_a)
        piece = Image.composite(
            Image.new("RGBA", piece.size, (220, 220, 220, 220)),
            piece,
            border_a,
        )

        dark = Image.new("RGB", bg.size, (0, 0, 0))
        bg = Image.composite(
            dark,
            bg,
            mask.point(lambda p: int(p * 0.55)),
        )

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
        solution = self._decrypt_token(challenge.random_data)
        bg_bytes, piece_bytes, piece_y = self._render_images(
            solution,
        )
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
