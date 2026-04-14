import base64
import hashlib
import hmac
import math
import random
import secrets
import struct
import time
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

from .base import DIFFICULTY_OFFSETS, ChallengeBase, ChallengeHandler, ChallengeType

_TOKEN_TTL = 1800
_MODELS_DIR = Path(__file__).parent / "models"
_ICON_CACHE_PATH = _MODELS_DIR / "icon_cache.bin"

_LIQUID_COLORS = [
    (230, 80, 30, 200),
    (50, 180, 80, 200),
    (200, 60, 130, 200),
    (70, 130, 230, 200),
    (180, 50, 50, 200),
    (50, 180, 180, 200),
]

_FILL_PRESETS = [
    [0.20, 0.40, 0.65, 0.88],
    [0.18, 0.42, 0.60, 0.90],
    [0.22, 0.38, 0.68, 0.85],
    [0.25, 0.45, 0.62, 0.92],
    [0.15, 0.48, 0.70, 0.87],
    [0.28, 0.50, 0.72, 0.95],
]


def _parse_bincode_cache(path: Path) -> tuple[dict, list[str]]:
    data = path.read_bytes()
    pos = 0

    def read_u64():
        nonlocal pos
        v = struct.unpack_from("<Q", data, pos)[0]
        pos += 8
        return v

    def read_u8():
        nonlocal pos
        v = data[pos]
        pos += 1
        return v

    def read_u32():
        nonlocal pos
        v = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        return v

    def read_str():
        n = read_u64()
        nonlocal pos
        s = data[pos : pos + n].decode()
        pos += n
        return s

    def read_bytes_val():
        n = read_u64()
        nonlocal pos
        b = data[pos : pos + n]
        pos += n
        return b

    icons = {}
    map_count = read_u64()
    for _ in range(map_count):
        name = read_str()
        bright = read_u8()
        size = read_u32()
        pixels = read_bytes_val()
        icons[(name, bright, size)] = pixels

    names_count = read_u64()
    names = [read_str() for _ in range(names_count)]
    return icons, names


_icon_cache: dict | None = None
_icon_names: list[str] = []


def _load_icons() -> tuple[dict, list[str]]:
    global _icon_cache, _icon_names
    if _icon_cache is None:
        _icon_cache, _icon_names = _parse_bincode_cache(_ICON_CACHE_PATH)
    return _icon_cache, _icon_names


def _get_icon_image(name: str, brightness: float, size: int = 22):
    from PIL import Image

    icons, _ = _load_icons()
    bright_key = round(brightness * 10)
    pixels = icons.get((name, bright_key, size))
    if pixels is None:
        return None
    return Image.frombytes("RGBA", (size, size), pixels)


def _blend_pixel(base, ox, oy, src_pixel):
    sr, sg, sb, sa = src_pixel
    if sa == 0:
        return
    if ox < 0 or oy < 0 or ox >= base.width or oy >= base.height:
        return
    if sa == 255:
        base.putpixel((ox, oy), (sr, sg, sb, 255))
        return
    br, bg, bb, ba = base.getpixel((ox, oy))
    inv = 255 - sa
    base.putpixel(
        (ox, oy),
        (
            (sr * sa + br * inv) // 255,
            (sg * sa + bg * inv) // 255,
            (sb * sa + bb * inv) // 255,
            min(255, sa + ba * inv // 255),
        ),
    )


def _overlay(base, overlay, x: int, y: int):
    for oy in range(overlay.height):
        by = y + oy
        if by < 0 or by >= base.height:
            continue
        for ox in range(overlay.width):
            bx = x + ox
            if bx < 0 or bx >= base.width:
                continue
            _blend_pixel(base, bx, by, overlay.getpixel((ox, oy)))


def _wood_background(width: int, height: int, rng: random.Random):
    from PIL import Image

    img = Image.new("RGBA", (width, height))
    pixels = img.load()
    for y in range(height):
        y_grain = math.sin(y * 0.3) * 0.1 + 0.9
        for x in range(width):
            grain = math.sin(x * 0.05) * 0.1
            factor = (y_grain + grain) * rng.uniform(0.85, 1.15)
            r = int(max(0, min(255, 140 * factor)))
            g = int(max(0, min(255, 90 * factor)))
            b = int(max(0, min(255, 50 * factor)))
            pixels[x, y] = (r, g, b, 255)
    return img


def _lerp(a, b, t):
    return a + (b - a) * t


def _draw_cup(img, cx: int, cy: int, w: int, h: int, fill: float, color):
    from PIL import ImageDraw

    draw = ImageDraw.Draw(img)
    bw = int(w * 0.75)
    tw, bwh, hh = w // 2, bw // 2, h // 2

    lt = (cx - tw, cy - hh)
    rt = (cx + tw, cy - hh)
    lb = (cx - bwh, cy + hh)
    rb = (cx + bwh, cy + hh)

    draw.polygon([lt, rt, rb, lb], fill=(200, 210, 220, 160))

    if fill > 0.05:
        lh = int(h * fill * 0.85)
        lty = cy + hh - lh
        ltw = int((bw + (w - bw) * lh / h) / 2)
        draw.polygon(
            [
                (cx - ltw + 2, lty),
                (cx + ltw - 2, lty),
                (cx + bwh - 2, cy + hh - 2),
                (cx - bwh + 2, cy + hh - 2),
            ],
            fill=color,
        )

    draw.line([lt, rt], fill=(230, 235, 240, 255), width=1)
    draw.line([lt, lb], fill=(150, 160, 170, 255), width=1)
    draw.line([rt, rb], fill=(150, 160, 170, 255), width=1)
    draw.line([lb, rb], fill=(150, 160, 170, 255), width=1)


def _add_noise(img, scale: int, rng: random.Random):
    from PIL import Image

    arr = list(img.tobytes())
    for i in range(0, len(arr), 4):
        noise = rng.randint(-scale, scale)
        arr[i] = max(0, min(255, arr[i] + noise))
        arr[i + 1] = max(0, min(255, arr[i + 1] + noise))
        arr[i + 2] = max(0, min(255, arr[i + 2] + noise))
    return Image.frombytes("RGBA", img.size, bytes(arr))


def _generate_positions(count: int, size: int, rng: random.Random):
    positions = []
    margin = size // 5
    for _ in range(count):
        for _ in range(50):
            x = rng.randint(margin, size - margin)
            y = rng.randint(size // 4, size - margin)
            if all(
                (x - px) ** 2 + (y - py) ** 2 >= (size // 4) ** 2
                for px, py in positions
            ):
                positions.append((x, y))
                break
        else:
            positions.append(
                (
                    rng.randint(margin, size - margin),
                    rng.randint(size // 4, size - margin),
                )
            )
    return positions


def _render_scene(
    icon_names: list[str],
    fills: list[float],
    target_cup: int,
    target_icon: str,
    target_brightness: float,
    seed: int,
    size: int = 200,
) -> bytes:
    from PIL import Image

    rng = random.Random(seed)
    img = _wood_background(size, size, rng)

    positions = _generate_positions(4, size, rng)
    order = list(range(4))
    order.sort(key=lambda i: positions[i][1])

    cup_w, cup_h = size // 6, size // 5

    for i in order:
        cx, cy = positions[i]
        cx += rng.randint(-3, 3)
        cy += rng.randint(-3, 3)
        liq = _LIQUID_COLORS[rng.randint(0, len(_LIQUID_COLORS) - 1)]
        _draw_cup(img, cx, cy, cup_w, cup_h, fills[i], liq)

        brightness = target_brightness if i == target_cup else rng.uniform(0.1, 0.9)
        icon = _get_icon_image(icon_names[i], brightness, 22)
        if icon:
            _overlay(img, icon, cx - 11, cy - cup_h // 2 - 24)

    img = _add_noise(img, 18, rng)
    buf = BytesIO()
    img.convert("RGB").save(buf, format="WEBP", quality=70, method=4)
    return buf.getvalue()


def _render_reference(
    icon_name: str, brightness: float, seed: int, size: int = 133
) -> bytes:
    from PIL import Image

    rng = random.Random(seed)
    img = _wood_background(size, size, rng)

    icon = _get_icon_image(icon_name, brightness, 28)
    if icon:
        ix = rng.randint(15, size - 43)
        iy = rng.randint(15, size - 43)
        _overlay(img, icon, ix, iy)

    img = _add_noise(img, 12, rng)
    buf = BytesIO()
    img.convert("RGB").save(buf, format="WEBP", quality=68, method=4)
    return buf.getvalue()


@dataclass
class CupCaptcha(ChallengeHandler):
    min_scenes: int = 5
    max_scenes: int = 9
    image_size: int = 200
    token_ttl: int = _TOKEN_TTL
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.CUP_CAPTCHA

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

    @property
    def template(self) -> str:
        return (Path(__file__).parent / "templates" / "cup_captcha.html").read_text()

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
        _, icon_names = _load_icons()
        rng = random.SystemRandom()

        scene_count = rng.randint(self.min_scenes, self.max_scenes)
        correct_scene = rng.randint(0, scene_count - 1)
        target_icon = rng.choice(icon_names)
        target_brightness = round(rng.uniform(0.15, 0.85), 2)
        seed = secrets.randbelow(2**31)

        solution = (
            f"{correct_scene}:{scene_count}:{target_icon}:{target_brightness}:{seed}"
        )
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
        return raw.strip()

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        try:
            solution = self._decrypt_token(random_data)
            correct_scene = int(solution.split(":")[0])
            return int(nonce) == correct_scene
        except Exception:
            return False

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        solution = self._decrypt_token(challenge.random_data)
        parts = solution.split(":")
        correct_scene = int(parts[0])
        scene_count = int(parts[1])
        target_icon = parts[2]
        target_brightness = float(parts[3])
        seed = int(parts[4])

        _, all_icon_names = _load_icons()
        rng = random.Random(seed)

        scenes_b64 = []
        for i in range(scene_count):
            scene_rng = random.Random(seed + i * 7919)
            fills = list(_FILL_PRESETS[scene_rng.randint(0, len(_FILL_PRESETS) - 1)])
            scene_rng.shuffle(fills)

            fullest = max(range(4), key=lambda j: fills[j])
            target_cup = (
                fullest
                if i == correct_scene
                else scene_rng.choice([j for j in range(4) if j != fullest])
            )

            icon_names = scene_rng.choices(all_icon_names, k=4)
            icon_names[target_cup] = target_icon

            img_bytes = _render_scene(
                icon_names,
                fills,
                target_cup,
                target_icon,
                target_brightness,
                seed + i * 7919,
                self.image_size,
            )
            scenes_b64.append(base64.b64encode(img_bytes).decode())

        ref_bytes = _render_reference(target_icon, target_brightness, seed, 133)
        ref_b64 = base64.b64encode(ref_bytes).decode()

        from PIL import Image

        frames = [Image.open(BytesIO(base64.b64decode(b))) for b in scenes_b64]
        sheet = Image.new("RGB", (self.image_size * scene_count, self.image_size))
        for i, frame in enumerate(frames):
            sheet.paste(frame.convert("RGB"), (i * self.image_size, 0))
        buf = BytesIO()
        sheet.save(buf, format="WEBP", quality=70, method=4)
        sheet_b64 = base64.b64encode(buf.getvalue()).decode()

        return {
            "id": challenge.id,
            "reference": ref_b64,
            "sheet": sheet_b64,
            "sceneCount": scene_count,
            "verifyPath": verify_path,
            "redirect": redirect,
        }
