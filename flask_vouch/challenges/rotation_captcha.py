import base64
import hashlib
import hmac
import json
import math
import secrets
import struct
import time
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

from .base import DIFFICULTY_OFFSETS, ChallengeBase, ChallengeHandler, ChallengeType

_TOKEN_TTL = 1800
_DEG = math.pi / 180
_MODELS_DIR = Path(__file__).parent / "models"


def _v3sub(a, b):
    return [a[0] - b[0], a[1] - b[1], a[2] - b[2]]


def _v3cross(a, b):
    return [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]


def _v3dot(a, b):
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def _v3normalize(v):
    length = math.sqrt(v[0] ** 2 + v[1] ** 2 + v[2] ** 2)
    if length < 1e-10:
        return [0.0, 0.0, 0.0]
    return [v[0] / length, v[1] / length, v[2] / length]


def _v3scale(v, s):
    return [v[0] * s, v[1] * s, v[2] * s]


def _v3add(a, b):
    return [a[0] + b[0], a[1] + b[1], a[2] + b[2]]


def _mat4_identity():
    m = [0.0] * 16
    m[0] = m[5] = m[10] = m[15] = 1.0
    return m


def _mat4_multiply(a, b):
    o = [0.0] * 16
    for c in range(4):
        for r in range(4):
            o[c * 4 + r] = (
                a[r] * b[c * 4]
                + a[4 + r] * b[c * 4 + 1]
                + a[8 + r] * b[c * 4 + 2]
                + a[12 + r] * b[c * 4 + 3]
            )
    return o


def _mat4_rotate_y(angle):
    m = _mat4_identity()
    c, s = math.cos(angle), math.sin(angle)
    m[0] = c
    m[8] = s
    m[2] = -s
    m[10] = c
    return m


def _mat4_translate(x, y, z):
    m = _mat4_identity()
    m[12] = x
    m[13] = y
    m[14] = z
    return m


def _mat4_look_at(eye, center, up):
    f = _v3normalize(_v3sub(center, eye))
    r = _v3normalize(_v3cross(f, up))
    u = _v3cross(r, f)
    m = [0.0] * 16
    m[0] = r[0]
    m[4] = r[1]
    m[8] = r[2]
    m[12] = -_v3dot(r, eye)
    m[1] = u[0]
    m[5] = u[1]
    m[9] = u[2]
    m[13] = -_v3dot(u, eye)
    m[2] = -f[0]
    m[6] = -f[1]
    m[10] = -f[2]
    m[14] = _v3dot(f, eye)
    m[3] = 0.0
    m[7] = 0.0
    m[11] = 0.0
    m[15] = 1.0
    return m


def _mat4_perspective(fov_deg, aspect, near, far):
    f = 1.0 / math.tan((fov_deg * _DEG) / 2)
    nf = 1.0 / (near - far)
    m = [0.0] * 16
    m[0] = f / aspect
    m[5] = f
    m[10] = (far + near) * nf
    m[11] = -1.0
    m[14] = 2.0 * far * near * nf
    return m


def _transform_point(m, p):
    x = m[0] * p[0] + m[4] * p[1] + m[8] * p[2] + m[12]
    y = m[1] * p[0] + m[5] * p[1] + m[9] * p[2] + m[13]
    z = m[2] * p[0] + m[6] * p[1] + m[10] * p[2] + m[14]
    w = m[3] * p[0] + m[7] * p[1] + m[11] * p[2] + m[15]
    return [x, y, z, w]


def _clip_to_screen(clip, size):
    if clip[3] <= 0:
        return None
    inv_w = 1.0 / clip[3]
    return [
        (clip[0] * inv_w * 0.5 + 0.5) * size,
        (1.0 - (clip[1] * inv_w * 0.5 + 0.5)) * size,
        clip[2] * inv_w,
        clip[3],
    ]


def _imul(a, b):
    return ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & 0xFFFFFFFF


def _create_rng(seed):
    state = [seed & 0xFFFFFFFF]

    def next_float():
        state[0] = (state[0] + 0x6D2B79F5) & 0xFFFFFFFF
        s = state[0]
        t = _imul(s ^ (s >> 15), 1 | s)
        t = ((t + _imul(t ^ (t >> 7), 61 | t)) ^ t) & 0xFFFFFFFF
        return ((t ^ (t >> 14)) & 0xFFFFFFFF) / 4294967296.0

    return next_float


_mesh_cache = None


def _load_mesh(gltf_path=None):
    global _mesh_cache
    if _mesh_cache is not None:
        return _mesh_cache

    if gltf_path is None:
        gltf_path = _MODELS_DIR / "scene.gltf"
    gltf_path = Path(gltf_path)

    with open(gltf_path) as f:
        gltf = json.load(f)

    bin_path = gltf_path.parent / gltf["buffers"][0]["uri"]
    with open(bin_path, "rb") as f:
        bin_data = f.read()

    primitive = gltf["meshes"][0]["primitives"][0]
    pos_acc = gltf["accessors"][primitive["attributes"]["POSITION"]]
    norm_acc = gltf["accessors"][primitive["attributes"]["NORMAL"]]
    idx_acc = gltf["accessors"][primitive["indices"]]

    def read_accessor(accessor, fmt_char, components):
        bv = gltf["bufferViews"][accessor["bufferView"]]
        byte_offset = bv.get("byteOffset", 0) + accessor.get("byteOffset", 0)
        elem_size = struct.calcsize(fmt_char)
        stride = bv.get("byteStride", components * elem_size)
        count = accessor["count"]

        result = []
        for i in range(count):
            src = byte_offset + i * stride
            for c in range(components):
                offset = src + c * elem_size
                result.append(struct.unpack_from(f"<{fmt_char}", bin_data, offset)[0])
        return result

    positions = read_accessor(pos_acc, "f", 3)
    normals = read_accessor(norm_acc, "f", 3)

    idx_type = idx_acc.get("componentType", 5125)
    idx_fmt = {5121: "B", 5123: "H", 5125: "I"}.get(idx_type, "I")
    indices = read_accessor(idx_acc, idx_fmt, 1)

    vertex_count = pos_acc["count"]
    triangle_count = idx_acc["count"] // 3

    min_x = min_y = min_z = float("inf")
    max_x = max_y = max_z = float("-inf")

    for i in range(vertex_count):
        x, y, z = positions[i * 3], positions[i * 3 + 1], positions[i * 3 + 2]
        min_x, max_x = min(min_x, x), max(max_x, x)
        min_y, max_y = min(min_y, y), max(max_y, y)
        min_z, max_z = min(min_z, z), max(max_z, z)

    center_x = (min_x + max_x) / 2
    center_y = min_y
    center_z = (min_z + max_z) / 2
    extent_x = (max_x - min_x) / 2
    extent_y = max_y - min_y
    extent_z = (max_z - min_z) / 2
    max_extent = max(extent_x, extent_y, extent_z)
    scale = 1.0 / max_extent if max_extent > 0 else 1.0

    for i in range(vertex_count):
        positions[i * 3] = (positions[i * 3] - center_x) * scale
        positions[i * 3 + 1] = (positions[i * 3 + 1] - center_y) * scale
        positions[i * 3 + 2] = (positions[i * 3 + 2] - center_z) * scale

    _mesh_cache = {
        "positions": positions,
        "normals": normals,
        "indices": indices,
        "vertex_count": vertex_count,
        "triangle_count": triangle_count,
        "height": extent_y * scale,
    }
    return _mesh_cache


def _sample_surface_np(mesh, count, seed):
    import numpy as np

    pos = np.asarray(mesh["positions"], dtype=np.float32).reshape(-1, 3)
    idx = np.asarray(mesh["indices"], dtype=np.int32).reshape(-1, 3)

    v0, v1, v2 = pos[idx[:, 0]], pos[idx[:, 1]], pos[idx[:, 2]]
    areas = np.linalg.norm(np.cross(v1 - v0, v2 - v0), axis=1)
    total = areas.sum()
    if total == 0:
        total = 1.0
    probs = areas / total

    rng = np.random.default_rng(seed)
    ti = rng.choice(len(areas), size=count, p=probs)

    u = rng.random(count, dtype=np.float32)
    v = rng.random(count, dtype=np.float32)
    flip = u + v > 1
    u[flip] = 1 - u[flip]
    v[flip] = 1 - v[flip]
    w = 1 - u - v

    return v0[ti] * w[:, None] + v1[ti] * u[:, None] + v2[ti] * v[:, None]


def _build_matrices(mesh, angle_deg, fov, camera_distance, camera_elevation):
    angle_rad = angle_deg * _DEG
    model = _mat4_multiply(_mat4_translate(0, 0, 0), _mat4_rotate_y(angle_rad))
    model_center_y = mesh["height"] / 2

    eye_y = model_center_y + camera_distance * math.sin(camera_elevation)
    eye_horiz = camera_distance * math.cos(camera_elevation)
    eye = [0.0, eye_y, eye_horiz]
    target = [0.0, model_center_y * 0.85, 0.0]

    view = _mat4_look_at(eye, target, [0.0, 1.0, 0.0])
    proj = _mat4_perspective(fov, 1.0, 0.1, 100.0)
    vp = _mat4_multiply(proj, view)
    mvp = _mat4_multiply(vp, model)

    return {"model": model, "vp": vp, "mvp": mvp, "eye": eye}


def _np_add_noise(arr, scale, seed):
    import numpy as np

    rng = np.random.default_rng(seed)
    noise = (rng.random(arr.shape, dtype=np.float32) - 0.5) * scale
    return np.clip(arr.astype(np.float32) + noise, 0, 255).astype(np.uint8)


def _batch_transform(mat_flat, points):
    import numpy as np

    mat = np.asarray(mat_flat, dtype=np.float32).reshape(4, 4)
    ones = np.ones((len(points), 1), dtype=np.float32)
    return np.hstack([points, ones]) @ mat


def _batch_to_screen(clip, size):
    import numpy as np

    valid = clip[:, 3] > 0
    inv_w = np.where(valid, 1.0 / np.maximum(clip[:, 3], 1e-10), 0)
    sx = (clip[:, 0] * inv_w * 0.5 + 0.5) * size
    sy = (1.0 - (clip[:, 1] * inv_w * 0.5 + 0.5)) * size
    sz = clip[:, 2] * inv_w
    return np.column_stack([sx, sy, sz]), valid


def _render_reference(mesh, angle_deg, size=300):
    try:
        import numpy as np
        from PIL import Image, ImageDraw
    except ImportError as e:
        raise ImportError(
            "Pillow and numpy are required for "
            "RotationCaptcha: pip install flask-bouncer[image]"
        ) from e

    fov, cam_dist, cam_elev = 45, 3.2, 0.35
    light = np.array([0.5, 0.8, 0.6], dtype=np.float32)
    light /= np.linalg.norm(light)
    base_color = np.array([200, 175, 145], dtype=np.float32)

    matrices = _build_matrices(mesh, angle_deg, fov, cam_dist, cam_elev)
    eye = np.array(matrices["eye"], dtype=np.float32)

    pos = np.asarray(mesh["positions"], dtype=np.float32).reshape(-1, 3)
    idx = np.asarray(mesh["indices"], dtype=np.int32).reshape(-1, 3)

    world = _batch_transform(matrices["model"], pos)[:, :3]
    clip = _batch_transform(matrices["mvp"], pos)
    screen, valid = _batch_to_screen(clip, size)

    v0, v1, v2 = (
        world[idx[:, 0]],
        world[idx[:, 1]],
        world[idx[:, 2]],
    )
    normals = np.cross(v1 - v0, v2 - v0)
    normals /= np.linalg.norm(normals, axis=1, keepdims=True) + 1e-10

    centers = (v0 + v1 + v2) / 3
    to_eye = eye - centers
    to_eye /= np.linalg.norm(to_eye, axis=1, keepdims=True) + 1e-10
    facing = np.sum(normals * to_eye, axis=1)
    normals[facing < 0] *= -1

    diff = np.maximum(0, np.sum(normals * light, axis=1))
    brightness = 0.3 + 0.7 * diff
    colors = np.clip(base_color * brightness[:, None], 0, 255).astype(np.uint8)

    avg_z = (screen[idx[:, 0], 2] + screen[idx[:, 1], 2] + screen[idx[:, 2], 2]) / 3
    tri_valid = valid[idx[:, 0]] & valid[idx[:, 1]] & valid[idx[:, 2]]
    order = np.argsort(-avg_z)

    ys = np.linspace(0, 1, size, dtype=np.float32)
    bg = np.stack(
        [
            (232 * (1 - ys) + 192 * ys),
            (228 * (1 - ys) + 188 * ys),
            (224 * (1 - ys) + 184 * ys),
        ],
        axis=1,
    ).astype(np.uint8)
    bg_arr = np.repeat(bg[:, np.newaxis, :], size, axis=1)

    img = Image.fromarray(bg_arr, "RGB").convert("RGBA")

    shadow_dir = np.array([-0.4, -1.0, -0.3], dtype=np.float32)
    shadow_dir /= np.linalg.norm(shadow_dir)

    if shadow_dir[1] < 0:
        t_vals = -world[:, 1] / shadow_dir[1]
        shadow_w = world + shadow_dir * t_vals[:, None]
        shadow_w[:, 1] = 0.0
        shadow_clip = _batch_transform(matrices["vp"], shadow_w)
        shadow_screen, shadow_valid = _batch_to_screen(shadow_clip, size)
        shadow_valid &= t_vals > 0

        shadow_layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        shadow_draw = ImageDraw.Draw(shadow_layer)

        for t in order:
            if not tri_valid[t]:
                continue
            i0, i1, i2 = idx[t]
            if not (shadow_valid[i0] and shadow_valid[i1] and shadow_valid[i2]):
                continue
            shadow_draw.polygon(
                [
                    (float(shadow_screen[i0, 0]), float(shadow_screen[i0, 1])),
                    (float(shadow_screen[i1, 0]), float(shadow_screen[i1, 1])),
                    (float(shadow_screen[i2, 0]), float(shadow_screen[i2, 1])),
                ],
                fill=(60, 55, 50, 51),
            )

        img = Image.alpha_composite(img, shadow_layer)

    tri_layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(tri_layer)

    for t in order:
        if not tri_valid[t]:
            continue
        i0, i1, i2 = idx[t]
        draw.polygon(
            [
                (float(screen[i0, 0]), float(screen[i0, 1])),
                (float(screen[i1, 0]), float(screen[i1, 1])),
                (float(screen[i2, 0]), float(screen[i2, 1])),
            ],
            fill=(*tuple(colors[t]), 255),
        )

    img = Image.alpha_composite(img, tri_layer).convert("RGB")

    small = round(size * 0.45)
    img = img.resize((small, small), Image.Resampling.BILINEAR).resize(
        (size, size), Image.Resampling.BILINEAR
    )

    arr = _np_add_noise(np.array(img), 35, int(angle_deg * 997))

    buf = BytesIO()
    Image.fromarray(arr).save(buf, format="WEBP", quality=72, method=4)
    return buf.getvalue()


_splat_cache = {}


def _splat_template(radius):
    if radius in _splat_cache:
        return _splat_cache[radius]

    import numpy as np
    from PIL import Image

    d = radius * 2
    coords = np.arange(d, dtype=np.float32) - radius + 0.5
    dist = np.sqrt(coords[None, :] ** 2 + coords[:, None] ** 2) / radius

    alpha_center = 0.45
    alpha_mid = 0.30
    alpha_edge = 0.10

    alpha = np.where(
        dist < 0.35,
        alpha_center + (alpha_mid - alpha_center) * (dist / 0.35),
        np.where(
            dist < 0.7,
            alpha_mid + (alpha_edge - alpha_mid) * ((dist - 0.35) / 0.35),
            np.where(
                dist < 1.0,
                alpha_edge * (1.0 - (dist - 0.7) / 0.3),
                0.0,
            ),
        ),
    )

    r = np.where(dist < 0.35, 255, np.where(dist < 0.7, 235, 200))
    g = np.where(dist < 0.35, 255, np.where(dist < 0.7, 240, 210))
    b = np.where(dist < 0.35, 255, np.where(dist < 0.7, 245, 220))

    out = np.stack([r, g, b, alpha * 255], axis=-1)
    out = np.clip(out, 0, 255).astype(np.uint8)

    img = Image.fromarray(out, "RGBA")
    _splat_cache[radius] = img
    return img


def _render_splat_image(mesh, angle_deg, seed, size=300):
    import numpy as np
    from PIL import Image, ImageDraw

    rng_np = np.random.default_rng(seed)
    points = _sample_surface_np(mesh, 900, seed)

    canvas = Image.new("RGBA", (size, size), (26, 28, 46, 255))
    draw = ImageDraw.Draw(canvas)

    cols = math.ceil(math.sqrt(30))
    cell = size / cols
    for i in range(30):
        col, row = i % cols, i // cols
        sx = (col + 0.3 + float(rng_np.random()) * 0.4) * cell
        sy = (row + 0.3 + float(rng_np.random()) * 0.4) * cell
        sr = int(12 + rng_np.random() * 20)
        warmth = float(rng_np.random())
        alpha = int((0.02 + float(rng_np.random()) * 0.04) * 255)

        cr = int(35 + warmth * 20)
        cg = int(33 + warmth * 18)
        cb = int(55 + warmth * 15)

        draw.ellipse(
            [sx - sr, sy - sr, sx + sr, sy + sr],
            fill=(cr, cg, cb, alpha),
        )

    matrices = _build_matrices(mesh, angle_deg, 45, 3.2, 0.35)
    clip = _batch_transform(matrices["mvp"], points)
    screen, valid = _batch_to_screen(clip, size)
    focal = size / (2 * math.tan(45 * _DEG / 2))

    order = np.argsort(-screen[:, 2])
    skip_mask = rng_np.random(len(order)) < 0.15

    for i in order:
        if not valid[i] or skip_mask[i]:
            continue

        x = float(screen[i, 0])
        y = float(screen[i, 1])
        r = max(4, int(0.055 * focal / clip[i, 3]))

        template = _splat_template(r)
        canvas.alpha_composite(template, (int(x - r), int(y - r)))

    for _ in range(20):
        dx = float(rng_np.random()) * size
        dy = float(rng_np.random()) * size
        dr = max(3, int(4 + rng_np.random() * 10))
        da = 0.08 + float(rng_np.random()) * 0.18

        a0 = int((da + 0.1) * 255)
        a1 = int(da * 0.5 * 255)

        decoy = _splat_template(dr)
        canvas.alpha_composite(decoy, (int(dx - dr), int(dy - dr)))

    arr = _np_add_noise(np.array(canvas.convert("RGB")), 22, seed + 3571)
    return Image.fromarray(arr)


def _render_sprite_sheet(mesh, angles, seed, size=300):
    from concurrent.futures import ThreadPoolExecutor

    from PIL import Image

    def render_frame(args):
        i, angle = args
        return i, _render_splat_image(mesh, angle, seed + i * 7919, size)

    count = len(angles)
    sheet = Image.new("RGB", (size * count, size))

    with ThreadPoolExecutor() as pool:
        for i, tile in pool.map(render_frame, enumerate(angles)):
            sheet.paste(tile, (i * size, 0))

    buf = BytesIO()
    sheet.save(buf, format="WEBP", quality=72, method=4)
    return buf.getvalue()


@dataclass
class RotationCaptcha(ChallengeHandler):
    choice_count: int = 6
    image_size: int = 300
    token_ttl: int = _TOKEN_TTL
    secret: bytes = field(
        default_factory=lambda: secrets.token_bytes(32),
    )

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.ROTATION_CAPTCHA

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

    @property
    def template(self) -> str:
        return (
            Path(__file__).parent / "templates" / "rotation_captcha.html"
        ).read_text()

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
        seed = secrets.randbelow(2**31)
        rng = _create_rng(seed)
        step_size = 360 / self.choice_count

        correct_idx = int(rng() * self.choice_count)
        base_angle = int(rng() * 360)

        angles = [(base_angle + i * step_size) % 360 for i in range(self.choice_count)]
        correct_angle = angles[correct_idx]

        solution = f"{correct_idx}:{seed}:{base_angle}"
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
            correct_idx = int(solution.split(":")[0])
            return int(nonce) == correct_idx
        except Exception:
            return False

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        solution = self._decrypt_token(challenge.random_data)
        correct_idx, seed, base_angle = solution.split(":")
        correct_idx = int(correct_idx)
        seed = int(seed)
        base_angle = int(base_angle)

        mesh = _load_mesh()
        step_size = 360 / self.choice_count
        angles = [(base_angle + i * step_size) % 360 for i in range(self.choice_count)]

        correct_angle = angles[correct_idx]
        reference_b64 = base64.b64encode(
            _render_reference(mesh, correct_angle, self.image_size)
        ).decode()

        sheet_bytes = _render_sprite_sheet(mesh, angles, seed, self.image_size)
        sheet_b64 = base64.b64encode(sheet_bytes).decode()

        return {
            "id": challenge.id,
            "reference": reference_b64,
            "sheet": sheet_b64,
            "choiceCount": self.choice_count,
            "verifyPath": verify_path,
            "redirect": redirect,
        }
