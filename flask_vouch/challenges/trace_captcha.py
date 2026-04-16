import base64
import hashlib
import hmac
import json
import math
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from .base import DIFFICULTY_OFFSETS, ChallengeBase, ChallengeHandler, ChallengeType

_TOKEN_TTL = 1800
_W = _H = 320
_MARGIN = 36
_ENDPOINT_TOLERANCE = 42
_PATH_TOLERANCE = 32
_MIN_SAMPLES = 12
_MIN_DURATION_MS = 250
_MAX_DURATION_MS = 15000
_CURVE_RESOLUTION = 240


def _bezier_point(t: float, p0, p1, p2, p3) -> tuple[float, float]:
    u = 1 - t
    uu, tt = u * u, t * t
    b0, b1, b2, b3 = uu * u, 3 * uu * t, 3 * u * tt, tt * t
    return (
        b0 * p0[0] + b1 * p1[0] + b2 * p2[0] + b3 * p3[0],
        b0 * p0[1] + b1 * p1[1] + b2 * p2[1] + b3 * p3[1],
    )


def _sample_curve(control_points, steps: int) -> list[tuple[float, float]]:
    p0, p1, p2, p3 = control_points
    return [_bezier_point(i / steps, p0, p1, p2, p3) for i in range(steps + 1)]


def _random_curve() -> list[tuple[int, int]]:
    start = (_MARGIN, secrets.randbelow(_H - 2 * _MARGIN) + _MARGIN)
    end = (_W - _MARGIN, secrets.randbelow(_H - 2 * _MARGIN) + _MARGIN)
    inner_x = _W - 2 * _MARGIN
    c1 = (
        _MARGIN + secrets.randbelow(inner_x // 2),
        secrets.randbelow(_H - 2 * _MARGIN) + _MARGIN,
    )
    c2 = (
        _MARGIN + inner_x // 2 + secrets.randbelow(inner_x // 2),
        secrets.randbelow(_H - 2 * _MARGIN) + _MARGIN,
    )
    return [start, c1, c2, end]


def _min_distance(point, curve) -> float:
    px, py = point
    best = float("inf")
    for cx, cy in curve:
        d = (px - cx) ** 2 + (py - cy) ** 2
        if d < best:
            best = d
    return math.sqrt(best)


def _coefficient_of_variation(values) -> float:
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    if mean <= 0:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance) / mean


@dataclass
class TraceCaptcha(ChallengeHandler):
    token_ttl: int = _TOKEN_TTL
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.TRACE_CAPTCHA

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

    @property
    def template(self) -> str:
        return (Path(__file__).parent / "templates" / "trace_captcha.html").read_text()

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()

    def _encrypt(self, plaintext: str, iv: str) -> str:
        key = hmac.new(self.secret, iv.encode(), hashlib.sha256).digest()
        stream = (key * (len(plaintext) // len(key) + 1))[: len(plaintext)]
        return bytes(a ^ b for a, b in zip(plaintext.encode(), stream)).hex()

    def _decrypt_token(self, token: str) -> str:
        iv, ct_hex, ts, nonce, sig = token.split(":")
        payload = f"{iv}:{ct_hex}:{ts}:{nonce}"
        if not hmac.compare_digest(self._sign(payload), sig):
            raise ValueError("invalid signature")
        if time.time() - int(ts) > self.token_ttl:
            raise ValueError("token expired")
        key = hmac.new(self.secret, iv.encode(), hashlib.sha256).digest()
        ct = bytes.fromhex(ct_hex)
        stream = (key * (len(ct) // len(key) + 1))[: len(ct)]
        return bytes(a ^ b for a, b in zip(ct, stream)).decode()

    def generate_random_data(self, difficulty: int = 0) -> str:
        curve = _random_curve()
        flat = ",".join(f"{x},{y}" for x, y in curve)
        iv = secrets.token_hex(16)
        ct = self._encrypt(flat, iv)
        ts = str(int(time.time()))
        nonce = secrets.token_hex(8)
        payload = f"{iv}:{ct}:{ts}:{nonce}"
        return f"{payload}:{self._sign(payload)}"

    @property
    def retry_on_failure(self) -> bool:
        return True

    def nonce_from_form(self, raw: str) -> str:
        return raw.strip()

    def _parse_samples(self, nonce: str) -> list[list[float]]:
        data = json.loads(nonce)
        if not isinstance(data, list):
            raise ValueError("invalid samples")
        return data

    def _control_points(self, random_data: str):
        raw = self._decrypt_token(random_data)
        nums = [int(n) for n in raw.split(",")]
        return [(nums[i], nums[i + 1]) for i in range(0, 8, 2)]

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        try:
            samples = self._parse_samples(str(nonce))
            control = self._control_points(random_data)
        except Exception:
            return False

        if len(samples) < _MIN_SAMPLES:
            return False

        curve = _sample_curve(control, _CURVE_RESOLUTION)
        start, end = control[0], control[-1]

        first, last = samples[0], samples[-1]
        if math.hypot(first[0] - start[0], first[1] - start[1]) > _ENDPOINT_TOLERANCE:
            return False
        if math.hypot(last[0] - end[0], last[1] - end[1]) > _ENDPOINT_TOLERANCE:
            return False

        duration = last[2] - first[2]
        if duration < _MIN_DURATION_MS or duration > _MAX_DURATION_MS:
            return False

        tolerance = max(20, _PATH_TOLERANCE - difficulty)
        deviations = [_min_distance((s[0], s[1]), curve) for s in samples]
        deviations.sort()
        trimmed = deviations[: max(1, int(len(deviations) * 0.9))]
        if sum(trimmed) / len(trimmed) > tolerance:
            return False
        if deviations[-1] > tolerance * 3:
            return False

        dts = [
            samples[i + 1][2] - samples[i][2]
            for i in range(len(samples) - 1)
            if samples[i + 1][2] > samples[i][2]
        ]
        if not dts or _coefficient_of_variation(dts) < 0.05:
            return False

        return True

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        control = self._control_points(challenge.random_data)
        polyline = _sample_curve(control, 80)
        path_points = [[round(x, 2), round(y, 2)] for x, y in polyline]
        return {
            "id": challenge.id,
            "width": _W,
            "height": _H,
            "pathJson": json.dumps(path_points),
            "startX": control[0][0],
            "startY": control[0][1],
            "endX": control[-1][0],
            "endY": control[-1][1],
            "verifyPath": verify_path,
            "redirect": redirect,
        }
