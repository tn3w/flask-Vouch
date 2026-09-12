# pyright: reportMissingImports=false

from __future__ import annotations

import base64
import io
import secrets
from dataclasses import dataclass, field

from .base import ChallengeBase, ChallengeType, RenderCache, SignedTokenHandler
from .datasets import get_default_store

_SAMPLE_RATE = 44100


def _ensure_audio_deps():
    try:
        import numpy as np
        from scipy.io.wavfile import write as write_wav

        return np, write_wav
    except ImportError as e:
        raise ImportError(
            "numpy and scipy are required: " "pip install flask-vouch[audio]"
        ) from e


def _to_audio_segment(samples, sample_rate=_SAMPLE_RATE) -> bytes:
    np, write_wav = _ensure_audio_deps()
    buf = io.BytesIO()
    write_wav(buf, sample_rate, samples.astype(np.int16))
    buf.seek(0)
    return buf.read()


def _sine_wave(freq: float, duration_ms: int):
    np, _ = _ensure_audio_deps()
    n = int(_SAMPLE_RATE * duration_ms / 1000)
    t = np.linspace(0, duration_ms / 1000, n, endpoint=False)
    return (np.sin(2 * np.pi * freq * t) * 32767).astype(np.int16)


def _noise(duration_ms: int, level: float = 0.05):
    np, _ = _ensure_audio_deps()
    n = int(_SAMPLE_RATE * duration_ms / 1000)
    return (np.random.uniform(-1, 1, n) * level * 32767).astype(np.int16)


def _wav_to_samples(wav_bytes: bytes):
    np, _ = _ensure_audio_deps()
    from scipy.io.wavfile import read as read_wav

    buf = io.BytesIO(wav_bytes)
    _, samples = read_wav(buf)

    if samples.ndim > 1:
        samples = samples[:, 0]

    return samples.astype(np.int16)


def _combine_audio(
    audio_files: list[bytes],
    hardness: int = 1,
) -> bytes:
    np, write_wav = _ensure_audio_deps()
    segments = []

    for wav_bytes in audio_files:
        samples = _wav_to_samples(wav_bytes)

        speed = 1.0 + (hardness - 1) * 0.05
        if speed != 1.0:
            indices = np.linspace(
                0,
                len(samples) - 1,
                int(len(samples) / speed),
            ).astype(int)
            samples = samples[indices]

        segments.append(samples)

    parts = []

    silence_min = max(200, 500 - hardness * 50)
    silence_max = max(400, 700 - hardness * 50)

    parts.append(
        np.zeros(
            int(_SAMPLE_RATE * secrets.randbelow(silence_max - silence_min + 1) / 1000)
            + int(_SAMPLE_RATE * silence_min / 1000),
            dtype=np.int16,
        )
    )

    for segment in segments:
        parts.append(segment)
        gap_ms = secrets.randbelow(silence_max - silence_min + 1) + silence_min
        parts.append(
            np.zeros(
                int(_SAMPLE_RATE * gap_ms / 1000),
                dtype=np.int16,
            )
        )

    combined = np.concatenate(parts)

    noise_level = 0.01 + hardness * 0.005
    bg_noise = _noise(
        int(len(combined) * 1000 / _SAMPLE_RATE),
        level=noise_level,
    )

    if len(bg_noise) > len(combined):
        bg_noise = bg_noise[: len(combined)]
    elif len(bg_noise) < len(combined):
        combined = combined[: len(bg_noise)]

    combined = np.clip(
        combined.astype(np.int32) + bg_noise.astype(np.int32),
        -32768,
        32767,
    ).astype(np.int16)

    for _ in range(hardness):
        freq = secrets.randbelow(400) + 200
        beep_ms = secrets.randbelow(50) + 30
        beep = (_sine_wave(freq, beep_ms) * 0.1).astype(np.int16)
        pos = secrets.randbelow(max(1, len(combined) - len(beep)))
        end = min(pos + len(beep), len(combined))
        combined[pos:end] = np.clip(
            combined[pos:end].astype(np.int32) + beep[: end - pos].astype(np.int32),
            -32768,
            32767,
        ).astype(np.int16)

    try:
        from pydub import AudioSegment

        wav_buf = io.BytesIO()
        write_wav(wav_buf, _SAMPLE_RATE, combined)
        wav_buf.seek(0)
        audio = AudioSegment.from_wav(wav_buf)
        mp3_buf = io.BytesIO()
        audio.export(mp3_buf, format="mp3")
        mp3_buf.seek(0)
        return mp3_buf.read()
    except ImportError:
        return _to_audio_segment(combined)


@dataclass
class AudioCaptcha(SignedTokenHandler):
    dataset: str = "characters"
    lang: str = "en"
    cache: RenderCache = field(default_factory=RenderCache)

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.AUDIO_CAPTCHA

    def generate_random_data(self, difficulty: int = 0) -> str:
        char_count = max(4, min(difficulty + 3, 8))
        store = get_default_store()
        audio_files, solution = store.get_audio(
            chars=char_count,
            lang=self.lang,
            dataset=self.dataset,
        )
        if not audio_files:
            raise RuntimeError(f"failed to load audio dataset '{self.dataset}'")

        hardness = max(1, min(difficulty, 5))
        audio_bytes = _combine_audio(audio_files, hardness)

        b64 = base64.b64encode(audio_bytes).decode()
        token = self.issue_token(solution)
        self.cache.put(token, {"audio": f"data:audio/mp3;base64,{b64}"})
        return token

    @property
    def extra_csp(self) -> str:
        return "media-src data:"

    def nonce_from_form(self, raw: str) -> str:
        return raw.strip().upper()

    def verify(
        self,
        random_data: str,
        nonce: int | str,
        difficulty: int,
    ) -> bool:
        try:
            correct = self.read_token(random_data)
            return correct.upper() == str(nonce).upper()
        except Exception:
            return False

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        cached = self.cache.pop(challenge.random_data)
        if not cached:
            raise RuntimeError("audio cache expired")

        return {
            "id": challenge.id,
            "audio": cached["audio"],
            "verifyPath": verify_path,
            "redirect": redirect,
        }
