"""Navigator attestation: scores browser signals for automation and spoofing."""

from __future__ import annotations

import math
import re

TRUSTED_SCORE = 0.85
SUSPICIOUS_SCORE = 0.6
LIKELY_AUTOMATED_SCORE = 0.3

VALID_DEVICE_MEMORY = {0.25, 0.5, 1, 2, 4, 8, 16, 32, 64}
VM_RESOLUTIONS = {(800, 600), (1024, 768)}

SOFTWARE_RENDERER = re.compile(
    r"SwiftShader|llvmpipe|softpipe|SVGA3D|VirtualBox|VMware|Parallels|QEMU"
    r"|Mesa DRI|Mesa OffScreen|Microsoft Basic Render",
    re.IGNORECASE,
)
HEADLESS_UA = re.compile(r"HeadlessChrome|PhantomJS|SlimerJS|Electron", re.IGNORECASE)
MOBILE_UA = re.compile(r"mobile|android", re.IGNORECASE)
CHROME_VERSION = re.compile(r"Chrome/(\d+)")


def _text(value) -> str:
    return value if isinstance(value, str) else ""


def _number(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value) if math.isfinite(value) else 0.0


def _names(value, limit: int = 8) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)][:limit]


class _Score:
    def __init__(self) -> None:
        self.value = 1.0
        self.flags: list[str] = []

    def penalize(self, amount: float, flag: str) -> None:
        self.value = max(0.0, self.value - amount)
        self.flags.append(flag)


def _check_automation(signals: dict, score: _Score) -> None:
    hits = _names(signals.get("automation"))
    if not hits:
        return
    penalty = min(0.8, 0.5 + 0.1 * (len(hits) - 1))
    score.penalize(penalty, "automation: " + ", ".join(hits))


def _check_tampering(signals: dict, score: _Score) -> None:
    tampered = _names(signals.get("tampered"))
    if tampered:
        penalty = min(0.4, 0.1 * len(tampered))
        score.penalize(penalty, "tampered natives: " + ", ".join(tampered))

    lies = _number(signals.get("protoLies"))
    if lies:
        score.penalize(min(0.4, 0.06 * lies), f"prototype lies: {lies:.0f}")

    if signals.get("cdp"):
        score.penalize(0.15, "cdp console side-effect")

    if signals.get("perfNowIdentical"):
        score.penalize(0.1, "identical performance.now deltas")


def _check_navigator(signals: dict, score: _Score) -> None:
    user_agent = _text(signals.get("ua"))
    cores = _number(signals.get("hardwareConcurrency"))
    if cores == 0:
        score.penalize(0.15, "zero cores")
    elif cores == 1:
        score.penalize(0.08, "single core")

    memory = signals.get("deviceMemory")
    if memory is not None and _number(memory) not in VALID_DEVICE_MEMORY:
        score.penalize(0.1, "invalid deviceMemory")

    if not _names(signals.get("languages"), 16) and not MOBILE_UA.search(user_agent):
        score.penalize(0.12, "no languages")

    if _language_prefix_mismatch(signals):
        score.penalize(0.1, "language prefix mismatch")

    _check_brand_fields(signals, user_agent, score)


def _language_prefix_mismatch(signals: dict) -> bool:
    languages = _names(signals.get("languages"), 16)
    language = _text(signals.get("language"))
    if not languages or not language:
        return False
    return not languages[0].startswith(language.split("-")[0])


def _check_brand_fields(signals: dict, user_agent: str, score: _Score) -> None:
    product_sub = _text(signals.get("productSub"))
    if "Chrome" in user_agent and product_sub != "20030107":
        score.penalize(0.08, "wrong productSub for Chrome")
    if "Firefox" in user_agent and product_sub != "20100101":
        score.penalize(0.08, "wrong productSub for Firefox")
    if "Chrome" in user_agent and _text(signals.get("vendor")) != "Google Inc.":
        score.penalize(0.08, "wrong vendor for Chrome")
    if HEADLESS_UA.search(user_agent):
        score.penalize(0.5, "headless user agent")


def _check_plugins(signals: dict, score: _Score) -> None:
    user_agent = _text(signals.get("ua"))
    if _text(signals.get("pluginsType")) not in ("", "[object PluginArray]"):
        score.penalize(0.1, "plugins not a PluginArray")
    if _text(signals.get("mimeTypesType")) not in ("", "[object MimeTypeArray]"):
        score.penalize(0.1, "mimeTypes not a MimeTypeArray")
    desktop_chrome = "Chrome" in user_agent and not MOBILE_UA.search(user_agent)
    if desktop_chrome and _number(signals.get("pluginCount")) == 0:
        score.penalize(0.1, "no plugins on desktop Chrome")


def _check_screen(signals: dict, score: _Score) -> None:
    screen = signals.get("screen") or {}
    width, height = _number(screen.get("width")), _number(screen.get("height"))
    if width == 0 or height == 0:
        score.penalize(0.15, "zero screen dimensions")
    if (int(width), int(height)) in VM_RESOLUTIONS:
        score.penalize(0.1, "VM-typical resolution")

    depth = _number(screen.get("colorDepth"))
    if 0 < depth < 24:
        score.penalize(0.1, "low colorDepth")
    if _number(screen.get("devicePixelRatio")) == 0:
        score.penalize(0.1, "zero devicePixelRatio")
    if (
        _number(screen.get("outerWidth")) == 0
        or _number(screen.get("outerHeight")) == 0
    ):
        score.penalize(0.1, "zero outer window size")


def _check_engine(signals: dict, score: _Score) -> None:
    engine = signals.get("engine") or {}
    user_agent = _text(signals.get("ua"))
    eval_length = _number(engine.get("evalLength"))
    if "Chrome" in user_agent and eval_length != 33:
        score.penalize(0.1, "wrong eval length for Chrome")
    if "Firefox" in user_agent and eval_length != 37:
        score.penalize(0.1, "wrong eval length for Firefox")

    stack = _text(engine.get("stackStyle"))
    if stack == "v8" and "Firefox" in user_agent:
        score.penalize(0.2, "V8 stack behind a Firefox user agent")
    if stack == "spidermonkey" and "Chrome" in user_agent:
        score.penalize(0.2, "SpiderMonkey stack behind a Chrome user agent")
    if _number(engine.get("mathTan")) == 0:
        score.penalize(0.05, "zero math fingerprint")


def _check_media(signals: dict, score: _Score) -> None:
    media = signals.get("media") or {}
    user_agent = _text(signals.get("ua"))
    if not media.get("pointerFine") and not media.get("touch"):
        score.penalize(0.1, "neither fine pointer nor touch")
    if not MOBILE_UA.search(user_agent) and not media.get("hover"):
        score.penalize(0.05, "no hover on desktop")
    if media.get("dimensionLie"):
        score.penalize(0.15, "screen dimensions spoofed")
    if bool(media.get("touch")) != (_number(signals.get("maxTouchPoints")) > 0):
        score.penalize(0.05, "touch support inconsistent")


def _check_environment(signals: dict, score: _Score) -> None:
    timezone = signals.get("timezone") or {}
    offset = _number(timezone.get("offset"))
    if offset < -720 or offset > 840:
        score.penalize(0.1, "impossible timezone offset")
    name = _text(timezone.get("name"))
    if not name:
        score.penalize(0.08, "empty timezone name")
    if name == "UTC" and offset != 0:
        score.penalize(0.1, "UTC zone with a non-zero offset")
    if _number(signals.get("fonts")) == 0:
        score.penalize(0.1, "no fonts detected")


def _check_webgl(signals: dict, score: _Score) -> None:
    webgl = signals.get("webgl")
    if not webgl:
        score.penalize(0.1, "no WebGL context")
        return

    renderer = _text(webgl.get("renderer"))
    if SOFTWARE_RENDERER.search(renderer):
        score.penalize(0.2, f"software renderer: {renderer[:40]}")
    if _number(webgl.get("maxTextureSize")) == 0:
        score.penalize(0.1, "zero maxTextureSize")


def _check_canvas(signals: dict, score: _Score) -> None:
    canvas = signals.get("canvas") or {}
    if canvas.get("random"):
        score.penalize(0.25, "canvas randomization")
    if canvas.get("blank"):
        score.penalize(0.15, "canvas renders blank")
    if not _text(canvas.get("hash")) or canvas.get("error"):
        score.penalize(0.1, "canvas unavailable")


HEADLESS_PENALTIES = (
    ("pdfOff", 0.1, "pdf viewer disabled"),
    ("noTaskbar", 0.03, "screen equals available screen"),
    ("viewportMatch", 0.04, "viewport matches screen"),
    ("uadBlank", 0.12, "blank userAgentData platform"),
    ("iframeProxy", 0.15, "iframe contentWindow proxied"),
    ("runtimeConstructable", 0.12, "chrome.runtime constructable"),
    ("activeTextRed", 0.05, "ActiveText renders red"),
)


def _check_headless(signals: dict, score: _Score) -> None:
    headless = signals.get("headless") or {}
    for key, penalty, flag in HEADLESS_PENALTIES:
        if headless.get(key):
            score.penalize(penalty, f"headless: {flag}")


def _check_client_hints(signals: dict, score: _Score) -> None:
    hints = signals.get("clientHints") or {}
    user_agent = _text(signals.get("ua"))
    if "Chrome" in user_agent and not hints.get("hasUAData"):
        score.penalize(0.08, "Chrome without userAgentData")
    if hints.get("mobileMismatch"):
        score.penalize(0.1, "client hint mobile mismatch")
    if hints.get("platformMismatch"):
        score.penalize(0.1, "client hint platform mismatch")
    if _platform_mismatch(signals):
        score.penalize(0.15, "platform contradicts user agent")


PLATFORM_TOKENS = (
    ("win", "Windows"),
    ("mac", "Mac"),
    ("linux", "Linux"),
    ("iphone", "iPhone"),
    ("ipad", "iPad"),
)


def _platform_mismatch(signals: dict) -> bool:
    platform = _text(signals.get("platform")).lower()
    user_agent = _text(signals.get("ua"))
    if not platform or not user_agent:
        return False
    for token, expected in PLATFORM_TOKENS:
        if token in platform:
            return expected not in user_agent and not MOBILE_UA.search(user_agent)
    return False


def _check_css_version(signals: dict, score: _Score) -> None:
    match = CHROME_VERSION.search(_text(signals.get("ua")))
    css_version = _number(signals.get("cssVersion"))
    if not match or not css_version:
        return

    claimed = int(match.group(1))
    if claimed < css_version or (css_version < 115 and claimed - css_version > 5):
        score.penalize(0.15, "CSS support contradicts the Chrome version")


def _check_media_apis(signals: dict, score: _Score) -> None:
    user_agent = _text(signals.get("ua"))
    if "Chrome" not in user_agent or MOBILE_UA.search(user_agent):
        return

    if _number(signals.get("speechVoices")) < 0:
        score.penalize(0.08, "no speechSynthesis")
    if not signals.get("mediaDevices"):
        score.penalize(0.1, "no mediaDevices")
    if not signals.get("webrtc"):
        score.penalize(0.05, "no WebRTC")


def _check_features(signals: dict, score: _Score) -> None:
    missing = _names(signals.get("missingFeatures"), 16)
    if len(missing) > 3:
        score.penalize(0.15, "missing features: " + ", ".join(missing[:5]))


NAVIGATOR_CHECKS = (
    _check_automation,
    _check_tampering,
    _check_navigator,
    _check_plugins,
    _check_screen,
    _check_engine,
    _check_media,
    _check_environment,
    _check_webgl,
    _check_canvas,
    _check_headless,
    _check_client_hints,
    _check_css_version,
    _check_media_apis,
    _check_features,
)

HEADER_PENALTIES = (
    ("accept", 0.05, "no Accept header"),
    ("accept-language", 0.05, "no Accept-Language header"),
    ("accept-encoding", 0.05, "no Accept-Encoding header"),
)


def _check_headers(signals: dict, headers: dict, score: _Score) -> None:
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    for key, penalty, flag in HEADER_PENALTIES:
        if not lowered.get(key):
            score.penalize(penalty, flag)

    header_agent = lowered.get("user-agent", "")
    if HEADLESS_UA.search(header_agent):
        score.penalize(0.2, "headless user agent header")
    if header_agent and not header_agent.startswith("Mozilla/"):
        score.penalize(0.08, "non-standard user agent header")
    if header_agent and _text(signals.get("ua")) != header_agent:
        score.penalize(0.4, "reported user agent differs from the request header")


def _verdict(score: float) -> str:
    if score >= TRUSTED_SCORE:
        return "trusted"
    if score >= SUSPICIOUS_SCORE:
        return "suspicious"
    if score >= LIKELY_AUTOMATED_SCORE:
        return "likely_automated"
    return "automated"


def score_navigator(signals, headers: dict | None = None) -> dict:
    """Score browser signals, 1.0 reads as a real browser."""
    if not isinstance(signals, dict):
        return {"score": 0.0, "verdict": "automated", "flags": ["no signals"]}

    score = _Score()
    for check in NAVIGATOR_CHECKS:
        check(signals, score)
    if headers:
        _check_headers(signals, headers, score)

    value = round(score.value, 4)
    return {"score": value, "verdict": _verdict(value), "flags": score.flags}
