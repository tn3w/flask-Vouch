import hashlib
import hmac as _hmac
import json
import random
import re as _re
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from .base import ChallengeBase, ChallengeHandler, ChallengeType

_CATEGORIES = [
    "automation",
    "browser",
    "properties",
    "natives",
    "features",
    "navigator",
    "screen",
    "engine",
    "mediaQueries",
    "environment",
    "timing",
    "webgl",
    "canvas",
    "fonts",
    "headless",
    "vm",
    "consistency",
    "devtools",
    "cdp",
    "cssVersion",
    "voices",
    "performance",
    "prototype",
    "drawing",
]


def _bits(n: int) -> int:
    n &= 0xFFFFFFFF
    c = 0
    while n:
        c += n & 1
        n >>= 1
    return c


def _p(s: dict, a: float, r: str) -> None:
    s["score"] = max(0.0, s["score"] - a)
    s["flags"].append(r)


def _check_automation(sig: dict, s: dict) -> None:
    auto = sig.get("automation")
    if not auto:
        return
    for key, factor, label in [
        ("globals", 0.15, "globals detected"),
        ("enhanced", 0.12, "enhanced signals"),
        ("extra", 0.12, "extra globals"),
    ]:
        bits = _bits(auto.get(key, 0))
        if bits > 0:
            _p(s, min(0.5, bits * factor), f"automation:{bits} {label}")


def _check_browser(sig: dict, s: dict) -> None:
    browser = sig.get("browser")
    if not browser:
        return
    ua = sig.get("navigator", {}).get("ua", "")
    apis = browser.get("apis", 0)
    if "Chrome" in ua:
        if not (apis & 1):
            _p(s, 0.08, "browser:chrome missing")
        if not (apis & 2):
            _p(s, 0.05, "browser:permissions missing")
    if not (apis & 4):
        _p(s, 0.1, "browser:no languages")
    sel = _bits(browser.get("selenium", 0))
    if sel > 0:
        _p(s, min(0.5, sel * 0.08), f"browser:{sel} selenium artifacts")
    stealth = _bits(browser.get("stealth", 0) & ~128)
    if stealth > 0:
        _p(s, min(0.5, stealth * 0.08), f"browser:{stealth} stealth signals")
    adv = _bits(browser.get("advanced", 0))
    if adv >= 3:
        _p(s, 0.35, f"browser:{adv} advanced detection")
    elif adv > 0:
        _p(s, adv * 0.08, f"browser:{adv} advanced detection")


def _check_properties(sig: dict, s: dict) -> None:
    props = sig.get("properties")
    if not props:
        return
    ig = props.get("integrity", 0)
    if not (ig & 1):
        _p(s, 0.1, "properties:defineProperty tampered")
    if not (ig & 2):
        _p(s, 0.1, "properties:getOwnPropDesc tampered")
    if not (ig & 4):
        _p(s, 0.08, "properties:Reflect.get tampered")
    if ig & (1 << 10):
        _p(s, 0.1, "properties:navigator.toString wrong")
    if ig & (1 << 11):
        _p(s, 0.15, "properties:navigator.toString throws")
    if ig & (1 << 13):
        _p(s, 0.1, "properties:toStringTag wrong")
    if ig & (1 << 14):
        _p(s, 0.15, "properties:proto getter not native")
    if ig & (1 << 15):
        _p(s, 0.1, "properties:Reflect.get tampered v2")
    ov = props.get("overrides", 0)
    if ov > 0:
        _p(s, min(0.3, ov * 0.1), f"properties:{ov} overrides")
    if props.get("protoInconsistency", 0) > 0:
        _p(s, 0.15, "properties:proto inconsistency")


def _check_natives(sig: dict, s: dict) -> None:
    natives = sig.get("natives")
    if natives is None:
        return
    bits = _bits(~natives & 0xFFF)
    if bits > 0:
        _p(s, min(0.4, bits * 0.08), f"natives:{bits} tampered functions")


def _check_features(sig: dict, s: dict) -> None:
    features = sig.get("features")
    if features is None:
        return
    missing = _bits(~features & 0x7FF)
    if missing > 3:
        _p(s, 0.15, f"features:{missing} missing")
    if (features & 0x30) == 0x30 and (not (features & 1) or not (features & 4)):
        _p(s, 0.2, "features:inconsistent")


def _check_navigator(sig: dict, s: dict) -> None:
    nav = sig.get("navigator")
    if not nav:
        return
    ua = nav.get("ua", "")
    hc = nav.get("hardwareConcurrency")
    if hc == 1:
        _p(s, 0.08, "navigator:1 core")
    if hc == 0:
        _p(s, 0.15, "navigator:0 cores")
    if nav.get("languageCount") == 0 and not _re.search(r"mobile|android", ua, _re.I):
        _p(s, 0.12, "navigator:no languages")
    dm = nav.get("deviceMemory")
    if dm is not None and dm not in {0.25, 0.5, 1, 2, 4, 8, 16, 32, 64}:
        _p(s, 0.1, "navigator:invalid deviceMemory")
    if nav.get("rtt") == 0:
        _p(s, 0.05, "navigator:rtt=0")
    if "Chrome" in ua and nav.get("productSub") != "20030107":
        _p(s, 0.08, "navigator:wrong productSub")
    if "Firefox" in ua and nav.get("productSub") != "20100101":
        _p(s, 0.08, "navigator:wrong productSub")
    if "Chrome" in ua and nav.get("vendor") != "Google Inc.":
        _p(s, 0.08, "navigator:wrong vendor")


def _check_screen(sig: dict, s: dict) -> None:
    scr = sig.get("screen")
    if not scr:
        return
    w, h = scr.get("width", 0), scr.get("height", 0)
    if w == 0 or h == 0:
        _p(s, 0.15, "screen:zero dimensions")
    if (w == 800 and h == 600) or (w == 1024 and h == 768):
        _p(s, 0.1, "screen:VM-typical resolution")
    cd = scr.get("colorDepth", 0)
    if 0 < cd < 24:
        _p(s, 0.1, "screen:low colorDepth")
    if scr.get("devicePixelRatio") == 0:
        _p(s, 0.1, "screen:zero DPR")


def _check_engine(sig: dict, s: dict) -> None:
    eng = sig.get("engine")
    if not eng:
        return
    ua = sig.get("navigator", {}).get("ua", "")
    el = eng.get("evalLength")
    if "Chrome" in ua and el != 33:
        _p(s, 0.1, "engine:wrong eval length Chrome")
    if "Firefox" in ua and el != 37:
        _p(s, 0.1, "engine:wrong eval length Firefox")
    ss = eng.get("stackStyle")
    if ss == "v8" and "Firefox" in ua:
        _p(s, 0.15, "engine:V8 stack in Firefox UA")
    if ss == "spidermonkey" and "Chrome" in ua:
        _p(s, 0.15, "engine:SpiderMonkey stack in Chrome UA")
    if eng.get("mathTan") == 0:
        _p(s, 0.05, "engine:math fingerprint zero")


def _check_media_queries(sig: dict, s: dict) -> None:
    mq = sig.get("mediaQueries")
    if not mq:
        return
    ua = sig.get("navigator", {}).get("ua", "")
    if not mq.get("pointerFine") and not mq.get("touch"):
        _p(s, 0.1, "mediaQueries:no pointer no touch")
    if not _re.search(r"mobile|android", ua, _re.I) and not mq.get("hover"):
        _p(s, 0.05, "mediaQueries:no hover on desktop")


def _check_environment(sig: dict, s: dict) -> None:
    env = sig.get("environment")
    if not env:
        return
    tz = env.get("timezoneOffset", 0)
    if tz < -720 or tz > 840:
        _p(s, 0.1, "environment:impossible timezone")
    if env.get("timezoneName") == "UTC" and tz != 0:
        _p(s, 0.1, "environment:UTC name non-zero offset")
    if env.get("timezoneName") == "":
        _p(s, 0.08, "environment:empty timezone name")
    touch = env.get("touch", 0)
    if (touch & 1) != ((touch >> 1) & 1):
        _p(s, 0.05, "environment:touch inconsistency")
    doc = env.get("document", 0)
    if (doc & 1) and (doc & 2):
        _p(s, 0.08, "environment:hidden+focused")


def _check_timing(sig: dict, s: dict) -> None:
    timing = sig.get("timing")
    if timing and timing.get("perfNowIdentical"):
        _p(s, 0.1, "timing:identical perf.now diffs")


def _check_webgl(sig: dict, s: dict) -> None:
    gl = sig.get("webgl")
    if not gl:
        return
    renderer = gl.get("renderer") or ""
    if gl.get("vendor") == "Google Inc." and "SwiftShader" in renderer:
        _p(s, 0.2, "webgl:Google+SwiftShader")
    if gl.get("maxTextureSize") == 0:
        _p(s, 0.1, "webgl:zero maxTextureSize")
    if _re.search(r"SwiftShader|llvmpipe|softpipe", renderer, _re.I):
        _p(s, 0.2, "webgl:software renderer")


def _check_canvas(sig: dict, s: dict) -> None:
    cv = sig.get("canvas")
    if not cv:
        return
    if cv.get("hash") == "err":
        _p(s, 0.1, "canvas:error")
    t = cv.get("tampering") or {}
    if t.get("random"):
        _p(s, 0.25, "canvas:randomization")
    if t.get("error"):
        _p(s, 0.05, "canvas:tampering error")
    if t.get("inconsistent"):
        _p(s, 0.15, "canvas:data/pixel mismatch")


def _check_fonts(sig: dict, s: dict) -> None:
    fonts = sig.get("fonts")
    if fonts and fonts.get("count") == 0 and fonts.get("widths"):
        _p(s, 0.1, "fonts:zero detected")


def _check_headless(sig: dict, s: dict) -> None:
    h = sig.get("headless")
    if not h:
        return
    ua = sig.get("navigator", {}).get("ua", "")
    is_chrome = "Chrome" in ua
    is_linux = "Linux" in ua and "Android" not in ua
    if is_chrome and h.get("pdfOff"):
        _p(s, 0.1, "headless:pdf viewer disabled")
    if h.get("noTaskbar"):
        _p(s, 0.03, "headless:no taskbar")
    if h.get("viewportMatch"):
        _p(s, 0.04, "headless:viewport matches screen")
    if is_chrome and not is_linux and h.get("noShare"):
        _p(s, 0.02, "headless:no Web Share API")
    if not is_linux and h.get("activeTextRed"):
        _p(s, 0.05, "headless:ActiveText red")
    if h.get("uadBlank"):
        _p(s, 0.12, "headless:blank UAData platform")
    if h.get("runtimeConstructable"):
        _p(s, 0.12, "headless:runtime constructable")
    if h.get("iframeProxy"):
        _p(s, 0.15, "headless:iframe proxy detected")
    if h.get("pluginsNotArray"):
        _p(s, 0.1, "headless:plugins not PluginArray")
    if h.get("mesa"):
        _p(s, 0.2, "headless:Mesa OffScreen renderer")


def _check_vm(sig: dict, s: dict) -> None:
    vmd = sig.get("vm")
    if not vmd:
        return
    if vmd.get("softwareGL"):
        _p(s, 0.2, "vm:software/VM GL renderer")
    if vmd.get("lowHardware"):
        _p(s, 0.06, "vm:low hardware specs")
    if vmd.get("vmResolution"):
        _p(s, 0.08, "vm:VM-typical resolution")
    if vmd.get("vmAudio"):
        _p(s, 0.1, "vm:zero audio channels")
    hits = sum(
        bool(vmd.get(k))
        for k in ("softwareGL", "lowHardware", "vmResolution", "vmAudio")
    )
    if hits >= 3:
        _p(s, 0.15, "vm:multiple indicators")


def _check_consistency(sig: dict, s: dict) -> None:
    cons = sig.get("consistency") or {}
    ua = sig.get("navigator", {}).get("ua", "")
    is_linux = "Linux" in ua and "Android" not in ua
    ch = cons.get("clientHints") or {}
    if ch:
        if "Chrome" in ua and not ch.get("hasUAData"):
            _p(s, 0.08, "consistency:no UAData Chrome")
        if ch.get("mobileMismatch"):
            _p(s, 0.1, "consistency:mobile mismatch")
        if ch.get("platformMismatch"):
            _p(s, 0.1, "consistency:platform mismatch")
    sc = cons.get("screen") or {}
    if sc.get("dimensionLie"):
        _p(s, 0.15, "consistency:screen dimensions spoofed")
    if sc.get("alwaysLight"):
        _p(s, 0.04, "consistency:always light scheme")
    lc = cons.get("locale") or {}
    if lc.get("languagePrefix"):
        _p(s, 0.1, "consistency:language prefix mismatch")
    if lc.get("localeLie") and not is_linux:
        _p(s, 0.02, "consistency:locale formatting mismatch")


def _check_devtools(sig: dict, s: dict) -> None:
    dt = sig.get("devtools")
    if dt and dt.get("sizeAnomaly"):
        _p(s, 0.05, "devtools:large size difference")


def _check_cdp(sig: dict, s: dict) -> None:
    if sig.get("cdp"):
        _p(s, 0.15, "cdp:console side-effect")


def _check_css_version(sig: dict, s: dict) -> None:
    if not sig.get("cssVersion") or not sig.get("navigator"):
        return
    ua = sig["navigator"].get("ua", "")
    m = _re.search(r"Chrome/(\d+)", ua)
    if not m:
        return
    ua_ver, css_ver = int(m.group(1)), sig["cssVersion"]
    if ua_ver < css_ver or (css_ver < 115 and ua_ver - css_ver > 5):
        _p(s, 0.15, "cssVersion:UA version mismatch")


def _check_voices(sig: dict, s: dict) -> None:
    vms = sig.get("voices")
    if not vms:
        return
    ua = sig.get("navigator", {}).get("ua", "")
    if "Chrome" in ua and "Android" not in ua:
        if vms.get("voiceCount") == -1:
            _p(s, 0.08, "voices:no speechSynthesis")
        if not vms.get("mediaDevices"):
            _p(s, 0.1, "voices:no mediaDevices")
    if "Chrome" in ua and not vms.get("webrtc"):
        _p(s, 0.05, "voices:no WebRTC Chrome")


def _check_performance(sig: dict, s: dict) -> None:
    perf = sig.get("performance")
    if not perf:
        return
    heap_limit = perf.get("jsHeapSizeLimit")
    total_heap = perf.get("totalJSHeapSize")
    if heap_limit and total_heap and total_heap > heap_limit:
        _p(s, 0.1, "performance:heap exceeds limit")


def _check_prototype(sig: dict, s: dict) -> None:
    pf = sig.get("prototype")
    if not pf:
        return
    lc = pf.get("lieCount", 0)
    if lc > 2:
        _p(s, min(0.4, lc * 0.06), f"prototype:{lc} API lies")
    elif lc > 0:
        _p(s, lc * 0.05, f"prototype:{lc} API lies")
    if pf.get("mimeTypeProto"):
        _p(s, 0.1, "prototype:MimeType proto tampered")


def _check_drawing(sig: dict, s: dict) -> None:
    dr = sig.get("drawing")
    if dr and dr.get("emojiWidth") == 0 and dr.get("emojiHeight") == 0:
        _p(s, 0.08, "drawing:zero emoji dimensions")


def _check_cross_validation(sig: dict, s: dict) -> None:
    nav = sig.get("navigator")
    if not nav:
        return
    ua = nav.get("ua", "")
    gl = sig.get("webgl") or {}
    eng = sig.get("engine") or {}
    scr = sig.get("screen") or {}
    renderer = gl.get("renderer") or ""
    is_chrome = "Chrome" in ua and "Edge" not in ua
    is_firefox = "Firefox" in ua
    is_safari = "Safari" in ua and not is_chrome
    is_linux = "Linux" in ua and "Android" not in ua
    is_mac = "Mac" in ua

    if is_chrome and _re.search(r"Gecko/\d", ua) and "like Gecko" not in ua:
        _p(s, 0.2, "crossValidation:Chrome UA with Gecko engine")
    if is_firefox and "ANGLE" in renderer:
        _p(s, 0.15, "crossValidation:Firefox UA with ANGLE")
    if is_safari and is_linux:
        _p(s, 0.2, "crossValidation:Safari UA on Linux")
    if (
        is_mac
        and _re.search(r"NVIDIA|GeForce", renderer, _re.I)
        and _re.search(r"Mac OS X 1[1-9]|macOS 1[2-9]", ua)
    ):
        _p(s, 0.1, "crossValidation:NVIDIA on modern macOS")
    if is_mac and scr.get("devicePixelRatio") == 1 and (scr.get("width") or 0) > 1920:
        _p(s, 0.08, "crossValidation:Mac non-retina high-res")
    if is_chrome and eng.get("stackStyle") == "spidermonkey":
        _p(s, 0.2, "crossValidation:Chrome UA SpiderMonkey")
    if is_firefox and eng.get("stackStyle") == "v8":
        _p(s, 0.2, "crossValidation:Firefox UA V8 stack")


def _check_headers(headers: dict, s: dict) -> None:
    for h, msg in [
        ("accept", "headers:no Accept"),
        ("accept-language", "headers:no Accept-Language"),
        ("accept-encoding", "headers:no Accept-Encoding"),
    ]:
        if not headers.get(h):
            _p(s, 0.05, msg)
    ua = headers.get("user-agent", "")
    if _re.search(r"HeadlessChrome|PhantomJS|SlimerJS", ua, _re.I):
        _p(s, 0.2, "headers:headless UA string")
    if ua and not _re.search(r"Mozilla/", ua):
        _p(s, 0.08, "headers:non-standard UA")


_CHECKS = [
    _check_automation,
    _check_browser,
    _check_properties,
    _check_natives,
    _check_features,
    _check_navigator,
    _check_screen,
    _check_engine,
    _check_media_queries,
    _check_environment,
    _check_timing,
    _check_webgl,
    _check_canvas,
    _check_fonts,
    _check_headless,
    _check_vm,
    _check_consistency,
    _check_devtools,
    _check_cdp,
    _check_css_version,
    _check_voices,
    _check_performance,
    _check_prototype,
    _check_drawing,
    _check_cross_validation,
]

_CATEGORY_MAP: dict[str, list] = {
    "automation": [_check_automation],
    "browser": [_check_browser],
    "properties": [_check_properties],
    "natives": [_check_natives],
    "features": [_check_features],
    "navigator": [_check_navigator],
    "screen": [_check_screen],
    "engine": [_check_engine],
    "mediaQueries": [_check_media_queries],
    "environment": [_check_environment],
    "timing": [_check_timing],
    "webgl": [_check_webgl],
    "canvas": [_check_canvas],
    "fonts": [_check_fonts],
    "headless": [_check_headless],
    "vm": [_check_vm],
    "consistency": [_check_consistency],
    "devtools": [_check_devtools],
    "cdp": [_check_cdp],
    "cssVersion": [_check_css_version],
    "voices": [_check_voices],
    "performance": [_check_performance],
    "prototype": [_check_prototype],
    "drawing": [_check_drawing],
    "crossValidation": [_check_cross_validation],
}


def _classify(score: float) -> str:
    if score >= 0.85:
        return "trusted"
    if score >= 0.6:
        return "suspicious"
    if score >= 0.3:
        return "likely_automated"
    return "automated"


def validate_signals(signals: dict, headers: dict | None = None) -> dict:
    s = {"score": 1.0, "flags": []}
    for check in _CHECKS:
        check(signals, s)
    if headers:
        _check_headers(headers, s)
    score = round(s["score"] * 10000) / 10000
    cats: dict = {}
    for name, checks in _CATEGORY_MAP.items():
        cs = {"score": 1.0, "flags": []}
        for check in checks:
            check(signals, cs)
        cats[name] = {"score": round(cs["score"] * 10000) / 10000, "flags": cs["flags"]}
    if headers:
        hs = {"score": 1.0, "flags": []}
        _check_headers(headers, hs)
        cats["headers"] = {
            "score": round(hs["score"] * 10000) / 10000,
            "flags": hs["flags"],
        }
    return {
        "score": score,
        "flags": s["flags"],
        "verdict": _classify(score),
        "categoryScores": cats,
    }


def _b64(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_token(payload: dict, secret: bytes) -> str:
    j = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = _hmac.new(secret, j.encode(), hashlib.sha256).hexdigest()
    return f"{_b64(j.encode())}.{sig}"


def _verify_token(token: str, secret: bytes) -> dict | None:
    try:
        dot = token.index(".")
        payload_b64, sig = token[:dot], token[dot + 1 :]
        j = urlsafe_b64decode(payload_b64 + "==").decode()
        expected = _hmac.new(secret, j.encode(), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, expected):
            return None
        return json.loads(j)
    except Exception:
        return None


@dataclass
class _Session:
    id: str
    rounds: list
    current_round: int = 0
    nonces: list = field(default_factory=list)
    all_signals: dict = field(default_factory=dict)
    started_at: float = field(default_factory=time.monotonic)


def _split_rounds(categories: list, count: int) -> list:
    shuffled = categories[:]
    random.shuffle(shuffled)
    rounds: list = [[] for _ in range(count)]
    for i, cat in enumerate(shuffled):
        rounds[i % count].append(cat)
    return rounds


def _next_msg(session: _Session) -> dict:
    nonce = secrets.token_hex(16)
    session.nonces.append(nonce)
    return {
        "type": "challenge",
        "round": session.current_round + 1,
        "totalRounds": len(session.rounds),
        "nonce": nonce,
        "checks": session.rounds[session.current_round],
    }


def _process(session: _Session, message: dict, challenge: ChallengeBase) -> dict:
    nonce = message.get("nonce")
    round_num = message.get("round")
    signals = message.get("signals") or {}

    if nonce != session.nonces[session.current_round]:
        return {"type": "error", "reason": "invalid nonce"}
    if round_num != session.current_round + 1:
        return {"type": "error", "reason": "wrong round"}

    session.all_signals.update(signals)
    session.current_round += 1

    if session.current_round < len(session.rounds):
        return _next_msg(session)

    result = validate_signals(session.all_signals)
    token = _sign_token(
        {
            "score": result["score"],
            "verdict": result["verdict"],
            "exp": int(time.time() + 300),
        },
        challenge.random_data.encode(),
    )
    return {"type": "result", "token": token}


class NavigatorAttestation(ChallengeHandler):
    ROUND_COUNT = 3
    ROUND_TIMEOUT = 45

    def __init__(self) -> None:
        self._sessions: dict[str, _Session] = {}
        self._lock = Lock()

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.NAVIGATOR_ATTESTATION

    def to_difficulty(self, base: int) -> int:
        return base

    @property
    def template(self) -> str:
        return (
            Path(__file__).parent / "templates" / "navigator_attestation.html"
        ).read_text()

    def generate_random_data(self, difficulty: int = 0) -> str:
        return secrets.token_hex(32)

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        payload = _verify_token(str(nonce), random_data.encode())
        if not payload or time.time() > payload.get("exp", 0):
            return False
        threshold = min(0.85, max(0.5, 0.5 + (difficulty - 5) * 0.02))
        return payload.get("score", 0) >= threshold

    def jwt_extra(self, random_data: str, nonce: int | str) -> dict:
        payload = _verify_token(str(nonce), random_data.encode())
        return {"score": payload["score"]} if payload else {}

    def handle_http_poll(self, body: dict, engine) -> dict:
        challenge_id = body.get("id", "")

        if body.get("init"):
            challenge = engine.store.get(challenge_id)
            if (
                not challenge
                or challenge.spent
                or challenge.challenge_type != ChallengeType.NAVIGATOR_ATTESTATION
            ):
                return {"type": "error", "reason": "invalid challenge"}
            session = _Session(
                id=challenge_id, rounds=_split_rounds(_CATEGORIES, self.ROUND_COUNT)
            )
            with self._lock:
                self._evict_sessions()
                self._sessions[challenge_id] = session
            return _next_msg(session)

        with self._lock:
            session = self._sessions.get(challenge_id)
        if not session:
            return {"type": "error", "reason": "no session"}

        challenge = engine.store.get(challenge_id)
        if not challenge:
            return {"type": "error", "reason": "invalid challenge"}

        response = _process(session, body, challenge)
        if response["type"] in ("result", "error"):
            with self._lock:
                self._sessions.pop(challenge_id, None)
        return response

    def _evict_sessions(self) -> None:
        cutoff = time.monotonic() - self.ROUND_TIMEOUT
        for k in [k for k, v in self._sessions.items() if v.started_at < cutoff]:
            del self._sessions[k]

    def nonce_from_form(self, raw: str) -> str:
        return raw

    def render_payload(
        self, challenge: ChallengeBase, verify_path: str, redirect: str
    ) -> dict:
        return {
            "id": challenge.id,
            "verifyPath": verify_path,
            "redirect": redirect,
        }

    @property
    def supports_websocket(self) -> bool:
        return True

    @property
    def supports_http_poll(self) -> bool:
        return True

    async def handle_websocket(self, scope, receive, send, engine) -> None:
        from urllib.parse import parse_qs

        query = scope.get("query_string", b"").decode()
        challenge_id = parse_qs(query).get("id", [""])[0]
        challenge = engine.store.get(challenge_id) if challenge_id else None

        await send({"type": "websocket.accept"})

        if (
            not challenge
            or challenge.spent
            or challenge.challenge_type != ChallengeType.NAVIGATOR_ATTESTATION
        ):
            await _ws_send(send, {"type": "error", "reason": "invalid challenge"})
            await send({"type": "websocket.close", "code": 4001})
            return

        session = _Session(
            id=challenge_id,
            rounds=_split_rounds(_CATEGORIES, self.ROUND_COUNT),
        )
        await _ws_send(send, _next_msg(session))

        deadline = time.monotonic() + self.ROUND_TIMEOUT

        while True:
            if time.monotonic() > deadline:
                await send({"type": "websocket.close", "code": 4001})
                return

            msg = await receive()
            if msg["type"] == "websocket.disconnect":
                return
            if msg["type"] != "websocket.receive":
                continue

            try:
                data = json.loads(msg.get("text") or (msg.get("bytes") or b"").decode())
            except Exception:
                await _ws_send(send, {"type": "error", "reason": "invalid message"})
                await send({"type": "websocket.close", "code": 4003})
                return

            response = _process(session, data, challenge)
            await _ws_send(send, response)

            if response["type"] == "result":
                return
            if response["type"] == "error":
                await send({"type": "websocket.close", "code": 4002})
                return


async def _ws_send(send, data: dict) -> None:
    await send({"type": "websocket.send", "text": json.dumps(data)})
