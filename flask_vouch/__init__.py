from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from flask_vouch.challenges import (
    SHA256,
    AudioCaptcha,
    ChainCaptcha,
    ChallengeHandler,
    ChallengeType,
    CharacterCaptcha,
    CircleCaptcha,
    CupCaptcha,
    ImageCaptcha,
    ImageGridCaptcha,
    NavigatorAttestation,
    QuirkProbe,
    RotationCaptcha,
    SHA256Balloon,
    SignedTokenHandler,
    SlidingCaptcha,
    ThirdPartyCaptchaChallenge,
    TraceCaptcha,
)
from flask_vouch.crawlers import (
    bot_operator,
    crawler_name,
    is_crawler,
    is_verified_bot,
    verify_operator,
)
from flask_vouch.engine import ChallengeError, Engine, EngineKwargs
from flask_vouch.extras.third_party_captcha import (
    AltchaCreds,
    ArkoseCreds,
    CaptchaCreds,
    CaptchaFoxCreds,
    GeeTestCreds,
    MTCaptchaCreds,
    ThirdPartyCaptcha,
)
from flask_vouch.netset import NetSet
from flask_vouch.policy import Policy, Request, Rule, load_policy
from flask_vouch.tokens import jwt_decode, jwt_encode
from flask_vouch.vouch import Vouch, VouchKwargs

try:
    __version__ = version("flask-Vouch")
except PackageNotFoundError:  # source checkout without an install
    __version__ = "0.0.0"

__all__ = [
    "Vouch",
    "VouchKwargs",
    "AudioCaptcha",
    "ChainCaptcha",
    "ChallengeError",
    "ChallengeHandler",
    "ChallengeType",
    "Engine",
    "EngineKwargs",
    "CharacterCaptcha",
    "CircleCaptcha",
    "ImageCaptcha",
    "ImageGridCaptcha",
    "RotationCaptcha",
    "NetSet",
    "NavigatorAttestation",
    "QuirkProbe",
    "Policy",
    "Request",
    "Rule",
    "SHA256",
    "SHA256Balloon",
    "SignedTokenHandler",
    "SlidingCaptcha",
    "ThirdPartyCaptchaChallenge",
    "TraceCaptcha",
    "CupCaptcha",
    "load_policy",
    "is_crawler",
    "crawler_name",
    "is_verified_bot",
    "verify_operator",
    "bot_operator",
    "jwt_encode",
    "jwt_decode",
    "ThirdPartyCaptcha",
    "CaptchaCreds",
    "AltchaCreds",
    "ArkoseCreds",
    "CaptchaFoxCreds",
    "GeeTestCreds",
    "MTCaptchaCreds",
    "__version__",
]
