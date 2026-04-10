import html
import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from flask_vouch.extras.third_party_captcha import (
    _ALTCHA_CDN,
    _JS_LOADER,
    _PROVIDERS,
    AltchaCreds,
    CaptchaCreds,
    _Altcha,
    _altcha_theme_js,
    _call_geetest_api,
    _call_provider_api,
)

from .base import DIFFICULTY_OFFSETS, ChallengeBase, ChallengeHandler, ChallengeType

_PROVIDER_CSP = {
    "recaptcha": (
        "script-src-elem 'unsafe-inline' https://www.google.com https://www.gstatic.com; "
        "frame-src https://www.google.com https://recaptcha.google.com"
    ),
    "hcaptcha": (
        "script-src-elem 'unsafe-inline' https://hcaptcha.com https://js.hcaptcha.com; "
        "frame-src https://hcaptcha.com https://newassets.hcaptcha.com"
    ),
    "turnstile": (
        "script-src-elem 'unsafe-inline' https://challenges.cloudflare.com; "
        "frame-src https://challenges.cloudflare.com"
    ),
    "friendly": "script-src-elem 'unsafe-inline' https://cdn.jsdelivr.net",
    "captchafox": "script-src-elem 'unsafe-inline' https://js.captchafox.com",
    "mtcaptcha": "script-src-elem 'unsafe-inline' https://service.mtcaptcha.com",
    "arkose": (
        "script-src-elem 'unsafe-inline' https://client-api.arkoselabs.com; "
        "frame-src https://client-api.arkoselabs.com"
    ),
    "geetest": "script-src-elem 'unsafe-inline' https://www.geetest.com",
    "altcha": "script-src-elem 'unsafe-inline' https://cdn.jsdelivr.net",
}


def _standard_embed(provider: str, site_key: str, language: str, theme: str) -> str:
    p = _PROVIDERS[provider]
    lang = f"?hl={language}" if language != "auto" else ""
    loader = _JS_LOADER.format(src=p["script"] + lang, extra="")
    return (
        f'<div id="{provider}Box" class="{p["class"]}"'
        f' data-sitekey="{site_key}" data-callback="_tbSubmit"'
        f' data-lang="{language}" data-theme="{theme}"></div>'
        f"<script>{loader}</script>"
    )


def _geetest_embed(site_key: str, language: str) -> str:
    return (
        '<div id="geetestBox"></div>'
        "<script>(function(){"
        'var t=document.createElement("script");'
        't.src="https://www.geetest.com/static/js/gt4.js";'
        "t.onload=function(){window.initGeetest4({"
        f'captchaId:"{site_key}",language:"{language}",'
        'product:"bind"},function(g){'
        'g.appendTo("#geetestBox");g.onSuccess(function(){'
        "var r=g.getValidate();"
        "_tbSubmit(JSON.stringify({lotNumber:r.lot_number,"
        "captchaOutput:r.captcha_output,passToken:r.pass_token,"
        "genTime:r.gen_time}));"
        "})})};document.head.appendChild(t)})();</script>"
    )


def _arkose_embed(site_key: str) -> str:
    src = f"https://client-api.arkoselabs.com/v2/{site_key}/api.js"
    return (
        '<div id="arkoselabsBox"></div>'
        f'<script data-callback="setupArkose" src="{src}" async defer></script>'
        "<script>function setupArkose(e){"
        'e.setConfig({selector:"#arkoselabsBox",'
        "onCompleted:function(r){_tbSubmit(r.token);}})"
        "}</script>"
    )


def _altcha_embed(altcha: _Altcha, hardness: int, theme: str) -> str:
    challenge = html.escape(json.dumps(altcha.create_challenge(hardness)))
    loader = _JS_LOADER.format(src=_ALTCHA_CDN, extra=',t.type="module"')
    return (
        '<altcha-widget id="tbAltcha" hidelogo'
        f' challengejson="{challenge}"></altcha-widget>'
        "<script>"
        "document.getElementById('tbAltcha').addEventListener('statechange',function(e)"
        "{if(e.detail&&e.detail.state==='verified'){_tbSubmit(e.detail.payload);}});"
        f"{_altcha_theme_js(theme)}{loader}"
        "</script>"
    )


@dataclass
class ThirdPartyCaptchaChallenge(ChallengeHandler):
    provider: str
    creds: CaptchaCreds | AltchaCreds
    language: str = "auto"
    theme: str = "auto"

    def __post_init__(self):
        if self.provider == "altcha" and isinstance(self.creds, AltchaCreds):
            self._altcha: _Altcha | None = _Altcha(self.creds.secret_key.encode())
        else:
            self._altcha = None

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.THIRD_PARTY_CAPTCHA

    def to_difficulty(self, base: int) -> int:
        return base + DIFFICULTY_OFFSETS[self.challenge_type]

    @property
    def template(self) -> str:
        return (
            Path(__file__).parent / "templates" / "third_party_captcha.html"
        ).read_text()

    def generate_random_data(self, difficulty: int = 0) -> str:
        return secrets.token_hex(32)

    @property
    def retry_on_failure(self) -> bool:
        return True

    @property
    def extra_csp(self) -> str:
        return _PROVIDER_CSP.get(self.provider, "")

    def nonce_from_form(self, raw: str) -> str:
        return raw.strip()

    def verify(self, random_data: str, nonce: int | str, difficulty: int) -> bool:
        token = str(nonce).strip()
        if not token:
            return False
        if self.provider == "altcha" and self._altcha:
            return self._altcha.verify_challenge(token)
        if not isinstance(self.creds, CaptchaCreds) or not self.creds.secret_key:
            return False
        if self.provider == "geetest":
            try:
                data = json.loads(token)
                return _call_geetest_api(
                    self.creds.site_key,
                    self.creds.secret_key,
                    data["lotNumber"],
                    data["captchaOutput"],
                    data["passToken"],
                    data["genTime"],
                )
            except (json.JSONDecodeError, KeyError):
                return False
        if self.provider not in _PROVIDERS:
            return False
        return _call_provider_api(self.provider, token, self.creds.secret_key)

    def _build_embed(self) -> str:
        if self.provider == "altcha" and self._altcha:
            return _altcha_embed(self._altcha, 2, self.theme)
        if not isinstance(self.creds, CaptchaCreds):
            return ""
        if self.provider == "geetest":
            return _geetest_embed(self.creds.site_key, self.language)
        if self.provider == "arkose":
            return _arkose_embed(self.creds.site_key)
        return _standard_embed(
            self.provider, self.creds.site_key, self.language, self.theme
        )

    def render_payload(
        self,
        challenge: ChallengeBase,
        verify_path: str,
        redirect: str,
    ) -> dict:
        return {
            "id": challenge.id,
            "verifyPath": verify_path,
            "redirect": redirect,
            "captchaEmbed": self._build_embed(),
        }
