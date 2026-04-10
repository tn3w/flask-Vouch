import hashlib
import hmac
import html
import json
import urllib.parse
import urllib.request
from base64 import b64decode
from dataclasses import dataclass
from secrets import randbelow, token_hex


class _Safe(str):
    def __html__(self):
        return self


@dataclass
class CaptchaCreds:
    site_key: str
    secret_key: str | None = None


ReCaptchaCreds = CaptchaCreds
HCaptchaCreds = CaptchaCreds
TurnstileCreds = CaptchaCreds
FriendlyCaptchaCreds = CaptchaCreds
CaptchaFoxCreds = CaptchaCreds
MTCaptchaCreds = CaptchaCreds
ArkoseCreds = CaptchaCreds
GeeTestCreds = CaptchaCreds


@dataclass
class AltchaCreds:
    secret_key: str


_PROVIDERS = {
    "recaptcha": {
        "class": "g-recaptcha",
        "script": "https://www.google.com/recaptcha/api.js",
        "api": "https://www.google.com/recaptcha/api/siteverify",
        "field": "response",
    },
    "hcaptcha": {
        "class": "h-captcha",
        "script": "https://hcaptcha.com/1/api.js",
        "api": "https://hcaptcha.com/siteverify",
        "field": "response",
    },
    "turnstile": {
        "class": "cf-turnstile",
        "script": "https://challenges.cloudflare.com/turnstile/v0/api.js",
        "api": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        "field": "response",
    },
    "friendly": {
        "class": "frc-captcha",
        "script": (
            "https://cdn.jsdelivr.net/npm/friendly-challenge/widget.module.min.js"
        ),
        "api": "https://api.friendlycaptcha.com/api/v1/siteverify",
        "field": "solution",
    },
    "captchafox": {
        "class": "captchafox-widget",
        "script": "https://js.captchafox.com/captchafox.js",
        "api": "https://api.captchafox.com/siteverify",
        "field": "response",
        "form_key": "cf-captcha-response",
    },
    "mtcaptcha": {
        "class": "mtcaptcha",
        "script": "https://service.mtcaptcha.com/mtcv1/client/mtcaptcha.min.js",
        "api": "https://service.mtcaptcha.com/mtcv1/api/checktoken",
        "field": "mtcaptchaToken",
        "form_key": "mtcaptchaToken",
        "secret_param": "privatekey",
        "token_param": "mtcaptchatoken",
        "http_method": "GET",
    },
    "arkose": {
        "class": "fc-widget",
        "api": "https://api.arkoselabs.com/fc/v/siteverify",
        "field": "session_token",
        "form_key": "fc-token",
        "secret_param": "private_key",
        "token_param": "session_token",
        "response_key": "solved",
    },
}

_GEETEST_FIELDS = [
    "geetest_lotNumber",
    "geetest_captchaOutput",
    "geetest_passToken",
    "geetest_genTime",
]

_JS_LOADER = (
    '(function(){{const t=document.createElement("script");'
    't.src="{src}",t.async=!0,t.defer=!0{extra},'
    "document.head.appendChild(t)}})();"
)

_ALTCHA_CDN = "https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js"


def _altcha_theme_js(theme: str) -> str:
    light = (
        "--altcha-color-base:#f2f2f2;--altcha-color-text:#181818;"
        "--altcha-color-border:rgba(0,0,0,.5);"
        "--altcha-color-border-focus:rgba(0,0,0,.5);"
        "--altcha-color-footer-bg:#f2f2f2"
    )
    dark = (
        "--altcha-color-base:#121212;--altcha-color-text:#f2f2f2;"
        "--altcha-color-border:rgba(255,255,255,.1);"
        "--altcha-color-border-focus:rgba(255,255,255,.1);"
        "--altcha-color-footer-bg:#121212"
    )
    return (
        f'function c(t){{const e="altcha-theme-styles";'
        f"let a=document.getElementById(e);a&&a.remove();"
        f'const s=document.createElement("style");s.id=e;'
        f"const l=':root{{{light}}}',o=':root{{{dark}}}',"
        f"r=':root{{{light}}}@media (prefers-color-scheme:dark)"
        f"{{:root{{{dark}}}}}';"
        f's.textContent="dark"===t?o:"light"===t?l:r;'
        f"document.head.appendChild(s)}}"
        f'"{theme}"==="auto"?c("auto"):c("{theme}");'
    )


class _Altcha:
    def __init__(self, secret: bytes):
        self.secret = secret

    def create_challenge(self, hardness=1) -> dict:
        salt = token_hex(12)
        number = 10000 * hardness + randbelow(15000 * hardness + 1)
        challenge = hashlib.sha256((salt + str(number)).encode()).hexdigest()
        signature = hmac.new(
            self.secret, challenge.encode(), hashlib.sha256
        ).hexdigest()
        return {
            "algorithm": "SHA-256",
            "challenge": challenge,
            "salt": salt,
            "signature": signature,
        }

    def verify_challenge(self, payload: str) -> bool:
        try:
            data = json.loads(b64decode(payload))
            challenge = hashlib.sha256(
                (data["salt"] + str(data["number"])).encode()
            ).hexdigest()
            signature = hmac.new(
                self.secret, data["challenge"].encode(), hashlib.sha256
            ).hexdigest()
            return (
                data["algorithm"] == "SHA-256"
                and challenge == data["challenge"]
                and signature == data["signature"]
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return False


def _call_provider_api(provider: str, token: str, secret: str) -> bool:
    p = _PROVIDERS[provider]
    field = p["field"]
    params = {
        p.get("secret_param", "secret"): secret,
        p.get("token_param", field): token,
    }
    key = p.get("response_key", "success")
    try:
        if p.get("http_method") == "GET":
            url = p["api"] + "?" + urllib.parse.urlencode(params)
            req = urllib.request.Request(url)
        else:
            req = urllib.request.Request(
                p["api"], data=urllib.parse.urlencode(params).encode()
            )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read()).get(key, False)
    except Exception:
        return False


def _call_geetest_api(
    site_key: str,
    secret: str,
    lot_number: str,
    captcha_output: str,
    pass_token: str,
    gen_time: str,
) -> bool:
    sign = hmac.new(secret.encode(), lot_number.encode(), hashlib.sha256).hexdigest()
    params = urllib.parse.urlencode(
        {
            "lot_number": lot_number,
            "captcha_output": captcha_output,
            "pass_token": pass_token,
            "gen_time": gen_time,
            "sign_token": sign,
        }
    ).encode()
    url = f"https://gcaptcha4.geetest.com/validate?captcha_id={site_key}"
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, data=params), timeout=3
        ) as resp:
            return json.loads(resp.read()).get("result") == "success"
    except Exception:
        return False


class ThirdPartyCaptcha:
    def __init__(self, language="auto", theme="auto", altcha_secret=None, **kwargs):
        self.language = language
        self.theme = theme
        self.kwargs = kwargs
        self.altcha = _Altcha(altcha_secret.encode()) if altcha_secret else None

    def init_flask(self, app):
        @app.context_processor
        def _():
            return self.get_context()

    def get_context(self) -> dict:
        embeds = {}
        if self.altcha:
            embeds["altcha"] = _Safe(self.get_embed("altcha"))
            for hardness in range(1, 6):
                embeds[f"altcha{hardness}"] = _Safe(
                    self.get_embed("altcha", hardness=hardness)
                )
        for provider in [*_PROVIDERS, "geetest"]:
            if site_key := self.kwargs.get(f"{provider}_site_key"):
                embeds[provider] = _Safe(self.get_embed(provider, site_key=site_key))
        return embeds

    def get_embed(self, captcha_type: str, hardness=2, site_key=None) -> str:
        if captcha_type == "altcha":
            return self._altcha_embed(hardness)
        site_key = site_key or self.kwargs.get(f"{captcha_type}_site_key")
        if not site_key:
            raise ValueError(f"No site key for: {captcha_type}")
        if captcha_type == "geetest":
            return self._geetest_embed(site_key)
        if captcha_type == "arkose":
            return self._arkose_embed(site_key)
        return self._standard_embed(captcha_type, site_key)

    def _standard_embed(self, captcha_type: str, site_key: str) -> str:
        if captcha_type not in _PROVIDERS:
            raise ValueError(f"Unsupported CAPTCHA: {captcha_type}")
        provider = _PROVIDERS[captcha_type]
        lang = f"?hl={self.language}" if self.language != "auto" else ""
        loader = _JS_LOADER.format(src=provider["script"] + lang, extra="")
        return (
            f'<div id="{captcha_type}Box" class="{provider["class"]}"'
            f' data-sitekey="{site_key}" data-lang="{self.language}"'
            f' data-theme="{self.theme}"></div>'
            f"<script>{loader}</script>"
        )

    def _geetest_embed(self, site_key: str) -> str:
        fields = "".join(f'<input type="hidden" name="{f}"/>' for f in _GEETEST_FIELDS)
        set_field = (
            "var s=function(n,v)" '{document.querySelector("[name="+n+"]").value=v;};'
        )
        return (
            f'<div id="geetestBox"></div>{fields}'
            "<script>(function(){"
            'var t=document.createElement("script");'
            't.src="https://www.geetest.com/static/js/gt4.js";'
            "t.onload=function(){window.initGeetest4({"
            f'captchaId:"{site_key}",language:"{self.language}",'
            'product:"bind"},function(g){'
            'g.appendTo("#geetestBox");g.onSuccess(function(){'
            f"var r=g.getValidate();{set_field}"
            "s('geetest_lotNumber',r.lot_number);"
            "s('geetest_captchaOutput',r.captcha_output);"
            "s('geetest_passToken',r.pass_token);"
            "s('geetest_genTime',r.gen_time);"
            "})})};document.head.appendChild(t)})();</script>"
        )

    def _arkose_embed(self, site_key: str) -> str:
        src = f"https://client-api.arkoselabs.com/v2/{site_key}/api.js"
        return (
            '<div id="arkoselabsBox"></div>'
            '<input type="hidden" name="fc-token"/>'
            f'<script data-callback="setupArkose" src="{src}"'
            " async defer></script>"
            "<script>function setupArkose(e){"
            'e.setConfig({selector:"#arkoselabsBox",'
            "onCompleted:function(r){"
            "document.querySelector(\"[name='fc-token']\").value=r.token;"
            "}})}</script>"
        )

    def _altcha_embed(self, hardness: int) -> str:
        if not self.altcha:
            raise ValueError("altcha_secret not provided")
        challenge = html.escape(json.dumps(self.altcha.create_challenge(hardness)))
        strings = html.escape(json.dumps({}))
        loader = _JS_LOADER.format(src=_ALTCHA_CDN, extra=',t.type="module"')
        return (
            '<altcha-widget style="font-family:Segoe UI,Arial,sans-serif"'
            f' hidelogo challengejson="{challenge}" strings="{strings}">'
            f"</altcha-widget>"
            f"<script>{_altcha_theme_js(self.theme)}{loader}</script>"
        )

    def _verify_http(self, captcha_type: str, token: str) -> bool:
        secret = self.kwargs.get(f"{captcha_type}_secret")
        if not secret:
            return False
        return _call_provider_api(captcha_type, token, secret)

    def _verify_geetest_http(
        self,
        site_key: str,
        secret: str,
        lot_number: str,
        captcha_output: str,
        pass_token: str,
        gen_time: str,
    ) -> bool:
        return _call_geetest_api(
            site_key, secret, lot_number, captcha_output, pass_token, gen_time
        )

    def _get_token(self, form_key: str) -> str | None:
        from flask import request as r

        src = r.form if r.method == "POST" else r.args
        return src.get(form_key)

    def _validate(self, captcha_type: str) -> bool:
        provider = _PROVIDERS[captcha_type]
        form_key = (
            provider.get("form_key") or f'{provider["class"]}-{provider["field"]}'
        )
        token = self._get_token(form_key)
        if not isinstance(token, str) or not token:
            return False
        return self._verify_http(captcha_type, token)

    def is_recaptcha_valid(self) -> bool:
        return self._validate("recaptcha")

    def is_hcaptcha_valid(self) -> bool:
        return self._validate("hcaptcha")

    def is_turnstile_valid(self) -> bool:
        return self._validate("turnstile")

    def is_friendly_valid(self) -> bool:
        return self._validate("friendly")

    def is_captchafox_valid(self) -> bool:
        return self._validate("captchafox")

    def is_mtcaptcha_valid(self) -> bool:
        return self._validate("mtcaptcha")

    def is_arkose_valid(self) -> bool:
        return self._validate("arkose")

    def is_geetest_valid(self) -> bool:
        site_key = self.kwargs.get("geetest_site_key")
        secret = self.kwargs.get("geetest_secret")
        if not site_key or not secret:
            return False
        lot, output, token, gentime = (self._get_token(f) for f in _GEETEST_FIELDS)
        if not (lot and output and token and gentime):
            return False
        return self._verify_geetest_http(site_key, secret, lot, output, token, gentime)

    def is_altcha_valid(self) -> bool:
        if not self.altcha:
            return False
        token = self._get_token("altcha")
        return isinstance(token, str) and self.altcha.verify_challenge(token)
