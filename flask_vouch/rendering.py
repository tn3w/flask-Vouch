from __future__ import annotations

import html
import json
from functools import lru_cache
from pathlib import Path

from flask_vouch.challenges import ChallengeBase, ChallengeHandler
from flask_vouch.challenges.base import TEMPLATES_DIR

BRANDING_HTML = (
    '<div class="branding">'
    "Protected by "
    '<a href="https://github.com/tn3w/flask-Vouch" target="_blank">flask-Vouch</a>'
    " · "
    '<a href="https://github.com/tn3w" target="_blank">tn3w</a>'
    "</div>"
)

RETRY_ERROR_HTML = '<p class="error">Incorrect, try again.</p>'

_BASE_CSP = (
    "default-src 'none'; "
    "script-src 'unsafe-inline'; "
    "worker-src blob:; "
    "style-src 'unsafe-inline'; "
    "img-src data: 'self'; "
    "connect-src 'self'"
)

_BASE_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def challenge_headers(handler: ChallengeHandler) -> dict[str, str]:
    extra = handler.extra_csp
    csp = f"{_BASE_CSP}; {extra}" if extra else _BASE_CSP
    return {**_BASE_HEADERS, "Content-Security-Policy": csp}


def safe_redirect(redirect: str) -> str:
    unsafe = (
        not redirect.startswith("/")
        or redirect.startswith("//")
        or redirect.startswith("/\\")
        or "\n" in redirect
        or "\r" in redirect
    )
    return "/" if unsafe else redirect


@lru_cache(maxsize=64)
def _read_template(path: str) -> str:
    return Path(path).read_text()


def template_name(handler: ChallengeHandler) -> str:
    return f"{handler.challenge_type.value.replace('-', '_')}.html"


def resolve_template(
    handler: ChallengeHandler,
    template_dir: str | Path | None = None,
) -> str:
    """Handler template wins, then ``template_dir``, then the bundled page."""
    if isinstance(handler.template, Path):
        return _read_template(str(handler.template))
    if handler.template is not None:
        return handler.template

    name = template_name(handler)
    if template_dir:
        override = Path(template_dir) / name
        if override.exists():
            return _read_template(str(override))

    return _read_template(str(TEMPLATES_DIR / name))


def _escape_payload(payload: dict) -> str:
    return (
        json.dumps(payload)
        .replace("'", "\\u0027")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def render_challenge(
    handler: ChallengeHandler,
    challenge: ChallengeBase,
    verify_path: str,
    redirect: str,
    accent_color: str,
    branding: bool = True,
    error: str = "",
    template_dir: str | Path | None = None,
) -> str:
    payload = handler.render_payload(challenge, verify_path, redirect)

    page = resolve_template(handler, template_dir)
    page = (
        page.replace("{{CHALLENGE_DATA}}", _escape_payload(payload))
        .replace("{{BRANDING}}", BRANDING_HTML if branding else "")
        .replace("{{ERROR}}", error)
        .replace("{{ACCENT_COLOR}}", accent_color)
    )

    for key, value in payload.items():
        raw = key == "captchaEmbed"
        page = page.replace(
            f"{{{{{key}}}}}", str(value) if raw else html.escape(str(value))
        )

    return page
