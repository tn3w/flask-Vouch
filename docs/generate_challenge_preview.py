"""Build docs/index-build.html with a live preview of every challenge page."""

import re
import secrets
import time
from pathlib import Path

from flask_vouch.challenges import (
    SHA256,
    AudioCaptcha,
    ChainCaptcha,
    ChallengeBase,
    ChallengeHandler,
    CharacterCaptcha,
    CircleCaptcha,
    CupCaptcha,
    ImageCaptcha,
    ImageGridCaptcha,
    NavigatorAttestation,
    QuirkProbe,
    RotationCaptcha,
    SHA256Balloon,
    SlidingCaptcha,
    TraceCaptcha,
)
from flask_vouch.rendering import render_challenge

DIFFICULTY = 10
ACCENT_COLOR = "#b85c00"
VERIFY_PATH = "/"
REDIRECT = "/"

DOCS_DIR = Path(__file__).parent
PLACEHOLDER = "<!-- CHALLENGE_PREVIEWS_PLACEHOLDER -->"

HANDLERS: list[ChallengeHandler] = [
    SHA256Balloon(),
    SHA256(),
    ChainCaptcha(),
    CharacterCaptcha(),
    ImageCaptcha(),
    RotationCaptcha(),
    CupCaptcha(),
    SlidingCaptcha(),
    CircleCaptcha(),
    TraceCaptcha(),
    ImageGridCaptcha(),
    AudioCaptcha(),
    NavigatorAttestation(),
    QuirkProbe(),
]

LABELS = {
    "sha256-balloon": "SHA-256 Balloon",
    "sha256": "SHA-256 PoW",
    "navigator-attestation": "Navigator Attestation",
    "quirk-probe": "Quirk Probe",
}


def label_of(slug: str) -> str:
    return LABELS.get(
        slug, slug.replace("-", " ").title().replace("Captcha", "CAPTCHA")
    )


def make_challenge(handler: ChallengeHandler) -> ChallengeBase:
    difficulty = handler.to_difficulty(DIFFICULTY)
    return ChallengeBase(
        id=secrets.token_urlsafe(24),
        random_data=handler.generate_random_data(difficulty),
        difficulty=difficulty,
        ip_hash="preview",
        created_at=time.time(),
        challenge_type=handler.challenge_type,
    )


def render(handler: ChallengeHandler) -> str:
    return render_challenge(
        handler,
        make_challenge(handler),
        VERIFY_PATH,
        REDIRECT,
        accent_color=ACCENT_COLOR,
        branding=False,
    )


def split_body_and_styles(page: str) -> tuple[str, str]:
    body = re.search(r"<body[^>]*>(.*?)</body>", page, re.DOTALL | re.IGNORECASE)
    styles = "\n".join(
        re.findall(r"<style[^>]*>.*?</style>", page, re.DOTALL | re.IGNORECASE)
    )
    return (
        body.group(1).strip() if body else page,
        re.sub(r"body\s*\{[^}]*\}", "", styles, flags=re.DOTALL),
    )


def drop_reload_button(body: str) -> str:
    pattern = (
        r'<(?:button|a)[^>]+class=["\'][^"\']*reload-btn[^"\']*["\'][^>]*>'
        r".*?</(?:button|a)>"
    )
    return re.sub(pattern, "", body, flags=re.DOTALL | re.IGNORECASE)


def scope_ids(slug: str, body: str, styles: str) -> tuple[str, str]:
    """Prefix every element id with the panel slug.

    All panels live in one document, and several challenge pages reuse ids like
    ``status`` or ``sheet-a``, so both the markup and anything pointing at it -
    ``getElementById`` calls and ``#id`` style rules - are rewritten per panel.
    """
    names = set(re.findall(r'id="([A-Za-z][\w-]*)"', body))

    for name in sorted(names, key=len, reverse=True):
        scoped = f"{slug}-{name}"
        body = body.replace(f'id="{name}"', f'id="{scoped}"')
        for quote in ("'", '"'):
            body = body.replace(
                f"getElementById({quote}{name}{quote})",
                f"getElementById({quote}{scoped}{quote})",
            )
        styles = re.sub(rf"#{re.escape(name)}(?![\w-])", f"#{scoped}", styles)

    return body, styles


def make_restartable(slug: str, body: str) -> str:
    """Turn a proof-of-work page's auto-running IIFE into a function the tabs can call.

    The panel is hidden until its tab is opened, so the workers have to start then
    instead of on load; ``showTab`` looks the function up in ``window.__vouchInits``.
    Raises if the page no longer matches the shape this rewrite expects.
    """
    if "var workerSrc" not in body:
        return body

    opener = re.search(r"\(function\s*\(\)\s*\{", body)
    closings = list(re.finditer(r"\}\)\(\);", body))
    if not opener or not closings or "var workers = [];" not in body:
        raise RuntimeError(f"{slug}: proof-of-work page no longer matches the rewrite")

    # The first opener and the last `})();` are the outer IIFE; inner ones are handlers.
    closing = closings[-1]
    body = (
        body[: opener.start()]
        + "window.__vouchInits = window.__vouchInits || {};\n"
        + f"                window.__vouchInits['{slug}'] = function () {{"
        + body[opener.end() : closing.start()]
        + "};"
        + body[closing.end() :]
    )
    return body.replace(
        "var workers = [];",
        "var workers = []; window.__vouchCurrentWorkers = workers;",
    )


def build_panel(index: int, slug: str, page: str) -> str:
    body, styles = split_body_and_styles(page)
    body, styles = scope_ids(slug, drop_reload_button(body), styles)
    body = make_restartable(slug, body)
    active = " active" if index == 0 else ""
    return f"""
<div class="tab-panel{active}" id="panel-{slug}">
    <style>{styles}</style>
    <div class="challenge-wrap">
        {body}
    </div>
</div>"""


def build_section(previews: list[tuple[str, str]]) -> str:
    tabs = "".join(
        f'<button class="tab-btn" data-tab="{slug}" onclick="showTab(\'{slug}\')">'
        f"{label_of(slug)}</button>"
        for slug, _ in previews
    )
    panels = "".join(
        build_panel(index, slug, page) for index, (slug, page) in enumerate(previews)
    )
    first = previews[0][0] if previews else ""

    section = f"""<div class="detector">
                    <div class="detector-header">
                        <span class="detector-title">Challenge Previews</span>
                    </div>
                    <div class="tabs" id="tabs">
                        {tabs}
                    </div>
                    {panels}
                </div>
                <script>
                    function showTab(slug) {{
                        var running = window.__vouchCurrentWorkers || [];
                        running.forEach(function (w) {{
                            try {{ w.terminate(); }} catch (e) {{}}
                        }});
                        window.__vouchCurrentWorkers = [];
                        document.querySelectorAll('.tab-panel').forEach(function (p) {{
                            p.classList.remove('active');
                        }});
                        document.querySelectorAll('.tab-btn').forEach(function (b) {{
                            b.classList.remove('active');
                        }});
                        var panel = document.getElementById('panel-' + slug);
                        if (panel) panel.classList.add('active');
                        var selector = '.tab-btn[data-tab="' + slug + '"]';
                        document.querySelectorAll(selector).forEach(function (b) {{
                            b.classList.add('active');
                        }});
                        var init = (window.__vouchInits || {{}})[slug];
                        if (init) init();
                    }}
                    showTab('{first}');
                </script>"""

    return section.replace("f.submit();", "").replace("POST", "GET")


def main() -> None:
    previews = []
    for handler in HANDLERS:
        slug = handler.challenge_type.value
        try:
            previews.append((slug, render(handler)))
            print(f"rendered {label_of(slug)}")
        except Exception as error:
            print(f"skipped {label_of(slug)}: {error}")

    index = (DOCS_DIR / "index.html").read_text(encoding="utf-8")
    out = DOCS_DIR / "index-build.html"
    out.write_text(
        index.replace(PLACEHOLDER, build_section(previews)), encoding="utf-8"
    )
    print(f"written {out}")


if __name__ == "__main__":
    main()
