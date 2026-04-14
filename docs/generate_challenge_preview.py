"""Generate docs/index-build.html with live challenge previews injected."""

import json
import re
import secrets
import time
from pathlib import Path

from flask_vouch.challenges import (
    SHA256,
    AudioCaptcha,
    ChallengeBase,
    ChallengeType,
    CharacterCaptcha,
    CircleCaptcha,
    CupCaptcha,
    ImageCaptcha,
    ImageGridCaptcha,
    NavigatorAttestation,
    RotationCaptcha,
    SHA256Balloon,
    SlidingCaptcha,
)
from flask_vouch.engine import Engine

SECRET = "preview-secret-key"
DIFFICULTY = 10
VERIFY_PATH = "/"
REDIRECT = "/"

FAKE_REQUEST = {
    "method": "GET",
    "path": "/",
    "query": "",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "remote_addr": "127.0.0.1",
    "headers": {},
    "cookies": {},
    "form": {},
}

# Element IDs that appear in multiple challenge templates and must be scoped.
SCOPE_IDS = ["status", "bar", "rounds"]

HANDLERS = [
    ("SHA-256 Balloon", "sha256-balloon", SHA256Balloon(), "sha256_balloon"),
    ("SHA-256 PoW", "sha256", SHA256(), "sha256"),
    ("Character CAPTCHA", "character-captcha", CharacterCaptcha(), "character_captcha"),
    ("Image CAPTCHA", "image-captcha", ImageCaptcha(), "image_captcha"),
    ("Rotation CAPTCHA", "rotation-captcha", RotationCaptcha(), "rotation_captcha"),
    ("Cup CAPTCHA", "cup-captcha", CupCaptcha(), "cup_captcha"),
    ("Sliding CAPTCHA", "sliding-captcha", SlidingCaptcha(), "sliding_captcha"),
    ("Circle CAPTCHA", "circle-captcha", CircleCaptcha(), "circle_captcha"),
    (
        "Image Grid CAPTCHA",
        "image-grid-captcha",
        ImageGridCaptcha(),
        "image_grid_captcha",
    ),
    ("Audio CAPTCHA", "audio-captcha", AudioCaptcha(), "audio_captcha"),
    (
        "Navigator Attestation",
        "navigator-attestation",
        NavigatorAttestation(),
        "navigator_attestation",
    ),
]


def make_challenge(handler) -> ChallengeBase:
    difficulty = handler.to_difficulty(DIFFICULTY)
    return ChallengeBase(
        id=secrets.token_urlsafe(24),
        random_data=handler.generate_random_data(difficulty),
        difficulty=difficulty,
        ip_hash="preview",
        created_at=time.time(),
        challenge_type=handler.challenge_type,
    )


def render_challenge_html(handler, challenge) -> str:
    payload = handler.render_payload(challenge, VERIFY_PATH, REDIRECT)
    payload["csrfToken"] = "preview-csrf-token"
    payload_json = json.dumps(payload)
    safe = (
        payload_json.replace("'", "\\u0027")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    html = (
        handler.template.replace("{{CHALLENGE_DATA}}", safe)
        .replace("{{BRANDING}}", "")
        .replace("{{ERROR}}", "")
        .replace("{{ACCENT_COLOR}}", "#b85c00")
    )
    for key, value in payload.items():
        html = html.replace(f"{{{{{key}}}}}", str(value))
    return html


def extract_body_and_scripts(full_html: str) -> tuple[str, str]:
    """Extract body content and scripts, remove redirects."""
    body_match = re.search(
        r"<body[^>]*>(.*?)</body>", full_html, re.DOTALL | re.IGNORECASE
    )
    body = body_match.group(1).strip() if body_match else full_html

    style_blocks = re.findall(
        r"<style[^>]*>.*?</style>", full_html, re.DOTALL | re.IGNORECASE
    )
    styles = "\n".join(style_blocks)

    styles = re.sub(r"body\s*\{[^}]*\}", "", styles, flags=re.DOTALL)

    return body, styles


def remove_reload_btn(body: str) -> str:
    """Strip reload/new-challenge buttons from preview panels."""
    body = re.sub(
        r'<(?:button|a)[^>]+class=["\'][^"\']*reload-btn[^"\']*["\'][^>]*>.*?</(?:button|a)>',
        "",
        body,
        flags=re.DOTALL | re.IGNORECASE,
    )
    return body


def scope_panel(slug: str, body: str) -> str:
    """Prefix shared element IDs with the panel slug to avoid cross-panel conflicts."""
    for eid in SCOPE_IDS:
        body = body.replace(f'id="{eid}"', f'id="{slug}-{eid}"')
        body = body.replace(
            f"getElementById('{eid}')", f"getElementById('{slug}-{eid}')"
        )
        body = body.replace(
            f'getElementById("{eid}")', f'getElementById("{slug}-{eid}")'
        )
    return body


def make_pow_restartable(slug: str, body: str) -> str:
    """Convert a PoW auto-running IIFE into a lazily-called, restartable init function.

    The converted function is stored as ``window.__vouchInits[slug]`` and called by
    ``showTab`` each time the panel becomes active, so workers restart on every visit.
    """
    if "var workerSrc" not in body:
        return body  # not a PoW challenge

    # Replace IIFE opening with a named init function stored globally.
    body = re.sub(
        r"\(function\s*\(\)\s*\{",
        (
            "window.__vouchInits = window.__vouchInits || {};\n"
            f"                window.__vouchInits['{slug}'] = function () {{"
        ),
        body,
        count=1,
    )
    # Remove the auto-invocation (the LAST })(); is the outer IIFE close).
    # count=1 would match the inner w.onmessage = (function(){...})(); instead.
    last = list(re.finditer(r"\}\)\(\);", body))[-1]
    body = body[: last.start()] + "};" + body[last.end() :]
    # Expose the workers array globally so showTab can terminate them on tab switch.
    body = body.replace(
        "var workers = [];",
        "var workers = []; window.__vouchCurrentWorkers = workers;",
    )
    return body


def build_challenge_section(
    rendered_challenges: list[tuple[str, str, str, str]],
) -> str:
    nav_items = "".join(
        f'<button class="tab-btn" data-tab="{slug}" onclick="showTab(\'{slug}\')">'
        f"{label}</button>"
        for label, slug, _, _ in rendered_challenges
    )

    panels = ""
    for i, (label, slug, body, styles) in enumerate(rendered_challenges):
        active = " active" if i == 0 else ""
        body = remove_reload_btn(body)
        body = scope_panel(slug, body)
        body = make_pow_restartable(slug, body)
        panels += f"""
<div class="tab-panel{active}" id="panel-{slug}">
    <style>{styles}</style>
    <div class="challenge-wrap">
        {body}
    </div>
</div>"""

    first_slug = rendered_challenges[0][1] if rendered_challenges else ""

    return f"""<div class="detector">
                    <div class="detector-header">
                        <span class="detector-title">Challenge Previews</span>
                    </div>
                    <div class="tabs" id="tabs">
                        {nav_items}
                    </div>
                    {panels}
                </div>
                <script>
                    function showTab(slug) {{
                        // Terminate any running PoW workers from the previous tab.
                        if (window.__vouchCurrentWorkers && window.__vouchCurrentWorkers.length) {{
                            window.__vouchCurrentWorkers.forEach(function(w) {{
                                try {{ w.terminate(); }} catch(e) {{}}
                            }});
                            window.__vouchCurrentWorkers = [];
                        }}
                        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
                        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                        const panel = document.getElementById('panel-' + slug);
                        if (panel) panel.classList.add('active');
                        document.querySelectorAll('.tab-btn[data-tab="' + slug + '"]').forEach(b => b.classList.add('active'));
                        // Restart the challenge if this panel has an init function (PoW panels).
                        if (window.__vouchInits && window.__vouchInits[slug]) {{
                            window.__vouchInits[slug]();
                        }}
                    }}
                    showTab('{first_slug}');
                </script>""".replace("f.submit();", "").replace("POST", "GET")


def main():
    rendered = []
    for label, slug, handler, template_name in HANDLERS:
        print(f"Rendering {label}...")
        try:
            challenge = make_challenge(handler)
            full_html = render_challenge_html(handler, challenge)
            body, styles = extract_body_and_scripts(full_html)
            rendered.append((label, slug, body, styles))
            print(f"  OK")
        except Exception as exc:
            print(f"  FAILED: {exc}")

    challenge_section = build_challenge_section(rendered)

    index_path = Path(__file__).parent / "index.html"
    index_html = index_path.read_text(encoding="utf-8")

    index_html = index_html.replace(
        "<!-- CHALLENGE_PREVIEWS_PLACEHOLDER -->", challenge_section
    )

    out = Path(__file__).parent / "index-build.html"
    out.write_text(index_html, encoding="utf-8")
    print(f"\nWritten to {out}")


if __name__ == "__main__":
    main()
