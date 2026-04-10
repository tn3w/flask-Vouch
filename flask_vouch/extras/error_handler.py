import re
from pathlib import Path

_DEFAULT_ACCENT = "#44ff88"

_DEFAULT_TEMPLATE = (Path(__file__).parent / "templates" / "error.html").read_text()

ERROR_CODES: dict[int, dict[str, str]] = {
    400: {
        "title": "Bad Request",
        "description": "The server could not understand the request due to invalid syntax.",
    },
    401: {
        "title": "Unauthorized",
        "description": "You must authenticate yourself to get the requested response.",
    },
    403: {
        "title": "Forbidden",
        "description": "You do not have access rights to the content.",
    },
    404: {
        "title": "Not Found",
        "description": "The server cannot find the requested resource.",
    },
    405: {
        "title": "Method Not Allowed",
        "description": "The request method is known by the server but is not supported by the target resource.",
    },
    406: {
        "title": "Not Acceptable",
        "description": "The server cannot produce a response matching the acceptable values defined in your request headers.",
    },
    408: {
        "title": "Request Timeout",
        "description": "The server did not receive a complete request within the time it was prepared to wait.",
    },
    409: {
        "title": "Conflict",
        "description": "The request could not be completed due to a conflict with the current state of the target resource.",
    },
    410: {
        "title": "Gone",
        "description": "The requested resource is no longer available and will not be available again.",
    },
    411: {
        "title": "Length Required",
        "description": "The server refuses to accept the request without a defined Content-Length header.",
    },
    412: {
        "title": "Precondition Failed",
        "description": "The server does not meet one of the preconditions in your request header fields.",
    },
    413: {
        "title": "Payload Too Large",
        "description": "The request entity is larger than limits defined by the server.",
    },
    414: {
        "title": "URI Too Long",
        "description": "The URI requested is longer than the server is willing to interpret.",
    },
    415: {
        "title": "Unsupported Media Type",
        "description": "The media format of the requested data is not supported by the server.",
    },
    416: {
        "title": "Range Not Satisfiable",
        "description": "The range specified by the Range header field in the request cannot be fulfilled.",
    },
    417: {
        "title": "Expectation Failed",
        "description": "The expectation given in the request Expect header could not be met by the server.",
    },
    418: {
        "title": "I'm a Teapot",
        "description": "The server refuses to brew coffee because it is a teapot.",
    },
    422: {
        "title": "Unprocessable Entity",
        "description": "The request was well-formed but could not be followed due to semantic errors.",
    },
    423: {
        "title": "Locked",
        "description": "The resource that is being accessed is locked.",
    },
    424: {
        "title": "Failed Dependency",
        "description": "The request failed due to failure of a previous request.",
    },
    428: {
        "title": "Precondition Required",
        "description": "The origin server requires the request to be conditional.",
    },
    429: {
        "title": "Too Many Requests",
        "description": "You have sent too many requests in a given amount of time.",
    },
    431: {
        "title": "Request Header Fields Too Large",
        "description": "The server is unwilling to process the request because its header fields are too large.",
    },
    451: {
        "title": "Unavailable For Legal Reasons",
        "description": "The server is denying access to the resource as a consequence of a legal demand.",
    },
    500: {
        "title": "Internal Server Error",
        "description": "The server encountered a situation it does not know how to handle.",
    },
    501: {
        "title": "Not Implemented",
        "description": "The request method is not supported by the server and cannot be handled.",
    },
    502: {
        "title": "Bad Gateway",
        "description": "The server, acting as a gateway or proxy, received an invalid response from the upstream server.",
    },
    503: {
        "title": "Service Unavailable",
        "description": "The server is not ready to handle the request.",
    },
    504: {
        "title": "Gateway Timeout",
        "description": "The server, acting as a gateway or proxy, did not receive a timely response from the upstream server.",
    },
    505: {
        "title": "HTTP Version Not Supported",
        "description": "The HTTP version used in the request is not supported by the server.",
    },
}


def _render(
    code: int,
    template: str,
    templates: dict[int, str],
    overrides: dict[int, dict],
    accent_color: str,
    **extra,
) -> str:
    info = overrides.get(code, ERROR_CODES.get(code, {}))
    tmpl = templates.get(code, template)
    ctx = {
        "status_code": str(code),
        "title": info.get("title", "Error"),
        "description": info.get("description", "An error occurred."),
        "ACCENT_COLOR": accent_color,
        **extra,
    }
    return re.sub(r"\{\{(\w+)\}\}", lambda m: ctx.get(m.group(1), m.group(0)), tmpl)


class ErrorHandler:
    """Flask HTTP error handler with template rendering.

    Renders HTML error pages for HTTP error codes using a customizable template.
    Template variables use ``{{key}}`` syntax: ``{{status_code}}``, ``{{title}}``,
    ``{{description}}``, ``{{ACCENT_COLOR}}``, plus any extra kwargs to ``render()``.

    Usage::

        eh = ErrorHandler()
        eh.init_flask(app)

    Inherit accent color from a Vouch instance::

        eh = ErrorHandler(bouncer=bouncer)

    Custom accent color::

        eh = ErrorHandler(accent_color="#ff6600")

    Custom global template::

        eh = ErrorHandler(template="<h1>{{status_code}} {{title}}</h1>")
        eh = ErrorHandler(template=Path("templates/error.html"))

    Per-status template::

        eh = ErrorHandler(templates={404: Path("templates/404.html")})

    Override messages::

        eh = ErrorHandler(overrides={404: {"title": "Oops", "description": "..."}})

    Limit which codes are handled::

        eh = ErrorHandler(codes={404, 500})
    """

    def __init__(
        self,
        template: str | Path = _DEFAULT_TEMPLATE,
        templates: dict[int, str | Path] | None = None,
        overrides: dict[int, dict] | None = None,
        codes: set[int] | None = None,
        accent_color: str | None = None,
        bouncer=None,
    ):
        self._template = (
            template.read_text() if isinstance(template, Path) else template
        )
        self._templates = {
            k: v.read_text() if isinstance(v, Path) else v
            for k, v in (templates or {}).items()
        }
        self._overrides = overrides or {}
        self._codes = codes if codes is not None else set(ERROR_CODES)
        self._accent_color = accent_color or (
            bouncer.engine.policy.accent_color if bouncer else None
        )

    def _accent(self, flask_app=None) -> str:
        if self._accent_color:
            return self._accent_color
        if flask_app is not None:
            tb = flask_app.extensions.get("bouncer")
            if tb and hasattr(tb, "engine"):
                return tb.engine.policy.accent_color
        return _DEFAULT_ACCENT

    def render(self, code: int, **extra) -> str:
        return _render(
            code,
            self._template,
            self._templates,
            self._overrides,
            self._accent_color or _DEFAULT_ACCENT,
            **extra,
        )

    def init_flask(self, app):
        accent = self._accent(app)
        tmpl, tmpls, ovrs = self._template, self._templates, self._overrides

        def handler(exc):
            code = getattr(exc, "code", 500)
            if not isinstance(code, int):
                code = 500
            body = _render(code, tmpl, tmpls, ovrs, accent)
            return body, code, {"Content-Type": "text/html; charset=utf-8"}

        for code in self._codes:
            app.register_error_handler(code, handler)
