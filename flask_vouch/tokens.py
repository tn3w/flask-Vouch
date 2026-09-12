from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (4 - len(value) % 4))


JWT_HEADER = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')


def jwt_encode(claims: dict, secret: bytes) -> str:
    payload = b64url_encode(json.dumps(claims).encode())
    signing_input = f"{JWT_HEADER}.{payload}"
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(signature)}"


def jwt_decode(token: str, secret: bytes) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid token")

    if parts[0] != JWT_HEADER:
        raise ValueError("unsupported algorithm")

    signing_input = f"{parts[0]}.{parts[1]}"
    expected = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64url_decode(parts[2])):
        raise ValueError("invalid signature")

    claims = json.loads(b64url_decode(parts[1]))
    if claims.get("exp", 0) < time.time():
        raise ValueError("token expired")

    return claims
