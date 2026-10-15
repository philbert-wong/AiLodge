"""Scoped agent tokens, signed with HMAC-SHA256.

Format:  lsh_<base64url(claims JSON)>.<base64url(HMAC-SHA256(claims))>

The claims (who, how long, how many calls, how much money) are readable,
but they cannot be changed: altering a single character breaks the
signature, and only this server holds the signing key. The same idea
underlies JSON Web Tokens.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

from . import config

PREFIX = "lsh_"


class TokenError(Exception):
    def __init__(self, code: str, message: str, claims=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.claims = claims  # set only when the signature was valid (e.g. expired)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(body: str) -> str:
    return _b64e(hmac.new(config.TOKEN_KEY, body.encode(), hashlib.sha256).digest())


def mint(space: str, agent: str, upstream: str, ttl_minutes: int, max_calls: int, budget_usd: float,
         jti: str | None = None, unlock: str | None = None) -> tuple[str, dict]:
    """`unlock` is a secret that only this pass carries: for a workspace's saved
    key, it is what unlocks the key. Leash never stores the pass itself."""
    now = int(time.time())
    claims = {
        "jti": jti or secrets.token_hex(8),
        "space": space,
        "agent": agent,
        "upstream": upstream,
        "iat": now,
        "exp": now + ttl_minutes * 60,
        "max_calls": max_calls,
        "budget_usd": round(budget_usd, 4),
    }
    if unlock:
        claims["k"] = unlock
    body = _b64e(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return f"{PREFIX}{body}.{_sign(body)}", claims


def verify(token: str) -> dict:
    """Return the claims if the token is genuine and unexpired, else raise TokenError."""
    if not token.startswith(PREFIX) or token.count(".") != 1:
        raise TokenError("MALFORMED_TOKEN", "Not a Leash token.")
    body, sig = token[len(PREFIX):].split(".")
    # Constant-time comparison, so an attacker can't learn the signature
    # byte by byte from how long the check takes.
    if not hmac.compare_digest(sig, _sign(body)):
        raise TokenError("BAD_SIGNATURE", "Signature check failed: the token was forged or altered.")
    try:
        claims = json.loads(_b64d(body))
    except (ValueError, json.JSONDecodeError):
        raise TokenError("MALFORMED_TOKEN", "Token body could not be decoded.")
    if not isinstance(claims, dict) or "jti" not in claims or "space" not in claims:
        raise TokenError("MALFORMED_TOKEN", "Token is missing required claims.")
    if time.time() >= claims.get("exp", 0):
        raise TokenError("TOKEN_EXPIRED", "Token has expired.", claims)
    return claims
