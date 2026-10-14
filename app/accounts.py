"""Customer accounts: password hashing and signed session cookies.

Passwords are hashed with scrypt (memory-hard, so guessing is slow and
expensive), each with its own random salt. Sessions are stateless: a cookie
holding the account id and an expiry, signed with HMAC-SHA256 so it can't be
forged or altered.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time

from . import config

COOKIE = "leash_session"
SESSION_DAYS = 7
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")

_N, _R, _P = 2**14, 8, 1  # scrypt cost: about 16 MB of memory per hash


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        check = hashlib.scrypt(password.encode(), salt=_b64d(salt), n=int(n), r=int(r), p=int(p), dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(check, _b64d(digest))


def _sign(body: str) -> str:
    return _b64e(hmac.new(config.SESSION_KEY, body.encode(), hashlib.sha256).digest())


def make_session(account_id: str) -> str:
    body = _b64e(json.dumps({"a": account_id, "exp": int(time.time()) + SESSION_DAYS * 86400}, separators=(",", ":")).encode())
    return f"{body}.{_sign(body)}"


def read_session(value: str):
    """Return the account id from a valid, unexpired session cookie, else None."""
    if not value or value.count(".") != 1:
        return None
    body, sig = value.split(".")
    if not hmac.compare_digest(sig, _sign(body)):
        return None
    try:
        data = json.loads(_b64d(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or time.time() >= data.get("exp", 0):
        return None
    return data.get("a")


def normalise_email(email: str) -> str:
    return email.strip().lower()
