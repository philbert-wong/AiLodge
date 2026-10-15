"""Encrypted storage for provider API keys ("bring your own key").

Envelope encryption, the same pattern cloud key-management services use:

  1. Every stored key gets its own random 256-bit data key (DEK).
  2. The API key is encrypted with the DEK using AES-256-GCM.
  3. The DEK itself is encrypted ("wrapped") with the master key (KEK),
     also with AES-256-GCM.
  4. The database stores only the two ciphertexts. The master key lives in
     an environment variable, never in the database.

So a full copy of the database holds nothing usable on its own. AES-GCM is
authenticated: change a single byte of the stored ciphertext and decryption
fails loudly instead of returning garbage. Both layers are also bound to the
row they belong to (associated data = space + connection id), so ciphertext
copied into another row won't decrypt either.

Rotating the master key only means re-wrapping the small DEKs, not
re-encrypting every API key; `kek_id` records which master key wrapped each one.

Customer workspaces add two more locks, so that a full copy of the database
AND the master key is still not enough to read a team's API key:

  * The data key is wrapped with an *account key* that combines the master key
    with a key derived from the team's password (scrypt). Leash never stores
    the password or the derived key; it exists only in the team's signed-in
    session (encrypted inside an HttpOnly cookie).
  * Each agent pass gets its own copy of the data key, wrapped with a *pass key*
    that combines the master key with a random secret carried inside the pass.
    Leash never stores the pass, so it can only unlock the API key while an
    agent is actually presenting its pass.
"""
import base64
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

ALGORITHM = "AES-256-GCM envelope (per-key data key, wrapped by master key)"
ACCOUNT_ALGORITHM = "AES-256-GCM envelope (per-key data key, wrapped by your password-derived key + master key; each pass holds its own unlock code)"


class KeyIntegrityError(Exception):
    """The stored ciphertext was altered, moved, or the master key changed."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode())


def _aad(space: str, conn_id: str) -> bytes:
    return f"leash/connection/{space}/{conn_id}".encode()


# kek_id for data keys wrapped with an account key instead of the master key alone.
ACCOUNT_KEK_ID = "acct-v1"


def _combined(purpose: bytes, secret: bytes) -> bytes:
    """A wrapping key that needs BOTH the master key and a secret Leash doesn't keep."""
    return hmac.new(config.KEY_ENCRYPTION_KEY, purpose + secret, hashlib.sha256).digest()


def account_key(user_key: bytes) -> bytes:
    return _combined(b"leash/account-wrap/v1|", user_key)


def pass_key(secret: bytes) -> bytes:
    return _combined(b"leash/pass-wrap/v1|", secret)


def pass_aad(space: str, conn_id: str, jti: str) -> bytes:
    return f"leash/pass/{space}/{conn_id}/{jti}".encode()


def seal(api_key: str, space: str, conn_id: str, wrap_key: bytes | None = None) -> dict:
    """Encrypt an API key for storage. Returns only ciphertexts and metadata.

    With `wrap_key` (an account key), the data key is wrapped with it instead
    of the master key alone."""
    aad = _aad(space, conn_id)
    dek = AESGCM.generate_key(bit_length=256)
    key_nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(key_nonce, api_key.encode(), aad)
    return {
        "ciphertext": _b64e(key_nonce + ciphertext),
        "wrapped_dek": wrap_dek(dek, wrap_key or config.KEY_ENCRYPTION_KEY, aad),
        "kek_id": ACCOUNT_KEK_ID if wrap_key else config.KEK_ID,
    }


def wrap_dek(dek: bytes, wrap_key: bytes, aad: bytes) -> str:
    nonce = os.urandom(12)
    return _b64e(nonce + AESGCM(wrap_key).encrypt(nonce, dek, aad))


def unwrap_dek(wrapped: str, wrap_key: bytes, aad: bytes) -> bytes:
    try:
        blob = _b64d(wrapped)
        return AESGCM(wrap_key).decrypt(blob[:12], blob[12:], aad)
    except (InvalidTag, ValueError) as exc:
        raise KeyIntegrityError("The stored key failed its integrity check.") from exc


def open_with_dek(ciphertext: str, dek: bytes, space: str, conn_id: str) -> str:
    try:
        blob = _b64d(ciphertext)
        return AESGCM(dek).decrypt(blob[:12], blob[12:], _aad(space, conn_id)).decode()
    except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
        raise KeyIntegrityError("The stored key failed its integrity check.") from exc


def connection_dek(wrapped_dek: str, space: str, conn_id: str, wrap_key: bytes | None = None) -> bytes:
    """The data key of a stored API key, unwrapped with the master key or an account key."""
    return unwrap_dek(wrapped_dek, wrap_key or config.KEY_ENCRYPTION_KEY, _aad(space, conn_id))


def unseal(ciphertext: str, wrapped_dek: str, space: str, conn_id: str, wrap_key: bytes | None = None) -> str:
    """Decrypt a stored API key, just in time for one forwarded call."""
    return open_with_dek(ciphertext, connection_dek(wrapped_dek, space, conn_id, wrap_key), space, conn_id)


def rewrap_for_account(wrapped_dek: str, space: str, conn_id: str, user_key: bytes) -> str:
    """Move a data key from the master key alone to the account key (master key + password)."""
    dek = connection_dek(wrapped_dek, space, conn_id)
    return wrap_dek(dek, account_key(user_key), _aad(space, conn_id))


def wrap_for_pass(dek: bytes, secret: bytes, space: str, conn_id: str, jti: str) -> str:
    """A copy of the data key that only this pass (its secret) can unlock."""
    return wrap_dek(dek, pass_key(secret), pass_aad(space, conn_id, jti))


def unseal_with_pass(ciphertext: str, pass_wrapped: str, secret: bytes, space: str, conn_id: str, jti: str) -> str:
    dek = unwrap_dek(pass_wrapped, pass_key(secret), pass_aad(space, conn_id, jti))
    return open_with_dek(ciphertext, dek, space, conn_id)


def fingerprint(api_key: str) -> str:
    """A keyed fingerprint (HMAC-SHA256) to recognise a key without storing it."""
    return hmac.new(config.FINGERPRINT_KEY, api_key.encode(), hashlib.sha256).hexdigest()


def hint(api_key: str) -> str:
    """Enough of the key for a person to tell keys apart, and no more."""
    return "…" + api_key[-4:] if len(api_key) >= 12 else "…"
