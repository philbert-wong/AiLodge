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
"""
import base64
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

ALGORITHM = "AES-256-GCM envelope (per-key data key, wrapped by master key)"


class KeyIntegrityError(Exception):
    """The stored ciphertext was altered, moved, or the master key changed."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode())


def _aad(space: str, conn_id: str) -> bytes:
    return f"leash/connection/{space}/{conn_id}".encode()


def seal(api_key: str, space: str, conn_id: str) -> dict:
    """Encrypt an API key for storage. Returns only ciphertexts and metadata."""
    aad = _aad(space, conn_id)
    dek = AESGCM.generate_key(bit_length=256)
    key_nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(key_nonce, api_key.encode(), aad)
    dek_nonce = os.urandom(12)
    wrapped_dek = AESGCM(config.KEY_ENCRYPTION_KEY).encrypt(dek_nonce, dek, aad)
    return {
        "ciphertext": _b64e(key_nonce + ciphertext),
        "wrapped_dek": _b64e(dek_nonce + wrapped_dek),
        "kek_id": config.KEK_ID,
    }


def unseal(ciphertext: str, wrapped_dek: str, space: str, conn_id: str) -> str:
    """Decrypt a stored API key, just in time for one forwarded call."""
    aad = _aad(space, conn_id)
    try:
        blob = _b64d(wrapped_dek)
        dek = AESGCM(config.KEY_ENCRYPTION_KEY).decrypt(blob[:12], blob[12:], aad)
        blob = _b64d(ciphertext)
        return AESGCM(dek).decrypt(blob[:12], blob[12:], aad).decode()
    except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
        raise KeyIntegrityError("The stored key failed its integrity check.") from exc


def fingerprint(api_key: str) -> str:
    """A keyed fingerprint (HMAC-SHA256) to recognise a key without storing it."""
    return hmac.new(config.FINGERPRINT_KEY, api_key.encode(), hashlib.sha256).hexdigest()


def hint(api_key: str) -> str:
    """Enough of the key for a person to tell keys apart, and no more."""
    return "…" + api_key[-4:] if len(api_key) >= 12 else "…"
