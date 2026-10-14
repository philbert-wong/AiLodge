"""Canary keys (honeytokens) and outbound secret scanning."""
import hashlib
import hmac
import re

from sqlalchemy import select

from . import config, db

# Decoy keys that look exactly like real OpenAI keys. No legitimate agent
# should ever have them, so any use of one is proof something read a place
# it shouldn't have, usually via prompt injection. Each space gets its own.
_CANARY_PLACES = [
    ("env", "A decoy .env file left in the agent's workspace"),
    ("docs", "A hidden comment inside an internal wiki page"),
    ("config", "An old config file named config/legacy_keys.json"),
    ("email", "A suspicious email in the support inbox"),
]

_CANARY_SHAPE = re.compile(r"sk-proj-[0-9a-f]{48}")


def _canary_value(space: str, slot: str) -> str:
    digest = hmac.new(config.CANARY_KEY, f"{space}/{slot}".encode(), hashlib.sha256).hexdigest()
    return f"sk-proj-{digest[:48]}"


def plant_canaries(conn, space: str) -> None:
    """Create a space's canary keys if they don't exist yet. Hold db.write_lock."""
    for slot, place in _CANARY_PLACES:
        value = _canary_value(space, slot)
        row = conn.execute(select(db.canaries).where(db.canaries.c.key == value)).first()
        if row is None:
            conn.execute(db.canaries.insert().values(key=value, space=space, planted_in=place))
        elif row.planted_in != place:  # keep descriptions current after a wording change
            conn.execute(db.canaries.update().where(db.canaries.c.key == value).values(planted_in=place))


def list_canaries(conn, space: str) -> list[dict]:
    rows = conn.execute(select(db.canaries).where(db.canaries.c.space == space)).all()
    return [{"key": r.key, "planted_in": r.planted_in} for r in rows]


def find_canary(conn, value: str):
    """Return (space, planted_in) if the value is a canary key, else None."""
    if not _CANARY_SHAPE.fullmatch(value):
        return None
    row = conn.execute(select(db.canaries).where(db.canaries.c.key == value)).first()
    return (row.space, row.planted_in) if row else None


# Patterns for things that should never leave in a prompt.
_SECRET_PATTERNS = [
    ("an API key", re.compile(r"sk-[A-Za-z0-9_\-]{20,}")),
    ("a Leash token", re.compile(r"lsh_[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}")),
    ("a private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("an AWS key", re.compile(r"AKIA[0-9A-Z]{16}")),
]


def scan_for_secrets(conn, text: str) -> list[str]:
    """Return a description of each kind of secret found in the text."""
    found = []
    if config.OPENAI_API_KEY and config.OPENAI_API_KEY in text:
        found.append("the server's real OpenAI key")
    for candidate in _CANARY_SHAPE.findall(text):
        if find_canary(conn, candidate):
            found.append("a trap key")
            break
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(text) and label not in found:
            found.append(label)
    return found


def flatten_messages(body: dict) -> str:
    """All text the agent is about to send upstream, as one string."""
    parts = []
    for message in body.get("messages", []) or []:
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for chunk in content:
                if isinstance(chunk, dict) and isinstance(chunk.get("text"), str):
                    parts.append(chunk["text"])
    return "\n".join(parts)
