"""Alerts to Slack or Discord through an incoming webhook.

A webhook URL is itself a secret (anyone holding it can post to the channel),
so it is encrypted the same way as saved API keys. Only Slack and Discord
webhook addresses are accepted, which stops the server from being pointed at
arbitrary internal addresses. Alerts are sent in the background so a slow
chat service never slows down an agent's call.
"""
import threading
import time
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from . import db, keyvault
from .ratelimit import limiter

_HOSTS = {
    "hooks.slack.com": ("slack", ("/services/", "/triggers/", "/workflows/")),
    "discord.com": ("discord", ("/api/webhooks/",)),
    "discordapp.com": ("discord", ("/api/webhooks/",)),
    "ptb.discord.com": ("discord", ("/api/webhooks/",)),
    "canary.discord.com": ("discord", ("/api/webhooks/",)),
}

TITLES = {
    "CANARY_TRIGGERED": "Trap key used",
    "SECRET_BLOCKED": "Leak blocked",
    "KEY_INTEGRITY_FAILED": "Saved key was tampered with",
    "KILL_SWITCH": "All agents stopped",
    "GLOBAL_BUDGET": "Global budget reached",
    "LIMIT_REACHED": "An agent hit its limit",
    "TEST": "Test alert",
}


class WebhookError(ValueError):
    pass


def check_url(url: str) -> str:
    """Return 'slack' or 'discord' for an accepted webhook URL, else raise."""
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in _HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise WebhookError("Use a Slack or Discord webhook address starting with https://hooks.slack.com/ or https://discord.com/api/webhooks/")
    kind, prefixes = _HOSTS[host]
    if not parsed.path.startswith(prefixes) or len(parsed.path) < 20:
        raise WebhookError("That doesn't look like a complete webhook address. Copy the whole URL from Slack or Discord.")
    return kind


def _hint(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.hostname}/…{url.rstrip('/')[-4:]}"


def save(conn, space: str, url: str) -> dict:
    kind = check_url(url)
    sealed = keyvault.seal(url.strip(), space, "webhook")
    w = db.webhooks.c
    values = dict(kind=kind, hint=_hint(url.strip()), ciphertext=sealed["ciphertext"], wrapped_dek=sealed["wrapped_dek"], created_ms=int(time.time() * 1000))
    if conn.execute(select(w.space).where(w.space == space)).first():
        conn.execute(db.webhooks.update().where(w.space == space).values(**values))
    else:
        conn.execute(db.webhooks.insert().values(space=space, **values))
    return view(conn, space)


def remove(conn, space: str) -> None:
    conn.execute(db.webhooks.delete().where(db.webhooks.c.space == space))


def view(conn, space: str) -> dict:
    row = conn.execute(select(db.webhooks).where(db.webhooks.c.space == space)).first()
    if row is None:
        return {"set": False}
    return {"set": True, "kind": row.kind, "hint": row.hint}


def _load(conn, space: str):
    row = conn.execute(select(db.webhooks).where(db.webhooks.c.space == space)).first()
    if row is None:
        return None
    try:
        return row.kind, keyvault.unseal(row.ciphertext, row.wrapped_dek, space, "webhook")
    except keyvault.KeyIntegrityError:
        return None


def _payload(kind: str, text: str) -> dict:
    return {"text": text} if kind == "slack" else {"content": text}


def _post(kind: str, url: str, text: str) -> tuple[bool, str]:
    try:
        response = httpx.post(url, json=_payload(kind, text), timeout=6)
    except httpx.HTTPError as exc:
        return False, f"Couldn't reach {kind.title()}: {exc.__class__.__name__}"
    if response.status_code >= 400:
        return False, f"{kind.title()} refused the alert (status {response.status_code}). Check the webhook address."
    return True, ""


def space_label(conn, space: str) -> str:
    if space == db.MAIN:
        return "the control room"
    row = conn.execute(select(db.accounts.c.team).where(db.accounts.c.space == space)).first()
    return f"team {row.team}" if row else "your workspace"


def format_text(label: str, kind: str, message: str) -> str:
    return f"Leash alert for {label}: {TITLES.get(kind, kind)}. {message}"


def notify(conn, space: str, kind: str, message: str) -> None:
    """Send an alert in the background, if this space has a webhook. Never raises."""
    if space.startswith("sb_"):
        return
    try:
        loaded = _load(conn, space)
        if not loaded or not limiter.allow(f"webhook:{space}", 20, 60):
            return
        text = format_text(space_label(conn, space), kind, message)
    except Exception:  # noqa: BLE001 - alerts must never break a call
        return
    hook_kind, url = loaded
    threading.Thread(target=_post, args=(hook_kind, url, text), daemon=True).start()


def send_test(conn, space: str) -> dict:
    loaded = _load(conn, space)
    if not loaded:
        return {"ok": False, "error": "No webhook is set up yet."}
    if not limiter.allow(f"webhook-test:{space}", 5, 60):
        return {"ok": False, "error": "Too many test alerts. Wait a minute."}
    hook_kind, url = loaded
    ok, error = _post(hook_kind, url, format_text(space_label(conn, space), "TEST", "Alerts from Leash will arrive here."))
    return {"ok": ok, "error": error}
