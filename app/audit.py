"""Tamper-evident audit log: an HMAC-SHA256 hash chain, one chain per space.

Each entry stores the hash of the entry before it, and its own hash is

    HMAC-SHA256(audit_key, prev_hash || canonical_json(entry))

Change any past entry and its hash no longer matches. Delete one and the
next entry's prev_hash points at nothing. Because the hash is keyed (HMAC
rather than plain SHA-256), someone with database access but without the
server's secret cannot quietly recompute the whole chain after editing it.
"""
import hashlib
import hmac
import json
import time

from sqlalchemy import func, select

from . import config, db

GENESIS = "0" * 64


def _canonical(space: str, entry_id: int, ts_ms: int, jti, event: str, detail: dict) -> str:
    return json.dumps(
        {"space": space, "id": entry_id, "ts_ms": ts_ms, "jti": jti, "event": event, "detail": detail},
        sort_keys=True,
        separators=(",", ":"),
    )


def _hash(prev_hash: str, canonical: str) -> str:
    return hmac.new(config.AUDIT_KEY, (prev_hash + canonical).encode(), hashlib.sha256).hexdigest()


def append(conn, space: str, event: str, detail: dict, jti=None) -> dict:
    """Add an entry to a space's chain. Call while holding db.write_lock."""
    a = db.audit.c
    last = conn.execute(select(db.audit).where(a.space == space).order_by(a.id.desc()).limit(1)).first()
    entry_id = (last.id + 1) if last else 1
    prev_hash = last.hash if last else GENESIS
    ts_ms = int(time.time() * 1000)
    entry_hash = _hash(prev_hash, _canonical(space, entry_id, ts_ms, jti, event, detail))
    conn.execute(
        db.audit.insert().values(
            space=space,
            id=entry_id,
            ts_ms=ts_ms,
            jti=jti,
            event=event,
            detail=json.dumps(detail, sort_keys=True, separators=(",", ":")),
            prev_hash=prev_hash,
            hash=entry_hash,
        )
    )
    return {"id": entry_id, "hash": entry_hash}


def verify_chain(conn, space: str) -> dict:
    """Recompute every hash in a space's chain from the start. Report the first failure."""
    a = db.audit.c
    return verify_rows(space, conn.execute(select(db.audit).where(a.space == space).order_by(a.id)))


def verify_rows(space: str, rows) -> dict:
    """Check a sequence of log rows (from the database, or an edited copy)."""
    expected_prev = GENESIS
    expected_id = 1
    checked = 0
    for row in rows:
        if row.id != expected_id:
            return {
                "ok": False,
                "checked": checked,
                "broken_at": expected_id,
                "reason": f"Entry #{expected_id} is missing: the log jumps from #{expected_id - 1} to #{row.id}.",
            }
        if row.prev_hash != expected_prev:
            return {
                "ok": False,
                "checked": checked,
                "broken_at": row.id,
                "reason": f"Entry #{row.id} no longer links to the entry before it.",
            }
        try:
            detail = json.loads(row.detail)
        except json.JSONDecodeError:
            return {"ok": False, "checked": checked, "broken_at": row.id, "reason": f"Entry #{row.id} is unreadable."}
        recomputed = _hash(row.prev_hash, _canonical(space, row.id, row.ts_ms, row.jti, row.event, detail))
        if not hmac.compare_digest(recomputed, row.hash):
            return {
                "ok": False,
                "checked": checked,
                "broken_at": row.id,
                "reason": f"Entry #{row.id} was changed after it was saved.",
            }
        expected_prev = row.hash
        expected_id += 1
        checked += 1
    return {
        "ok": True,
        "checked": checked,
        "broken_at": None,
        "head": expected_prev if checked else None,
        "reason": "Nothing has been changed since it was saved.",
    }


def count(conn, space: str) -> int:
    return conn.execute(select(func.count()).select_from(db.audit).where(db.audit.c.space == space)).scalar() or 0
