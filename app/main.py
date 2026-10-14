"""Leash: a safety proxy that puts AI agents on a leash.

Agents never hold the real API key. They get short-lived, signed tokens
with hard limits; every decision is written to a tamper-evident log.

Pages:
    /          public landing page
    /try       public sandbox: Maya's weekend demo, isolated per visitor, fake AI only
    /signup    create a team account (Leash as a service)
    /login     log in
    /app       a team's private workspace: keys, agents, alerts, activity log
    /control   the operator's control room (password)

Spaces: "main" is the operator, "sb_<id>" a public sandbox, "acct_<id>" a
customer's workspace. Rows in every table belong to exactly one space.
"""
import base64
import hashlib
import hmac
import html
import json
import logging
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from starlette.concurrency import run_in_threadpool

from . import accounts, audit, config, db, guards, keyvault, notify, tokens, upstream
from .ratelimit import client_ip, limiter

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("leash")

STATIC_DIR = Path(__file__).parent / "static"
SANDBOX_COOKIE = "leash_sb"
_SANDBOX_ID = re.compile(r"^[0-9a-f]{24}$")


def _now_ms() -> int:
    return int(time.time() * 1000)


def is_sandbox(space: str) -> bool:
    return space.startswith("sb_")


def is_workspace(space: str) -> bool:
    return space.startswith("acct_")


def ensure_space(conn, space: str) -> None:
    """Create a space with its canary keys and the first link of its chain. Hold db.write_lock."""
    if not conn.execute(select(db.spaces.c.space).where(db.spaces.c.space == space)).first():
        conn.execute(db.spaces.insert().values(space=space, created_ms=_now_ms()))
    guards.plant_canaries(conn, space)
    if audit.count(conn, space) == 0:
        audit.append(conn, space, "LOG_STARTED", {"note": "Audit chain created."})


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    with db.write_lock, db.engine.begin() as conn:
        ensure_space(conn, db.MAIN)
    log.info("Leash ready. OpenAI enabled: %s. Public sandbox: %s", config.OPENAI_ENABLED, config.SANDBOX_ENABLED)
    yield


app = FastAPI(title="Leash", version="1.1.0", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _alert(conn, space: str, kind: str, message: str, jti=None) -> None:
    conn.execute(db.alerts.insert().values(space=space, ts_ms=_now_ms(), kind=kind, message=message, jti=jti))
    notify.notify(conn, space, kind, message)  # Slack or Discord, if set up


def _alert_once(conn, space: str, kind: str, message: str, jti: str) -> None:
    """Alert the first time a token hits this condition, not on every retry."""
    al = db.alerts.c
    seen = conn.execute(select(al.id).where(al.space == space, al.kind == kind, al.jti == jti).limit(1)).first()
    if not seen:
        _alert(conn, space, kind, message, jti=jti)


def _usd(amount: float) -> str:
    """Money for messages: cents normally, more digits for fractions of a cent."""
    return f"${amount:.2f}" if amount >= 0.01 or amount == 0 else f"${amount:.5f}"


# Real-AI spending through the server's own key, kept as running totals in the
# settings table. Unlike the passes, these survive a demo reset, so the caps
# below can't be reopened by deleting passes.
GLOBAL = "global"


def _spent(conn, space: str, name: str = "real_spent_usd") -> float:
    try:
        return float(db.get_setting(conn, space, name, "0") or 0)
    except ValueError:
        return 0.0


def _bump(conn, space: str, delta: float, name: str = "real_spent_usd") -> None:
    db.set_setting(conn, space, name, f"{max(0.0, _spent(conn, space, name) + delta):.8f}")


def _real_demo(conn, space: str) -> dict:
    """What's left of the real-AI budgets, as seen from a space."""
    global_left = max(0.0, config.GLOBAL_REAL_BUDGET_USD - _spent(conn, GLOBAL))
    if is_sandbox(space):
        public_left = max(0.0, config.PUBLIC_REAL_BUDGET_USD - _spent(conn, GLOBAL, "public_real_spent_usd"))
        visitor_left = max(0.0, config.SANDBOX_REAL_PER_VISITOR_USD - _spent(conn, space))
        left = min(global_left, public_left, visitor_left)
        return {
            "available": config.OPENAI_ENABLED and left >= 0.0005,
            "model": config.OPENAI_MODEL or None,
            "left_usd": round(left, 6),
            "public_left_usd": round(min(public_left, global_left), 6),
            "public_budget_usd": config.PUBLIC_REAL_BUDGET_USD,
            "visitor_budget_usd": config.SANDBOX_REAL_PER_VISITOR_USD,
        }
    if space == db.MAIN:
        return {
            "available": config.OPENAI_ENABLED and global_left >= 0.0005,
            "model": config.OPENAI_MODEL or None,
            "left_usd": round(global_left, 6),
            "public_left_usd": round(max(0.0, config.PUBLIC_REAL_BUDGET_USD - _spent(conn, GLOBAL, "public_real_spent_usd")), 6),
            "public_budget_usd": config.PUBLIC_REAL_BUDGET_USD,
        }
    return {"available": False}


def _blocked(status: int, code: str, message: str) -> JSONResponse:
    """OpenAI-shaped error, so existing agent SDKs surface it cleanly."""
    return JSONResponse(status_code=status, content={"error": {"message": message, "type": "leash_blocked", "code": code}})


def _too_many(message: str = "Too many requests. Slow down and try again in a minute.") -> JSONResponse:
    return _blocked(429, "RATE_LIMITED", message)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def _page(name: str, **replacements: str) -> HTMLResponse:
    text = (STATIC_DIR / name).read_text(encoding="utf-8")
    for key, value in replacements.items():
        text = text.replace(key, value)
    return HTMLResponse(text)


@app.get("/", include_in_schema=False)
def landing():
    repo = ""
    if config.REPO_URL:
        repo = f'<a href="{html.escape(config.REPO_URL)}" rel="noopener">Source code on GitHub</a>'
    return _page("landing.html", **{"<!--REPO_LINK-->": repo})


@app.get("/try", include_in_schema=False)
def sandbox_page():
    if not config.SANDBOX_ENABLED:
        return HTMLResponse("<p>The public sandbox is turned off. <a href='/'>Back to Leash</a></p>", status_code=404)
    return _page("dashboard.html", **{'data-mode="operator"': 'data-mode="sandbox"'})


@app.get("/control", include_in_schema=False)
def control_page():
    return _page("dashboard.html")


def _session_account(request: Request):
    account_id = accounts.read_session(request.cookies.get(accounts.COOKIE, ""))
    if not account_id:
        return None
    with db.engine.connect() as conn:
        return conn.execute(select(db.accounts).where(db.accounts.c.id == account_id)).first()


@app.get("/signup", include_in_schema=False)
def signup_page(request: Request):
    if not config.ACCOUNTS_ENABLED:
        return RedirectResponse("/", status_code=303)
    if _session_account(request):
        return RedirectResponse("/app", status_code=303)
    return _page("auth.html", **{'data-auth="login"': 'data-auth="signup"'})


@app.get("/login", include_in_schema=False)
def login_page(request: Request):
    if not config.ACCOUNTS_ENABLED:
        return RedirectResponse("/", status_code=303)
    if _session_account(request):
        return RedirectResponse("/app", status_code=303)
    return _page("auth.html")


@app.get("/app", include_in_schema=False)
def workspace_page(request: Request):
    if not config.ACCOUNTS_ENABLED or not _session_account(request):
        return RedirectResponse("/login", status_code=303)
    return _page("workspace.html")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"ok": True}


# ---------------------------------------------------------------------------
# The proxy: an OpenAI-compatible endpoint. Point any OpenAI SDK's base_url
# at <your-app>/v1 and pass a Leash token as the API key.
# ---------------------------------------------------------------------------
@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request):
    ip = client_ip(request)
    if not limiter.allow(f"proxy:{ip}", 300, 60) or not limiter.allow("proxy:all", 3000, 60):
        return _too_many()
    auth = request.headers.get("authorization", "")
    presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        body = None
    # Database work and the upstream call are blocking, so run them off the event loop.
    return await run_in_threadpool(_handle_proxy, presented, body, ip)


def _log_unattributed(conn, ip: str, event: str, detail: dict) -> None:
    """Failed attempts we can't tie to a space go to the operator's log, rate-limited
    so the public can't flood it."""
    if limiter.allow(f"unattributed-log:{ip}", 20, 60):
        audit.append(conn, db.MAIN, event, detail)


def _handle_proxy(presented: str, body, ip: str):
    if not presented:
        return _blocked(401, "NO_TOKEN", "Send a Leash token as 'Authorization: Bearer lsh_...'.")
    fingerprint = hashlib.sha256(presented.encode()).hexdigest()

    # 1. Canary keys: decoys that only an injected or rogue agent would find.
    with db.write_lock, db.engine.begin() as conn:
        hit = guards.find_canary(conn, presented)
        if hit:
            space, place = hit
            audit.append(conn, space, "CANARY_TRIGGERED", {"planted_in": place, "key_sha256": fingerprint})
            _alert(
                conn,
                space,
                "CANARY_TRIGGERED",
                f"A trap key was used. It was planted in: {place}. Something read a place it should never have touched.",
            )
            return _blocked(403, "CANARY_TRIGGERED", "This key is a trap. The attempt has been recorded and reported.")

        # 2. Raw provider keys are never accepted. Agents must hold Leash tokens.
        if presented.startswith("sk-"):
            _log_unattributed(conn, ip, "RAW_KEY_REJECTED", {"key_sha256": fingerprint})
            return _blocked(401, "RAW_KEY_REJECTED", "Raw provider keys are not accepted here. Ask your operator for a Leash token.")

        # 3. Signature and expiry.
        try:
            claims = tokens.verify(presented)
        except tokens.TokenError as err:
            owner = err.claims["space"] if err.claims else None
            if owner and conn.execute(select(db.spaces.c.space).where(db.spaces.c.space == owner)).first():
                audit.append(
                    conn,
                    owner,
                    "CALL_BLOCKED",
                    {"agent": err.claims.get("agent"), "code": err.code, "reason": err.message},
                    jti=err.claims["jti"],
                )
            else:
                _log_unattributed(conn, ip, "CALL_BLOCKED", {"code": err.code, "reason": err.message, "token_sha256": fingerprint})
            return _blocked(401, err.code, err.message)

    jti, space, upstream_name = claims["jti"], claims["space"], claims["upstream"]
    if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
        return _blocked(400, "BAD_REQUEST", "Request body must be JSON with a 'messages' list.")
    prompt_text = guards.flatten_messages(body)
    prompt_sha = hashlib.sha256(prompt_text.encode()).hexdigest()

    # 4. Reserve the call under the lock: every limit is checked atomically.
    with db.write_lock, db.engine.begin() as conn:
        row = conn.execute(select(db.tokens).where(db.tokens.c.jti == jti)).first()
        if row is None or row.space != space:
            return _blocked(401, "UNKNOWN_TOKEN", "This token is signed correctly but is not on record (it may have been reset).")
        if is_sandbox(space) and audit.count(conn, space) >= config.SANDBOX_MAX_AUDIT:
            return _blocked(429, "SANDBOX_FULL", "This sandbox's log is full. Click 'Reset demo' to start fresh.")

        def block(status, code, message, extra=None):
            detail = {"agent": claims["agent"], "code": code, "reason": message}
            detail.update(extra or {})
            audit.append(conn, space, "CALL_BLOCKED", detail, jti=jti)
            return _blocked(status, code, message)

        if db.get_setting(conn, space, "kill_all") == "on":
            return block(403, "KILL_SWITCH", "The global kill switch is on. All agents are stopped.")
        if row.revoked:
            return block(403, "TOKEN_REVOKED", f"This token was revoked: {row.revoked_reason or 'by an operator'}.")

        leaks = guards.scan_for_secrets(conn, prompt_text)
        if leaks:
            message = f"Blocked an outgoing message containing {' and '.join(leaks)}. Possible attempt to leak a key."
            _alert(conn, space, "SECRET_BLOCKED", f"Agent '{claims['agent']}': {message}", jti=jti)
            return block(400, "SECRET_BLOCKED", message, {"found": leaks, "prompt_sha256": prompt_sha})

        if upstream_name == "openai":
            if space != db.MAIN and not is_sandbox(space):
                return block(403, "UPSTREAM_DISABLED", "Only the operator and the public demo can use the server's own key.")
            if not config.OPENAI_ENABLED:
                return block(503, "UPSTREAM_DISABLED", "Real AI is not configured on this server.")
            if body.get("model") != config.OPENAI_MODEL:
                return block(403, "MODEL_NOT_ALLOWED", f"This token may only use model '{config.OPENAI_MODEL}'.")
            if is_sandbox(space):
                # The public demo spends real money, so every call is kept small.
                if len(prompt_text) > config.SANDBOX_REAL_MAX_PROMPT_CHARS:
                    return block(413, "PROMPT_TOO_LONG", "Messages in the public demo are limited in length.")
                if not limiter.allow(f"sb-real:{ip}", 40, 60) or not limiter.allow("sb-real:all", 400, 60):
                    return _too_many()
                try:
                    requested = int(body.get("max_tokens") or body.get("max_completion_tokens") or config.SANDBOX_REAL_MAX_TOKENS)
                except (TypeError, ValueError):
                    requested = config.SANDBOX_REAL_MAX_TOKENS
                body.pop("max_completion_tokens", None)
                body["max_tokens"] = max(1, min(requested, config.SANDBOX_REAL_MAX_TOKENS))

        # A token issued for a team's own stored key ("bring your own key").
        connection = None
        if upstream_name.startswith("c_"):
            c = db.connections.c
            connection = conn.execute(select(db.connections).where(c.id == upstream_name, c.space == space)).first()
            if connection is None or connection.revoked:
                return block(403, "CONNECTION_REMOVED", "The provider key this token was issued for has been removed.")
            if body.get("model") != connection.model:
                return block(403, "MODEL_NOT_ALLOWED", f"This token may only use model '{connection.model}'.")

        # Real calls in the control room and in customer workspaces; public
        # sandboxes always use the fake AI, even with a saved key.
        kind = "real" if upstream_name == "openai" or (connection is not None and not is_sandbox(space)) else "fake"

        if row.calls_used >= row.max_calls:
            _alert_once(
                conn, space, "LIMIT_REACHED",
                f"Agent '{claims['agent']}' used all {row.max_calls} of its calls and was stopped.", jti,
            )
            return block(429, "CALL_LIMIT", f"Call limit reached ({row.max_calls} calls).")

        estimate = upstream.estimate_worst_case(kind, body, prompt_text)
        if row.spent_usd + estimate > row.budget_usd + 1e-9:
            _alert_once(
                conn, space, "LIMIT_REACHED",
                f"Agent '{claims['agent']}' reached its {_usd(row.budget_usd)} money limit and was stopped.", jti,
            )
            return block(
                402,
                "BUDGET_EXCEEDED",
                f"Budget reached: {_usd(row.spent_usd)} of {_usd(row.budget_usd)} spent; the next call could cost up to {_usd(estimate)}, which would go over.",
                {"spent_usd": round(row.spent_usd, 8), "budget_usd": row.budget_usd, "next_call_up_to_usd": round(estimate, 8)},
            )

        # Running totals to reserve this call against, besides the pass itself.
        counters = []
        if upstream_name == "openai":
            if _spent(conn, GLOBAL) + estimate > config.GLOBAL_REAL_BUDGET_USD:
                _alert(conn, db.MAIN, "GLOBAL_BUDGET", "The server-wide real-AI budget is used up. Real calls are paused.")
                return block(402, "GLOBAL_BUDGET", "The server-wide spending ceiling for real API calls has been reached.")
            counters.append((GLOBAL, "real_spent_usd"))
            if is_sandbox(space):
                if _spent(conn, GLOBAL, "public_real_spent_usd") + estimate > config.PUBLIC_REAL_BUDGET_USD:
                    return block(402, "PUBLIC_BUDGET", "The public demo's real-AI budget is used up. The demo will use the free fake AI.")
                if _spent(conn, space) + estimate > config.SANDBOX_REAL_PER_VISITOR_USD:
                    return block(
                        402,
                        "VISITOR_BUDGET",
                        f"You've used your {_usd(config.SANDBOX_REAL_PER_VISITOR_USD)} of real AI in this demo. Sign up to run agents on your own key.",
                    )
                counters += [(GLOBAL, "public_real_spent_usd"), (space, "real_spent_usd")]
            for counter_space, name in counters:
                _bump(conn, counter_space, estimate, name)

        conn.execute(
            db.tokens.update().where(db.tokens.c.jti == jti).values(calls_used=row.calls_used + 1, spent_usd=row.spent_usd + estimate)
        )

    def refund_and_log(event: str, detail: dict) -> None:
        with db.write_lock, db.engine.begin() as conn:
            for counter_space, name in counters:
                _bump(conn, counter_space, -estimate, name)
            current = conn.execute(select(db.tokens).where(db.tokens.c.jti == jti)).first()
            if current is not None:
                conn.execute(db.tokens.update().where(db.tokens.c.jti == jti).values(spent_usd=max(0.0, current.spent_usd - estimate)))
                audit.append(conn, space, event, {"agent": claims["agent"], **detail}, jti=jti)
                if event == "KEY_INTEGRITY_FAILED":
                    _alert(conn, space, event, f"The saved key '{connection.name}' was changed in the database, so Leash refused to use it.", jti=jti)
                    db.set_setting(conn, space, _tamper_flag(connection.id), "1")

    # 5. Forward. The lock is released so a slow upstream can't freeze the dashboard.
    try:
        if connection is not None:
            # Decrypt the team's key just in time, use it for this one call, drop it.
            try:
                api_key = keyvault.unseal(connection.ciphertext, connection.wrapped_dek, space, connection.id)
            except keyvault.KeyIntegrityError:
                refund_and_log("KEY_INTEGRITY_FAILED", {"connection": connection.name, "connection_id": connection.id})
                return _blocked(
                    409,
                    "KEY_INTEGRITY_FAILED",
                    "This saved key was changed in the database, so Leash refused to use it. No call was made.",
                )
            try:
                if kind == "real":
                    result = upstream.openai_completion(body, base_url=connection.base_url, api_key=api_key)
                else:
                    result = upstream.fake_completion(body)
            finally:
                del api_key
        elif upstream_name == "openai":
            result = upstream.openai_completion(body)
        else:
            result = upstream.fake_completion(body)
    except upstream.UpstreamError as err:
        refund_and_log("UPSTREAM_ERROR", {"status": err.status, "reason": err.message})
        return _blocked(502, "UPSTREAM_ERROR", err.message)

    # 6. Settle the real cost and record the call.
    usage = result.get("usage") or {}
    actual = upstream.cost_of(kind, usage)
    with db.write_lock, db.engine.begin() as conn:
        for counter_space, name in counters:
            _bump(conn, counter_space, actual - estimate, name)
        current = conn.execute(select(db.tokens).where(db.tokens.c.jti == jti)).first()
        if current is None:  # the sandbox was reset mid-call
            return JSONResponse(result)
        spent = max(0.0, current.spent_usd - estimate + actual)
        conn.execute(db.tokens.update().where(db.tokens.c.jti == jti).values(spent_usd=spent))
        audit.append(
            conn,
            space,
            "CALL_ALLOWED",
            {
                "agent": claims["agent"],
                "upstream": upstream_name,
                "connection": connection.name if connection is not None else None,
                "model": result.get("model"),
                "prompt_sha256": prompt_sha,
                "prompt_preview": prompt_text[:60],
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "cost_usd": round(actual, 6),
                "calls_used": current.calls_used,
                "spent_usd": round(spent, 6),
            },
            jti=jti,
        )
        remaining_calls = current.max_calls - current.calls_used
        remaining_budget = max(0.0, current.budget_usd - spent)

    response = JSONResponse(result)
    response.headers["X-Leash-Calls-Remaining"] = str(remaining_calls)
    response.headers["X-Leash-Budget-Remaining"] = f"{remaining_budget:.8f}"
    response.headers["X-Leash-Call-Cost"] = f"{actual:.8f}"
    return response


# ---------------------------------------------------------------------------
# The unprotected path, for the "before" half of the demo. It calls the fake
# upstream with no checks and no log, just like a raw long-lived key would.
# ---------------------------------------------------------------------------
@app.post("/unprotected/v1/chat/completions")
async def unprotected(request: Request):
    ip = client_ip(request)
    if not limiter.allow(f"unprotected:{ip}", 400, 60) or not limiter.allow("unprotected:all", 4000, 60):
        return _too_many()
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        body = {}
    return upstream.fake_completion(body if isinstance(body, dict) else {})


# ---------------------------------------------------------------------------
# Space-scoped operations, shared by the operator API and the sandbox API
# ---------------------------------------------------------------------------
class IssueRequest(BaseModel):
    agent: str = Field(min_length=1, max_length=64)
    # "fake", "openai" (the server's own key), or the id of a stored provider key.
    upstream: str = Field(default="fake", pattern="^(fake|openai|c_[0-9a-f]{12})$")
    ttl_minutes: int = Field(default=15, ge=1)
    max_calls: int = Field(default=20, ge=1)
    budget_usd: float = Field(default=1.0, gt=0)


class RevokeRequest(BaseModel):
    reason: str = Field(default="Revoked by operator", max_length=200)


class KillRequest(BaseModel):
    on: bool


def _tier(space: str) -> dict:
    """Limits for each kind of space."""
    if is_sandbox(space):
        return {
            "mode": "sandbox", "max_keys": config.SANDBOX_MAX_CONNECTIONS, "max_tokens": config.SANDBOX_MAX_TOKENS,
            "max_ttl_minutes": config.SANDBOX_MAX_TTL_MINUTES, "max_calls": config.SANDBOX_MAX_CALLS,
            "max_budget_usd": config.SANDBOX_MAX_BUDGET_USD,
        }
    if is_workspace(space):
        return {
            "mode": "workspace", "max_keys": config.ACCOUNT_MAX_CONNECTIONS, "max_tokens": config.ACCOUNT_MAX_TOKENS,
            "max_ttl_minutes": config.ACCOUNT_MAX_TTL_MINUTES, "max_calls": config.ACCOUNT_MAX_CALLS,
            "max_budget_usd": config.ACCOUNT_MAX_BUDGET_USD,
        }
    return {
        "mode": "operator", "max_keys": config.MAX_CONNECTIONS, "max_tokens": None,
        "max_ttl_minutes": config.MAX_TTL_MINUTES, "max_calls": config.MAX_CALLS_PER_TOKEN,
        "max_budget_usd": config.MAX_BUDGET_PER_TOKEN_USD,
    }


def op_config(space: str) -> dict:
    tier = _tier(space)
    operator = space == db.MAIN
    with db.engine.connect() as conn:
        real_demo = _real_demo(conn, space)
    return {
        "real_demo": real_demo,
        "mode": tier["mode"],
        "openai_enabled": config.OPENAI_ENABLED and operator,
        "openai_model": (config.OPENAI_MODEL or None) if operator else None,
        "fake_cost_per_call": config.FAKE_COST_PER_CALL,
        "global_real_budget_usd": config.GLOBAL_REAL_BUDGET_USD,
        "max_stored_keys": tier["max_keys"],
        "limits": {
            "max_ttl_minutes": tier["max_ttl_minutes"],
            "max_calls": tier["max_calls"],
            "max_budget_usd": tier["max_budget_usd"],
        },
    }


def op_issue(space: str, req: IssueRequest) -> dict:
    if req.upstream == "openai" and (not config.OPENAI_ENABLED or not (space == db.MAIN or is_sandbox(space))):
        raise HTTPException(400, "The server's own key isn't available here. Use one of your saved keys or the free practice AI.")
    tier = _tier(space)
    ttl = min(req.ttl_minutes, tier["max_ttl_minutes"])
    max_calls = min(req.max_calls, tier["max_calls"])
    budget = min(req.budget_usd, tier["max_budget_usd"])
    with db.write_lock, db.engine.begin() as conn:
        if req.upstream == "openai":
            real = _real_demo(conn, space)
            if not real["available"]:
                raise HTTPException(409, "The real-AI budget for this demo is used up. Use the free fake AI instead.")
            budget = min(budget, real["left_usd"])
        t = db.tokens.c
        if is_sandbox(space):
            existing = conn.execute(select(func.count()).select_from(db.tokens).where(t.space == space)).scalar()
            if existing >= config.SANDBOX_MAX_TOKENS:
                raise HTTPException(429, "This sandbox has issued too many tokens. Click 'Reset demo' to start fresh.")
        elif is_workspace(space):
            live = conn.execute(
                select(func.count()).select_from(db.tokens).where(t.space == space, t.revoked.is_(False), t.exp > time.time())
            ).scalar()
            if live >= config.ACCOUNT_MAX_TOKENS:
                raise HTTPException(429, f"You have {live} live agent passes. Stop some before creating more.")
        if req.upstream.startswith("c_"):
            c = db.connections.c
            stored = conn.execute(select(db.connections).where(c.id == req.upstream, c.space == space)).first()
            if stored is None or stored.revoked:
                raise HTTPException(404, "No stored provider key with that id.")
            if _is_tampered(conn, space, stored.id):
                raise HTTPException(409, "This saved key was tampered with. Remove it and add the key again.")
        token, claims = tokens.mint(space, req.agent, req.upstream, ttl, max_calls, budget)
        conn.execute(
            db.tokens.insert().values(
                jti=claims["jti"],
                space=space,
                agent=claims["agent"],
                upstream=claims["upstream"],
                created_ms=_now_ms(),
                exp=claims["exp"],
                max_calls=max_calls,
                budget_usd=budget,
                calls_used=0,
                spent_usd=0.0,
                revoked=False,
            )
        )
        audit.append(
            conn,
            space,
            "TOKEN_ISSUED",
            {"agent": req.agent, "upstream": req.upstream, "ttl_minutes": ttl, "max_calls": max_calls, "budget_usd": budget},
            jti=claims["jti"],
        )
    # The token itself is returned once and never stored. Only its id is kept.
    return {"token": token, "claims": claims}


def op_list_tokens(space: str) -> list:
    now = time.time()
    t = db.tokens.c
    with db.engine.connect() as conn:
        rows = conn.execute(select(db.tokens).where(t.space == space).order_by(t.created_ms.desc()).limit(50)).all()
        names = {
            row.id: row.name
            for row in conn.execute(select(db.connections.c.id, db.connections.c.name).where(db.connections.c.space == space)).all()
        }
    out = []
    for r in rows:
        if r.revoked:
            status = "revoked"
        elif now >= r.exp:
            status = "expired"
        elif r.calls_used >= r.max_calls:
            status = "call limit"
        elif r.spent_usd + 1e-9 >= r.budget_usd:
            status = "budget spent"
        else:
            status = "active"
        out.append(
            {
                "jti": r.jti,
                "agent": r.agent,
                "upstream": r.upstream,
                "upstream_label": "Practice AI (free)" if r.upstream == "fake" else ("Server key" if r.upstream == "openai" else names.get(r.upstream, "Removed key")),
                "status": status,
                "expires_in_s": max(0, int(r.exp - now)),
                "calls_used": r.calls_used,
                "max_calls": r.max_calls,
                "spent_usd": round(r.spent_usd, 6),
                "budget_usd": r.budget_usd,
                "revoked_reason": r.revoked_reason,
                "created_ms": r.created_ms,
            }
        )
    return out


def op_revoke(space: str, jti: str, reason: str) -> dict:
    t = db.tokens.c
    with db.write_lock, db.engine.begin() as conn:
        row = conn.execute(select(db.tokens).where(t.jti == jti, t.space == space)).first()
        if row is None:
            raise HTTPException(404, "No token with that id.")
        if not row.revoked:
            conn.execute(db.tokens.update().where(t.jti == jti).values(revoked=True, revoked_reason=reason))
            audit.append(conn, space, "TOKEN_REVOKED", {"agent": row.agent, "reason": reason}, jti=jti)
    return {"ok": True}


def op_kill(space: str, on: bool) -> dict:
    with db.write_lock, db.engine.begin() as conn:
        db.set_setting(conn, space, "kill_all", "on" if on else "off")
        audit.append(conn, space, "KILL_SWITCH_ON" if on else "KILL_SWITCH_OFF", {"by": "operator"})
        if on:
            _alert(conn, space, "KILL_SWITCH", "Global kill switch turned on. Every agent is stopped.")
    return {"kill_all": on}


def op_audit(space: str, limit: int) -> list:
    limit = max(1, min(limit, 500))
    a = db.audit.c
    with db.engine.connect() as conn:
        rows = conn.execute(select(db.audit).where(a.space == space).order_by(a.id.desc()).limit(limit)).all()
    out = []
    for r in rows:
        try:
            detail = json.loads(r.detail)
        except json.JSONDecodeError:
            detail = {"unreadable": r.detail[:80]}
        out.append({"id": r.id, "ts_ms": r.ts_ms, "jti": r.jti, "event": r.event, "detail": detail, "prev_hash": r.prev_hash, "hash": r.hash})
    return out


def op_verify(space: str) -> dict:
    with db.engine.connect() as conn:
        return audit.verify_chain(conn, space)


def op_alerts(space: str) -> list:
    al = db.alerts.c
    with db.engine.connect() as conn:
        rows = conn.execute(select(db.alerts).where(al.space == space).order_by(al.id.desc()).limit(30)).all()
    return [{"id": r.id, "ts_ms": r.ts_ms, "kind": r.kind, "message": r.message, "jti": r.jti} for r in rows]


def op_canaries(space: str) -> list:
    with db.engine.connect() as conn:
        return guards.list_canaries(conn, space)


def op_stats(space: str) -> dict:
    now = time.time()
    t, a = db.tokens.c, db.audit.c
    with db.engine.connect() as conn:
        active = conn.execute(
            select(func.count())
            .select_from(db.tokens)
            .where(t.space == space, t.revoked.is_(False), t.exp > now, t.calls_used < t.max_calls, t.spent_usd < t.budget_usd - 1e-9)
        ).scalar()
        allowed = conn.execute(select(func.count()).select_from(db.audit).where(a.space == space, a.event == "CALL_ALLOWED")).scalar()
        blocked = conn.execute(
            select(func.count())
            .select_from(db.audit)
            .where(a.space == space, a.event.in_(["CALL_BLOCKED", "CANARY_TRIGGERED", "RAW_KEY_REJECTED"]))
        ).scalar()
        spent = conn.execute(select(func.coalesce(func.sum(t.spent_usd), 0.0)).where(t.space == space)).scalar()
        alerts_count = conn.execute(select(func.count()).select_from(db.alerts).where(db.alerts.c.space == space)).scalar()
        kill_all = db.get_setting(conn, space, "kill_all") == "on"
        sandboxes = conn.execute(select(func.count()).select_from(db.spaces).where(db.spaces.c.space.startswith("sb_", autoescape=True))).scalar()
        workspaces = conn.execute(select(func.count()).select_from(db.accounts)).scalar()
    stats = {
        "active_tokens": active,
        "calls_allowed": allowed,
        "calls_blocked": blocked,
        "spent_usd": round(spent or 0.0, 6),
        "alerts": alerts_count,
        "kill_all": kill_all,
    }
    if space == db.MAIN:
        stats["public_sandboxes"] = sandboxes
        stats["customer_workspaces"] = workspaces
    return stats


def op_tamper(space: str, target: str = "cost", jti: str = "") -> dict:
    """Simulate an attacker with database access quietly editing history.

    target="cost": rewrite the latest allowed call to say it cost nothing
    (hiding a runaway bill). target="attack": rewrite the record of the
    latest blocked attack to say nothing happened (covering it up).
    """
    a = db.audit.c
    with db.write_lock, db.engine.begin() as conn:
        row = None
        if target == "attack":
            row = conn.execute(
                select(db.audit)
                .where(a.space == space, a.event.in_(["CANARY_TRIGGERED", "CALL_BLOCKED"]))
                .order_by((a.event == "CANARY_TRIGGERED").desc(), a.id.desc())
                .limit(1)
            ).first()
        if row is None and jti:
            row = conn.execute(
                select(db.audit).where(a.space == space, a.event == "CALL_ALLOWED", a.jti == jti).order_by(a.id.desc()).limit(1)
            ).first()
        if row is None:
            row = conn.execute(
                select(db.audit).where(a.space == space, a.event == "CALL_ALLOWED").order_by(a.id.desc()).limit(1)
            ).first()
        if row is None:
            row = conn.execute(select(db.audit).where(a.space == space).order_by(a.id.desc()).limit(1)).first()
        detail = json.loads(row.detail)
        before = dict(detail)
        if row.event == "CANARY_TRIGGERED":
            detail["planted_in"] = "nothing suspicious, routine check"
        elif row.event == "CALL_BLOCKED":
            detail["reason"] = "Nothing suspicious happened."
        elif "cost_usd" in detail:
            detail["cost_usd"] = 0.0
            detail["spent_usd"] = 0.0
        else:
            detail["note"] = "edited"
        conn.execute(
            db.audit.update()
            .where(a.space == space, a.id == row.id)
            .values(detail=json.dumps(detail, sort_keys=True, separators=(",", ":")))
        )
    return {"tampered_id": row.id, "event": row.event, "before": before, "after": detail}


def op_receipt(space: str, jti: str) -> dict:
    """Leash's own account of one pass: built from the sealed log, not from the agent."""
    a, t = db.audit.c, db.tokens.c
    with db.engine.connect() as conn:
        token = conn.execute(select(db.tokens).where(t.jti == jti, t.space == space)).first()
        if token is None:
            raise HTTPException(404, "No pass with that id.")
        rows = conn.execute(select(db.audit).where(a.space == space, a.jti == jti).order_by(a.id)).all()
        seal = audit.verify_chain(conn, space)
    allowed = [r for r in rows if r.event == "CALL_ALLOWED"]
    blocked = [r for r in rows if r.event == "CALL_BLOCKED"]
    last_block = json.loads(blocked[-1].detail) if blocked else {}
    logged_cost = sum(float(json.loads(r.detail).get("cost_usd") or 0) for r in allowed)
    return {
        "agent": token.agent,
        "calls_allowed": len(allowed),
        "calls_blocked": len(blocked),
        "spent_usd": round(token.spent_usd, 8),
        "logged_cost_usd": round(logged_cost, 8),
        "budget_usd": token.budget_usd,
        "stopped_by": last_block.get("code"),
        "stop_reason": last_block.get("reason"),
        "first_entry": rows[0].id if rows else None,
        "last_entry": rows[-1].id if rows else None,
        "last_seal": rows[-1].hash if rows else None,
        "seal": seal,
    }


def op_seal_test(space: str, jti: str) -> dict:
    """Show the seal at work without touching the real log: copy the log, edit
    one entry in the copy the way a cover-up would, and check the copy."""
    a = db.audit.c
    with db.engine.connect() as conn:
        rows = [dict(r._mapping) for r in conn.execute(select(db.audit).where(a.space == space).order_by(a.id)).all()]
    allowed = [r for r in rows if r["event"] == "CALL_ALLOWED" and (not jti or r["jti"] == jti)]
    if not allowed:
        raise HTTPException(404, "There's no allowed call in the log to test with yet. Run an agent first.")
    target = allowed[-1]
    detail = json.loads(target["detail"])
    before = dict(detail)
    detail["cost_usd"] = 0.0
    detail["spent_usd"] = 0.0
    target["detail"] = json.dumps(detail, sort_keys=True, separators=(",", ":"))
    copy = [type("Row", (), r) for r in rows]
    result = audit.verify_rows(space, copy)
    return {"tampered_id": target["id"], "before": before, "after": detail, "result": result, "copy": True}


def _wipe_space(conn, space: str) -> None:
    conn.execute(db.audit.delete().where(db.audit.c.space == space))
    conn.execute(db.tokens.delete().where(db.tokens.c.space == space))
    conn.execute(db.alerts.delete().where(db.alerts.c.space == space))
    conn.execute(db.settings.delete().where(db.settings.c.key == f"{space}:kill_all"))


def _tamper_flag(conn_id: str) -> str:
    return f"tampered:{conn_id}"


def _is_tampered(conn, space: str, conn_id: str) -> bool:
    return db.get_setting(conn, space, _tamper_flag(conn_id)) == "1"


def _drop_connection(conn, space: str, conn_id: str) -> None:
    conn.execute(db.connections.delete().where(db.connections.c.id == conn_id, db.connections.c.space == space))
    conn.execute(db.settings.delete().where(db.settings.c.key == f"{space}:{_tamper_flag(conn_id)}"))


def op_reset(space: str) -> dict:
    with db.write_lock, db.engine.begin() as conn:
        _wipe_space(conn, space)
        # Working saved keys survive a reset; removed or tampered ones are cleared out.
        for row in conn.execute(select(db.connections).where(db.connections.c.space == space)).all():
            if row.revoked or _is_tampered(conn, space, row.id):
                _drop_connection(conn, space, row.id)
        audit.append(conn, space, "LOG_STARTED", {"note": "Demo reset. New audit chain created."})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Bring your own key: stored provider keys, encrypted (see keyvault.py)
# ---------------------------------------------------------------------------
class ConnectionRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    base_url: str = Field(default="https://api.openai.com/v1", min_length=8, max_length=200)
    model: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9._:/\-]+$")
    api_key: str = Field(min_length=8, max_length=300)


def _check_base_url(url: str) -> str:
    """Only HTTPS endpoints (plain HTTP just for localhost during development)."""
    parsed = urlparse(url.strip())
    local = parsed.hostname in ("localhost", "127.0.0.1")
    if parsed.scheme not in ("https", "http") or (parsed.scheme == "http" and not local):
        raise HTTPException(400, "The base URL must start with https://")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(400, "The base URL should look like https://api.example.com/v1")
    return url.strip().rstrip("/")


def _connection_view(row, tampered: bool = False) -> dict:
    """What the dashboard may see. Never the key, only proof that it's encrypted."""
    erased = not row.ciphertext
    return {
        "id": row.id,
        "name": row.name,
        "base_url": row.base_url,
        "model": row.model,
        "key_hint": row.key_hint,
        "fingerprint": row.key_fingerprint[:16],
        "status": "removed" if row.revoked else ("tampered" if tampered else "active"),
        "created_ms": row.created_ms,
        "stored": {
            "algorithm": keyvault.ALGORITHM,
            "ciphertext": "(erased)" if erased else row.ciphertext[:40] + "…",
            "wrapped_data_key": "(erased)" if erased else row.wrapped_dek[:40] + "…",
            "master_key_id": row.kek_id,
            "master_key_location": "Environment variable on the server, never in the database",
        },
    }


def op_list_connections(space: str) -> list:
    c = db.connections.c
    with db.engine.connect() as conn:
        rows = conn.execute(
            select(db.connections).where(c.space == space, c.revoked.is_(False)).order_by(c.created_ms.desc())
        ).all()
        return [_connection_view(r, _is_tampered(conn, space, r.id)) for r in rows]


def op_add_connection(space: str, req: ConnectionRequest) -> dict:
    api_key = req.api_key.strip()
    if any(ch.isspace() for ch in api_key):
        raise HTTPException(400, "The API key can't contain spaces.")
    base_url = _check_base_url(req.base_url)
    limit = _tier(space)["max_keys"]
    fingerprint = keyvault.fingerprint(api_key)
    c = db.connections.c
    with db.write_lock, db.engine.begin() as conn:
        active = conn.execute(select(db.connections).where(c.space == space, c.revoked.is_(False))).all()
        if len(active) >= limit:
            raise HTTPException(429, f"You can store up to {limit} provider keys here. Remove one first.")
        for existing in active:
            if hmac.compare_digest(existing.key_fingerprint, fingerprint):
                raise HTTPException(409, f"This key is already stored as '{existing.name}'.")
        conn_id = "c_" + secrets.token_hex(6)
        sealed = keyvault.seal(api_key, space, conn_id)
        conn.execute(
            db.connections.insert().values(
                id=conn_id,
                space=space,
                name=req.name.strip(),
                base_url=base_url,
                model=req.model,
                key_hint=keyvault.hint(api_key),
                key_fingerprint=fingerprint,
                ciphertext=sealed["ciphertext"],
                wrapped_dek=sealed["wrapped_dek"],
                kek_id=sealed["kek_id"],
                created_ms=_now_ms(),
                revoked=False,
            )
        )
        audit.append(
            conn,
            space,
            "KEY_STORED",
            {
                "name": req.name.strip(),
                "model": req.model,
                "base_url": base_url,
                "key_hint": keyvault.hint(api_key),
                "key_fingerprint": fingerprint[:16],
                "master_key_id": sealed["kek_id"],
            },
        )
        row = conn.execute(select(db.connections).where(c.id == conn_id)).first()
    del api_key
    return _connection_view(row)


def op_remove_connection(space: str, conn_id: str) -> dict:
    """Remove a stored key by erasing its ciphertext and wrapped data key
    ("crypto-shredding"). Tokens issued for it stop working immediately."""
    c = db.connections.c
    with db.write_lock, db.engine.begin() as conn:
        row = conn.execute(select(db.connections).where(c.id == conn_id, c.space == space)).first()
        if row is None:
            raise HTTPException(404, "No stored provider key with that id.")
        if not row.revoked:
            conn.execute(db.connections.update().where(c.id == conn_id).values(revoked=True, ciphertext="", wrapped_dek=""))
            conn.execute(db.settings.delete().where(db.settings.c.key == f"{space}:{_tamper_flag(conn_id)}"))
            audit.append(conn, space, "KEY_REMOVED", {"name": row.name, "key_hint": row.key_hint, "note": "Ciphertext and data key erased."})
    return {"ok": True, "name": row.name}


def op_test_connection(space: str, conn_id: str) -> dict:
    """Issue a tiny token for the stored key and send one call through the full proxy."""
    c = db.connections.c
    with db.engine.connect() as conn:
        row = conn.execute(select(db.connections).where(c.id == conn_id, c.space == space)).first()
    if row is None or row.revoked:
        raise HTTPException(404, "No stored provider key with that id.")
    issued = op_issue(space, IssueRequest(agent="key-test", upstream=conn_id, ttl_minutes=5, max_calls=3, budget_usd=0.05))
    body = {"model": row.model, "messages": [{"role": "user", "content": "In one short sentence: why should AI agents use short-lived, limited credentials?"}]}
    response = _handle_proxy(issued["token"], body, "internal")
    data = json.loads(response.body)
    if response.status_code == 200:
        reply = (data.get("choices") or [{}])[0].get("message", {}).get("content") or "(empty reply)"
        return {"ok": True, "reply": reply, "fake": is_sandbox(space)}
    error = data.get("error", {})
    return {"ok": False, "code": error.get("code"), "reply": error.get("message", "The call failed.")}


def op_tamper_key(space: str, conn_id: str) -> dict:
    """Demo: an attacker with database access flips one bit of a stored key's ciphertext."""
    c = db.connections.c
    with db.write_lock, db.engine.begin() as conn:
        row = conn.execute(select(db.connections).where(c.id == conn_id, c.space == space)).first()
        if row is None or row.revoked:
            raise HTTPException(404, "No stored provider key with that id.")
        raw = bytearray(base64.b64decode(row.ciphertext))
        raw[-1] ^= 0x01
        conn.execute(db.connections.update().where(c.id == conn_id).values(ciphertext=base64.b64encode(bytes(raw)).decode()))
    return {"ok": True}


def mount_space_routes(router: APIRouter, get_space, demo: bool = True, webhooks: bool = True) -> None:
    """The same endpoints for the operator (/api), sandboxes (/api/sb) and
    customer workspaces (/api/ws). Workspaces get no demo buttons (tampering,
    reset); sandboxes get no Slack or Discord alerts."""

    @router.get("/config")
    def _config(space: str = Depends(get_space)):
        return op_config(space)

    @router.post("/tokens")
    def _issue(req: IssueRequest, space: str = Depends(get_space)):
        return op_issue(space, req)

    @router.get("/tokens")
    def _tokens(space: str = Depends(get_space)):
        return op_list_tokens(space)

    @router.post("/tokens/{jti}/revoke")
    def _revoke(jti: str, req: RevokeRequest, space: str = Depends(get_space)):
        return op_revoke(space, jti, req.reason)

    @router.post("/kill")
    def _kill(req: KillRequest, space: str = Depends(get_space)):
        return op_kill(space, req.on)

    @router.get("/audit")
    def _audit(limit: int = 60, space: str = Depends(get_space)):
        return op_audit(space, limit)

    @router.get("/audit/verify")
    def _verify(space: str = Depends(get_space)):
        return op_verify(space)

    @router.get("/alerts")
    def _alerts(space: str = Depends(get_space)):
        return op_alerts(space)

    @router.get("/canaries")
    def _canaries(space: str = Depends(get_space)):
        return op_canaries(space)

    @router.get("/stats")
    def _stats(space: str = Depends(get_space)):
        return op_stats(space)

    @router.get("/tokens/{jti}/receipt")
    def _receipt(jti: str, space: str = Depends(get_space)):
        return op_receipt(space, jti)

    @router.post("/audit/seal-test")
    def _seal_test(jti: str = "", space: str = Depends(get_space)):
        return op_seal_test(space, jti[:32])

    @router.get("/connections")
    def _connections(space: str = Depends(get_space)):
        return op_list_connections(space)

    @router.post("/connections")
    def _add_connection(req: ConnectionRequest, space: str = Depends(get_space)):
        return op_add_connection(space, req)

    @router.post("/connections/{conn_id}/remove")
    def _remove_connection(conn_id: str, space: str = Depends(get_space)):
        return op_remove_connection(space, conn_id)

    @router.post("/connections/{conn_id}/test")
    def _test_connection(conn_id: str, space: str = Depends(get_space)):
        return op_test_connection(space, conn_id)

    if webhooks:

        @router.get("/webhook")
        def _webhook(space: str = Depends(get_space)):
            with db.engine.connect() as conn:
                return notify.view(conn, space)

        @router.post("/webhook")
        def _set_webhook(req: WebhookRequest, space: str = Depends(get_space)):
            return op_set_webhook(space, req.url)

        @router.post("/webhook/remove")
        def _remove_webhook(space: str = Depends(get_space)):
            with db.write_lock, db.engine.begin() as conn:
                notify.remove(conn, space)
                audit.append(conn, space, "ALERTS_DISCONNECTED", {"note": "Slack or Discord alerts turned off."})
            return {"set": False}

        @router.post("/webhook/test")
        def _test_webhook(space: str = Depends(get_space)):
            with db.engine.connect() as conn:
                return notify.send_test(conn, space)

    if demo:

        @router.post("/demo/tamper")
        def _tamper(target: str = "cost", jti: str = "", space: str = Depends(get_space)):
            return op_tamper(space, "attack" if target == "attack" else "cost", jti[:32])

        @router.post("/demo/tamper-key/{conn_id}")
        def _tamper_key(conn_id: str, space: str = Depends(get_space)):
            return op_tamper_key(space, conn_id)

        @router.post("/demo/reset")
        def _reset(space: str = Depends(get_space)):
            return op_reset(space)


class WebhookRequest(BaseModel):
    url: str = Field(min_length=20, max_length=500)


def op_set_webhook(space: str, url: str) -> dict:
    try:
        with db.write_lock, db.engine.begin() as conn:
            view = notify.save(conn, space, url)
            audit.append(conn, space, "ALERTS_CONNECTED", {"service": view["kind"], "webhook": view["hint"]})
    except notify.WebhookError as err:
        raise HTTPException(400, str(err))
    return view


# ---------------------------------------------------------------------------
# Operator API: password required, works on the "main" space
# ---------------------------------------------------------------------------
def operator_space(request: Request, x_admin_key: str = Header(default="")) -> str:
    ip = client_ip(request)
    if not hmac.compare_digest(x_admin_key.encode(), config.ADMIN_PASSWORD.encode()):
        # Slow down password guessing.
        if not limiter.allow(f"admin-fail:{ip}", 10, 300):
            raise HTTPException(429, "Too many wrong passwords. Wait a few minutes.")
        raise HTTPException(401, "Wrong or missing admin password.")
    return db.MAIN


operator_router = APIRouter(prefix="/api")
mount_space_routes(operator_router, operator_space)
app.include_router(operator_router)


# ---------------------------------------------------------------------------
# Sandbox API: no password, one isolated space per visitor (cookie), fake
# upstream only, rate-limited, deleted after a few hours.
# ---------------------------------------------------------------------------
def _sandbox_checks(request: Request) -> None:
    if not config.SANDBOX_ENABLED:
        raise HTTPException(404, "The public sandbox is turned off.")
    # A custom header can't be sent cross-site without a CORS preflight,
    # which this server never grants: that blocks cross-site request forgery.
    if request.headers.get("x-leash-sandbox") != "1":
        raise HTTPException(403, "Missing sandbox header.")
    if not limiter.allow(f"sandbox-api:{client_ip(request)}", 300, 60):
        raise HTTPException(429, "Too many requests. Slow down and try again in a minute.")


def sandbox_space(request: Request) -> str:
    _sandbox_checks(request)
    sid = request.cookies.get(SANDBOX_COOKIE, "")
    if _SANDBOX_ID.fullmatch(sid):
        space = f"sb_{sid}"
        with db.engine.connect() as conn:
            if conn.execute(select(db.spaces.c.space).where(db.spaces.c.space == space)).first():
                return space
    raise HTTPException(401, "Your sandbox session has expired. Reload the page.")


_last_cleanup = 0.0


def _cleanup_sandboxes(conn) -> None:
    """Delete sandboxes older than the time limit. Hold db.write_lock."""
    global _last_cleanup
    if time.time() - _last_cleanup < 60:
        return
    _last_cleanup = time.time()
    cutoff = _now_ms() - config.SANDBOX_TTL_HOURS * 3600 * 1000
    # Only public sandboxes expire. Customer workspaces ("acct_") are never touched.
    old = conn.execute(
        select(db.spaces.c.space).where(db.spaces.c.space.startswith("sb_", autoescape=True), db.spaces.c.created_ms < cutoff)
    ).scalars().all()
    for space in old:
        _wipe_space(conn, space)
        conn.execute(db.canaries.delete().where(db.canaries.c.space == space))
        conn.execute(db.connections.delete().where(db.connections.c.space == space))
        conn.execute(db.settings.delete().where(db.settings.c.key.like(f"{space}:%")))
        conn.execute(db.spaces.delete().where(db.spaces.c.space == space))


sandbox_router = APIRouter(prefix="/api/sb")


@sandbox_router.post("/session")
def sandbox_session(request: Request, response: Response):
    """Reuse the visitor's sandbox if it still exists, otherwise create one."""
    _sandbox_checks(request)
    sid = request.cookies.get(SANDBOX_COOKIE, "")
    with db.write_lock, db.engine.begin() as conn:
        _cleanup_sandboxes(conn)
        if _SANDBOX_ID.fullmatch(sid):
            space = f"sb_{sid}"
            if conn.execute(select(db.spaces.c.space).where(db.spaces.c.space == space)).first():
                guards.plant_canaries(conn, space)  # adds any trap keys introduced since it was created
                return {"ok": True, "new": False}
        if not limiter.allow(f"sandbox-new:{client_ip(request)}", 20, 3600):
            raise HTTPException(429, "Too many new sandboxes from your network. Try again later.")
        active = conn.execute(
            select(func.count()).select_from(db.spaces).where(db.spaces.c.space.startswith("sb_", autoescape=True))
        ).scalar()
        if active >= config.SANDBOX_MAX_SPACES:
            raise HTTPException(503, "The sandbox is busy right now. Please try again in a few minutes.")
        sid = secrets.token_hex(12)
        ensure_space(conn, f"sb_{sid}")
    secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
    response.set_cookie(
        SANDBOX_COOKIE,
        sid,
        max_age=config.SANDBOX_TTL_HOURS * 3600,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )
    return {"ok": True, "new": True}


mount_space_routes(sandbox_router, sandbox_space, webhooks=False)
app.include_router(sandbox_router)


# ---------------------------------------------------------------------------
# Customer accounts: sign up, log in, and a private workspace per team.
# Workspaces use the same checks as everything else, with real calls through
# the team's own saved keys and Slack or Discord alerts.
# ---------------------------------------------------------------------------
class SignupRequest(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=200)
    team: str = Field(max_length=80)


class LoginRequest(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=200)


_dummy_hash = ""


def _account_checks(request: Request) -> None:
    if not config.ACCOUNTS_ENABLED:
        raise HTTPException(404, "Accounts are turned off on this server.")
    # Same cross-site request forgery defence as the sandbox: a custom header.
    if request.headers.get("x-leash-app") != "1":
        raise HTTPException(403, "Missing app header.")


def _set_session(request: Request, response: Response, account_id: str) -> None:
    secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
    response.set_cookie(
        accounts.COOKIE,
        accounts.make_session(account_id),
        max_age=accounts.SESSION_DAYS * 86400,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )


def _account_summary(conn, row) -> dict:
    space = row.space
    t, c = db.tokens.c, db.connections.c
    keys = conn.execute(select(func.count()).select_from(db.connections).where(c.space == space, c.revoked.is_(False))).scalar()
    # Passes made by the "Test it" button on a saved key don't count as agents.
    # Passes made by the "Test it" button or the test agent don't count as your agents.
    agents = conn.execute(
        select(func.count()).select_from(db.tokens).where(t.space == space, t.agent.notin_(["key-test", "task-agent", "task-agent-report"]))
    ).scalar()
    return {
        "email": row.email,
        "team": row.team,
        "created_ms": row.created_ms,
        "setup": {"keys": keys, "agents": agents, "alerts": notify.view(conn, space)["set"]},
    }


account_router = APIRouter(prefix="/api/account")


@account_router.post("/signup")
def account_signup(req: SignupRequest, request: Request, response: Response):
    _account_checks(request)
    if not limiter.allow(f"signup:{client_ip(request)}", 5, 3600):
        raise HTTPException(429, "Too many sign-ups from your network. Try again later.")
    email = accounts.normalise_email(req.email)
    team = " ".join(req.team.split())
    if not accounts.EMAIL_RE.fullmatch(email):
        raise HTTPException(400, "Enter a valid email address.")
    if not team:
        raise HTTPException(400, "Enter your team or company name.")
    if len(req.password) < 10:
        raise HTTPException(400, "Use at least 10 characters for your password.")
    password_hash = accounts.hash_password(req.password)  # slow on purpose, so done outside the lock
    with db.write_lock, db.engine.begin() as conn:
        a = db.accounts.c
        if conn.execute(select(func.count()).select_from(db.accounts)).scalar() >= config.ACCOUNT_MAX:
            raise HTTPException(503, "Sign-ups are full right now. Please try again later.")
        if conn.execute(select(a.id).where(a.email == email)).first():
            raise HTTPException(409, "An account with this email already exists. Log in instead.")
        account_id = secrets.token_hex(8)
        space = f"acct_{account_id}"
        conn.execute(
            db.accounts.insert().values(
                id=account_id, email=email, team=team, password_hash=password_hash, space=space, created_ms=_now_ms()
            )
        )
        ensure_space(conn, space)
        audit.append(conn, space, "ACCOUNT_CREATED", {"team": team})
    _set_session(request, response, account_id)
    return {"ok": True}


@account_router.post("/login")
def account_login(req: LoginRequest, request: Request, response: Response):
    global _dummy_hash
    _account_checks(request)
    email = accounts.normalise_email(req.email)
    if not limiter.allow(f"login:{client_ip(request)}", 20, 300) or not limiter.allow(f"login-email:{email}", 10, 300):
        raise HTTPException(429, "Too many attempts. Wait a few minutes and try again.")
    with db.engine.connect() as conn:
        row = conn.execute(select(db.accounts).where(db.accounts.c.email == email)).first()
    if row is None:
        # Spend the same time as a real check, so response times don't reveal
        # which emails have accounts.
        _dummy_hash = _dummy_hash or accounts.hash_password(secrets.token_hex(8))
        accounts.verify_password(req.password, _dummy_hash)
        raise HTTPException(401, "Wrong email or password.")
    if not accounts.verify_password(req.password, row.password_hash):
        raise HTTPException(401, "Wrong email or password.")
    _set_session(request, response, row.id)
    return {"ok": True}


@account_router.post("/logout")
def account_logout(request: Request, response: Response):
    _account_checks(request)
    response.delete_cookie(accounts.COOKIE, path="/")
    return {"ok": True}


@account_router.get("/me")
def account_me(request: Request):
    _account_checks(request)
    row = _session_account(request)
    if row is None:
        raise HTTPException(401, "Please log in.")
    with db.engine.connect() as conn:
        return _account_summary(conn, row)


app.include_router(account_router)


def workspace_space(request: Request) -> str:
    _account_checks(request)
    row = _session_account(request)
    if row is None:
        raise HTTPException(401, "Your session has ended. Please log in again.")
    if not limiter.allow(f"ws-api:{row.id}", 300, 60):
        raise HTTPException(429, "Too many requests. Slow down and try again in a minute.")
    return row.space


workspace_router = APIRouter(prefix="/api/ws")
mount_space_routes(workspace_router, workspace_space, demo=False)
app.include_router(workspace_router)
