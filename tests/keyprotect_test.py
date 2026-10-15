"""Attacker's-eye tests for workspace key protection.

Run from the repo root:  python tests/keyprotect_test.py
(set TEST_DB to a Postgres URL to run against Postgres instead of a temporary SQLite file).

Plays someone who has stolen a full copy of the database AND the master key
(and, in places, even the signing secret), and checks they still can't read a
team's API key or make calls with it.
"""
import base64, json, os, sys, tempfile, time
DBURL = os.environ.get("TEST_DB") or f"sqlite:///{tempfile.mkdtemp()}/k.db"
os.environ.update(SIGNING_SECRET="k-secret", ADMIN_PASSWORD="demo123", KEY_ENCRYPTION_KEY="k-kek", DATABASE_URL=DBURL,
                  OPENAI_API_KEY="", OPENAI_MODEL="")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the repo root
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from app import main, upstream, db, keyvault, tokens, accounts, config

REAL_KEY = "sk-proj-VERYSECRET-abcdef1234567890"
calls = []
def fake_real(body, base_url="", api_key=""):
    calls.append(api_key)
    return {"id": "x", "model": body["model"], "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
upstream.openai_completion = fake_real

H = {"X-Leash-App": "1"}
ok = 0
def check(cond, label):
    global ok
    if not cond:
        print("FAIL:", label); sys.exit(1)
    ok += 1

def dump_db():
    """Everything an attacker would get from a database copy."""
    with db.engine.connect() as c:
        out = {}
        for t in db.metadata.sorted_tables:
            out[t.name] = [dict(r._mapping) for r in c.execute(select(t)).all()]
        return out

body = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}

with TestClient(main.app) as a, TestClient(main.app) as anon:
    r = a.post("/api/account/signup", json={"email": "kim@shop.test", "password": "correct-horse-1", "team": "Kim's"}, headers=H)
    check(r.status_code == 200, "signup")
    r = a.post("/api/ws/connections", json={"name": "Prod", "base_url": "https://api.example.com/v1", "model": "gpt-4o-mini",
                                             "api_key": REAL_KEY}, headers=H)
    check(r.status_code == 200, f"save key {r.text}")
    cid = r.json()["id"]
    keys = a.get("/api/ws/connections", headers=H).json()
    view = [k for k in keys if k["id"] == cid][0]
    check("password-derived" in view["stored"]["algorithm"], "key view explains the password lock")
    check("Neither one alone" in view["stored"]["master_key_location"], "key view explains both locks")

    r = a.post("/api/ws/tokens", json={"agent": "bot", "upstream": cid, "ttl_minutes": 60, "max_calls": 20, "budget_usd": 1}, headers=H)
    check(r.status_code == 200, f"issue {r.text}")
    tok, shown = r.json()["token"], r.json()["claims"]
    check("k" not in shown and shown.get("key_unlock") == "inside this pass", "unlock code not repeated in readable claims")
    real_claims = tokens.verify(tok)
    check(isinstance(real_claims.get("k"), str) and len(real_claims["k"]) >= 20, "pass carries its unlock code")
    jti = real_claims["jti"]

    r = anon.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {tok}"})
    check(r.status_code == 200 and calls[-1] == REAL_KEY, f"pass works {r.text}")

    # ---- The attacker: full DB copy + master key ------------------------------
    dump = dump_db()
    blob = json.dumps(dump, default=str)
    check(REAL_KEY not in blob and "VERYSECRET" not in blob, "API key isn't anywhere in the database")
    check(real_claims["k"] not in blob, "unlock code isn't anywhere in the database")
    check(tok not in blob and tok.split(".")[1] not in blob, "pass isn't anywhere in the database")
    check("correct-horse-1" not in blob, "password isn't in the database")
    row = [x for x in dump["leash_connections"] if x["id"] == cid][0]
    check(row["kek_id"] == keyvault.ACCOUNT_KEK_ID, "workspace key is locked with the account key")
    space = row["space"]
    try:
        keyvault.unseal(row["ciphertext"], row["wrapped_dek"], space, cid)  # master key only
        check(False, "DB + master key opened the key")
    except keyvault.KeyIntegrityError:
        check(True, "DB + master key can't open the key")
    pk = [x for x in dump["leash_pass_keys"] if x["jti"] == jti][0]
    for guess in (b"", b"\x00" * 16, os.urandom(16)):
        try:
            keyvault.unseal_with_pass(row["ciphertext"], pk["wrapped_dek"], guess, space, cid, jti)
            check(False, "guessed pass secret worked")
        except keyvault.KeyIntegrityError:
            check(True, "pass copy needs the real unlock code")
    # The password hash is in the DB, but the account key is a different scrypt (different salt key).
    acct = dump["leash_accounts"][0]
    try:
        wrong = accounts.user_key("not-the-password", acct["id"])
        keyvault.unseal(row["ciphertext"], row["wrapped_dek"], space, cid, keyvault.account_key(wrong))
        check(False, "wrong password opened key")
    except keyvault.KeyIntegrityError:
        check(True, "wrong password can't open the key")
    right = accounts.user_key("correct-horse-1", acct["id"])
    check(keyvault.unseal(row["ciphertext"], row["wrapped_dek"], space, cid, keyvault.account_key(right)) == REAL_KEY,
          "the real password (plus master key) does open it")

    # ---- Even with the signing secret, a forged pass can't use the key ----------
    forged, fc = tokens.mint(space, "evil", cid, 60, 50, 5.0)  # no unlock code
    r = anon.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {forged}"})
    check(r.status_code == 401 and r.json()["error"]["code"] == "UNKNOWN_TOKEN", "forged pass not on record is refused")
    # The attacker can also write to the database: add a record for the forged pass.
    with db.engine.begin() as c:
        c.execute(db.tokens.insert().values(jti=fc["jti"], space=space, agent="evil", upstream=cid, created_ms=0, exp=fc["exp"],
                                            max_calls=50, budget_usd=5.0, calls_used=0, spent_usd=0.0, revoked=False))
    r = anon.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {forged}"})
    check(r.status_code == 403 and r.json()["error"]["code"] == "PASS_CANT_UNLOCK", f"forged pass with no row {r.text}")
    # Forge a pass reusing the real jti (its row exists) but with a guessed unlock code.
    forged2, _ = tokens.mint(space, "evil", cid, 60, 50, 5.0, jti=jti, unlock=base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("="))
    n = len(calls)
    r = anon.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {forged2}"})
    check(r.status_code == 403 and r.json()["error"]["code"] == "PASS_CANT_UNLOCK", f"forged pass with wrong code {r.text}")
    check(len(calls) == n, "no upstream call was made for forged passes")
    keys = a.get("/api/ws/connections", headers=H).json()
    check([k for k in keys if k["id"] == cid][0]["status"] == "active", "a bad pass doesn't mark the real key as tampered")
    r = anon.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {tok}"})
    check(r.status_code == 200 and calls[-1] == REAL_KEY, "real pass still works afterwards")
    # A pass for a different workspace key can't borrow another pass's row
    forged3, _ = tokens.mint(space, "evil", "c_000000000000", 60, 50, 5.0, jti=jti, unlock=real_claims["k"])
    r = anon.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {forged3}"})
    check(r.status_code == 403, "pass row is bound to its key")

    # ---- Tampering with the stored key is still caught ----------------------------
    r = a.post(f"/api/ws/connections/{cid}/test", headers=H)
    check(r.status_code == 200 and r.json()["ok"], f"test key {r.text}")
    with db.engine.connect() as c:
        left = c.execute(select(db.pass_keys).where(db.pass_keys.c.space == space)).all()
    check(len(left) == 1 and left[0].jti == jti, "key test doesn't leave a pass lock behind")

    # ---- Stopping a pass drops its lock ---------------------------------------------
    r = a.post(f"/api/ws/tokens/{jti}/revoke", json={"reason": "test"}, headers=H)
    check(r.status_code == 200, f"revoke {r.text}")
    with db.engine.connect() as c:
        check(c.execute(select(db.pass_keys).where(db.pass_keys.c.jti == jti)).first() is None, "revoked pass loses its lock")
    r = anon.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {tok}"})
    check(r.status_code in (401, 403), "revoked pass refused")

    # ---- Old sessions (no key inside) count as signed out --------------------------
    old_body = accounts._b64e(json.dumps({"a": acct["id"], "exp": int(time.time()) + 3600}, separators=(",", ":")).encode())
    old_cookie = f"{old_body}.{accounts._sign(old_body)}"
    with TestClient(main.app) as old:
        old.cookies.set("leash_session", old_cookie)
        check(old.get("/api/ws/config", headers=H).status_code == 401, "pre-upgrade session is signed out")
    # A session's key can't be moved to another account
    sess = accounts.read_session(a.cookies.get("leash_session"))
    check(sess and sess[0] == acct["id"] and sess[1] == right, "session carries the account key")
    claims = json.loads(accounts._b64d(a.cookies.get("leash_session").split(".")[0]))
    check(claims["k"] and right.hex() not in json.dumps(claims) and accounts._b64e(right) not in json.dumps(claims),
          "account key is encrypted inside the cookie")

    # ---- Keys saved before the upgrade get re-locked at the next login ------------
    r = a.post("/api/ws/connections", json={"name": "Legacy", "base_url": "https://api.example.com/v1", "model": "gpt-4o-mini",
                                             "api_key": "sk-legacy-OLDKEY-0987654321"}, headers=H)
    lid = r.json()["id"]
    legacy = keyvault.seal("sk-legacy-OLDKEY-0987654321", space, lid)  # how it was stored before
    with db.engine.begin() as c:
        c.execute(db.connections.update().where(db.connections.c.id == lid).values(
            ciphertext=legacy["ciphertext"], wrapped_dek=legacy["wrapped_dek"], kek_id=legacy["kek_id"]))
    r = a.post("/api/ws/tokens", json={"agent": "legacy-bot", "upstream": lid, "ttl_minutes": 60, "max_calls": 5, "budget_usd": 1}, headers=H)
    ltok = r.json()["token"]
    r = anon.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {ltok}"})
    check(r.status_code == 200 and calls[-1] == "sk-legacy-OLDKEY-0987654321", "legacy key still works before login")
    a.post("/api/account/logout", headers=H)
    r = a.post("/api/account/login", json={"email": "kim@shop.test", "password": "correct-horse-1"}, headers=H)
    check(r.status_code == 200, "login")
    with db.engine.connect() as c:
        lrow = c.execute(select(db.connections).where(db.connections.c.id == lid)).first()
    check(lrow.kek_id == keyvault.ACCOUNT_KEK_ID, "legacy key re-locked at login")
    try:
        keyvault.unseal(lrow.ciphertext, lrow.wrapped_dek, space, lid)
        check(False, "legacy key still opens with master key alone")
    except keyvault.KeyIntegrityError:
        check(True, "legacy key no longer opens with master key alone")
    r = anon.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {ltok}"})
    check(r.status_code == 403 and r.json()["error"]["code"] == "PASS_CANT_UNLOCK", "old pass for a re-locked key asks for a new pass")
    r = a.post("/api/ws/tokens", json={"agent": "legacy-bot2", "upstream": lid, "ttl_minutes": 60, "max_calls": 5, "budget_usd": 1}, headers=H)
    r = anon.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {r.json()['token']}"})
    check(r.status_code == 200 and calls[-1] == "sk-legacy-OLDKEY-0987654321", "new pass on re-locked key works")
    log = a.get("/api/ws/audit", headers=H).json()
    entries = log if isinstance(log, list) else log.get("entries", [])
    check(any(e["event"] == "KEYS_UPGRADED" for e in entries), "upgrade recorded")
    check(a.get("/api/ws/audit/verify", headers=H).json().get("ok"), "audit chain intact")

    # ---- Security headers -------------------------------------------------------
    r = anon.get("/", headers={"x-forwarded-proto": "https"})
    csp = r.headers.get("content-security-policy", "")
    check("script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "connect-src 'self'" in csp, f"CSP {csp}")
    check("max-age=" in r.headers.get("strict-transport-security", ""), "HSTS on https")
    check("camera=()" in r.headers.get("permissions-policy", ""), "permissions policy")
    check(anon.get("/").headers.get("strict-transport-security") is None, "no HSTS on plain http (local)")

    # ---- Removing a key wipes its pass locks -----------------------------------
    r = a.post("/api/ws/tokens", json={"agent": "bot3", "upstream": cid, "ttl_minutes": 60, "max_calls": 5, "budget_usd": 1}, headers=H)
    check(r.status_code == 200, "issue before delete")
    r = a.post(f"/api/ws/connections/{cid}/remove", headers=H)
    check(r.status_code == 200, f"delete key {r.text}")
    with db.engine.connect() as c:
        check(c.execute(select(db.pass_keys).where(db.pass_keys.c.conn_id == cid)).first() is None, "deleted key leaves no pass locks")

print(f"ALL {ok} CHECKS PASSED on {DBURL.split(':')[0]}")
