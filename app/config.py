"""Configuration, all read from environment variables.

Nothing secret is ever hard-coded. Locally, put values in a .env file;
on Render, set them under the service's Environment tab.
"""
import hashlib
import hmac
import logging
import os
import secrets

log = logging.getLogger("leash")


def _load_dotenv(path: str = ".env") -> None:
    """Tiny .env loader so local runs work without extra packages."""
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


# --- Master secret -----------------------------------------------------------
# Every other key is derived from this one, so one secret controls everything.
SIGNING_SECRET = os.environ.get("SIGNING_SECRET", "")
if not SIGNING_SECRET:
    SIGNING_SECRET = secrets.token_hex(32)
    log.warning(
        "SIGNING_SECRET is not set. Using a random one for this run only; "
        "all tokens and the audit chain will be invalid after a restart."
    )


def derive_key(purpose: str) -> bytes:
    """Key separation: a different HMAC key per job, all derived from the master.

    If one derived key were ever exposed, the others stay safe.
    """
    return hmac.new(SIGNING_SECRET.encode(), purpose.encode(), hashlib.sha256).digest()


TOKEN_KEY = derive_key("leash/token-signing/v1")
AUDIT_KEY = derive_key("leash/audit-chain/v1")
CANARY_KEY = derive_key("leash/canary/v1")
FINGERPRINT_KEY = derive_key("leash/key-fingerprint/v1")
SESSION_KEY = derive_key("leash/session/v1")

# --- Master key for encrypting stored provider keys ----------------------------
# Kept separate from SIGNING_SECRET so each can be rotated on its own. If it's
# not set (local development), one is derived from SIGNING_SECRET instead.
_kek_source = os.environ.get("KEY_ENCRYPTION_KEY", "")
if _kek_source:
    KEY_ENCRYPTION_KEY = hmac.new(_kek_source.encode(), b"leash/kek/v1", hashlib.sha256).digest()
else:
    KEY_ENCRYPTION_KEY = derive_key("leash/kek/v1")
    log.warning("KEY_ENCRYPTION_KEY is not set; deriving the master key from SIGNING_SECRET.")
# A short, non-secret id for the master key, stored next to each wrapped key.
KEK_ID = hashlib.sha256(b"leash/kek-id/" + KEY_ENCRYPTION_KEY).hexdigest()[:12]

# --- Admin access to the dashboard ------------------------------------------
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(12)
    log.warning("ADMIN_PASSWORD is not set. Generated one for this run: %s", ADMIN_PASSWORD)

# --- Upstream (the real AI provider) ----------------------------------------
def _optional(name: str) -> str:
    """Treat blank, 'none' or '-' as not set (handy in Render's setup form)."""
    value = os.environ.get(name, "").strip()
    return "" if value.lower() in ("", "none", "-") else value


OPENAI_API_KEY = _optional("OPENAI_API_KEY")
OPENAI_MODEL = _optional("OPENAI_MODEL")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OPENAI_ENABLED = bool(OPENAI_API_KEY and OPENAI_MODEL)

# Prices in USD per 1M tokens, used to turn OpenAI's `usage` into dollars.
# Set these from OpenAI's pricing page for the model you use.
PRICE_INPUT_PER_1M = _float("PRICE_INPUT_PER_1M", 0.15)
PRICE_OUTPUT_PER_1M = _float("PRICE_OUTPUT_PER_1M", 0.60)
# Hard ceiling on real OpenAI spend across every token, ever (defence in depth).
GLOBAL_REAL_BUDGET_USD = _float("GLOBAL_REAL_BUDGET_USD", 1.00)
# Cap on output tokens per real call if the agent doesn't set one.
DEFAULT_MAX_COMPLETION_TOKENS = int(_float("DEFAULT_MAX_COMPLETION_TOKENS", 300))

# The fake upstream pretends every call costs this much.
FAKE_COST_PER_CALL = _float("FAKE_COST_PER_CALL", 0.05)

# Upper bounds on what any single token may be granted.
MAX_TTL_MINUTES = 60
MAX_CALLS_PER_TOKEN = 1000
MAX_BUDGET_PER_TOKEN_USD = 5.00

# --- Public sandbox -------------------------------------------------------------
# Lets anyone run the demo at /try in an isolated space, fake upstream only.
SANDBOX_ENABLED = os.environ.get("SANDBOX_ENABLED", "true").strip().lower() not in ("false", "0", "no", "off")
SANDBOX_TTL_HOURS = 3            # sandboxes are deleted after this long
SANDBOX_MAX_SPACES = 300         # active sandboxes at once
SANDBOX_MAX_AUDIT = 3000         # log entries per sandbox before it asks for a reset
SANDBOX_MAX_TOKENS = 60          # tokens per sandbox
SANDBOX_MAX_TTL_MINUTES = 10
SANDBOX_MAX_CALLS = 100
SANDBOX_MAX_BUDGET_USD = 5.00    # pretend money, fake upstream only
SANDBOX_MAX_CONNECTIONS = 5      # stored provider keys per sandbox
# Real AI in the public demo, paid from the server's own key, with hard caps.
PUBLIC_REAL_BUDGET_USD = _float("PUBLIC_REAL_BUDGET_USD", 0.20)          # all visitors together, ever
SANDBOX_REAL_PER_VISITOR_USD = _float("SANDBOX_REAL_PER_VISITOR_USD", 0.01)  # each visitor's share
SANDBOX_REAL_MAX_TOKENS = 150        # output cap per public real call
SANDBOX_REAL_MAX_PROMPT_CHARS = 8000 # input cap per public real call
MAX_CONNECTIONS = 20             # stored provider keys in the control room

# --- Customer accounts (Leash as a service) --------------------------------------
ACCOUNTS_ENABLED = os.environ.get("ACCOUNTS_ENABLED", "true").strip().lower() not in ("false", "0", "no", "off")
ACCOUNT_MAX = 1000                  # accounts the server will hold
ACCOUNT_MAX_CONNECTIONS = 10        # saved keys per workspace
ACCOUNT_MAX_TOKENS = 500            # agent passes per workspace
ACCOUNT_MAX_TTL_MINUTES = 30 * 24 * 60   # an agent's pass can last up to 30 days
ACCOUNT_MAX_CALLS = 100_000
ACCOUNT_MAX_BUDGET_USD = 500.00

# Link to the source code on the landing page. On Render this is filled in
# automatically from the repo the service deploys from.
REPO_URL = _optional("REPO_URL")
if not REPO_URL and os.environ.get("RENDER_GIT_REPO_SLUG"):
    REPO_URL = f"https://github.com/{os.environ['RENDER_GIT_REPO_SLUG']}"

# --- Database -----------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./leash.db")
# Render gives a plain postgres:// or postgresql:// URL. Name the driver we
# install (psycopg2) explicitly, since newer SQLAlchemy defaults to another one.
for _prefix in ("postgres://", "postgresql://"):
    if DATABASE_URL.startswith(_prefix):
        DATABASE_URL = "postgresql+psycopg2://" + DATABASE_URL[len(_prefix):]
        break
