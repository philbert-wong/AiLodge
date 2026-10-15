# Leash

**A budget your AI agent can't overspend, and a record it can't fake.** Each agent gets an HMAC-signed pass with a hard money limit instead of your API key. The key stays encrypted with AES-256-GCM where the agent can't reach it, and every call is sealed into an HMAC-chained record that catches any edit.

Hackathon track: *Safety by Design*. Live at **https://leash-jy30.onrender.com**: [watch a real agent hit its limit](https://leash-jy30.onrender.com/try), or [create a free workspace](https://leash-jy30.onrender.com/signup).

![Leash](docs/screenshots/00-cover.png)

## Why

A developer left an AI agent to finish a task with a $100 budget. When he came back, it had spent about $5,000, doing far more than he asked. When he checked its logs, they said nothing had gone wrong.

Three things failed, and Leash fixes each one:

| What failed | What Leash does |
|---|---|
| **The budget was a request, not a limit.** | The agent holds a pass signed with HMAC-SHA256 that carries its budget. Before every call Leash reserves the most that call could cost and refuses it if it could go over, then settles the real cost from the provider's usage numbers. Changing the pass breaks its signature. |
| **The agent held the real API key.** | The key is encrypted with AES-256-GCM (envelope encryption, master key outside the database) and decrypted only inside Leash for the moment of each approved call. |
| **The agent wrote its own logs.** | Leash writes the record, not the agent. Each entry is sealed with `HMAC-SHA256(key, previous seal ‖ entry)`, so changing or deleting any entry is caught at that exact entry. |

## Demo 1: an agent with a budget, running for real

On `/try` (the first tab), anyone can give a real AI agent (gpt-4o-mini) a task and a budget of a tenth of a cent, paid from the server's key:

1. The agent is told to keep improving its work, so it overdoes it, like the agent in the story. Every step is a real call through Leash, with its real cost.
2. Leash refuses the step that could take it over budget, before it is sent. It stops just under the limit, never over.
3. The agent writes its own status report. Leash shows it next to its own record of the same run: steps allowed and refused, real spend, and the seal check.
4. **Try to fake the record** really edits the database, changing one step's cost to $0.00, and Leash names the entry that was changed.

![A real agent stopped at its budget](docs/screenshots/17-agent-run.png)

The exact instructions given to the agent are shown on the page. Spending by the public demo is capped: **$0.20 in total for all visitors and 1 cent per visitor**, at most 150 output tokens and 8,000 characters per call, and per-address rate limits. When the shared budget runs out, the demo switches to the free fake AI. These totals are kept as running counters that survive demo resets, so deleting passes can't reopen the caps.

## Demo 2: Maya's weekend (attacks)

Maya runs a small online shop. On Friday she lets an AI assistant answer customer emails while she's away.

| Fri 11pm: a fake "IT Support" email tricks the assistant; Leash blocks it | Sat 3am: an auto-reply loop; Leash stops it at its limit | Mon: someone edits the record; Leash catches it |
|---|---|---|
| ![](docs/screenshots/03-story-attack.png) | ![](docs/screenshots/04-story-limit.png) | ![](docs/screenshots/05-story-coverup.png) |

The "admin key" in the email is a trap key Leash planted, the reply carrying it is blocked before it leaves, the loop stops at the limit, Maya gets a Slack message, and the record proves what happened.

## Leash as a service

Teams sign up at `/signup` and get a private workspace at `/app`:

1. **Save your AI key.** Any OpenAI-compatible provider. Encrypted before it's saved (see below).
2. **Give each agent a pass.** A money limit, a call limit and an end date (1 hour to 30 days). The pass is shown once, with the two lines to change in your agent and a **Try it** button that sends a test call through Leash.
3. **Get alerts in Slack or Discord.** Trap key used, leak blocked, an agent hit its limit, or every agent stopped.
4. **Run a test agent** on your own saved key: the same run as Demo 1, so a team can watch its limit hold and check its record before connecting a real agent. In a workspace, **Try to fake the record** edits a copy of the record, so the real one is never touched.

Plus a list of every agent with its spend and a **Stop** button, a kill switch for all of them, trap keys to plant in your own files, and the activity log with **Check the log**.

| Workspace | Agents |
|---|---|
| ![](docs/screenshots/14-workspace.png) | ![](docs/screenshots/16-workspace-agents.png) |

How accounts are protected:

- **Passwords** are hashed with scrypt (memory-hard, random salt per password). Log-in attempts are rate-limited per address and per email, and take the same time whether or not the email has an account.
- **Sessions** are a signed cookie (HMAC-SHA256 with its own derived key), HttpOnly, SameSite=Lax, Secure over HTTPS, valid for 7 days.
- **Cross-site request forgery** is blocked by requiring an `X-Leash-App: 1` header on every account and workspace request.
- **Isolation:** each workspace is its own space (`acct_<id>`). Every key, pass, alert, trap key, setting and log entry belongs to exactly one space, and tests check one team can't see, stop or use another's.
- **Webhooks are secrets**, so Slack and Discord addresses are encrypted like API keys. Only `https://hooks.slack.com/...` and `https://discord.com/api/webhooks/...` are accepted, so the server can't be aimed at internal addresses. Alerts are sent in the background and rate-limited.
- Workspaces can't use the server's own key, have no demo buttons (tampering, reset), and are never touched by the clean-up that deletes old public demos.

## What Leash does

Leash is a proxy that sits between agents and the AI provider. The real key stays on the server. Agents get a **Leash token** instead.

```
Agent ──(Leash token)──▶ Leash ──(real OpenAI key)──▶ OpenAI
                           │
             1. canary key?            → block + alert
             2. raw provider key?      → reject
             3. signature + expiry     → HMAC-SHA256 check
             4. revoked / kill switch? → block
             5. secrets in the prompt? → block + alert
             6. call limit + budget    → block
             7. forward, settle real cost, seal into the audit chain
```

| Protection | How it works |
|---|---|
| **Scoped tokens** | `lsh_<claims>.<HMAC-SHA256 signature>`. Claims hold agent name, expiry, max calls and budget. Changing one character breaks the signature. Compared in constant time. |
| **Budgets that hold** | Every call is reserved before forwarding using a worst-case cost estimate, then settled using OpenAI's `usage` numbers. A server-wide ceiling caps total real spend. |
| **Kill switch** | Revoke one token, or stop every agent at once. Takes effect on the agent's next call. |
| **Tamper-evident log** | Each entry's seal is `HMAC-SHA256(key, previous_seal ‖ entry)`. Editing or deleting any entry breaks the chain at that exact point. Keyed hashing means someone with only database access can't recompute the chain. |
| **Canary keys** | Decoy keys that look exactly like OpenAI keys are planted where only an injected agent would find them. Any use fires an alert. |
| **Outbound secret scanning** | Prompts containing API keys, Leash tokens, private keys or canaries are blocked before they leave. |
| **Privacy in the log** | Raw keys are never logged, only their SHA-256 fingerprints. Prompts are stored as a SHA-256 hash plus a short preview. |
| **Key separation** | One master secret; separate HMAC keys are derived from it for tokens, the audit chain and canaries. |
| **Tokens never stored** | Leash keeps only each token's id and counters. The token itself is shown once. |
| **Bring your own key, encrypted** | Teams can store their own OpenAI-compatible provider key. See below. |

### Bring your own key, encrypted

Teams can connect their own provider (any OpenAI-compatible base URL, model and key) and issue Leash tokens against it. The key is protected with **envelope encryption**, the pattern cloud key-management services use:

1. A fresh random 256-bit **data key** encrypts the API key with **AES-256-GCM**.
2. The **master key** (`KEY_ENCRYPTION_KEY`, an environment variable, never in the database) encrypts the data key, also with AES-256-GCM.
3. The database stores only the two ciphertexts, plus a short hint (`…3456`) and an HMAC-SHA256 fingerprint to spot duplicates.

### If the website is attacked

Envelope encryption alone has a weak spot: someone who steals the database **and** the master key (for example from the host's settings) can decrypt every key. So keys saved in a customer workspace get two more locks, and Leash keeps neither secret:

1. **Locked to the team's password.** At sign-up and login, Leash derives an *account key* from the password with scrypt (salted per account with a server-side HMAC key, so it differs from the stored password hash). The data key is wrapped with `HMAC(master key, account key)`, which needs both. The account key is never stored; it lives only in the session cookie, encrypted with AES-256-GCM and bound to the account id.
2. **Each pass carries its own unlock code.** When a pass is created, Leash unwraps the data key with the account key, then stores a second copy wrapped with `HMAC(master key, pass secret)`. The 128-bit pass secret sits only inside the pass (`k` in its signed claims) and is never stored or shown in the readable claims. At call time the pass presents its secret, the copy is unwrapped, the key is decrypted for that one call and dropped.

| What the attacker has | Can they read a workspace key? |
| --- | --- |
| A copy of the database | No |
| The database and the master key | No: they also need a team's password or a live pass |
| The database, the master key and the signing secret | No: they can forge a pass, but not its unlock code (`PASS_CANT_UNLOCK`) |
| Control of the running server | Yes, for keys used while they're in control. Nothing can fully stop this, so use a key made just for Leash with a spending limit at the provider |

Stopping a pass deletes its copy of the lock, removing a key deletes all of them, and expired passes' copies are cleaned up. Keys saved before this upgrade are re-locked automatically the next time the team logs in (`KEYS_UPGRADED` in the log), and older sessions simply ask the team to log in again. The pages also send a strict Content-Security-Policy (only Leash's own scripts may run, and pages may only talk to Leash), HSTS, and `frame-ancestors 'none'`, so injected markup can't send a key anywhere. `tests/keyprotect_test.py` plays this attacker (49 checks, passing on SQLite and Postgres): `python tests/keyprotect_test.py`.

Details that matter:

- **Tamper-proof:** AES-GCM is authenticated. Flip one bit of the stored ciphertext and decryption fails, so the call is refused (`KEY_INTEGRITY_FAILED`) and an alert fires. Both layers are bound to their row as associated data, so ciphertext copied into another row won't decrypt either.
- **Decrypted just in time:** a key is decrypted only inside the request that forwards a call, then dropped. It's never returned by the API, shown in the dashboard or written to the log, and provider error messages are scrubbed of key fragments.
- **Crypto-shredding:** removing a key erases its ciphertext and wrapped data key, so it can never be recovered and its tokens stop working immediately.
- **Rotation-friendly:** each record notes which master key wrapped it (`kek_id`). Rotating the master key only means re-wrapping the small data keys, not touching the API keys.
- **Safe in the sandbox:** visitors can store keys to see exactly what the database keeps, but sandbox calls always go to the fake AI, so the page asks for a made-up key. Sandboxes are deleted after 3 hours.

![Bring your own key](docs/screenshots/11-key-tamper-caught.png)

It is **OpenAI-compatible**: any agent built on the OpenAI SDK works by changing `base_url` and `api_key`:

```python
from openai import OpenAI
client = OpenAI(base_url="https://<your-app>.onrender.com/v1", api_key="lsh_...")
```

## The pages

| Page | Who | What |
|---|---|---|
| `/` | everyone | Landing page in six tabs with Back and Next: why Leash exists, how it works, the seven checks, security, attacks (Maya's weekend), and who it's for with plans. |
| `/try` | everyone | Public demo in five tabs with Back and Next: a real agent with a budget (real AI within the caps above), Maya's weekend, each protection on its own, your key (encrypted), and the log and tools. Each visitor gets an isolated copy. Rate-limited, and deleted after 3 hours. |
| `/signup`, `/login` | everyone | Create a team account or log in. |
| `/app` | customers | A team's private workspace: keys, agents, Slack or Discord alerts, trap keys, activity log. Real calls go through the team's own saved keys. |
| `/control` | you | The password-protected control room. Same dashboard as `/try`, plus real calls through the server's key or your stored keys, and Slack or Discord alerts. |

## Demo script (about 3 minutes)

1. **The story (20 seconds).** Open the landing page and read the "Why we built Leash" section: $100 budget, $5,000 bill, logs that said all was fine.
2. **Demo 1 (90 seconds).** On `/try` or `/control`, pick a task, keep the budget at $0.001, press **Start the agent**. Point at the money meter filling up and the agent's "Next:" plans. When it's refused: "It wanted to keep going. In the story it went to $5,000; here it can't go over a tenth of a cent." Read the agent's own report next to Leash's record, then press **Try to fake the record** and show the entry that was caught.
3. **Demo 2 (optional, 60 seconds).** Run Maya's weekend for prompt injection: the trap key and the blocked leak. With a Slack webhook saved in `/control`, the alerts arrive live.
4. **The service (40 seconds).** Sign up, save a key, run the same test agent on your own key, create a pass for a real agent and show the two-line code change.

## Run it locally

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # then fill in SIGNING_SECRET and ADMIN_PASSWORD
uvicorn app.main:app --reload
```

Open http://localhost:8000 for the landing page, http://localhost:8000/try for the sandbox, or http://localhost:8000/control and sign in with your `ADMIN_PASSWORD`.

To watch an external agent get cut off, issue a token in the dashboard and run:

```bash
python examples/agent.py http://localhost:8000 lsh_...
```

## Deploy to Render

1. **Push this folder to a GitHub repo.** Check that `.env` is *not* in it (`.gitignore` already excludes it).
2. In the [Render Dashboard](https://dashboard.render.com), click **New > Blueprint** and choose your repo. Render reads `render.yaml` and creates:
   - a free web service called `leash`
   - a free Postgres database called `leash-db`
3. Render asks for the secret values:
   - `ADMIN_PASSWORD`: choose a strong password for the dashboard
   - `OPENAI_API_KEY`: your OpenAI key (or type `none` to run fake-only)
   - `OPENAI_MODEL`: a small, cheap model your key can use (check your OpenAI dashboard), or `none`
   - `SIGNING_SECRET` and `KEY_ENCRYPTION_KEY` are generated for you automatically.
   - If your key comes from a gateway rather than OpenAI itself, either add `OPENAI_BASE_URL` (the gateway's address, ending in `/v1`) under the service's **Environment** tab afterwards, or store the gateway as a key in the control room's **Bring your own key** section.
4. Click **Apply**. When the deploy finishes, open the `onrender.com` URL. Share that link with judges; your control room is at `/control`.

**Free-tier notes:** a free web service sleeps after 15 minutes without traffic and takes about a minute to wake, so open the page a few minutes before you present. A free Render Postgres database expires 30 days after creation, which is fine for a hackathon.

**Before demoing with a real key:** set a usage limit on your OpenAI project as well. `GLOBAL_REAL_BUDGET_USD` (default $1.00) is Leash's own ceiling on real spend.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `SIGNING_SECRET` | yes | Master secret. All signing keys derive from it. Render generates it. |
| `KEY_ENCRYPTION_KEY` | yes on Render | Master key that encrypts stored provider keys. Render generates it. Kept separate from `SIGNING_SECRET` so each can be rotated on its own; changing it makes existing stored keys unreadable, so re-add them. |
| `ADMIN_PASSWORD` | yes | Password for the dashboard. |
| `DATABASE_URL` | on Render | Postgres connection. Locally, SQLite is used if unset. |
| `OPENAI_API_KEY` | no | Enables the real OpenAI upstream. |
| `OPENAI_MODEL` | no | The only model real-upstream tokens may use. |
| `PRICE_INPUT_PER_1M`, `PRICE_OUTPUT_PER_1M` | no | Your model's prices, for accurate budgets. Defaults: 0.15 / 0.60. |
| `GLOBAL_REAL_BUDGET_USD` | no | Ceiling on all real spend. Default 1.00. |
| `DEFAULT_MAX_COMPLETION_TOKENS` | no | Output cap per real call if the agent sets none. Default 300. |
| `SANDBOX_ENABLED` | no | Set to `false` to turn off the public sandbox at `/try`. Default on. |
| `ACCOUNTS_ENABLED` | no | Set to `false` to turn off sign-up and customer workspaces. Default on. |
| `PUBLIC_REAL_BUDGET_USD` | no | Real-AI spending the public demo may use, in total, from the server's key. Default 0.20. |
| `SANDBOX_REAL_PER_VISITOR_USD` | no | Each public visitor's share of that. Default 0.01. |
| `REPO_URL` | no | Source code link on the landing page. On Render it's filled in automatically from your repo. |

## API

| Endpoint | Who | What |
|---|---|---|
| `POST /v1/chat/completions` | agents | OpenAI-compatible proxy. `Authorization: Bearer lsh_...` |
| `POST /api/tokens` | operator | Issue a token |
| `POST /api/tokens/{id}/revoke` | operator | Revoke one token |
| `POST /api/kill` | operator | Stop or release every agent |
| `GET /api/connections`, `POST /api/connections` | operator | List or store provider keys (encrypted; the key is never returned) |
| `POST /api/connections/{id}/test`, `POST /api/connections/{id}/remove` | operator | Send one call through a stored key, or erase it |
| `GET /api/audit`, `GET /api/audit/verify` | operator | Read and verify the chain |
| `GET /api/alerts`, `GET /api/stats` | operator | Alerts and counters |
| `GET /api/tokens/{id}/receipt` | operator | Leash's own account of one pass, built from the sealed log, with the seal check |
| `POST /api/audit/seal-test?jti=` | operator | Edit a copy of the log the way a cover-up would and check it; the real log is untouched |
| `GET /api/webhook`, `POST /api/webhook`, `POST /api/webhook/test`, `POST /api/webhook/remove` | operator | Slack or Discord alerts |
| `POST /api/account/signup`, `/login`, `/logout`, `GET /api/account/me` | customers | Accounts and the setup checklist |

Operator endpoints need the `X-Admin-Key` header. The sandbox exposes the same endpoints under `/api/sb/...`, scoped to the visitor's own space by a cookie (created with `POST /api/sb/session`) and requiring an `X-Leash-Sandbox: 1` header, which blocks cross-site request forgery. Customer workspaces use `/api/ws/...` with the session cookie and an `X-Leash-App: 1` header; they have no demo endpoints, and the sandbox has no webhook endpoints.

## Abuse protection on the public pages

- Real AI in the public demo is capped: $0.20 in total and 1 cent per visitor (both configurable), at most 150 output tokens and 8,000 characters per call, 40 real calls per minute per address. The caps are running totals that survive demo resets. When they run out, `/try` uses the free fake AI. Visitors' own saved keys are never used for real calls.
- Sandbox limits are clamped: 10 minutes, 100 calls and $5 of pretend money per token, 60 tokens and 3,000 log entries per sandbox, 300 sandboxes at once.
- Rate limits per IP address and overall on the proxy, the sandbox API, new sandboxes and the unprotected demo path.
- Wrong operator passwords are throttled after 10 tries in 5 minutes.
- Failed attempts that can't be tied to a sandbox are logged to the operator's chain at a limited rate, so the public can't flood it.

## Project layout

```
app/
  main.py        pages, proxy, operator, sandbox and workspace APIs, accounts
  accounts.py    scrypt password hashing and signed session cookies
  notify.py      Slack and Discord alerts (encrypted webhook addresses)
  tokens.py      HMAC-signed scoped tokens
  audit.py       HMAC hash chain and verification, one chain per space
  guards.py      canary keys and outbound secret scanning
  upstream.py    fake upstream, OpenAI forwarding, cost accounting
  ratelimit.py   per-IP sliding-window rate limits
  keyvault.py    AES-256-GCM envelope encryption, plus password- and pass-bound locks
  config.py      settings from environment variables, key derivation
  db.py          tables (SQLite locally, Postgres on Render)
  static/        landing page, demo dashboard, sign-up and workspace pages
examples/agent.py   a runaway agent to point at Leash
render.yaml         Render Blueprint
```

## Limits and next steps

- **Single instance.** A process lock keeps budgets and the chain consistent, and rate limits live in memory, so the start command pins one worker. Scaling out would need a database-level lock and a shared store such as Redis.
- **Deleting the newest entries** can't be detected from the chain alone. Fix: periodically publish the chain's head hash somewhere external (an email, a public repo, a timestamping service).
- **Streaming** responses aren't supported yet; `stream` is forced off.
- **Changing `SIGNING_SECRET`** invalidates every token and makes the old log fail verification from entry #1. That's by design. Use **Reset demo** to start a fresh chain.
- **Master key in an environment variable.** Good for a hackathon, and no longer enough on its own to read a workspace key. In production it would live in a key management service (AWS KMS, Google Cloud KMS, HashiCorp Vault) so the server never holds it in plain form.
- **A taken-over server** could still see keys while they're in use. Mitigations: provider-side spending limits, a key made just for Leash, alerts on unusual use, and in future an isolated signing service that holds keys apart from the web app.
- **No password reset yet.** Because saved keys are tied to the team's password, a reset (when added) would mean adding keys again. That's the price of the database alone being useless to an attacker.
- **The operator's own key** (`OPENAI_API_KEY`) and the control room's saved keys are locked with the master key only, because the server needs them without anyone logged in.
- **Accounts are single-user** and sessions can't be revoked server-side before they expire (7 days). Team plans would add several people per workspace, roles and a session list.
- **Next:** per-tool scopes (not just per-model), human approval with signed sign-off for risky actions, Ed25519 signatures so third parties can verify the log without the secret, and a one-click master-key rotation.
