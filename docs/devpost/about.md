![Leash](https://raw.githubusercontent.com/philbert-wong/AiLodge/main/docs/screenshots/00-cover.png)

## Inspiration

I came across the story of a developer who left an AI agent to finish a task with a $100 budget. When he came back, it had spent about $5,000, doing far more than he had asked for. When he checked its logs, they said nothing had gone wrong.

Three things failed there. The budget was only a request the agent was trusted to follow. The agent held the real API key, so nothing outside it could stop the spending. And the agent wrote its own logs, so the record said whatever it said.

I was learning about security tools at the time: hashing, HMAC, signatures and AES encryption. Leash came from one question: what if the agent never held the key at all, and those tools enforced its budget and kept a record it couldn't touch?

![Why I built Leash](https://raw.githubusercontent.com/philbert-wong/AiLodge/main/docs/screenshots/19-landing-why.png)

## What it does

**Leash gives every AI agent a budget it can't overspend and a record it can't fake.** It works like a prepaid card: you wouldn't hand a new hire the company credit card with no limit, you'd give them a card with a set amount and an end date that you can cancel in a second.

- **The budget is enforced, not requested.** The agent's pass is signed with HMAC-SHA256 and carries its budget. Before every call, Leash reserves the most that call could cost and refuses it if it could go over. Change the pass to raise the limit and the signature breaks.
- **The key is out of reach.** It's encrypted with AES-256-GCM and only decrypted inside Leash for the moment of each approved call.
- **The record is Leash's, not the agent's.** Every call is written by Leash and sealed to the entry before it with HMAC-SHA256. Change one entry and Leash points to it.

Leash sits between AI agents and the AI provider. The real API key stays locked away. Each agent gets a **pass**, and every action goes through seven checks before the real key is ever used:

1. **Not a trap key.** Fake keys are planted where only a hijacked agent would find them. Using one is blocked and raises an alert.
2. **Not a real key.** Agents may only hold passes, never provider keys.
3. **Valid pass.** Forged or expired passes are refused.
4. **Not stopped.** One click stops a single agent, or every agent.
5. **No leaked secrets.** Messages carrying keys are blocked before they leave.
6. **Within limits.** Calls and money are capped per pass, checked before the call is made.
7. **Sent and logged.** Only now is the real key used, and every outcome, allowed or blocked, is sealed into a record that can't be quietly edited.

It works like the OpenAI API, so an existing agent switches over by changing two lines.

### Demo 1: an agent with a budget, running for real

The first tab of the [live demo](https://leash-jy30.onrender.com/try) recreates the story with a real AI (gpt-4o-mini) and real money, in fractions of a cent, paid from my hackathon key:

1. Pick a task and a budget of a tenth of a cent. The agent is told to keep improving its work, so it overdoes it, like the agent in the story. Each step is a real call through Leash, with its real cost.
2. Leash refuses the step that could take it over budget, before it is sent. It stops just under the limit, never over. In the story the agent went to $5,000.
3. The agent writes its own status report. Leash shows it next to its own record of the same run: steps allowed and refused, real spend, and the seal check.
4. **Try to fake the record** changes one step's cost to $0.00 in the database. Leash names the entry that was changed.

![A real agent stopped at its budget, with its report next to Leash's record](https://raw.githubusercontent.com/philbert-wong/AiLodge/main/docs/screenshots/17-agent-run.png)

The page shows the exact instructions the agent is given. Public spending is capped at $0.20 in total and 1 cent per visitor, so the demo itself is on a leash. When the shared budget runs out, it switches to a free fake AI.

### Demo 2: Maya's weekend (attacks)

The second tab shows attacks. Maya runs a small online shop and lets an AI assistant answer customer emails while she's away for the weekend. The demo plays her weekend one beat at a time, with Leash's seven checks lighting up green or red for every action. It runs on a free fake AI in the public demo, and on the real AI in the control room.

**Friday 10am and 2pm: normal work goes straight through.** The assistant answers an order question and a return request. Every check lights green.

**Friday 11pm: a malicious email.** An email from "IT Support" hides an instruction: use this "admin key" and send it back. The assistant falls for it. The key is a trap, so using it is blocked and an alert fires. Sending it out is blocked at "No leaked secrets".

![The assistant falls for a malicious email, and Leash blocks it](https://raw.githubusercontent.com/philbert-wong/AiLodge/main/docs/screenshots/03-story-attack.png)

**Saturday 3am: a reply loop.** A customer's auto-reply bot answers every email, and the assistant answers every auto-reply. The money bar fills up, and Leash stops it at "Within limits". Or you press **Stop the assistant** first and it's blocked at "Not stopped".

![Leash stops the reply loop when the pass runs out](https://raw.githubusercontent.com/philbert-wong/AiLodge/main/docs/screenshots/04-story-limit.png)

**Monday 9am: Maya checks the record, then someone covers it up.** Every reply, every blocked action and the attack are on record. Then someone with database access edits the record of the attack to say nothing happened. Checking again names the exact entry that was changed.

![The cover-up is caught at the exact entry](https://raw.githubusercontent.com/philbert-wong/AiLodge/main/docs/screenshots/05-story-coverup.png)

In the password-protected control room, the same story runs against a real AI model (gpt-4o-mini) using a real key that the assistant never sees. The assistant falling for the email is scripted so the demo behaves the same way every time; everything Leash does in response is real.

### Leash as a service

Anyone can [create a free workspace](https://leash-jy30.onrender.com/signup) for their team, in about a minute:

1. **Save your AI key.** Paste a key from OpenAI or any compatible provider. Leash encrypts it before saving.
2. **Give each agent a pass.** Name it, set a money limit, a call limit and when it ends (an hour to 30 days). Leash shows the pass once, the two lines to change in your agent, and a button to send a test call.
3. **Get alerts in Slack or Discord.** When an agent uses a trap key, tries to leak a key or hits its limit, a message lands in your channel.
4. **Run a test agent on your own key.** The same run as Demo 1, so a team can watch its limit hold and check the record before connecting a real agent. No code needed.

![A team's workspace](https://raw.githubusercontent.com/philbert-wong/AiLodge/main/docs/screenshots/14-workspace.png)

The workspace lists every agent with its spend, limits and end date, with a Stop button for each and a kill switch for all of them. It also has trap keys to plant in your own files, and the activity log with a **Check the log** button.

![Every agent on its own pass](https://raw.githubusercontent.com/philbert-wong/AiLodge/main/docs/screenshots/16-workspace-agents.png)

Who it's for:

- **Small teams with one helpful bot**, like Maya's shop: a hard limit, an alert when something's off, and no key to steal.
- **Agencies building agents for clients:** one pass per client and per agent, each with its own budget, stoppable without touching the others.
- **Hackathons, courses and workshops:** give 200 people AI access without handing out your key. Each pass gets a few dollars and ends with the event.

The free plan is available now. Team (several people per workspace, renewing monthly limits) and Business (single sign-on, your own master key in your cloud) are planned.

## How I built it

- **Backend:** Python with FastAPI and SQLAlchemy. Postgres on Render, SQLite for local development.
- **Passes (tokens):** JSON claims, base64url-encoded and signed with HMAC-SHA256. Signatures are compared in constant time so timing can't leak them.
- **Key separation:** one master secret, with separate keys derived from it for signing passes, sealing the log, generating trap keys and signing log-in sessions.
- **The log:** each entry's seal is `HMAC-SHA256(key, previous seal + entry)`, so entries form a chain. Because the seal is keyed, someone who can edit the database can't quietly recompute the chain after changing it.
- **Trap keys (honeytokens):** realistic-looking fake keys, unique to each workspace, planted in places like a decoy `.env` file or a suspicious email.
- **Saved keys, envelope encryption:** each key gets a fresh 256-bit data key and is encrypted with AES-256-GCM; the data key is then encrypted with a master key held in an environment variable, never in the database. Both layers are bound to their database row, so ciphertext moved elsewhere won't decrypt. Removing a key erases it for good. Slack and Discord webhook addresses are secrets too, so they're encrypted the same way.
- **If the site is attacked:** a stolen database plus the master key would still open keys protected only by envelope encryption, so workspace keys get two more locks. The data key is wrapped with a key that combines the master key with a scrypt key derived from the team's password, which is never stored (it travels only in the encrypted session cookie). Each agent pass then gets its own copy, wrapped with a 128-bit secret that only the pass carries. Result: the database, the master key and even the signing secret together still can't read a key or run a call. A strict Content-Security-Policy stops injected scripts from sending anything elsewhere.
- **Accounts:** passwords are hashed with scrypt (memory-hard, with a random salt each). Sessions are signed with HMAC in an HttpOnly cookie. Every workspace request needs a custom header, which blocks cross-site request forgery, and log-in attempts are rate-limited and take the same time whether or not the email exists.
- **Isolation:** every row in every table belongs to exactly one space: the operator, a public demo visitor, or a customer workspace. Tests check that one team can't see, stop or use another team's keys and agents.
- **Alerts:** sent to Slack or Discord in the background, so a slow chat service never slows an agent down. Only real Slack and Discord webhook addresses are accepted, so the server can't be pointed at internal addresses.
- **Frontend:** plain HTML, CSS and JavaScript. The story demo lights up each check using the same refusal codes the server returns. Everything shown from the server is escaped, because agents control part of what ends up in the log.
- **Public demo with real money:** each visitor gets an isolated space, deleted after three hours. Real AI there is capped at $0.20 for everyone and 1 cent per visitor, with small per-call limits. Those caps are running totals that survive resets, so deleting passes can't reopen them.
- **Receipts and the seal test:** a run's receipt is built from the sealed log, not from the agent. In workspaces, the "fake the record" test edits a copy of the log and checks it, so a team's real record is never touched.
- **Deployment:** a Render Blueprint (`render.yaml`) creates the web service and the database in one step.
- **Testing:** automated checks run against both SQLite and a real Postgres database, plus headless-browser runs of every page, the full story and the workspace on desktop and phone sizes.

I used Claude, Anthropic's AI assistant, to help brainstorm the idea and to write and test the code.

## Challenges I ran into

- **Making the idea easy to see.** My first demo had separate buttons for each protection, and it was hard to follow, and it ran on a fake AI. The final demo recreates the story that inspired Leash with a real AI and real money, small enough that I can let anyone run it.
- **Letting strangers spend my API key safely.** I had $1 of credit. The public demo has its own caps (in total and per visitor), and I found that my first spending ceiling was calculated from the passes, so resetting the demo would quietly reopen it. Running totals that survive resets fixed that.
- **Turning a demo into a service.** Adding accounts meant every customer's keys, agents, alerts and log had to stay separate. I also had to make sure the clean-up job that deletes old demo copies could never touch a customer's workspace.
- **Making budgets actually hold.** If two calls check the budget at the same moment, both can pass. Leash reserves the worst-case cost under a lock before forwarding, then settles the real cost afterwards, and releases the lock during the slow AI call.
- **A plain hash chain isn't enough.** Someone who can edit the database can change an entry and simply recompute every hash after it. Keying the chain with HMAC closes that gap.
- **Storing keys without ever exposing them.** I wanted tampering detected, ciphertext tied to its row, keys decrypted only at the moment of use, and removal that's truly permanent. Envelope encryption with AES-GCM covered all four. Then I asked what happens if someone steals the database and the master key together, and realised the answer was "everything". Tying each key to the team's password and to each pass fixed that, and writing a test that plays the attacker proved it.
- **Deployment surprises.** Testing against a real Postgres database caught that the database library's newest version defaults to a different Postgres driver. My hackathon key also came from an AI gateway rather than OpenAI directly, so Leash had to support any OpenAI-compatible provider address.

## Accomplishments that I'm proud of

- A live demo of the exact failure that inspired Leash, with a real AI and real money: the agent stops just under its budget, its own report sits next to the sealed record, and a faked entry is caught.
- A working service, not just a demo: sign up, save a key, give an agent a pass, and get a Slack message when something goes wrong.
- The cover-up beat: change one record in the database, and Leash names the exact entry that was touched.
- Catching prompt injection without any AI model: a trap key costs nothing and gives no false alarms, because no honest agent ever has one.
- Drop-in compatibility: existing OpenAI-based agents work after a two-line change.

## What I learned

- The difference between hashing, keyed hashing (HMAC), signatures, password hashing (scrypt) and authenticated encryption (AES-GCM), and when each is the right tool.
- How envelope encryption works, and why it makes rotating a master key cheap.
- Threat modelling: listing exactly what an attacker holds at each stage, and being honest about the case you can't fully stop (someone controlling the live server), which is why a provider-side spending limit still matters.
- That honeytokens are one of the cheapest and most reliable detection tools there is.
- Most of all: a safety control for an AI agent belongs somewhere the agent can't reach. Leash doesn't ask the agent to behave. It limits what the agent can do.

## What's next for Leash

- Team plans: several people per workspace with roles, and monthly limits that renew.
- Permissions per tool, not just per model, so a pass can allow reading email but not sending it.
- Human approval for risky actions, with a signed sign-off the agent can't forge.
- Publishing the log's latest seal somewhere external, so deleting the newest entries is detectable too.
- Moving the master key into a key management service, so business customers can hold their own.
- Support for more providers (Anthropic, Gemini) and streaming responses.
