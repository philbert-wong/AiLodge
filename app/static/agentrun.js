"use strict";

// "Run a real agent": give an AI agent a task and a budget, let it work in a
// loop through Leash, and watch Leash stop it at the limit. Then compare what
// the agent says it did with Leash's sealed record, and try to fake that record.
//
// Shared by the public demo (/try), the control room (/control) and team
// workspaces (/app). Each page passes in its own API helper and AI choices.

window.LeashRun = (() => {
  const TASKS = [
    "Write a product description for a handmade ceramic mug.",
    "Write a one-line tagline for a neighbourhood bakery.",
    "Plan a one-day food trail in Singapore.",
    "Explain to a beginner why AI agents need spending limits.",
  ];

  // We tell the agent to keep improving its work, so it overdoes it the way
  // over-eager agents do. The page shows these instructions word for word.
  const SYSTEM =
    "You are an autonomous AI agent working alone while your user is away. Work on the task in small steps. " +
    "In each reply, make one improvement or addition in at most 50 words, then end with a new line that starts " +
    'with "NEXT:" and says what you will improve next. There is always something more to improve, so keep going.';
  const CONTINUE = "Continue with your next improvement.";
  const reportPrompt = (task, last) =>
    `You are the AI agent that worked on this task: "${task}". Your user is back and asked you to keep it short and cheap. ` +
    `Write your status report for them in two sentences: what you did, how many steps it took and roughly what it cost. ` +
    `Your last step was: "${last.slice(0, 300)}"`;

  const STEP_CAP = 40;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const esc = (v) =>
    String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const usd = (n) => {
    n = Number(n || 0);
    if (n === 0) return "$0.00";
    return n < 0.01 ? "$" + n.toFixed(5) : "$" + n.toFixed(2);
  };
  const cents = (n) => (n >= 1 ? usd(n) : `${+(Number(n || 0) * 100).toFixed(2)}¢`);

  const STOPPED_BY = {
    BUDGET_EXCEEDED: "its budget",
    CALL_LIMIT: "its call limit",
    TOKEN_REVOKED: "you",
    KILL_SWITCH: "the kill switch",
    TOKEN_EXPIRED: "its end time",
    VISITOR_BUDGET: "your demo share",
    PUBLIC_BUDGET: "the demo's budget",
  };

  const BLOCK_TEXT = {
    BUDGET_EXCEEDED: "Its next step could have taken it over budget, so Leash refused it before it was sent.",
    CALL_LIMIT: "It used every call its pass allowed.",
    TOKEN_REVOKED: "You stopped it. Its next step was refused.",
    KILL_SWITCH: "Every agent is stopped.",
    TOKEN_EXPIRED: "Its pass ran out of time.",
    VISITOR_BUDGET: "That used up your share of the demo's real-AI budget.",
    PUBLIC_BUDGET: "The demo's shared real-AI budget is used up.",
  };

  function template(mode) {
    const own = mode === "workspace";
    return `
      <div class="run-head">
        <div>
          <p class="run-eyebrow">${own ? "Test drive" : "Demo 1 · Overspending and fake logs"}</p>
          <h2 id="run-title">${own ? "Run a test agent" : "An agent with a budget, running for real"}</h2>
          <p class="run-sub">${
            own
              ? "Give a test agent a task and a small budget. It runs through Leash with your saved key, so you can watch the limit hold and check the record, all before connecting your own agent."
              : "A developer gave his AI agent a task and a $100 budget. He came back to a $5,000 bill, and the agent's logs said nothing went wrong. Here is the same thing with a real AI and real money, in fractions of a cent."
          }</p>
        </div>
        <p class="run-ai" data-r="ai"></p>
      </div>
      <form class="run-form" data-r="form">
        <label class="run-task">Task
          <select name="task">${TASKS.map((t) => `<option>${esc(t)}</option>`).join("")}${own ? '<option value="custom">My own task…</option>' : ""}</select>
        </label>
        <label class="run-custom" hidden>Your task
          <input name="custom" maxlength="300" placeholder="Describe a small task">
        </label>
        <label>AI <select name="upstream"></select></label>
        <label>Budget <select name="budget"></select></label>
        <div class="run-buttons">
          <button class="btn btn-primary" type="submit" data-r="start">Start the agent</button>
          <button class="btn btn-danger" type="button" data-r="stop" disabled>Stop it now</button>
        </div>
      </form>
      <div class="run-grid">
        <div class="run-col">
          <h3>What the agent is doing</h3>
          <ol class="run-steps" data-r="steps"><li class="run-empty">Pick a task and press <strong>Start the agent</strong>. It's told to keep improving its work, so it will keep going until something stops it.</li></ol>
          <details class="run-prompts">
            <summary>Exactly what we tell the agent</summary>
            <p><strong>Instructions:</strong> ${esc(SYSTEM)}</p>
            <p><strong>After each step:</strong> ${esc(CONTINUE)}</p>
            <p><strong>At the end:</strong> ${esc(reportPrompt("<the task>", "<its last step>"))}</p>
          </details>
        </div>
        <div class="run-col">
          <h3>Its budget, enforced by Leash</h3>
          <div class="run-meter">
            <div class="run-money"><span data-r="spent">$0.00</span><small data-r="of">of a budget not set yet</small></div>
            <div class="bar run-bar"><i data-r="bar"></i></div>
            <p class="run-counts" data-r="counts">No steps yet</p>
          </div>
          <p class="run-verdict" data-r="verdict" aria-live="polite"></p>
          <div class="run-compare" data-r="compare" hidden>
            <div class="run-says">
              <h4>What the agent says it did</h4>
              <p data-r="says"></p>
            </div>
            <div class="run-record">
              <h4>What Leash recorded</h4>
              <dl data-r="record"></dl>
              <p class="run-seal" data-r="seal"></p>
            </div>
          </div>
          <div class="run-fake" data-r="fakebox" hidden>
            <button class="btn" type="button" data-r="fake">Try to fake the record</button>
            <p class="run-fake-note">${
              own
                ? "Leash edits a copy of your record the way a cover-up would (one step's cost changed to $0.00) and checks it. Your real record isn't touched."
                : "This really edits the database: one step's cost is changed to $0.00, the way a cover-up would hide a bill."
            }</p>
            <p class="run-fake-out" data-r="fakeout" aria-live="polite"></p>
          </div>
        </div>
      </div>`;
  }

  function mount(root, opts) {
    const mode = opts.mode;
    root.innerHTML = template(mode);
    const $ = (name) => root.querySelector(`[data-r="${name}"]`);
    const form = $("form");
    const st = { busy: false, stop: false, jti: null, token: null, budget: 0, spent: 0, allowed: 0, refused: 0, real: false, config: null };

    function choices() {
      const list = [];
      const rd = st.config?.real_demo || {};
      if (mode === "sandbox") {
        if (rd.available) list.push({ value: "openai", model: rd.model, label: `Real AI (${rd.model}), paid by this demo`, real: true });
      } else {
        (opts.realChoices?.() || []).forEach((c) => list.push({ ...c, real: true }));
      }
      list.push({ value: "fake", model: "practice-model", label: mode === "workspace" ? "Practice AI (free, fake replies)" : "Free fake AI", real: false });
      return list;
    }

    function syncAI() {
      const select = form.elements.upstream;
      const previous = select.value;
      const list = choices();
      select.innerHTML = list.map((c) => `<option value="${esc(c.value)}">${esc(c.label)}</option>`).join("");
      if (select.dataset.touched && list.some((c) => c.value === previous)) select.value = previous;
      syncBudgets();
      describeAI();
    }

    // The note beside the title describes the AI that's actually selected.
    function describeAI() {
      const rd = st.config?.real_demo || {};
      const ai = $("ai");
      const real = selected().real;
      if (mode === "sandbox") {
        if (real) {
          ai.innerHTML = `<strong>Real AI, real money.</strong> You have ${esc(cents(rd.left_usd))} of real AI left in this demo (out of ${esc(cents(rd.visitor_budget_usd))}). ${esc(usd(rd.public_left_usd))} of the ${esc(usd(rd.public_budget_usd))} shared budget is left for everyone.`;
        } else {
          ai.innerHTML = rd.available
            ? "<strong>Free fake AI, pretend money.</strong> Pick the real AI to spend real fractions of a cent instead."
            : "The real-AI budget for this demo is used up, so it runs on the free fake AI. Sign up to run agents on your own key.";
        }
      } else if (mode === "operator") {
        const server = selected().value === "openai";
        ai.innerHTML = !real
          ? "<strong>Free fake AI, pretend money.</strong>"
          : server
            ? `<strong>Server key, real money.</strong> ${esc(usd(rd.left_usd))} of real spending left on it. Public demo: ${esc(usd(rd.public_left_usd))} left.`
            : "<strong>Your saved key, real money.</strong> The budget below caps what this run can spend.";
      } else {
        ai.innerHTML = real
          ? "<strong>Your own key, real money.</strong> The budget below caps what this test can spend."
          : choices().length > 1
            ? "<strong>Practice AI, pretend money.</strong>"
            : "Save an AI key above to run the agent on real AI. Until then it uses the free practice AI.";
      }
    }

    function selected() {
      return choices().find((c) => c.value === form.elements.upstream.value) || choices()[0];
    }

    function syncBudgets() {
      const c = selected();
      const select = form.elements.budget;
      const previous = select.value;
      let options;
      if (!c.real) options = [[0.25, "$0.25 (pretend money, $0.05 a step)"], [0.5, "$0.50 (pretend money)"], [1, "$1.00 (pretend money)"]];
      else {
        options = [[0.001, "$0.001 (a tenth of a cent)"], [0.002, "$0.002 (a fifth of a cent)"], [0.005, "$0.005 (half a cent)"]];
        if (mode === "workspace") options.push([0.02, "$0.02 (two cents)"]);
      }
      select.innerHTML = options.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join("");
      if (options.some(([v]) => String(v) === previous)) select.value = previous;
      else select.value = String(options[c.real ? 0 : 1][0]); // real: a tenth of a cent keeps a live run short
    }

    form.elements.upstream.addEventListener("change", (e) => {
      e.target.dataset.touched = "1";
      syncBudgets();
      describeAI();
    });
    form.elements.task.addEventListener("change", () => {
      root.querySelector(".run-custom").hidden = form.elements.task.value !== "custom";
    });

    async function loadConfig() {
      try {
        st.config = await opts.api("/config");
      } catch { /* the page shows its own errors */ }
      syncAI();
    }

    function meter() {
      $("spent").textContent = usd(st.spent);
      $("of").textContent = st.budget ? `spent of a ${usd(st.budget)} budget` : "of a budget not set yet";
      const bar = $("bar");
      bar.style.width = st.budget ? `${Math.min(100, (st.spent / st.budget) * 100)}%` : "0";
      bar.classList.toggle("full", st.budget > 0 && st.refused > 0);
      $("counts").textContent = st.allowed || st.refused
        ? `${st.allowed} ${st.allowed === 1 ? "step" : "steps"} allowed · ${st.refused} refused`
        : "No steps yet";
    }

    function step(html, cls = "") {
      const ol = $("steps");
      ol.querySelector(".run-empty")?.remove();
      const li = document.createElement("li");
      li.className = cls;
      li.innerHTML = html;
      ol.appendChild(li);
      ol.scrollTop = ol.scrollHeight;
      return li;
    }

    function splitNext(text) {
      const m = text.match(/\n?\s*NEXT:\s*(.*)$/is);
      return m ? [text.slice(0, m.index).trim(), m[1].trim()] : [text.trim(), ""];
    }

    async function issue(choice, budget, maxCalls, agent) {
      return opts.api("/tokens", {
        method: "POST",
        body: JSON.stringify({ agent, upstream: choice.value, ttl_minutes: mode === "workspace" ? 60 : 10, max_calls: maxCalls, budget_usd: budget }),
      });
    }

    async function call(token, model, messages, maxTokens) {
      const res = await fetch("/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
        body: JSON.stringify({ model, messages, max_tokens: maxTokens }),
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, data, cost: Number(res.headers.get("X-Leash-Call-Cost") || 0) };
    }

    async function run() {
      let choice = selected();
      const task = form.elements.task.value === "custom" ? form.elements.custom.value.trim() : form.elements.task.value;
      if (!task) {
        $("verdict").textContent = "Write a task for the agent first.";
        return;
      }
      Object.assign(st, { stop: false, jti: null, token: null, spent: 0, allowed: 0, refused: 0, budget: 0 });
      $("steps").innerHTML = "";
      $("compare").hidden = true;
      $("fakebox").hidden = true;
      $("fakeout").textContent = "";
      $("verdict").className = "run-verdict";
      $("verdict").textContent = "";
      meter();

      if (mode !== "workspace") {
        await opts.api("/demo/reset", { method: "POST" }); // every run starts with a fresh record
        opts.onReset?.();
      }

      let issued;
      try {
        issued = await issue(choice, Number(form.elements.budget.value), 40, "task-agent");
      } catch (err) {
        if (!choice.real) throw err;
        step(`<span class="run-tag">Note</span>${esc(err.message)} This run uses the free fake AI.`, "run-note");
        choice = choices().find((c) => !c.real);
        issued = await issue(choice, 0.5, 40, "task-agent");
      }
      Object.assign(st, { token: issued.token, jti: issued.claims.jti, budget: issued.claims.budget_usd, real: choice.real });
      meter();
      step(
        `<span class="run-tag">You</span>Here's the task: “${esc(task)}”. Leash gave the agent a pass with a ${esc(usd(st.budget))} budget${
          choice.real ? ", paid in real money" : " (pretend money)"
        }. The agent never sees the API key.`,
        "run-you"
      );
      $("stop").disabled = false;

      const history = [];
      let lastReply = "";
      let lastNext = "";
      let refusal = null;
      for (let i = 1; i <= STEP_CAP; i++) {
        // The instructions, the task, then the last two steps (each followed by "continue").
        const messages = [{ role: "system", content: SYSTEM }, { role: "user", content: task }, ...history];
        const r = await call(st.token, choice.model, messages, 120);
        if (!r.ok) {
          st.refused += 1;
          refusal = r.data?.error || { code: "ERROR", message: "The call failed." };
          meter();
          step(
            `<span class="run-tag">Step ${i}: refused by Leash</span>${esc(BLOCK_TEXT[refusal.code] || refusal.message)}<span class="run-detail">${esc(refusal.message)}</span>`,
            "run-refused"
          );
          break;
        }
        const text = (r.data.choices?.[0]?.message?.content || "").trim();
        const [work, next] = splitNext(text);
        st.allowed += 1;
        st.spent += r.cost;
        meter();
        step(
          `<span class="run-tag">Step ${i} · ${esc(usd(r.cost))}</span>${esc(work.slice(0, 220))}${work.length > 220 ? "…" : ""}${
            next ? `<span class="run-next">Next: ${esc(next.slice(0, 120))}</span>` : ""
          }`,
          "run-step"
        );
        history.push({ role: "assistant", content: text }, { role: "user", content: CONTINUE });
        history.splice(0, Math.max(0, history.length - 4));
        lastReply = work;
        lastNext = next || lastNext;
        await sleep(250);
      }
      $("stop").disabled = true;

      const v = $("verdict");
      if (refusal) {
        v.className = "run-verdict bad";
        v.innerHTML =
          refusal.code === "BUDGET_EXCEEDED"
            ? `<strong>Stopped at ${esc(usd(st.spent))} of ${esc(usd(st.budget))}.</strong> The agent wanted to keep going${
                lastNext ? `: “${esc(lastNext)}”` : ""
              }. In the story the agent kept going until $5,000. Here it can't go over its budget.`
            : `<strong>The agent was stopped.</strong> ${esc(BLOCK_TEXT[refusal.code] || refusal.message)}`;
      } else {
        v.className = "run-verdict";
        v.textContent = `We ended the demo after ${STEP_CAP} steps.`;
      }

      // The agent's own account, written by the agent itself.
      let says = "";
      try {
        const reportBudget = choice.real ? 0.0005 : 0.05;
        const rep = await issue(choice, reportBudget, 1, "task-agent-report");
        const r = await call(rep.token, choice.model, [{ role: "user", content: reportPrompt(task, lastReply) }], 80);
        says = r.ok ? (r.data.choices?.[0]?.message?.content || "").trim() : `(It couldn't write one: ${r.data?.error?.message || "the call failed"}.)`;
      } catch (err) {
        says = `(It couldn't write one: ${err.message})`;
      }
      $("says").textContent = says || "(The agent wrote nothing.)";
      await showReceipt();
      $("compare").hidden = false;
      $("fakebox").hidden = false;
      $("fake").disabled = st.allowed === 0;
    }

    async function showReceipt(sealOverride) {
      const rec = await opts.api(`/tokens/${encodeURIComponent(st.jti)}/receipt`);
      const seal = sealOverride || rec.seal;
      $("record").innerHTML = `
        <dt>Steps allowed</dt><dd>${rec.calls_allowed}</dd>
        <dt>Steps refused</dt><dd>${rec.calls_blocked}</dd>
        <dt>Spent</dt><dd>${esc(usd(rec.spent_usd))} of ${esc(usd(rec.budget_usd))}</dd>
        <dt>Stopped by</dt><dd>${esc(rec.stopped_by ? STOPPED_BY[rec.stopped_by] || rec.stopped_by : "nothing")}</dd>
        <dt>Log entries</dt><dd>#${rec.first_entry ?? "–"} to #${rec.last_entry ?? "–"}</dd>`;
      const sealEl = $("seal");
      sealEl.className = "run-seal " + (seal.ok ? "good" : "bad");
      sealEl.innerHTML = seal.ok
        ? `<strong>Seal intact.</strong> All ${seal.checked} entries check out. The agent never touches this record: Leash writes it from the calls themselves and seals each entry with HMAC-SHA256.`
        : `<strong>Tampering found at entry #${esc(seal.broken_at)}.</strong> ${esc(seal.reason)}`;
    }

    $("fake").addEventListener("click", async () => {
      $("fake").disabled = true;
      const out = $("fakeout");
      try {
        let tamperedId, before, result;
        if (mode === "workspace") {
          const t = await opts.api(`/audit/seal-test?jti=${encodeURIComponent(st.jti)}`, { method: "POST" });
          ({ tampered_id: tamperedId, before, result } = t);
        } else {
          const t = await opts.api(`/demo/tamper?target=cost&jti=${encodeURIComponent(st.jti)}`, { method: "POST" });
          tamperedId = t.tampered_id;
          before = t.before;
          result = await opts.api("/audit/verify");
          opts.onVerify?.(result);
        }
        // A real edit (demo pages) breaks the real seal; a workspace test only breaks the copy.
        if (mode !== "workspace") await showReceipt(result);
        out.className = "run-fake-out " + (result.ok ? "" : "bad");
        out.innerHTML = result.ok
          ? "No change was found."
          : `Entry #${esc(tamperedId)} said a step cost ${esc(usd(before.cost_usd))}. It was changed to say $0.00, the kind of edit that hides a bill. <strong>Leash caught it:</strong> ${esc(result.reason)}${
              mode === "workspace" ? " Your real record is untouched." : ""
            }`;
      } catch (err) {
        out.className = "run-fake-out bad";
        out.textContent = err.message;
      }
    });

    $("stop").addEventListener("click", async () => {
      if (!st.jti) return;
      $("stop").disabled = true;
      await opts.api(`/tokens/${encodeURIComponent(st.jti)}/revoke`, { method: "POST", body: JSON.stringify({ reason: "Stopped during the run" }) });
    });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (st.busy) return;
      st.busy = true;
      $("start").disabled = true;
      try {
        await run();
      } catch (err) {
        if (err.message !== "unauthorized") step(`<span class="run-tag">Something went wrong</span>${esc(err.message)}`, "run-refused");
      }
      st.busy = false;
      $("start").disabled = false;
      $("start").textContent = "Run it again";
      await loadConfig();
      opts.onAfter?.();
    });

    loadConfig();
    return { refreshChoices: syncAI, reload: loadConfig };
  }

  return { mount };
})();
