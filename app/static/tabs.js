"use strict";

// Tabs with Back / Next buttons, shared by the landing page and the demo page.
//
// Markup: a container with data-tabs, holding buttons [role=tab][data-tab=name]
// and panels [data-panel=name]. Each panel may contain an empty [data-tab-step]
// element, which gets Back and Next buttons. The address bar keeps the open tab
// (#name), and a link to any element inside a panel (#some-id) opens that panel.
(() => {
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function init(root) {
    const tabs = [...root.querySelectorAll('[role="tab"][data-tab]')];
    const panels = tabs.map((t) => root.querySelector(`[data-panel="${t.dataset.tab}"]`));
    const bar = root.querySelector('[role="tablist"]');
    const label = (i) => tabs[i].dataset.label || tabs[i].textContent.trim(); // data-label skips the number badge
    let current = -1;

    tabs.forEach((tab, i) => {
      tab.id = tab.id || `tab-${tab.dataset.tab}`;
      tab.type = "button";
      tab.setAttribute("aria-controls", panels[i].id || (panels[i].id = `panel-${tab.dataset.tab}`));
      panels[i].setAttribute("role", "tabpanel");
      panels[i].setAttribute("aria-labelledby", tab.id);
      panels[i].tabIndex = -1;
      tab.addEventListener("click", () => show(i, { scroll: "up" }));
    });

    // Back / Next at the bottom of each panel.
    panels.forEach((panel, i) => {
      const slot = panel.querySelector("[data-tab-step]");
      if (!slot) return;
      slot.classList.add("tab-step");
      const back = i > 0 ? `<button type="button" class="btn tab-back" data-go="${i - 1}">← ${escapeHtml(label(i - 1))}</button>` : "<span></span>";
      const next = i < tabs.length - 1
        ? `<button type="button" class="btn btn-primary tab-next" data-go="${i + 1}">Next: ${escapeHtml(label(i + 1))} →</button>`
        : "";
      slot.innerHTML = back + next;
      slot.addEventListener("click", (e) => {
        const btn = e.target.closest("[data-go]");
        if (btn) show(Number(btn.dataset.go), { scroll: "up", focusPanel: true });
      });
    });

    bar.addEventListener("keydown", (e) => {
      const keys = { ArrowRight: current + 1, ArrowLeft: current - 1, Home: 0, End: tabs.length - 1 };
      if (!(e.key in keys)) return;
      e.preventDefault();
      const i = (keys[e.key] + tabs.length) % tabs.length;
      show(i, { scroll: false });
      tabs[i].focus();
    });

    // scroll: "up" brings the tab bar back into view if you're below it (tab and
    // Next clicks); "to" always goes to it (links from elsewhere on the page).
    function show(i, { scroll = false, focusPanel = false, hash = true } = {}) {
      if (i === current) {
        if (scroll) scrollToBar(scroll);
        return;
      }
      current = i;
      tabs.forEach((tab, j) => {
        const on = j === i;
        tab.setAttribute("aria-selected", String(on));
        tab.tabIndex = on ? 0 : -1;
        panels[j].hidden = !on;
      });
      // Keep the open tab visible in a sideways-scrolling bar (phones) without moving the page.
      const t = tabs[i];
      if (t.offsetLeft < bar.scrollLeft) bar.scrollLeft = t.offsetLeft - 8;
      else if (t.offsetLeft + t.offsetWidth > bar.scrollLeft + bar.clientWidth) bar.scrollLeft = t.offsetLeft + t.offsetWidth - bar.clientWidth + 8;
      if (hash) history.replaceState(null, "", `#${tabs[i].dataset.tab}`);
      if (scroll) scrollToBar(scroll);
      if (focusPanel) panels[i].focus({ preventScroll: true });
      root.dispatchEvent(new CustomEvent("tabshow", { detail: { name: tabs[i].dataset.tab } }));
    }

    function scrollToBar(mode) {
      const top = root.getBoundingClientRect().top + window.scrollY - 8;
      if (mode === "to" || window.scrollY > top) window.scrollTo({ top, behavior: reducedMotion ? "auto" : "smooth" });
    }

    // Open the tab named in the address bar, or the tab holding the linked element.
    function fromHash(initial) {
      const id = decodeURIComponent(location.hash.slice(1));
      if (!id) return show(0, { hash: false });
      const byName = tabs.findIndex((t) => t.dataset.tab === id);
      if (byName >= 0) return show(byName, { scroll: "to", hash: false });
      const target = document.getElementById(id);
      const panel = target && target.closest("[data-panel]");
      const i = panel ? panels.indexOf(panel) : -1;
      if (i < 0) return initial ? show(0, { hash: false }) : undefined;
      show(i, { hash: false });
      requestAnimationFrame(() => target.scrollIntoView({ block: "start" }));
    }

    window.addEventListener("hashchange", () => fromHash(false));
    fromHash(true);
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  }

  document.querySelectorAll("[data-tabs]").forEach(init);
})();
