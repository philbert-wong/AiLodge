"use strict";

// Sign-up and log-in share one page; the server sets data-auth="signup" on /signup.
const MODE = document.body.dataset.auth === "signup" ? "signup" : "login";
const form = document.getElementById("auth-form");
const errorEl = document.getElementById("auth-error");
const submit = document.getElementById("auth-submit");

form.elements.password.autocomplete = MODE === "signup" ? "new-password" : "current-password";
form.elements.team.required = MODE === "signup";
(MODE === "signup" ? form.elements.team : form.elements.email).focus();

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorEl.textContent = "";
  const email = form.elements.email.value.trim();
  const password = form.elements.password.value;
  const team = form.elements.team.value.trim();
  if (MODE === "signup" && !team) return (errorEl.textContent = "Enter your team or company name.");
  if (!email) return (errorEl.textContent = "Enter your email.");
  if (MODE === "signup" && password.length < 10) return (errorEl.textContent = "Use at least 10 characters for your password.");
  if (!password) return (errorEl.textContent = "Enter your password.");

  submit.disabled = true;
  try {
    const body = MODE === "signup" ? { team, email, password } : { email, password };
    const res = await fetch(`/api/account/${MODE}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Leash-App": "1" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "That didn't work. Check the form and try again.");
    window.location.assign("/app");
  } catch (err) {
    errorEl.textContent = err.message;
    submit.disabled = false;
  }
});
