"""The two places a request can go after it passes every check."""
import itertools
import re
import secrets
import time

import httpx

from . import config

_FAKE_REPLIES = itertools.cycle(
    [
        "Step complete. The task isn't finished yet, so I'll call the API again.",
        "Still working. One more call should do it.",
        "Progress made. Calling the API again to continue.",
        "Almost there. Requesting another completion.",
        "Retrying to be thorough.",
    ]
)


class UpstreamError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _fake_reply(prompt: str) -> str:
    """Believable canned answers for Maya's support-inbox story; generic ones otherwise."""
    if "Draft a short" in prompt:
        if "#1042" in prompt or "Priya" in prompt:
            return "Hi Priya, thanks for your patience! Your mug set shipped yesterday and should arrive in 2 to 3 days. Maya's Shop"
        if "cracked" in prompt or "return" in prompt.lower():
            return "Hi Daniel, we're so sorry about the bowl! Send us a photo and we'll ship a replacement or refund you, no need to return it. Maya's Shop"
        return "Thanks for your email. We'll get back to you shortly. Maya's Shop"
    if prompt.startswith("Reply to the auto-reply"):
        return "Thank you for letting us know. Maya's Shop"
    if "say hello" in prompt.lower():  # the workspace's "Try it" button
        return "Hello! I can hear you. This reply came from Leash's free practice AI."
    return next(_FAKE_REPLIES)


_AGENT_STEPS = itertools.cycle(
    [
        "Drafted a first version and tightened the opening line.\nNEXT: make the wording warmer",
        "Made the wording warmer and added a concrete detail.\nNEXT: add a second version to compare",
        "Wrote a second version with a different angle.\nNEXT: polish both versions again",
        "Polished both versions and fixed the rhythm.\nNEXT: add a short call to action",
        "Added a call to action to each version.\nNEXT: try a third, bolder version",
        "Wrote a bolder third version.\nNEXT: review everything one more time",
    ]
)


def fake_completion(body: dict) -> dict:
    """An OpenAI-shaped response that costs nothing. Safe for runaway demos."""
    messages = [m for m in body.get("messages", []) if isinstance(m, dict)]
    prompt_chars = sum(len(str(m.get("content", ""))) for m in messages)
    last = str(messages[-1].get("content", "")) if messages else ""
    first = str(messages[0].get("content", "")) if messages else ""
    if "status report" in last:  # the test agent's own account of its work
        reply = "I completed the task in a few quick steps and kept the cost low. Everything went to plan."
    elif "NEXT:" in first:  # the test agent, told to keep improving its work
        reply = next(_AGENT_STEPS)
    else:
        reply = _fake_reply(last)
    prompt_tokens = max(1, prompt_chars // 4)
    completion_tokens = max(1, len(reply) // 4)
    return {
        "id": f"chatcmpl-fake-{secrets.token_hex(6)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model") or "fake-model",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


# A key-like word: "sk-…" or "lsh_…", including keys a provider has partly
# starred out ("sk-Ab12****9xYz"). The word boundary keeps ordinary words like
# "task-runner" intact, and a trailing full stop is left in place.
_KEYLIKE = re.compile(r"\b(?:sk|lsh)[-_](?=[A-Za-z0-9_\-.*•]{4,})[A-Za-z0-9_\-*•]+(?:\.[A-Za-z0-9_\-*•]+)*")


def _scrub(message: str, api_key: str) -> str:
    """Providers sometimes echo part of a bad key in errors. Never pass that on."""
    if api_key:
        message = message.replace(api_key, "[key]")
    return _KEYLIKE.sub("[key]", message)


def openai_completion(body: dict, base_url: str = "", api_key: str = "") -> dict:
    """Forward to an OpenAI-compatible API. This is the ONLY place a real key is used.

    With no arguments it uses the server's own key from the environment. For a
    team's stored key ("bring your own key"), the caller passes the base URL
    and the key it has just decrypted.
    """
    base_url = (base_url or config.OPENAI_BASE_URL).rstrip("/")
    api_key = api_key or config.OPENAI_API_KEY
    payload = dict(body)
    payload["stream"] = False
    if "max_tokens" not in payload and "max_completion_tokens" not in payload:
        payload["max_completion_tokens"] = config.DEFAULT_MAX_COMPLETION_TOKENS
    try:
        response = httpx.post(
            f"{base_url}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json=payload,
            timeout=60,
        )
    except httpx.HTTPError as exc:
        raise UpstreamError(502, f"Could not reach the AI provider: {exc.__class__.__name__}")
    if response.status_code >= 400:
        try:
            message = response.json().get("error", {}).get("message", response.text[:200])
        except (ValueError, AttributeError):
            message = response.text[:200]
        raise UpstreamError(response.status_code, f"The AI provider returned an error: {_scrub(str(message), api_key)}")
    return response.json()


def cost_of(kind: str, usage: dict) -> float:
    """`kind` is "fake" for the free fake AI, anything else for a real provider."""
    if kind == "fake":
        return config.FAKE_COST_PER_CALL
    prompt = usage.get("prompt_tokens", 0) or 0
    completion = usage.get("completion_tokens", 0) or 0
    return (prompt * config.PRICE_INPUT_PER_1M + completion * config.PRICE_OUTPUT_PER_1M) / 1_000_000


def estimate_worst_case(kind: str, body: dict, prompt_text: str) -> float:
    """Pre-flight estimate, so a single call can't blow far past the budget."""
    if kind == "fake":
        return config.FAKE_COST_PER_CALL
    max_out = body.get("max_completion_tokens") or body.get("max_tokens") or config.DEFAULT_MAX_COMPLETION_TOKENS
    # Deliberately on the high side (about 3 characters per token, plus a little
    # per message), so the real cost settled afterwards is never above it.
    messages = body.get("messages") or []
    prompt_tokens = len(prompt_text) / 3 + 8 * len(messages) + 16
    return (prompt_tokens * config.PRICE_INPUT_PER_1M + max_out * config.PRICE_OUTPUT_PER_1M) / 1_000_000
