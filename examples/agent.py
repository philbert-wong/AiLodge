"""A deliberately runaway agent that talks to Leash.

Usage:
    python examples/agent.py <leash-url> <leash-token> [model]

Example:
    python examples/agent.py https://leash.onrender.com lsh_eyJ...

It keeps calling the API "until the task is done", which it never is.
Watch Leash cut it off when the budget or call limit runs out, or revoke
the token from the dashboard and watch it stop on the next call.

Any OpenAI SDK works the same way, just point base_url at Leash:
    from openai import OpenAI
    client = OpenAI(base_url="<leash-url>/v1", api_key="<leash-token>")
"""
import sys
import time

import httpx


def main() -> None:
    if len(sys.argv) not in (3, 4):
        print(__doc__)
        sys.exit(1)
    base_url, token = sys.argv[1].rstrip("/"), sys.argv[2]
    # For a token issued with the OpenAI upstream, pass the server's OPENAI_MODEL as a 3rd argument.
    model = sys.argv[3] if len(sys.argv) == 4 else "fake-model"
    call = 0
    while True:
        call += 1
        response = httpx.post(
            f"{base_url}/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": model, "messages": [{"role": "user", "content": "Continue the task."}]},
            timeout=60,
        )
        data = response.json()
        if response.status_code != 200:
            error = data.get("error", {})
            print(f"\nStopped by Leash after {call - 1} calls: {error.get('code')} - {error.get('message')}")
            break
        reply = data["choices"][0]["message"]["content"]
        remaining = response.headers.get("X-Leash-Budget-Remaining")
        print(f"call {call:>3}: {reply}  (budget left ${float(remaining):.2f})")
        time.sleep(0.3)


if __name__ == "__main__":
    main()
