"""In-memory sliding-window rate limits.

Fine for a single-process app (Leash runs one worker on purpose). A larger
deployment would move this to Redis or similar.
"""
import threading
import time
from collections import defaultdict, deque

from fastapi import Request


class SlidingWindow:
    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def allow(self, key: str, limit: int, window_s: float) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - window_s:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            if now - self._last_sweep > 300:
                self._sweep(now)
            return True

    def _sweep(self, now: float) -> None:
        stale = [k for k, q in self._hits.items() if not q or q[-1] < now - 3600]
        for k in stale:
            del self._hits[k]
        self._last_sweep = now


limiter = SlidingWindow()


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"
