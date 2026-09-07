import time
from collections import defaultdict, deque


RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 30

RATE_LIMITED_PATHS = frozenset({
    "/login",
    "/auth/challenge",
    "/auth/verify",
})


_lock = __import__("threading").Lock()
_rate_limit_hits = defaultdict(deque)


def is_rate_limited(
    client_ip: str,
    path: str
) -> bool:
    now = time.monotonic()
    key = f"{client_ip}:{path}"

    with _lock:
        hits = _rate_limit_hits[key]

        while (
            hits
            and now - hits[0] > RATE_LIMIT_WINDOW_SECONDS
        ):
            hits.popleft()

        if len(hits) >= RATE_LIMIT_MAX_REQUESTS:
            return True

        hits.append(now)

        return False


def clear_rate_limits():
    with _lock:
        _rate_limit_hits.clear()
