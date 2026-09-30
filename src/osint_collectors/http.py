"""HTTP GET with a shared session, retries on 5xx/timeouts, and 429 handling.

On HTTP 429 the client raises RateLimited (it never retries a 429 itself):
callers should stop querying that service for the run and can persist the
Retry-After window with record_backoff() so later runs wait too.
"""

import datetime as _dt
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Callable, Dict, Optional

import requests

from . import __version__, clock
from .cache import Cache

DEFAULT_USER_AGENT = f"osint-collectors/{__version__} (+https://github.com/N3bula04/osint-collectors)"
RETRY_STATUSES = (500, 502, 503, 504)
DEFAULT_BACKOFF_SECONDS = 600  # used when a 429 carries no usable Retry-After


class RateLimited(Exception):
    """A server answered HTTP 429."""

    def __init__(self, retry_after: int, host: str, detail: str):
        super().__init__(detail)
        self.retry_after = retry_after
        self.host = host
        self.detail = detail


def parse_retry_after(value: Optional[str]) -> int:
    """Retry-After is delta-seconds or an HTTP date. Returns seconds (>= 0)."""
    if not value:
        return DEFAULT_BACKOFF_SECONDS
    value = value.strip()
    if value.isdigit():
        return int(value)
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
        return max(0, int((when - clock.utcnow()).total_seconds()))
    except (TypeError, ValueError, IndexError):
        return DEFAULT_BACKOFF_SECONDS


def host_of(url: str) -> str:
    parts = str(url).split("/")
    return parts[2] if len(parts) > 2 else str(url)


@dataclass
class HttpOutcome:
    """kind: 'response' (response is set), 'timeout' or 'error' (network-level failure)."""
    kind: str
    response: Optional[requests.Response]
    detail: str
    attempts: int


class HttpClient:
    def __init__(self, user_agent: str = DEFAULT_USER_AGENT, attempts: int = 1, backoff_base: float = 2.0,
                 max_backoff: float = 30.0, sleep: Callable[[float], None] = time.sleep,
                 session: Optional[requests.Session] = None):
        self.user_agent = user_agent
        self.attempts = max(1, attempts)
        self.backoff_base = backoff_base
        self.max_backoff = max_backoff
        self.sleep = sleep
        self.session = session or requests.Session()

    def get(self, url: str, *, params: Optional[dict] = None, headers: Optional[Dict[str, str]] = None,
            timeout: float = 30.0, attempts: Optional[int] = None) -> HttpOutcome:
        """GET with retries on timeouts and 5xx (backoff base**attempt seconds, capped).

        Connection-level errors are not retried (they rarely fix themselves in
        seconds). Raises RateLimited on 429. Never raises requests exceptions.
        """
        n = max(1, attempts or self.attempts)
        h = {"User-Agent": self.user_agent}
        h.update(headers or {})
        outcome = HttpOutcome("error", None, "not attempted", 0)
        for attempt in range(1, n + 1):
            try:
                resp = self.session.get(url, params=params, headers=h, timeout=timeout, allow_redirects=True)
            except requests.Timeout:
                outcome = HttpOutcome("timeout", None, f"no answer within {timeout:.0f}s", attempt)
            except requests.RequestException as e:
                return HttpOutcome("error", None, f"network error: {type(e).__name__}: {e}", attempt)
            else:
                if resp.status_code == 429:
                    raw = resp.headers.get("Retry-After")
                    host = host_of(resp.url)
                    raise RateLimited(parse_retry_after(raw), host,
                                      f"HTTP 429 rate limited by {host} (Retry-After: {raw or 'not given'})")
                outcome = HttpOutcome("response", resp, f"HTTP {resp.status_code}", attempt)
                if resp.status_code not in RETRY_STATUSES:
                    return outcome
            if attempt < n:
                self.sleep(min(self.max_backoff, self.backoff_base ** attempt))
        return outcome


# --- persisted back-off ----------------------------------------------------------

def backoff_until(cache: Cache, namespace: str, key: str = "ratelimit") -> Optional[_dt.datetime]:
    """If an earlier 429 asked us to back off from `namespace`, return when that ends (else None)."""
    if not cache.enabled:
        return None
    p = cache.path_for(namespace, key)  # read directly: --refresh must not bypass a back-off
    try:
        import json
        until = _dt.datetime.fromisoformat(json.loads(p.read_text(encoding="utf-8"))["until"])
    except (OSError, ValueError, KeyError):
        return None
    return until if until > clock.utcnow() else None


def record_backoff(cache: Cache, namespace: str, seconds: int, key: str = "ratelimit") -> _dt.datetime:
    until = clock.utcnow().replace(microsecond=0) + _dt.timedelta(seconds=seconds)
    cache.put(namespace, key, {"status": "rate_limited", "until": until.isoformat()})
    return until
