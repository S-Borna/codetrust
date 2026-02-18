"""IP-based rate limiting and abuse protection middleware."""

import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# --- Rate Limiting ---
IP_RATE_LIMIT = 600          # requests per window (supports workspace-wide scans)
IP_RATE_WINDOW = 60          # seconds (1 minute)
IP_BURST_LIMIT = 200         # max requests in burst window (startup scan of ~100 files)
IP_BURST_WINDOW = 10         # seconds
IP_BAN_THRESHOLD = 10        # consecutive limit hits before temp ban
IP_BAN_DURATION = 120        # seconds (2 minutes)

CLEANUP_INTERVAL_SECS: float = 300.0   # 5 minutes between stale-bucket sweeps
STALE_BUCKET_SECS: float = 600.0       # 10 minutes before a bucket is stale

# --- Request Size Limits ---
MAX_BODY_SIZE = 1_048_576    # 1 MB max request body
MAX_URL_LENGTH = 2048        # max URL length

# Paths exempt from IP rate limiting (health checks, status, docs)
EXEMPT_PATHS = frozenset({
    "/v1/status",
    "/v1/stats/public",
    "/v1/stats/live",
    "/v1/telemetry",
    "/health",
    "/",
    "/docs",
    "/openapi.json",
    "/metrics",
})


class _IPBucket:
    """Sliding window counter for a single IP."""

    __slots__ = ("banned_until", "burst_hits", "burst_start", "hits", "violations", "window_start")

    def __init__(self) -> None:
        now = time.monotonic()
        self.hits: int = 0
        self.burst_hits: int = 0
        self.window_start: float = now
        self.burst_start: float = now
        self.violations: int = 0
        self.banned_until: float = 0.0

    def check(self, now: float) -> bool:
        """Return True if request is allowed, False if rate-limited."""
        # Check ban
        if now < self.banned_until:
            return False

        # Reset window if expired
        if now - self.window_start >= IP_RATE_WINDOW:
            self.hits = 0
            self.window_start = now

        # Reset burst window if expired
        if now - self.burst_start >= IP_BURST_WINDOW:
            self.burst_hits = 0
            self.burst_start = now

        # Check limits
        self.hits += 1
        self.burst_hits += 1

        if self.burst_hits > IP_BURST_LIMIT or self.hits > IP_RATE_LIMIT:
            self.violations += 1
            if self.violations >= IP_BAN_THRESHOLD:
                self.banned_until = now + IP_BAN_DURATION
                self.violations = 0
            return False

        # Successful request resets violation counter gradually
        if self.violations > 0 and self.hits % 20 == 0:
            self.violations = max(0, self.violations - 1)

        return True


class IPRateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware that rate-limits requests by client IP before auth runs.

    Uses in-memory sliding windows - lightweight, no external dependencies.
    Tracks per-IP request counts and temporarily bans repeat offenders.
    """

    def __init__(self, app: object) -> None:
        super().__init__(app)
        self._buckets: dict[str, _IPBucket] = defaultdict(_IPBucket)
        self._last_cleanup: float = time.monotonic()
        self._cleanup_interval: float = CLEANUP_INTERVAL_SECS

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, respecting X-Forwarded-For from trusted proxies."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _cleanup_stale(self, now: float) -> None:
        """Remove buckets that haven't been used in 10 minutes."""
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        stale_threshold = now - STALE_BUCKET_SECS
        stale_ips = [
            ip for ip, bucket in self._buckets.items()
            if bucket.window_start < stale_threshold and bucket.banned_until < now
        ]
        for ip in stale_ips:
            del self._buckets[ip]

    def _check_request_size(self, request: Request) -> JSONResponse | None:
        """Return an error response if URL or body exceeds size limits."""
        if len(str(request.url)) > MAX_URL_LENGTH:
            return JSONResponse(
                status_code=414,
                content={"error": "uri_too_long", "message": "Request URL too long."},
            )

        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_BODY_SIZE:
            return JSONResponse(
                status_code=413,
                content={
                    "error": "payload_too_large",
                    "message": f"Request body exceeds {MAX_BODY_SIZE // 1024}KB limit.",
                },
            )
        return None

    def _check_rate_limit(self, request: Request) -> JSONResponse | None:
        """Return a 429 response if the client IP is rate-limited."""
        now = time.monotonic()
        self._cleanup_stale(now)

        client_ip = self._get_client_ip(request)
        bucket = self._buckets[client_ip]

        if not bucket.check(now):
            retry_after = int(IP_RATE_WINDOW - (now - bucket.window_start))
            if bucket.banned_until > now:
                retry_after = int(bucket.banned_until - now)

            return JSONResponse(
                status_code=429,
                content={
                    "error": "too_many_requests",
                    "message": "Rate limit exceeded. Slow down.",
                    "retry_after": max(1, retry_after),
                },
                headers={"Retry-After": str(max(1, retry_after))},
            )
        return None

    async def dispatch(self, request: Request, call_next: object) -> object:
        """Check IP rate limit, request size, and URL length before processing."""
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        size_error = self._check_request_size(request)
        if size_error is not None:
            return size_error

        rate_error = self._check_rate_limit(request)
        if rate_error is not None:
            return rate_error

        response: object = await call_next(request)
        return response
