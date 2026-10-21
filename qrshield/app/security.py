"""
Web-layer protections: admin authentication, rate limiting, upload limits and response headers.

* Privileged routes need the admin token (header `X-Admin-Token`), compared in constant time.
  The token lives in <home>/admin_token (or QRSHIELD_ADMIN_TOKEN) and is printed on server start.
* A sliding-window limiter per client IP bounds scan/report abuse.
* Uploads are read in chunks and refused beyond MAX_UPLOAD_BYTES *before* being buffered whole.
* A strict Content-Security-Policy plus the usual hardening headers stop injected markup from running
  and keep the page from being framed (clickjacking a "SAFE" verdict).
"""
from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Optional

from fastapi import Depends, HTTPException, Request, UploadFile
from starlette.middleware.base import BaseHTTPMiddleware

from qrshield import config

CSP = ("default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self'; "
       "script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(self), microphone=(), geolocation=()")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


class RateLimiter:
    """Sliding window per (bucket, client). Memory is bounded by pruning idle clients."""

    def __init__(self) -> None:
        self._hits: Dict[tuple, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, bucket: str, client: str, limit: int, window: float = 60.0) -> None:
        now = time.monotonic()
        with self._lock:
            q = self._hits[(bucket, client)]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                retry = int(window - (now - q[0])) + 1
                raise HTTPException(status_code=429, detail=f"Too many requests. Try again in {retry}s.",
                                    headers={"Retry-After": str(retry)})
            q.append(now)
            if len(self._hits) > 5000:                      # prune idle keys
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > window]:
                    self._hits.pop(k, None)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def limit(bucket: str, per_minute: int):
    def dep(request: Request) -> None:
        limiter: RateLimiter = request.app.state.limiter
        limiter.check(bucket, client_ip(request), per_minute)
    return Depends(dep)


def require_admin(request: Request) -> str:
    supplied = request.headers.get("x-admin-token", "")
    expected = request.app.state.registry.admin_token()
    if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Admin token required (X-Admin-Token).")
    return "admin"


async def read_upload(upload: Optional[UploadFile], max_bytes: int = config.MAX_UPLOAD_BYTES) -> Optional[bytes]:
    """Read an upload in chunks, aborting as soon as it exceeds the limit."""
    if upload is None:
        return None
    chunks, total = [], 0
    while True:
        chunk = await upload.read(1 << 16)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail=f"Image larger than {max_bytes // (1024 * 1024)} MB.")
        chunks.append(chunk)
    return b"".join(chunks)
