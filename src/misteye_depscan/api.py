from __future__ import annotations

import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

DETECT_URL = "https://app-api.misteye.io/functions/v1/detect"
MISTEYE_WEB_BASE = "https://app.misteye.io/home"
DEFAULT_RATE_LIMIT = 10.0  # requests per second
API_STATUS_MALICIOUS = "malicious"
API_STATUS_UNKNOWN = "unknown"

# API package_type → MistEye web UI type parameter
_WEB_TYPE_MAP: dict[str, str] = {
    "package:pypi": "pip",
    "package:npm": "npm",
    "package:go": "go",
    "package:nuget": "nuget",
    "package:rubygems": "rubygems",
    "package:cratesio": "cratesio",
}


def build_search_url(target: str, package_type: str) -> str:
    """Build the MistEye web console URL for viewing threat details."""
    from urllib.parse import quote
    web_type = _WEB_TYPE_MAP.get(package_type, package_type)
    ioc = quote(target, safe="")
    return f"{MISTEYE_WEB_BASE}?ioc={ioc}&type={web_type}"


class RateLimiter:
    def __init__(self, rate: float = DEFAULT_RATE_LIMIT) -> None:
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next_time = 0.0

    def wait(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_time:
                time.sleep(self._next_time - now)
            self._next_time = max(now, self._next_time) + self._interval


class MistEyeAPIError(Exception):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def parse_detect_response(response: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Parse MistEye detect API response into (api_status, matches)."""
    matches = response.get("matches") or []
    api_status = response.get("status")

    if api_status in {API_STATUS_MALICIOUS, API_STATUS_UNKNOWN}:
        if api_status == API_STATUS_UNKNOWN and matches:
            return API_STATUS_MALICIOUS, matches
        return api_status, matches

    # Backward compatibility for legacy responses that still return `safe`.
    safe = response.get("safe")
    if safe is False or matches:
        return API_STATUS_MALICIOUS, matches
    if safe is True:
        return API_STATUS_UNKNOWN, matches
    raise MistEyeAPIError("Response missing status/matches fields.")


class MistEyeClient:
    def __init__(
        self,
        api_key: str,
        *,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        timeout: float = 60.0,
        max_retries: int = 3,
    ) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self._limiter = RateLimiter(rate_limit)

    def detect(self, target: str, package_type: str) -> dict[str, Any]:
        payload = json.dumps({"target": target, "type": package_type}).encode("utf-8")
        request = urllib.request.Request(
            DETECT_URL,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
            },
        )

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._limiter.wait()
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8")
                    return json.loads(body)
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code == 429 and attempt < self.max_retries:
                    retry_after = exc.headers.get("Retry-After")
                    delay = float(retry_after) if retry_after else min(2**attempt, 8)
                    time.sleep(delay)
                    continue
                raise MistEyeAPIError(self._format_http_error(exc), status_code=exc.code) from exc
            except urllib.error.URLError as exc:
                last_error = exc
                if attempt < self.max_retries and _is_retryable_url_error(exc):
                    delay = min(2**attempt, 8)
                    logger.warning(
                        "MistEye API network error for %s (attempt %s/%s): %s; retry in %ss",
                        target,
                        attempt + 1,
                        self.max_retries + 1,
                        exc.reason,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                raise MistEyeAPIError(f"Network error: {exc.reason}") from exc
            except (TimeoutError, socket.timeout) as exc:
                last_error = exc
                if attempt < self.max_retries:
                    delay = min(2**attempt, 8)
                    logger.warning(
                        "MistEye API timeout for %s (attempt %s/%s); retry in %ss",
                        target,
                        attempt + 1,
                        self.max_retries + 1,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                raise MistEyeAPIError(
                    f"Request timed out after {self.timeout}s: {target}"
                ) from exc
            except json.JSONDecodeError as exc:
                raise MistEyeAPIError("Invalid JSON response from MistEye API.") from exc

        raise MistEyeAPIError(str(last_error) if last_error else "Unknown API error.")

    @staticmethod
    def _format_http_error(exc: urllib.error.HTTPError) -> str:
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = exc.reason
        return f"HTTP {exc.code}: {detail or exc.reason}"

    def test_connection(self) -> dict[str, Any]:
        return self.detect("example.com", "domain")


def _is_retryable_url_error(exc: urllib.error.URLError) -> bool:
    reason = exc.reason
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return True
    if isinstance(reason, OSError) and reason.errno is not None:
        return reason.errno in {110, 60}  # ETIMEDOUT, ECONNRESET (platform-dependent)
    return True
