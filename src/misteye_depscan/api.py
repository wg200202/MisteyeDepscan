from __future__ import annotations

import json
import logging
import random
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

    def _build_request(self, target: str, package_type: str) -> urllib.request.Request:
        """Build a fresh POST request (must be recreated on each retry attempt)."""
        payload = json.dumps({"target": target, "type": package_type}).encode("utf-8")
        return urllib.request.Request(
            DETECT_URL,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
            },
        )

    def detect(self, target: str, package_type: str) -> dict[str, Any]:
        """Call the detect API. Any request failure is retried up to ``max_retries`` times."""
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._limiter.wait()
            request = self._build_request(target, package_type)
            try:
                data = self._fetch_json(request)
                if _response_is_valid(data):
                    return data
                detail = data.get("error", data) if isinstance(data, dict) else data
                raise MistEyeAPIError(f"API error: {detail}")
            except Exception as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    break
                delay = self._backoff(attempt)
                if isinstance(exc, urllib.error.HTTPError) and exc.code == 429:
                    retry_after = exc.headers.get("Retry-After")
                    if retry_after:
                        try:
                            delay = float(retry_after)
                        except ValueError:
                            pass
                self._log_retry(target, attempt, _failure_reason(exc), delay)
                time.sleep(delay)

        if last_error is None:
            raise MistEyeAPIError("Unknown API error.")
        raise self._to_api_error(last_error) from last_error

    def _fetch_json(self, request: urllib.request.Request) -> dict[str, Any]:
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = response.read().decode("utf-8")
        data = json.loads(body)
        if not isinstance(data, dict):
            raise MistEyeAPIError(f"Unexpected API response type: {type(data).__name__}")
        return data

    @staticmethod
    def _backoff(attempt: int) -> float:
        """Exponential backoff (capped) with a little jitter to avoid sync retries."""
        base = min(2**attempt, 8)
        return base + random.uniform(0.0, 0.5)

    def _log_retry(self, target: str, attempt: int, reason: str, delay: float) -> None:
        logger.warning(
            "MistEye API transient error for %s (attempt %s/%s): %s; retry in %.1fs",
            target,
            attempt + 1,
            self.max_retries + 1,
            reason,
            delay,
        )

    @staticmethod
    def _format_http_error(
        exc: urllib.error.HTTPError,
        *,
        body: str | None = None,
    ) -> str:
        detail = body
        if detail is None:
            try:
                detail = exc.read().decode("utf-8")
            except Exception as read_exc:
                logger.warning("Failed to read HTTP error body: %s", read_exc)
                detail = exc.reason
        return f"HTTP {exc.code}: {detail or exc.reason}"

    @staticmethod
    def _to_api_error(exc: Exception) -> MistEyeAPIError:
        if isinstance(exc, MistEyeAPIError):
            return exc
        if isinstance(exc, urllib.error.HTTPError):
            body = _read_http_error_body(exc)
            return MistEyeAPIError(
                MistEyeClient._format_http_error(exc, body=body),
                status_code=exc.code,
            )
        if isinstance(exc, urllib.error.URLError):
            return MistEyeAPIError(f"Network error: {exc.reason}")
        if isinstance(exc, json.JSONDecodeError):
            return MistEyeAPIError("Invalid JSON response from MistEye API.")
        return MistEyeAPIError(str(exc))

    def test_connection(self) -> dict[str, Any]:
        return self.detect("example.com", "domain")


def _response_is_valid(data: dict[str, Any]) -> bool:
    """True when the payload is a successful detect response (not an error object)."""
    try:
        parse_detect_response(data)
        return True
    except MistEyeAPIError:
        return False


def _failure_reason(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        body = _read_http_error_body(exc)
        return f"HTTP {exc.code}: {body or exc.reason}"
    if isinstance(exc, urllib.error.URLError):
        return f"Network error: {exc.reason}"
    if isinstance(exc, json.JSONDecodeError):
        return "Invalid JSON response from MistEye API."
    return str(exc) or type(exc).__name__


def _read_http_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        return exc.read().decode("utf-8")
    except Exception as read_exc:
        logger.warning("Failed to read HTTP error body: %s", read_exc)
        return ""
