"""Shared retrying HTTP-JSON request helper.

Used by every external API client in this project (OSV, PyPI, npm
registry) so retry/backoff/rate-limit handling lives in exactly one
place instead of being copy-pasted per client.
"""

import time
from typing import Any

import requests

_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class HttpError(Exception):
    """Raised when a request can't be completed after retries are exhausted."""


def request_json(
    session: requests.Session,
    method: str,
    url: str,
    *,
    json_body: dict | None = None,
    headers: dict | None = None,
    timeout: float = 10.0,
    max_retries: int = 3,
    backoff_seconds: float = 1.0,
) -> dict[str, Any]:
    last_error: Exception = HttpError(f"no attempts made for {url}")

    for attempt in range(max_retries + 1):
        if attempt > 0:
            time.sleep(backoff_seconds * (2 ** (attempt - 1)))

        try:
            response = session.request(
                method, url, json=json_body, headers=headers, timeout=timeout
            )
        except requests.exceptions.RequestException as exc:
            last_error = exc
            continue

        if response.status_code == 200:
            return response.json()

        if response.status_code not in _RETRYABLE_STATUS_CODES:
            response.raise_for_status()

        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            if retry_after is not None:
                time.sleep(float(retry_after))

        last_error = requests.exceptions.HTTPError(
            f"{response.status_code} {response.reason} from {url}",
            response=response,
        )

    raise HttpError(
        f"Request to {url} failed after {max_retries + 1} attempts"
    ) from last_error
