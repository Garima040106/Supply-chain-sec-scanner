"""Test doubles standing in for requests.Session, so vuln-matching tests
never make real network calls."""

import requests


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, headers=None, reason="", content=b""):
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers or {}
        self.reason = reason
        self.content = content

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code} {self.reason}", response=self)


class FakeSession:
    """Returns canned responses (or raises canned exceptions) in call order."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def request(self, method, url, json=None, headers=None, timeout=None):
        self.calls.append(
            {"method": method, "url": url, "json": json, "headers": headers, "timeout": timeout}
        )
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeRoutedSession:
    """Like FakeSession, but responses are matched by a URL substring
    rather than call order. Strict ordering gets unmanageable once a test
    exercises many dependencies across several unrelated API clients (as
    the full-pipeline integration tests do) - order-independent routing
    makes those tests robust to exactly how many calls happen or in what
    sequence, at the cost of not verifying call order itself (the
    ordering-sensitive retry/caching tests use plain FakeSession instead).
    """

    def __init__(self, routes, default=None):
        self._routes = routes
        self._default = default
        self.calls = []

    def request(self, method, url, json=None, headers=None, timeout=None):
        self.calls.append(
            {"method": method, "url": url, "json": json, "headers": headers, "timeout": timeout}
        )
        for substring, response in self._routes.items():
            if substring in url:
                if isinstance(response, Exception):
                    raise response
                return response

        if self._default is not None:
            if isinstance(self._default, Exception):
                raise self._default
            return self._default

        raise AssertionError(f"FakeRoutedSession: no route configured for {url}")
