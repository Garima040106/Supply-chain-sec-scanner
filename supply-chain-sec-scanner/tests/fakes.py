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
