"""Generic on-disk JSON cache, keyed by an arbitrary string.

Shared by every API client that needs to avoid re-querying the network
for something it's already looked up in a previous run (OSV vuln records,
PyPI/npm registry metadata).
"""

import hashlib
import json
from pathlib import Path
from typing import Any


class DiskCache:
    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._directory.mkdir(parents=True, exist_ok=True)

    def get(self, key: str) -> Any | None:
        path = self._path_for(key)
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def set(self, key: str, value: Any) -> None:
        self._path_for(key).write_text(json.dumps(value))

    def _path_for(self, key: str) -> Path:
        # Hash the key so arbitrary characters (npm scopes like "@babel/core",
        # version strings, etc.) always produce a valid filename.
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self._directory / f"{digest}.json"
