"""Parser for pip's requirements.txt.

Only exact pins (``name==version``) are extracted. Unpinned or ranged
requirements (``requests``, ``requests>=2.0``) don't name a single resolved
version, so they're skipped rather than guessed at.
"""

import re
from pathlib import Path

from sc_scanner.models import Dependency, Ecosystem

_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]*\])?"  # optional extras, e.g. uvicorn[standard]
    r"\s*==\s*"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)"
)


def parse(path: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []

    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue  # blank/comment-only line, or a pip option like -r/-e/--index-url

        line = line.split(";", 1)[0].strip()  # drop environment markers

        match = _PIN_RE.match(line)
        if not match:
            continue  # unpinned or otherwise-specified requirement

        dependencies.append(
            Dependency(
                name=match.group("name"),
                version=match.group("version"),
                ecosystem=Ecosystem.PYPI,
            )
        )

    return dependencies
