"""Parser for Poetry's poetry.lock (TOML format)."""

import tomllib
from pathlib import Path

from sc_scanner.models import Dependency, Ecosystem


def parse(path: Path) -> list[Dependency]:
    with path.open("rb") as f:
        data = tomllib.load(f)

    return [
        Dependency(
            name=package["name"],
            version=package["version"],
            ecosystem=Ecosystem.PYPI,
        )
        for package in data.get("package", [])
    ]
