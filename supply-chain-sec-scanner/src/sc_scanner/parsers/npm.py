"""Parser for npm's package-lock.json.

Only the "packages" format is supported (lockfileVersion 2 or 3, produced
by npm 7+). The older lockfileVersion 1 nested-"dependencies" format is not
handled.
"""

import json
from pathlib import Path

from sc_scanner.models import Dependency, Ecosystem


def parse(path: Path) -> list[Dependency]:
    data = json.loads(path.read_text())
    packages = data.get("packages")
    if packages is None:
        raise ValueError(
            f"{path}: unsupported package-lock.json format "
            "(expected lockfileVersion 2 or 3 with a top-level 'packages' key)"
        )

    dependencies: list[Dependency] = []
    for package_path, info in packages.items():
        if package_path == "":
            continue  # the root project itself, not a dependency

        version = info.get("version")
        if version is None:
            continue  # e.g. a local workspace "link" entry with no version

        # Keys look like "node_modules/chalk" or, for nested/deduped
        # copies, "node_modules/chalk/node_modules/ansi-styles". The real
        # package name is whatever comes after the last "node_modules/".
        name = package_path.rsplit("node_modules/", 1)[-1]

        dependencies.append(
            Dependency(name=name, version=version, ecosystem=Ecosystem.NPM)
        )

    return dependencies
