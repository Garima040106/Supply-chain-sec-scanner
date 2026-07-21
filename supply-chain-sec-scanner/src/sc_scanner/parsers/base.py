"""Ties individual format parsers together: which filename maps to which
parser, and how to find supported manifests under a project path."""

from pathlib import Path

from sc_scanner.models import Dependency
from sc_scanner.parsers import npm, pip, poetry

_PARSERS = {
    "package-lock.json": npm.parse,
    "requirements.txt": pip.parse,
    "poetry.lock": poetry.parse,
}


def find_manifests(project_path: Path) -> list[Path]:
    """Return every supported manifest/lockfile found at or under a path."""
    if project_path.is_file():
        return [project_path] if project_path.name in _PARSERS else []
    return sorted(p for p in project_path.iterdir() if p.name in _PARSERS)


def parse_manifest(manifest_path: Path) -> list[Dependency]:
    """Parse a single manifest/lockfile into a list of Dependencies."""
    parser = _PARSERS[manifest_path.name]
    return parser(manifest_path)
