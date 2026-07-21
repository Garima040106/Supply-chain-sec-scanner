"""Shared data types used across every stage of the scan pipeline."""

import re
from dataclasses import dataclass
from enum import Enum


class Ecosystem(str, Enum):
    """Which package registry a dependency belongs to."""

    PYPI = "pypi"
    NPM = "npm"


@dataclass(frozen=True, slots=True)
class Dependency:
    """A single resolved package: what it's called, which version is
    locked, and which registry it comes from."""

    name: str
    version: str
    ecosystem: Ecosystem


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization: "Typing_Extensions" and "typing-extensions"
    are the same project as far as PyPI is concerned."""
    return re.sub(r"[-_.]+", "-", name).lower()
