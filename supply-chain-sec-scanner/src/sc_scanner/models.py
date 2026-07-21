"""Shared data types used across every stage of the scan pipeline."""

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
