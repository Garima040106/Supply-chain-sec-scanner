# Supply-Chain Security Scanner

## What this project does

A CLI tool that scans a software project for supply-chain risk in its
dependencies. Given a project directory, it:

1. Reads dependency manifests/lockfiles (`package-lock.json`,
   `requirements.txt`, `poetry.lock`, ...).
2. Builds the full dependency graph (direct + transitive dependencies).
3. Matches every resolved package version against known-vulnerability
   databases (e.g. OSV).
4. Flags packages that look malicious rather than just vulnerable:
   typosquatted names, suspicious install scripts (`postinstall`, setup.py
   side effects, etc.), anomalous age or popularity for a package that's
   suddenly a dependency.
5. Combines both signals into a per-package and per-project risk score.
6. Renders results as a CLI table and as a standalone HTML report.

## Architecture

Pipeline, one directory per stage, data flows left to right:

```
parser -> graph builder -> vuln matcher -> heuristics -> risk scorer -> reporter
```

- **parser** (`src/sc_scanner/parsers/`) — Reads a single manifest/lockfile
  and extracts `(name, version, ecosystem)` triples. One module per file
  format. No cross-file or cross-package logic lives here; a parser only
  knows how to read its own file.
- **graph builder** (`src/sc_scanner/graph/`, *planned*) — Takes the flat
  dependency lists from every manifest found in a project and links them
  into a graph: which package pulls in which, direct vs. transitive, and
  resolves duplicate/conflicting versions across manifests.
- **vuln matcher** (`src/sc_scanner/vuln/`) — Queries the OSV.dev API for
  each `(ecosystem, name, version)` and attaches known CVEs/advisories.
  OSV's server-side batch query does the affected-version-range
  evaluation; this stage only parses the matched records back out (CVE
  IDs, severity, fix ranges) and caches every response to disk. See the
  module docstring in `matcher.py` for why range matching isn't
  reimplemented locally. Currently operates on a flat dependency list
  (from the parser stage directly) since the graph builder doesn't exist
  yet; once it does, this stage will run against graph nodes instead.
- **heuristics** (`src/sc_scanner/heuristics/`, *planned*) — Independent of
  known-CVE data. Runs checks like: edit-distance/typosquat detection
  against popular package names, presence of install-time scripts,
  package age and download-count anomalies. Each heuristic produces a
  signal, not a final verdict.
- **risk scorer** (`src/sc_scanner/scoring/`, *planned*) — Combines vuln
  matches and heuristic signals per package into one risk score/severity,
  and rolls those up into a project-level summary.
- **reporter** (`src/sc_scanner/report/`, *planned*) — Renders the scored
  results: a table for the terminal and a static HTML report.

Shared, stage-agnostic data types (e.g. the `Dependency` record and the
`Ecosystem` enum) live in `src/sc_scanner/models.py` so every stage speaks
the same vocabulary without importing from each other's internals.

## Current status

Implemented: package skeleton, CLI entrypoint, parsers for
`package-lock.json` (npm), `requirements.txt` (pip), and `poetry.lock`
(Poetry), and an OSV.dev vulnerability matcher (`src/sc_scanner/vuln/`) —
each with unit tests (parsers against fixture files, the vuln matcher
against mocked API responses). The vuln matcher is not yet wired into the
`scan` CLI command; it's exercised directly via `sc_scanner.vuln.matcher.match()`
for now, since running it meaningfully over a whole project really wants
the graph builder in place first. The `scan` CLI command currently only
discovers manifests under a path and prints the parsed dependency list —
graph building, heuristics, scoring, and HTML reporting are not
implemented yet.

## File layout

```
supply-chain-sec-scanner/
├── CLAUDE.md
├── pyproject.toml              # uv-managed project config, deps, CLI entry point
├── src/
│   └── sc_scanner/
│       ├── __init__.py
│       ├── cli.py              # Typer app; `sc-scan scan <path>` command
│       ├── models.py           # Dependency, Ecosystem — shared across all stages
│       ├── parsers/
│       │   ├── __init__.py
│       │   ├── base.py         # manifest filename -> parser registry, find_manifests()
│       │   ├── npm.py          # package-lock.json (lockfileVersion 2/3, "packages" format)
│       │   ├── pip.py          # requirements.txt (pinned "==" entries)
│       │   └── poetry.py       # poetry.lock (TOML, [[package]] tables)
│       ├── graph/              # [planned] dependency graph builder
│       ├── vuln/
│       │   ├── __init__.py
│       │   ├── models.py       # Severity, AffectedRange, Vulnerability, MatchResult
│       │   ├── cache.py        # generic on-disk JSON cache (DiskCache)
│       │   ├── client.py       # OSVClient: querybatch + vulns/{id}, retries, caching
│       │   └── matcher.py      # match(dependencies) -> list[MatchResult]
│       ├── heuristics/          # [planned] typosquat / install-script / anomaly checks
│       ├── scoring/             # [planned] risk scorer combining vuln + heuristic signals
│       └── report/              # [planned] CLI table + HTML report renderers
└── tests/
    ├── fakes.py                 # FakeSession/FakeResponse test doubles for OSV client tests
    ├── fixtures/
    │   ├── package-lock.json
    │   ├── requirements.txt
    │   └── poetry.lock
    ├── test_npm_parser.py
    ├── test_pip_parser.py
    ├── test_poetry_parser.py
    ├── test_cli.py
    ├── test_disk_cache.py
    ├── test_osv_client.py
    ├── test_vuln_matcher.py
    └── test_vuln_models.py
```

## Tooling

- **Dependency management**: [uv](https://docs.astral.sh/uv/). Run
  `uv sync` to create the virtualenv and install dependencies,
  `uv add <package>` to add a new dependency.
- **Tests**: pytest, run with `uv run pytest`.
- **CLI framework**: [Typer](https://typer.tiangolo.com/). The app object
  lives in `src/sc_scanner/cli.py`; run it locally with
  `uv run sc-scan scan <path>` (entry point registered in
  `pyproject.toml`).
- Python 3.11+ is required (the poetry.lock parser uses the stdlib
  `tomllib`, added in 3.11).
- **Vulnerability data**: [OSV.dev](https://osv.dev) API. Responses are
  cached to disk at `~/.cache/sc-scanner/osv/` by default (configurable
  via `OSVClient(cache_dir=...)`) so re-scanning a project doesn't re-hit
  the network. Delete that directory to force fresh lookups.

## Notes for future sessions

- This file is intentionally listed in `.gitignore` and untracked — it's
  local Claude Code context, not project documentation for humans. Don't
  be alarmed that `git status` shows it as untracked; that's expected.

## Conventions

- One parser module per manifest format; each exposes a single
  `parse(path: Path) -> list[Dependency]` function. New formats (e.g.
  `yarn.lock`, `Pipfile.lock`) should follow the same shape and register
  in `parsers/base.py`.
- Parsers only extract `(name, version, ecosystem)`. They don't resolve
  dependency relationships (that's the graph builder's job) and don't
  reach out to the network.
- Unpinned/range requirements (e.g. `requests>=2.0`) are skipped by the
  pip parser rather than guessed at — the scanner matches vulnerabilities
  against exact versions, and a range isn't one.
