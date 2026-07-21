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
- **graph builder** (`src/sc_scanner/graph/`) — Builds a `DependencyGraph`:
  nodes are `Dependency` (ecosystem, name, version — identity includes the
  version, so a real version conflict is just two nodes sharing a name,
  not a special case), edges are "parent depends on child", roots are the
  project's direct dependencies. Two sources:
  - **From a lockfile** (`npm_lock.py`, `poetry_lock.py`) — the resolved
    tree already exists; these parse it into real edges. npm's edges
    require replicating Node's own `node_modules` resolution walk (see
    `npm_lock.py`'s docstring); Poetry's are a simple name lookup since
    Poetry's resolver guarantees one version per package per lock file.
    Poetry also needs `pyproject.toml` (if available) to know which
    packages are actually direct dependencies — `poetry.lock` alone
    doesn't record that.
  - **From a plain manifest with no lockfile** (`pypi_resolver.py` for
    `requirements.txt`, `npm_resolver.py` for `package.json`) — no ground
    truth exists, so one level of transitive dependencies is resolved
    best-effort via the PyPI JSON API / npm registry, delegating
    PEP 440/semver-range correctness to the `packaging` and `node-semver`
    libraries rather than reimplementing version comparison. Anything
    that can't be resolved is recorded in `DependencyGraph.unresolved`
    instead of failing the whole scan.

  `graph/models.py` also provides `shortest_path(graph, target)`: a
  multi-source BFS from every root simultaneously, so it finds the
  globally shortest "root → ... → target" path — the "this CVE reaches
  you via A → B → C" explanation — and handles cycles safely via a
  visited set. Not yet wired into the `scan` CLI command or the vuln
  matcher; each graph-building function is used directly for now (see
  "Current status").
- **vuln matcher** (`src/sc_scanner/vuln/`) — Queries the OSV.dev API for
  each `(ecosystem, name, version)` and attaches known CVEs/advisories.
  OSV's server-side batch query does the affected-version-range
  evaluation; this stage only parses the matched records back out (CVE
  IDs, severity, fix ranges) and caches every response to disk. See the
  module docstring in `matcher.py` for why range matching isn't
  reimplemented locally. Currently takes a flat dependency list directly
  (not graph nodes) — wiring it to run per-graph-node, and to look up
  `shortest_path` for any match, is future work (see "Current status").
- **heuristics** (`src/sc_scanner/heuristics/`) — Independent of known-CVE
  data. Five independently-scored `Signal`s, combined by `scorer.py` into
  a weighted `RiskAssessment` (never a single collapsed verdict): edit-
  distance typosquat detection against a bundled top-1000-per-ecosystem
  list (`typosquat.py`); npm install-hook presence and PyPI `setup.py`
  exec/eval/network-call detection via AST (`install_scripts.py`);
  package age, download counts, and (npm-only) maintainer-change
  detection (`metadata.py`). Every signal module's docstring documents
  its own false-positive tradeoffs in detail - read those before tuning
  weights or thresholds. Not yet wired into the `scan` CLI command,
  consistent with the vuln matcher and graph builder (see "Current
  status").
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
(Poetry); an OSV.dev vulnerability matcher (`src/sc_scanner/vuln/`); the
dependency graph builder (`src/sc_scanner/graph/`) covering both lockfile
parsing (npm, Poetry) and best-effort one-level resolution for plain
manifests (`requirements.txt` via PyPI, `package.json` via the npm
registry — `package.json` parsing exists only inside the graph package
for now, not as a registered CLI-facing manifest parser); and the
malicious-package heuristics layer (`src/sc_scanner/heuristics/`) —
typosquat detection, install-script analysis, and metadata anomalies,
combined into a weighted `RiskAssessment`. Every stage has unit tests
(parsers/graph builders/heuristics against fixture files and crafted
inputs, network clients against mocked responses); the whole pipeline has
also been smoke-tested against the real OSV/PyPI/npm APIs at least once
during development.

Not yet done: the graph builder, vuln matcher, and heuristics layer
aren't wired together or into the `scan` CLI command, which still only
discovers manifests and prints the flat parsed dependency list. In
particular, nothing yet calls `shortest_path` with a matched
vulnerability's node as the target. Risk scoring that combines vuln
matches *with* heuristic signals (as opposed to each producing its own
separate score) and HTML reporting are also not implemented yet.

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
│       ├── http.py             # shared retrying request()/request_json()/request_bytes()
│       ├── cache.py            # generic on-disk JSON cache (DiskCache), shared too
│       ├── graph/
│       │   ├── __init__.py
│       │   ├── models.py       # DependencyGraph, shortest_path()
│       │   ├── npm_lock.py     # package-lock.json -> graph (node_modules resolution walk)
│       │   ├── poetry_lock.py  # poetry.lock (+ pyproject.toml) -> graph
│       │   ├── pypi_resolver.py  # requirements.txt -> one-level graph via PyPI JSON API
│       │   └── npm_resolver.py   # package.json -> one-level graph via npm registry
│       ├── vuln/
│       │   ├── __init__.py
│       │   ├── models.py       # Severity, AffectedRange, Vulnerability, MatchResult
│       │   ├── client.py       # OSVClient: querybatch + vulns/{id}
│       │   └── matcher.py      # match(dependencies) -> list[MatchResult]
│       ├── heuristics/
│       │   ├── __init__.py
│       │   ├── models.py       # Signal, SignalType, RiskAssessment
│       │   ├── typosquat.py    # edit distance vs. bundled top-1000-per-ecosystem lists
│       │   ├── install_scripts.py  # npm hasInstallScript; PyPI setup.py AST scan
│       │   ├── metadata.py     # package age, download counts, npm maintainer change
│       │   ├── scorer.py       # combine(signals) -> RiskAssessment, documented weights
│       │   └── data/
│       │       ├── top-npm-packages.txt   # ~1000 names, ranked (see typosquat.py docstring)
│       │       └── top-pypi-packages.txt  # ~1000 names, ranked by real download counts
│       ├── scoring/             # [planned] risk scorer combining vuln + heuristic signals
│       └── report/              # [planned] CLI table + HTML report renderers
└── tests/
    ├── fakes.py                 # FakeSession/FakeResponse test doubles for every API client
    ├── fixtures/
    │   ├── package-lock.json
    │   ├── package-lock-graph.json  # hoisting + a genuine version conflict, for graph tests
    │   ├── package.json
    │   ├── requirements.txt
    │   ├── poetry.lock
    │   └── pyproject.toml
    ├── test_npm_parser.py
    ├── test_pip_parser.py
    ├── test_poetry_parser.py
    ├── test_cli.py
    ├── test_disk_cache.py
    ├── test_osv_client.py
    ├── test_vuln_matcher.py
    ├── test_vuln_models.py
    ├── test_graph_models.py
    ├── test_npm_lock_graph.py
    ├── test_poetry_lock_graph.py
    ├── test_pypi_resolver.py
    ├── test_npm_resolver.py
    ├── test_typosquat.py
    ├── test_install_scripts.py
    ├── test_metadata_heuristics.py
    └── test_heuristic_scorer.py
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
- **External data sources**: [OSV.dev](https://osv.dev) (vulnerabilities),
  [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html)
  (Python package metadata/releases), the
  [npm registry](https://registry.npmjs.org) (npm package metadata — both
  the abbreviated "corgi" packument used for dependency resolution, via
  `get_package()`, and the full packument used by the metadata heuristics
  for `time`/`_npmUser`, via `get_full_package()` — these are cached
  separately since they're genuinely different response shapes for the
  same URL), [pypistats.org](https://pypistats.org) (PyPI download
  counts — PyPI's own JSON API doesn't expose these), and
  [api.npmjs.org](https://api.npmjs.org) (npm download counts). Every
  client caches responses to disk under `~/.cache/sc-scanner/<source>/` by
  default, each configurable via a `cache_dir=` constructor argument.
  Delete the relevant directory to force fresh lookups. Retry/backoff/
  rate-limit handling lives once in `sc_scanner/http.py`, shared by every
  client.
- Version-range correctness is delegated rather than reimplemented:
  `packaging` for PEP 440 (PyPI) version ordering/specifiers, `node-semver`
  for npm-style ranges (caret/tilde/hyphen/etc). Both are already
  full, well-tested implementations of genuinely fiddly logic.
- The bundled top-package lists (`heuristics/data/`) are static snapshots,
  not live data — PyPI's is current download-count-ranked data
  (hugovk/top-pypi-packages); npm's is a 2019 dependency-graph-rank
  snapshot (Meyond/npm-top-1000-packages), which is stale on exact
  ranking but the *names* of top packages change slowly. Regenerating
  them isn't automated.

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
