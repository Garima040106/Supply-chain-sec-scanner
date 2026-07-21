# Supply-Chain Security Scanner

## What this project does

A CLI tool that scans a software project for supply-chain risk in its
dependencies. Running `sc-scan scan <path>`:

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
6. Renders results as a colored CLI table and a standalone HTML report.

This is now a real, working end-to-end pipeline (see "Current status") —
not just independently-implemented stages.

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
  visited set.
- **vuln matcher** (`src/sc_scanner/vuln/`) — Queries the OSV.dev API for
  each `(ecosystem, name, version)` and attaches known CVEs/advisories.
  OSV's server-side batch query does the affected-version-range
  evaluation; this stage only parses the matched records back out (CVE
  IDs, severity, fix ranges) and caches every response to disk. See the
  module docstring in `matcher.py` for why range matching isn't
  reimplemented locally.
- **heuristics** (`src/sc_scanner/heuristics/`) — Independent of known-CVE
  data. Five independently-scored `Signal`s, combined by `scorer.py` into
  a weighted `RiskAssessment` (never a single collapsed verdict): edit-
  distance typosquat detection against a bundled top-1000-per-ecosystem
  list (`typosquat.py`); npm install-hook presence and PyPI `setup.py`
  exec/eval/network-call detection via AST (`install_scripts.py`);
  package age, download counts, and (npm-only) maintainer-change
  detection (`metadata.py`). Every signal module's docstring documents
  its own false-positive tradeoffs in detail - read those before tuning
  weights or thresholds.
- **risk scorer** (`src/sc_scanner/scoring/`) — Combines a package's
  worst known-CVE severity (`cvss.py` normalizes CVSS vectors/qualitative
  labels to 0.0-1.0, delegating the actual CVSS base-score math to the
  `cvss` library for the same reason PEP 440/semver math is delegated
  elsewhere) with its `RiskAssessment` from heuristics into one
  `PackageRisk` (`scorer.py`, weighted 0.6 vuln / 0.4 heuristics -
  confirmed CVEs count for more than probabilistic signals; see the
  module docstring for the full reasoning). `score_project()` rolls
  per-package scores up into a `ProjectRisk` - sorted, with per-tier
  counts, scored as the single highest package score ("a project is only
  as risky as its riskiest dependency").
- **reporter** (`src/sc_scanner/report/`) — `cli_table.py` renders every
  scanned package as a colored, risk-sorted Rich table. `html_report.py`
  renders one self-contained HTML file (inline CSS, no external assets,
  every piece of external-registry-sourced text HTML-escaped) with a
  full detail card - CVEs, heuristic signals, introduction path - per
  MEDIUM/HIGH tier package; LOW tier packages are summarized as a count
  rather than each getting a card.
- **pipeline** (`src/sc_scanner/pipeline.py`) — The only module that
  imports across every stage above; `run_scan(path)` is what the `scan`
  CLI command actually calls, and every network client it builds
  (OSV/PyPI/npm registry/download stats) can be injected for testing.

Shared, stage-agnostic data types (e.g. the `Dependency` record and the
`Ecosystem` enum) live in `src/sc_scanner/models.py`, and the LOW/MEDIUM/
HIGH tier thresholds live in `src/sc_scanner/risk_tier.py` (used by both
`heuristics.models.RiskAssessment` and `scoring.models.PackageRisk`/
`ProjectRisk`, so "HIGH" means the same thing everywhere) — so every
stage speaks the same vocabulary without importing from each other's
internals.

## Current status

The full pipeline is implemented and wired together: `sc-scan scan <path>`
parses manifests, builds whatever dependency graph it can, matches known
CVEs via OSV, runs the heuristic checks, scores everything, prints a
colored risk-sorted CLI table, and writes a self-contained HTML report.
Every stage has unit tests (parsers/graph builders/heuristics/scoring/
report against fixture files and crafted inputs, network clients against
mocked responses, `pipeline.py` itself against a full mocked scan), and
the whole pipeline has also been smoke-tested against the real OSV/PyPI/
npm APIs multiple times during development (most recently the fully
wired CLI end-to-end, against a real known-vulnerable `lodash` version).

Known gaps, by design (not oversights):
- `package.json` parsing (for npm projects with no lockfile) exists only
  inside `graph/npm_resolver.py`, not as a registered CLI-facing manifest
  parser in `parsers/base.py` - so `scan` won't currently pick up a
  lockfile-less npm project on its own.
- The heuristic checks run for every dependency on every scan; there's
  no flag to skip the network-heavy ones for a faster/lighter run.
  Disk caching (per stage, under `~/.cache/sc-scanner/`) is what makes
  re-scanning the same project fast, not reduced scope.

## File layout

```
supply-chain-sec-scanner/
├── CLAUDE.md
├── pyproject.toml              # uv-managed project config, deps, CLI entry point
├── src/
│   └── sc_scanner/
│       ├── __init__.py
│       ├── cli.py              # Typer app; `sc-scan scan <path>` command
│       ├── pipeline.py         # run_scan(path) -> ProjectRisk; wires every stage together
│       ├── models.py           # Dependency, Ecosystem — shared across all stages
│       ├── risk_tier.py        # tier_for_score() — one LOW/MEDIUM/HIGH definition, shared
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
│       ├── scoring/
│       │   ├── __init__.py
│       │   ├── models.py       # PackageRisk, ProjectRisk
│       │   ├── cvss.py         # normalize_severity()/worst_severity_score() -> 0.0-1.0
│       │   └── scorer.py       # score_package()/score_project(), documented weights
│       └── report/
│           ├── __init__.py
│           ├── cli_table.py    # render_cli_table() — colored Rich table, every package
│           └── html_report.py  # render_html_report() — self-contained HTML, risky packages only
└── tests/
    ├── fakes.py                 # FakeSession/FakeResponse/FakeRoutedSession for every API client
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
    ├── test_scoring_cvss.py
    ├── test_scoring_scorer.py
    ├── test_report_cli_table.py
    ├── test_report_html.py
    ├── test_pipeline.py
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
- Same reasoning for CVSS: `scoring/cvss.py` delegates base-score
  computation to the `cvss` library rather than hand-rolling the v2/v3/v4
  formulas. Its `base_score` is a `decimal.Decimal`, not a `float` - cast
  explicitly (a real bug caught during development: dividing a Decimal by
  a bare `float` literal raises `TypeError`).
- **CLI table colors**: [Rich](https://rich.readthedocs.io/) (`report/cli_table.py`).
  Typer already depends on it transitively; it's declared as a direct
  dependency too since the CLI table relies on it directly.
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
