# Supply-Chain Security Scanner

A CLI tool that scans a project's dependencies for supply-chain risk — not just
known CVEs, but signals that a package might be actively malicious.

Given a project directory, it's designed to:

1. **Parse** dependency manifests/lockfiles (`package-lock.json`, `requirements.txt`,
   `poetry.lock`) into `(name, version, ecosystem)` triples.
2. **Build the dependency graph** — direct and transitive dependencies, resolved
   from lockfiles where available, or best-effort via the PyPI/npm registries
   when there's no lockfile to work from.
3. **Match known vulnerabilities** for every resolved package version against
   [OSV.dev](https://osv.dev).
4. **Flag likely-malicious packages independent of known CVEs**: typosquatted
   names, suspicious install-time scripts, and anomalous registry metadata
   (very new, very low downloads, unexpected maintainer changes).
5. **Score and report** — combine both kinds of signal into a per-package risk
   score, rendered as a CLI table and an HTML report.

## Status

Under active development. The parser, dependency graph builder, OSV vulnerability
matcher, and malicious-package heuristics are implemented and unit-tested
independently, but **not yet wired together into one end-to-end scan** — the
`scan` CLI command currently only parses manifests and lists dependencies.
Risk scoring that combines vulnerability + heuristic signals, and HTML
reporting, don't exist yet.

## Getting started

Requires [uv](https://docs.astral.sh/uv/) and Python 3.11+.

```bash
cd supply-chain-sec-scanner
uv sync                      # install dependencies
uv run pytest                # run the test suite
uv run sc-scan scan <path>   # parse a project's manifests (early-stage stub)
```

## Project layout

The actual project lives in [`supply-chain-sec-scanner/`](supply-chain-sec-scanner/).
