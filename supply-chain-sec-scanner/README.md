# Supply-Chain Security Scanner (`sc-scan`)

A CLI tool that scans a project's dependencies for supply-chain risk —
not just known CVEs, but signals that a package might be actively
malicious: typosquatted names, suspicious install-time scripts, and
anomalous registry metadata.

## Why

In March 2024, a backdoor was discovered in `xz-utils`
([CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)), a
compression library present in most Linux distributions. It wasn't
injected by an outsider exploiting a bug — it was added by a co-maintainer
who had spent roughly two years building trust through ordinary-looking
contributions, then hid the backdoor inside obfuscated build scripts and
binary test fixtures rather than in reviewable source code. It was found
almost by accident, because one engineer noticed SSH logins were a few
hundred milliseconds slower than expected.

That incident is the motivating case for this project, and it's also a
useful honesty check on it (see [Threat model](#threat-model) below): a
vulnerability database only tells you about problems that have already
been found and disclosed, and it wouldn't have caught xz-utils at all —
nothing was "vulnerable" until the backdoor was discovered. Malicious
packages, typosquats, and hijacked maintainer accounts don't show up in a
CVE feed until someone notices and reports them, often long after the
damage is done. This tool exists to catch a *different, complementary*
slice of that risk: cheap, mostly-automatable warning signs — a name one
character off from a popular package, an install script added out of
nowhere, a package that's a week old with three downloads — layered on
top of standard vulnerability scanning, not instead of it.

## What it does

Running `sc-scan scan <path>`:

1. **Parses** dependency manifests/lockfiles (`package-lock.json`,
   `requirements.txt`, `poetry.lock`) into `(name, version, ecosystem)`
   triples.
2. **Builds the dependency graph** — direct and transitive dependencies,
   resolved from lockfiles where available, or best-effort via the
   PyPI/npm registries when there's no lockfile.
3. **Matches known vulnerabilities** for every resolved version against
   [OSV.dev](https://osv.dev).
4. **Runs malicious-package heuristics**, independent of known CVEs:
   typosquat detection (edit distance against a bundled list of popular
   packages), suspicious install-time behavior (npm lifecycle hooks,
   PyPI `setup.py` that `exec`/`eval`s or reaches out over the network),
   and anomalous metadata (brand new, barely downloaded, or an
   unexplained maintainer change).
5. **Scores** each package by combining CVE severity with heuristic
   signals, and rolls that up into a project-level score.
6. **Reports**: a colored, risk-sorted table in the terminal, and a
   self-contained HTML report (no external assets) with full detail —
   CVEs, heuristic signals, and the exact dependency chain that
   introduced each risky package — for anything worth a second look.

## Demo

[`examples/vulnerable-npm-app/`](examples/vulnerable-npm-app/) is a small,
deliberately outdated npm project checked into this repo so you can see
this work in one command:

```bash
uv run sc-scan scan examples/vulnerable-npm-app
```

Real output, captured against the live OSV/npm data at the time of writing:

```
Found 1 manifest(s): package-lock.json

                                                      Dependency Risk Report
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package               ┃ Ecosystem ┃ Score ┃ Tier ┃ CVEs                                 ┃ Heuristic signals                    ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ minimist@0.0.8        │ npm       │  0.59 │ HIGH │ CVE-2020-7598, CVE-2021-44906        │ -                                    │
│ lodash@4.17.4         │ npm       │  0.55 │ HIGH │ CVE-2018-16487, CVE-2018-3721,       │ -                                    │
│                       │           │       │      │ CVE-2019-1010266, CVE-2019-10744,    │                                      │
│                       │           │       │      │ CVE-2020-28500, CVE-2020-8203,       │                                      │
│                       │           │       │      │ CVE-2021-23337, CVE-2025-13465,      │                                      │
│                       │           │       │      │ CVE-2026-2950, CVE-2026-4800         │                                      │
│ lodahs@0.0.1-security │ npm       │  0.12 │ LOW  │ -                                    │ typosquat, maintainer_change,        │
│                       │           │       │      │                                      │ low_downloads                        │
│ left-pad@1.3.0        │ npm       │  0.00 │ LOW  │ -                                    │ -                                    │
└───────────────────────┴───────────┴───────┴──────┴──────────────────────────────────────┴──────────────────────────────────────┘

Project risk: HIGH (highest package score 0.59) — 2 high, 0 medium, 2 low

HTML report written to sc-scan-report.html
```

A few things worth noticing in that output:

- `minimist@0.0.8` and `lodash@4.17.4` are both flagged HIGH from real,
  disclosed CVEs (a prototype-pollution bug in minimist, and ten CVEs in
  that old lodash release including a critical one).
- `lodahs` is a real historical npm typosquat of `lodash` — npm caught it
  years ago and replaced its contents with a "security holding package"
  stub, but the name is still registered. The scanner flags it via the
  `typosquat` signal (plus `maintainer_change` and `low_downloads`) even
  though it has no CVEs, and even though its *combined* score only
  reaches LOW — by design, heuristic signals alone are weighted low
  enough that they surface for review rather than triggering a false
  alarm on their own (see [Threat model](#threat-model)). The signal is
  still right there in the table; nothing is hidden.
- `left-pad@1.3.0` is old but clean, and correctly scores 0.

The HTML report (`sc-scan-report.html` by default, `--html <path>` to
change it) shows the same data with full CVE descriptions and, for
lockfile-based scans, the dependency chain that introduced each risky
package.

## Install & usage

Requires [uv](https://docs.astral.sh/uv/) and Python 3.11+.

```bash
git clone https://github.com/Garima040106/Supply-chain-sec-scanner.git
cd Supply-chain-sec-scanner/supply-chain-sec-scanner
uv sync

uv run pytest                              # run the test suite
uv run sc-scan scan <path-to-a-project>    # scan a real project
uv run sc-scan scan examples/vulnerable-npm-app --html report.html
```

`scan` makes real network calls (OSV, PyPI, the npm registry, download
stats) — responses are cached to disk under `~/.cache/sc-scanner/`, so
re-scanning the same project is much faster the second time.

## Threat model

This section is here to be honest about what a "supply-chain scanner"
can and can't actually promise — see [Why](#why) above for the incident
that motivates drawing this line carefully.

**Catches:**
- Dependencies with **known, publicly disclosed vulnerabilities** (OSV.dev
  covers npm and PyPI advisories, including GHSA/PYSEC/NVD-sourced ones).
- **Typosquatting**: names a short edit distance from a well-known
  package (`lodahs` vs. `lodash`).
- **Unsophisticated malicious install behavior**: an npm package that
  suddenly has a `postinstall` hook, or a PyPI `setup.py` that fetches
  something over the network and executes it — the kind of payload that
  doesn't bother hiding what it's doing.
- **Sudden, unexplained changes**: a package that's brand new, has
  almost no downloads, or was just published by an account with no prior
  history on that package (excluding recognized CI/trusted-publisher
  accounts) — the pattern behind several real incidents (`event-stream`,
  `ua-parser-js`, `coa`/`rc`) where a hijacked or newly-added maintainer
  shipped something bad shortly after gaining access.

**Does not catch:**
- **Zero-days and undisclosed vulnerabilities.** OSV only knows about
  what's already been found and reported; a scan is only as current as
  that database.
- **Patient, sophisticated attacks like xz-utils itself**: a backdoor
  introduced by a long-standing, trusted maintainer, hidden in obfuscated
  build scripts or binary test fixtures rather than visible source
  code — and in an ecosystem (a C library shipped as a source tarball,
  not an npm/PyPI package) this tool doesn't even scan. No typosquat (the
  name was genuine), no metadata anomaly (the trust was built over
  years, not days), nothing for a static exec/eval scanner to find. This
  is the sharpest limit of everything in this tool: it looks for *signs
  of newness or sloppiness* in an attack, and the attacks worth worrying
  about most are neither new nor sloppy.
- **Compromised build/CI infrastructure** that publishes an
  otherwise-legitimate-looking release through the maintainer's normal,
  trusted channel.
- **Dependency confusion** against a private/internal package namespace
  — the typosquat list only covers ~1000 *public* popular packages per
  ecosystem, not your organization's own package names.
- **Homoglyph/Unicode lookalikes** — typosquat detection is plain
  Levenshtein distance on the literal name, not Unicode-confusable-aware.
- **Anything outside npm and PyPI** — no Cargo, Go modules, RubyGems, or
  native/system-level dependencies.
- **Runtime behavior.** Everything here is static: parsed manifests,
  registry metadata, and (for PyPI `setup.py`) an AST scan of source
  text. Nothing is executed or sandboxed, so a payload that only
  activates under specific runtime conditions — exactly how the xz-utils
  backdoor was built to behave — is invisible to it either way.

In short: this catches the *lazy and the loud* — obvious typosquats,
undisguised install scripts, a hijack-and-ship-immediately pattern, and
anything with a known CVE. It is not a defense against a patient,
targeted attack from a trusted insider, which is exactly the category
xz-utils fell into.

## Development

```bash
uv sync
uv run ruff check .   # lint
uv run pytest         # tests
```

CI (`.github/workflows/ci.yml`, repo root) runs both on every push and
pull request against `main`.
