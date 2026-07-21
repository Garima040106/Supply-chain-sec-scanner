# vulnerable-npm-app (sample project)

A deliberately outdated `package-lock.json`, used as the demo target for
`sc-scan`. **Do not use these dependency versions in a real project** -
they're pinned to old, vulnerable releases on purpose:

| Package    | Version           | Why it's here                                                                    |
| ---------- | ----------------- | --------------------------------------------------------------------------------- |
| `lodash`   | `4.17.4`          | 10 known CVEs, including a CRITICAL prototype-pollution vulnerability.            |
| `minimist` | `0.0.8`           | A real prototype-pollution CVE (CVE-2020-7598).                                   |
| `lodahs`   | `0.0.1-security`  | A real historical npm typosquat of `lodash` - npm has since replaced its contents with a "security holding package" stub, but the name is still registered, which is exactly what the typosquat heuristic is meant to catch. |
| `left-pad` | `1.3.0`           | Old, but clean - included as a contrast so the report isn't all red.              |

Run the scanner against this directory from the repo root:

```bash
uv run sc-scan scan examples/vulnerable-npm-app
```
