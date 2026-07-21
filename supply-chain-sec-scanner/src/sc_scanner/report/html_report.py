"""Renders a ProjectRisk as a single, self-contained HTML file: no
external stylesheets, fonts, scripts, or images - everything needed to
render is inlined, so the report works as a standalone file with no
network access.

Only MEDIUM/HIGH tier packages get a full detail card; LOW tier packages
are summarized as a count rather than each getting a card, so a project
with a hundred clean dependencies doesn't bury the ones worth reading
about (the CLI table, by contrast, lists everything - see its module
docstring).

Every piece of text that ultimately comes from an external registry or
advisory (package names, CVE ids/summaries, signal evidence strings) is
HTML-escaped before being interpolated - this report renders untrusted
third-party data, so treating it as such isn't optional.
"""

import html
from datetime import datetime, timezone

from sc_scanner.models import Dependency
from sc_scanner.scoring.models import PackageRisk, ProjectRisk

_TIER_COLORS = {"HIGH": "#b91c1c", "MEDIUM": "#b45309", "LOW": "#15803d"}

_STYLE = """
    body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
           background: #f8fafc; color: #1e293b; margin: 0; padding: 2rem; }
    .container { max-width: 900px; margin: 0 auto; }
    h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
    .generated { color: #64748b; font-size: 0.85rem; margin-bottom: 1.5rem; }
    .summary { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
               padding: 1rem 1.5rem; margin-bottom: 1.5rem; display: flex; gap: 2rem;
               align-items: center; flex-wrap: wrap; }
    .summary .score { font-size: 2rem; font-weight: 700; }
    .summary .counts { color: #475569; font-size: 0.9rem; }
    .badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px;
             color: #fff; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.02em; }
    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
            padding: 1.25rem 1.5rem; margin-bottom: 1rem; }
    .card-header { display: flex; justify-content: space-between; align-items: center;
                   flex-wrap: wrap; gap: 0.5rem; }
    .card-header .name { font-size: 1.1rem; font-weight: 600; }
    .card-header .ecosystem { color: #64748b; font-size: 0.85rem; }
    .score-line { color: #475569; font-size: 0.85rem; margin: 0.5rem 0; }
    h3 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.04em;
         color: #64748b; margin: 1rem 0 0.4rem; }
    ul { margin: 0; padding-left: 1.2rem; }
    li { margin-bottom: 0.3rem; }
    .path { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 0.85rem;
            background: #f1f5f9; border-radius: 6px; padding: 0.5rem 0.75rem;
            overflow-x: auto; white-space: nowrap; }
    .low-tier-note { color: #64748b; font-size: 0.9rem; margin-top: 1.5rem; }
"""


def render_html_report(project_risk: ProjectRisk, generated_at: datetime | None = None) -> str:
    generated_at = generated_at or datetime.now(timezone.utc)
    flagged = [p for p in project_risk.packages if p.tier != "LOW"]
    low_tier_count = len(project_risk.packages) - len(flagged)

    cards = "\n".join(_render_card(package) for package in flagged)
    low_tier_note = (
        f'<p class="low-tier-note">{low_tier_count} other package(s) scanned with no '
        f"notable findings (LOW tier) - not shown individually.</p>"
        if low_tier_count
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Supply-chain risk report</title>
<style>{_STYLE}</style>
</head>
<body>
<div class="container">
  <h1>Supply-chain risk report</h1>
  <div class="generated">Generated {html.escape(generated_at.strftime("%Y-%m-%d %H:%M UTC"))}</div>

  <div class="summary">
    <div class="score">{project_risk.score:.2f}</div>
    <div>
      <span class="badge" style="background:{_TIER_COLORS[project_risk.tier]}">{project_risk.tier}</span>
      <div class="counts">
        {project_risk.tier_counts['HIGH']} high &middot;
        {project_risk.tier_counts['MEDIUM']} medium &middot;
        {project_risk.tier_counts['LOW']} low
        &middot; {len(project_risk.packages)} package(s) scanned
      </div>
    </div>
  </div>

  {cards}
  {low_tier_note}
</div>
</body>
</html>
"""


def _render_card(package: PackageRisk) -> str:
    dep = package.dependency
    color = _TIER_COLORS[package.tier]

    cve_section = _render_cve_section(package)
    signal_section = _render_signal_section(package)
    path_section = _render_path_section(package.introduction_path)

    return f"""  <div class="card">
    <div class="card-header">
      <div>
        <span class="name">{html.escape(dep.name)}@{html.escape(dep.version)}</span>
        <span class="ecosystem">({html.escape(dep.ecosystem.value)})</span>
      </div>
      <span class="badge" style="background:{color}">{package.tier} &middot; {package.combined_score:.2f}</span>
    </div>
    <div class="score-line">
      vulnerability severity {package.vuln_score:.2f} &middot;
      heuristic score {package.heuristic_assessment.score:.2f}
    </div>
    {cve_section}
    {signal_section}
    {path_section}
  </div>"""


def _render_cve_section(package: PackageRisk) -> str:
    if not package.vulnerabilities:
        return ""

    items = []
    for vuln in package.vulnerabilities:
        cve_ids = ", ".join(vuln.cve_ids) or vuln.id
        severities = ", ".join(f"{s.type}: {s.score}" for s in vuln.severities) or "no severity data"
        summary = f" - {html.escape(vuln.summary)}" if vuln.summary else ""
        items.append(f"<li><strong>{html.escape(cve_ids)}</strong> ({html.escape(severities)}){summary}</li>")

    return f'<h3>Known vulnerabilities</h3><ul>{"".join(items)}</ul>'


def _render_signal_section(package: PackageRisk) -> str:
    if not package.heuristic_assessment.signals:
        return ""

    items = [
        f"<li><strong>{html.escape(signal.type.value)}</strong> "
        f"(score {signal.score:.2f}) - {html.escape(signal.evidence)}</li>"
        for signal in package.heuristic_assessment.signals
    ]
    return f'<h3>Heuristic signals</h3><ul>{"".join(items)}</ul>'


def _render_path_section(path: tuple[Dependency, ...] | None) -> str:
    if path is None:
        return '<h3>Introduction path</h3><div class="path">not available - no dependency graph for this project</div>'

    chain = " &rarr; ".join(html.escape(f"{d.name}@{d.version}") for d in path)
    return f'<h3>Introduction path</h3><div class="path">{chain}</div>'
