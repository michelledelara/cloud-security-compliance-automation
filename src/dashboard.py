from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, Iterable, List


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SERVICE_FALLBACK = {
    "S3": "Amazon S3",
    "IAM": "AWS IAM",
    "CT": "AWS CloudTrail",
    "SG": "Amazon EC2",
    "RDS": "Amazon RDS",
    "LOG": "Amazon S3",
    "TAG": "Multi-service",
}


def _service_for(finding: Dict[str, Any]) -> str:
    if finding.get("service"):
        return str(finding["service"])
    prefix = str(finding.get("control_id", "")).split("-", 1)[0]
    return SERVICE_FALLBACK.get(prefix, "Other")


def _percent(part: int, whole: int) -> float:
    return round((part / whole) * 100, 1) if whole else 0.0


def _bar(label: str, value: int, total: int, detail: str = "") -> str:
    pct = _percent(value, total)
    return f"""
    <div class="bar-row">
      <div class="bar-label">
        <span>{escape(label)}</span>
        <span>{value}{escape(detail)}</span>
      </div>
      <div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>
    </div>
    """


def _framework_rows(all_counts: Counter, failed_counts: Counter) -> str:
    if not all_counts:
        return '<p class="muted">No mappings available.</p>'
    rows = []
    for name, total in sorted(all_counts.items(), key=lambda item: (-item[1], item[0])):
        failed = failed_counts.get(name, 0)
        rows.append(
            "<tr>"
            f"<td>{escape(str(name))}</td>"
            f"<td>{total}</td>"
            f"<td>{failed}</td>"
            f"<td>{_percent(total - failed, total)}%</td>"
            "</tr>"
        )
    return "\n".join(rows)


def build_dashboard(
    findings: List[Dict[str, Any]],
    account_id: str,
    region: str,
) -> str:
    total = len(findings)
    passed = sum(1 for f in findings if f.get("status") == "PASS")
    failed = sum(1 for f in findings if f.get("status") == "FAIL")
    posture = _percent(passed, total)
    unique_controls = len({f.get("control_id") for f in findings if f.get("control_id")})

    failed_by_severity = Counter(
        f.get("severity", "INFO")
        for f in findings
        if f.get("status") == "FAIL"
    )

    service_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "pass": 0, "fail": 0})
    nist_all, nist_fail = Counter(), Counter()
    lgpd_all, lgpd_fail = Counter(), Counter()

    for finding in findings:
        service = _service_for(finding)
        service_stats[service]["total"] += 1
        if finding.get("status") == "PASS":
            service_stats[service]["pass"] += 1
        elif finding.get("status") == "FAIL":
            service_stats[service]["fail"] += 1

        for mapping in finding.get("nist_csf_2_0", []):
            nist_all[mapping] += 1
            if finding.get("status") == "FAIL":
                nist_fail[mapping] += 1

        for mapping in finding.get("lgpd", []):
            lgpd_all[mapping] += 1
            if finding.get("status") == "FAIL":
                lgpd_fail[mapping] += 1

    service_rows = []
    for service, stats in sorted(service_stats.items()):
        service_rows.append(
            "<tr>"
            f"<td>{escape(service)}</td>"
            f"<td>{stats['total']}</td>"
            f"<td>{stats['pass']}</td>"
            f"<td>{stats['fail']}</td>"
            f"<td>{_percent(stats['pass'], stats['total'])}%</td>"
            "</tr>"
        )

    severity_bars = "".join(
        _bar(severity, failed_by_severity.get(severity, 0), max(failed, 1))
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )

    prioritized = sorted(
        (f for f in findings if f.get("status") == "FAIL"),
        key=lambda f: (
            SEVERITY_ORDER.get(str(f.get("severity", "INFO")), 99),
            str(f.get("control_id", "")),
            str(f.get("resource", "")),
        ),
    )

    priority_cards = []
    for finding in prioritized[:8]:
        priority_cards.append(
            '<article class="finding">'
            f'<div class="finding-head"><span class="badge fail">{escape(str(finding.get("severity", "INFO")))}</span>'
            f'<strong>{escape(str(finding.get("control_id", "")))}</strong></div>'
            f'<h3>{escape(str(finding.get("title", "")))}</h3>'
            f'<p class="resource">{escape(str(finding.get("resource", "")))}</p>'
            f'<p>{escape(str(finding.get("recommendation", "")))}</p>'
            '</article>'
        )

    findings_rows = []
    for finding in sorted(
        findings,
        key=lambda f: (
            0 if f.get("status") == "FAIL" else 1,
            SEVERITY_ORDER.get(str(f.get("severity", "INFO")), 99),
            str(f.get("control_id", "")),
        ),
    ):
        status = escape(str(finding.get("status", "")))
        severity = escape(str(finding.get("severity", "")))
        findings_rows.append(
            "<tr>"
            f"<td>{escape(str(finding.get('control_id', '')))}</td>"
            f'<td><span class="badge {"fail" if status == "FAIL" else "pass"}">{status}</span></td>'
            f"<td>{severity}</td>"
            f"<td>{escape(_service_for(finding))}</td>"
            f"<td><code>{escape(str(finding.get('resource', '')))}</code></td>"
            "</tr>"
        )

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cloud Security & Compliance Dashboard</title>
<style>
:root {{
  --bg: #0b1020;
  --panel: #121a2f;
  --panel-2: #17223d;
  --text: #edf3ff;
  --muted: #9eb0cf;
  --line: #2b3a60;
  --accent: #6aa8ff;
  --pass: #42d392;
  --fail: #ff6b6b;
  --warn: #f5c451;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--text);
}}
.container {{ max-width: 1180px; margin: 0 auto; padding: 36px 24px 60px; }}
header {{ margin-bottom: 28px; }}
.eyebrow {{ color: var(--accent); font-weight: 700; letter-spacing: .08em; text-transform: uppercase; font-size: .8rem; }}
h1 {{ margin: 8px 0 8px; font-size: clamp(2rem, 4vw, 3.4rem); }}
.subtitle, .muted {{ color: var(--muted); }}
.meta {{ display: flex; flex-wrap: wrap; gap: 10px 18px; margin-top: 14px; color: var(--muted); font-size: .92rem; }}
.grid {{ display: grid; gap: 16px; }}
.cards {{ grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin: 22px 0; }}
.card, .section {{
  background: linear-gradient(180deg, var(--panel-2), var(--panel));
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 20px;
}}
.metric {{ font-size: 2rem; font-weight: 800; margin-top: 4px; }}
.metric.pass {{ color: var(--pass); }}
.metric.fail {{ color: var(--fail); }}
.two {{ grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); margin-top: 16px; }}
.section h2 {{ margin-top: 0; }}
.bar-row {{ margin: 15px 0; }}
.bar-label {{ display: flex; justify-content: space-between; color: var(--muted); font-size: .92rem; margin-bottom: 6px; }}
.bar-track {{ height: 10px; background: #0d1427; border-radius: 999px; overflow: hidden; border: 1px solid var(--line); }}
.bar-fill {{ height: 100%; background: linear-gradient(90deg, var(--accent), #9f7aea); border-radius: inherit; }}
table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
th, td {{ text-align: left; padding: 11px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
th {{ color: var(--muted); font-weight: 600; }}
.badge {{ display: inline-block; border-radius: 999px; padding: 4px 9px; font-size: .76rem; font-weight: 800; }}
.badge.pass {{ background: rgba(66, 211, 146, .14); color: var(--pass); }}
.badge.fail {{ background: rgba(255, 107, 107, .14); color: var(--fail); }}
.findings {{ grid-template-columns: repeat(auto-fit, minmax(270px, 1fr)); }}
.finding {{ border: 1px solid var(--line); border-radius: 14px; padding: 16px; background: #0f172b; }}
.finding h3 {{ font-size: 1rem; margin: 12px 0 8px; }}
.finding p {{ color: var(--muted); font-size: .9rem; line-height: 1.45; }}
.finding .resource {{ color: var(--text); word-break: break-word; }}
.finding-head {{ display: flex; gap: 8px; align-items: center; }}
.note {{ border-left: 4px solid var(--warn); padding: 14px 16px; background: rgba(245, 196, 81, .08); border-radius: 8px; color: #f8e4a7; }}
code {{ color: #c8dbff; }}
footer {{ margin-top: 28px; color: var(--muted); font-size: .9rem; }}
@media (max-width: 640px) {{
  .container {{ padding: 24px 14px 40px; }}
  .two {{ grid-template-columns: 1fr; }}
  .section {{ overflow-x: auto; }}
}}
</style>
</head>
<body>
<div class="container">
<header>
  <div class="eyebrow">Cloud Security & Compliance Automation Lab</div>
  <h1>Security Control Dashboard</h1>
  <p class="subtitle">Automated view of technical control checks, failed findings, AWS services, and framework mappings.</p>
  <div class="meta">
    <span>Account: <code>{escape(str(account_id))}</code></span>
    <span>Region: <code>{escape(str(region))}</code></span>
    <span>Generated: {generated}</span>
  </div>
</header>

<section class="grid cards">
  <div class="card"><div class="muted">Technical posture</div><div class="metric">{posture}%</div><div class="muted">PASS / total resource-level checks</div></div>
  <div class="card"><div class="muted">PASS</div><div class="metric pass">{passed}</div><div class="muted">successful checks</div></div>
  <div class="card"><div class="muted">FAIL</div><div class="metric fail">{failed}</div><div class="muted">findings requiring review</div></div>
  <div class="card"><div class="muted">Control IDs</div><div class="metric">{unique_controls}</div><div class="muted">unique automated controls</div></div>
</section>

<div class="note">
<strong>Interpretation:</strong> Technical posture is an operational metric for these automated checks. It is not an LGPD compliance score, legal opinion, audit conclusion, or certification.
</div>

<section class="grid two">
  <div class="section">
    <h2>Failed findings by severity</h2>
    {severity_bars}
  </div>
  <div class="section">
    <h2>Controls by AWS service</h2>
    <table>
      <thead><tr><th>Service</th><th>Checks</th><th>PASS</th><th>FAIL</th><th>Posture</th></tr></thead>
      <tbody>{''.join(service_rows)}</tbody>
    </table>
  </div>
</section>

<section class="grid two">
  <div class="section">
    <h2>NIST CSF 2.0 mapping</h2>
    <table>
      <thead><tr><th>Mapping</th><th>Checks</th><th>Failed</th><th>PASS rate</th></tr></thead>
      <tbody>{_framework_rows(nist_all, nist_fail)}</tbody>
    </table>
  </div>
  <div class="section">
    <h2>LGPD mapping</h2>
    <table>
      <thead><tr><th>Reference</th><th>Checks</th><th>Failed</th><th>PASS rate</th></tr></thead>
      <tbody>{_framework_rows(lgpd_all, lgpd_fail)}</tbody>
    </table>
  </div>
</section>

<section class="section" style="margin-top:16px">
  <h2>Priority findings</h2>
  <div class="grid findings">{''.join(priority_cards) if priority_cards else '<p class="muted">No failed findings.</p>'}</div>
</section>

<section class="section" style="margin-top:16px">
  <h2>All checks</h2>
  <table>
    <thead><tr><th>Control</th><th>Status</th><th>Severity</th><th>Service</th><th>Resource</th></tr></thead>
    <tbody>{''.join(findings_rows)}</tbody>
  </table>
</section>

<footer>
  <strong>Author:</strong> Michelle de Lara Ferraz Silveira Almeida<br>
  Cloud Security · Cyber GRC · Technology Governance · Evidence Automation
</footer>
</div>
</body>
</html>
"""
