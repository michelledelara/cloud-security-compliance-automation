from collections import Counter

def build_markdown_report(findings, account_id, region):
    status = Counter(f["status"] for f in findings)
    sev = Counter(f["severity"] for f in findings if f["status"] == "FAIL")
    lines = [
        "# Cloud Security & Compliance Assessment","",
        f"- **Account:** `{account_id}`", f"- **Region:** `{region}`",
        f"- **Checks generated:** {len(findings)}",
        f"- **PASS:** {status.get('PASS',0)}", f"- **FAIL:** {status.get('FAIL',0)}","",
        "## Failed findings by severity","",
        f"- CRITICAL: {sev.get('CRITICAL',0)}", f"- HIGH: {sev.get('HIGH',0)}",
        f"- MEDIUM: {sev.get('MEDIUM',0)}", f"- LOW: {sev.get('LOW',0)}","",
        "## Findings","",
        "| Control | Status | Severity | Resource | NIST CSF 2.0 | LGPD |",
        "|---|---|---|---|---|---|"
    ]
    for f in findings:
        lines.append(f"| {f['control_id']} | {f['status']} | {f['severity']} | `{f['resource']}` | {', '.join(f.get('nist_csf_2_0',[]))} | {', '.join(f.get('lgpd',[]))} |")
    lines += ["","## Remediation priorities",""]
    rank = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    failed = sorted((f for f in findings if f["status"]=="FAIL"), key=lambda x:(rank.get(x["severity"],99),x["control_id"],x["resource"]))
    if not failed:
        lines.append("No failed controls in this assessment.")
    else:
        for f in failed:
            lines.append(f"- **{f['severity']} · {f['control_id']} · {f['resource']}** — {f['recommendation']}")
    lines += ["","## Governance note","",
              "Framework mappings in this lab are illustrative and support control analysis. They do not constitute legal advice, formal audit evidence, certification, or a conclusion of LGPD compliance.",""]
    return "\n".join(lines)
