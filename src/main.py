from __future__ import annotations
import argparse, json
from pathlib import Path
import yaml
from .dashboard import build_dashboard
from .evaluate import evaluate
from .report import build_markdown_report

ROOT = Path(__file__).resolve().parents[1]

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def main():
    parser = argparse.ArgumentParser(description="Cloud Security & Compliance Automation Lab")
    parser.add_argument("--mode", choices=["mock","live"], default="mock")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--input", default=str(ROOT/"sample_data"/"aws_inventory.json"))
    args = parser.parse_args()

    library = yaml.safe_load((ROOT/"controls"/"control-library.yaml").read_text(encoding="utf-8"))
    if args.mode == "mock":
        inventory = load_json(args.input)
    else:
        from .aws_collector import collect_inventory
        inventory = collect_inventory(args.region)

    findings = evaluate(inventory, library)
    (ROOT/"findings").mkdir(exist_ok=True)
    (ROOT/"reports").mkdir(exist_ok=True)

    account_id = inventory.get("account_id", "unknown")
    region = inventory.get("region", args.region)

    findings_path = ROOT/"findings"/"findings.json"
    report_path = ROOT/"reports"/"compliance-report.md"
    dashboard_path = ROOT/"reports"/"dashboard.html"

    findings_path.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    report_path.write_text(
        build_markdown_report(findings, account_id, region),
        encoding="utf-8",
    )
    dashboard_path.write_text(
        build_dashboard(findings, account_id, region),
        encoding="utf-8",
    )

    passed = sum(f["status"] == "PASS" for f in findings)
    failed = sum(f["status"] == "FAIL" for f in findings)
    print(f"Assessment complete: {passed} PASS / {failed} FAIL")
    print(f"Findings:  {findings_path}")
    print(f"Report:    {report_path}")
    print(f"Dashboard: {dashboard_path}")

if __name__ == "__main__":
    main()
