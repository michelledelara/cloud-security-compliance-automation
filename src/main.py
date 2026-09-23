from __future__ import annotations
import argparse, json
from pathlib import Path
import yaml
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
    (ROOT/"findings"/"findings.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    (ROOT/"reports"/"compliance-report.md").write_text(
        build_markdown_report(findings, inventory.get("account_id","unknown"), inventory.get("region",args.region)),
        encoding="utf-8"
    )
    print(f"Assessment complete: {sum(f['status']=='PASS' for f in findings)} PASS / {sum(f['status']=='FAIL' for f in findings)} FAIL")

if __name__ == "__main__":
    main()
