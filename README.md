# Cloud Security & Compliance Automation Lab

**AWS · Python · Boto3 · NIST CSF 2.0 · LGPD · Security Controls · Evidence Automation**

A practical Cloud Security and GRC automation project that converts AWS configuration data into repeatable security-control tests, structured findings, evidence, risk ratings, and compliance-oriented reporting.

## Why this project exists

Cloud security assessments are often performed manually: analysts inspect AWS services, collect screenshots or configuration evidence, update spreadsheets, map findings to frameworks, and prepare reports.

This project demonstrates a more reproducible approach:

**AWS → Python/Boto3 → Control Tests → Findings → Risk → Evidence → Report**

The goal is not to replace professional judgment. It is to automate repeatable evidence collection and first-level control validation so that analysts can spend more time on risk analysis, remediation, and governance.

## MVP controls

| ID | Control | AWS scope |
|---|---|---|
| S3-01 | Block public access | Amazon S3 |
| IAM-01 | MFA enabled for console users | AWS IAM |
| CT-01 | CloudTrail enabled | AWS CloudTrail |
| SG-01 | Sensitive ports not open to the internet | EC2 Security Groups |
| S3-02 | Default encryption enabled | Amazon S3 |
| RDS-01 | Storage encryption enabled | Amazon RDS |
| LOG-01 | S3 access logging enabled | Amazon S3 |
| IAM-02 | Avoid broad `*:*\` customer-managed IAM policies | AWS IAM |
| TAG-01 | Required tags present | S3 / EC2 / RDS |

Framework mappings are intentionally treated as **illustrative control mappings**, not legal conclusions or audit certification.

## Project structure

```text
cloud-security-compliance-automation/
├── README.md
├── requirements.txt
├── controls/
│   └── control-library.yaml
├── sample_data/
│   └── aws_inventory.json
├── src/
│   ├── __init__.py
│   ├── aws_collector.py
│   ├── checks.py
│   ├── evaluate.py
│   ├── main.py
│   └── report.py
├── findings/
│   └── sample-findings.json
├── reports/
│   └── sample-compliance-report.md
├── docs/
│   ├── architecture.md
│   ├── methodology.md
│   └── framework-mapping.md
└── tests/
    └── test_checks.py
```

## Quick start — mock mode

No AWS account is required for the first run.

```bash
python -m src.main --mode mock
```

The script reads `sample_data/aws_inventory.json` and generates:

- `findings/findings.json`
- `reports/compliance-report.md`

## Live AWS mode

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure AWS credentials using your normal AWS CLI / environment-variable workflow and use a **read-only assessment identity**.

Then run:

```bash
python -m src.main --mode live --region us-east-1
```

The live collector uses Boto3 to retrieve configuration metadata. The project is designed for assessment only and does not remediate or modify cloud resources.

## Example finding

```json
{
  "control_id": "IAM-01",
  "title": "MFA enabled for console users",
  "status": "FAIL",
  "severity": "HIGH",
  "resource": "user/alice",
  "evidence": {
    "password_enabled": true,
    "mfa_active": false
  },
  "nist_csf_2_0": ["PR.AA"],
  "lgpd": ["Art. 46", "Art. 49"],
  "recommendation": "Require MFA for all IAM users with console access."
}
```

## Security and governance principles

- Read-only evidence collection
- No automatic remediation
- Least-privilege assessment identity
- Structured findings instead of screenshots only
- Human validation before governance or legal conclusions
- Version-controlled control logic
- Explicit framework mappings
- Reproducible reports

## Roadmap

- [x] Mock AWS inventory
- [x] Nine baseline checks
- [x] JSON findings
- [x] Markdown compliance report
- [x] NIST CSF 2.0 + LGPD mappings
- [ ] CIS AWS Foundations mappings
- [ ] ISO/IEC 27001 mappings
- [ ] CSV export
- [ ] HTML dashboard
- [ ] GitHub Actions security pipeline
- [ ] Unit-test expansion
- [ ] AWS Security Hub / Config integration
- [ ] Evidence history and control trend analysis

## Author

**Michelle de Lara Ferraz Silveira Almeida**

Focus: Cloud Security · Cyber GRC · Technology Governance · Data & AI Governance
