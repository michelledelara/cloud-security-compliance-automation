# Cloud Security & Compliance Automation Lab

[![CI - Security Controls](https://github.com/michelledelara/cloud-security-compliance-automation/actions/workflows/ci.yml/badge.svg)](https://github.com/michelledelara/cloud-security-compliance-automation/actions/workflows/ci.yml)

**AWS · Python · Boto3 · NIST CSF 2.0 · LGPD · Security Controls · Evidence Automation**

A practical Cloud Security and GRC automation project that converts AWS configuration data into repeatable security-control tests, structured findings, evidence, risk ratings, reports, and an automatically generated security dashboard.

## Why this project exists

Cloud security assessments are often performed manually: analysts inspect AWS services, collect screenshots or configuration evidence, update spreadsheets, map findings to frameworks, and prepare reports.

This project demonstrates a more reproducible approach:

**AWS → Python/Boto3 → Control Tests → Findings → Risk → Evidence → Report → Dashboard**

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
| IAM-02 | Avoid broad `*:*` customer-managed IAM policies | AWS IAM |
| TAG-01 | Required tags present | S3 / EC2 / RDS |

Framework mappings are intentionally treated as **illustrative control mappings**, not legal conclusions or audit certification.

## Automated dashboard

Every assessment now generates `reports/dashboard.html`.

The dashboard shows:

- overall technical posture (PASS / total resource-level checks);
- PASS and FAIL totals;
- failed findings by severity;
- checks and posture by AWS service;
- NIST CSF 2.0 mapping coverage and failed mapped checks;
- LGPD reference mapping coverage and failed mapped checks;
- prioritized findings and remediation guidance;
- a complete control-check table.

**Important:** the technical posture metric is not an LGPD compliance score, audit opinion, or certification.

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
│   ├── dashboard.py
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
    ├── test_checks.py
    └── test_dashboard.py
```

## Quick start — mock mode

No AWS account is required for the first run.

```bash
python -m src.main --mode mock
```

The script reads `sample_data/aws_inventory.json` and generates:

- `findings/findings.json`
- `reports/compliance-report.md`
- `reports/dashboard.html`

Open `reports/dashboard.html` in a browser to view the dashboard.

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

## Continuous Integration

GitHub Actions runs automatically on every push and pull request, and can also be started manually.

The CI pipeline:

1. checks out the repository;
2. tests the project on Python 3.11 and 3.12;
3. installs the declared dependencies;
4. runs the unit-test suite;
5. executes the mock cloud-security assessment;
6. generates JSON findings, the Markdown report, and the HTML dashboard;
7. validates the generated outputs;
8. publishes all three assessment outputs as a downloadable workflow artifact.

This provides a repeatable validation layer for the control logic before future integrations with live AWS evidence sources.

## Example finding

```json
{
  "control_id": "IAM-01",
  "title": "MFA enabled for console users",
  "service": "iam",
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
- Reproducible reports and dashboards

## Roadmap

- [x] Mock AWS inventory
- [x] Nine baseline checks
- [x] JSON findings
- [x] Markdown compliance report
- [x] NIST CSF 2.0 + LGPD mappings
- [x] HTML security-control dashboard
- [x] GitHub Actions security pipeline
- [x] Dashboard unit test
- [ ] CIS AWS Foundations mappings
- [ ] ISO/IEC 27001 mappings
- [ ] CSV export
- [ ] AWS Security Hub / Config integration
- [ ] Evidence history and control trend analysis
- [ ] Optional GitHub Pages dashboard publication

## Author

**Michelle de Lara Ferraz Silveira Almeida**

Focus: Cloud Security · Cyber GRC · Technology Governance · Data & AI Governance
