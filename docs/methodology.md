# Methodology

1. Define a narrow, testable control objective.
2. Collect evidence from mock JSON or AWS APIs through Boto3.
3. Normalize AWS responses into consistent JSON.
4. Evaluate controls as PASS/FAIL.
5. Attach severity, resource, evidence, framework mappings, and remediation guidance.
6. Prioritize failed findings.
7. Perform human validation.

Severity in this MVP is control-defined. A future version can calculate likelihood × impact and distinguish inherent from residual risk.
