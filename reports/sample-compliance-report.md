# Cloud Security & Compliance Assessment

- **Account:** `123456789012`
- **Region:** `us-east-1`
- **Assessment mode:** Mock evidence
- **Purpose:** Demonstrate automated control testing and evidence generation

## Example failed findings

- **CRITICAL · S3-01 · s3://novashop-marketing-assets** — Public-access protections are not fully enabled and the bucket policy is identified as public.
- **HIGH · IAM-01 · user/alice** — Console access exists without MFA.
- **HIGH · SG-01 · security-group/sg-002** — SSH (22) is open to `0.0.0.0/0`.
- **HIGH · S3-02 · s3://novashop-marketing-assets** — Default bucket encryption is disabled.
- **HIGH · RDS-01 · rds/novashop-db** — Storage encryption is disabled.
- **MEDIUM · LOG-01 · s3://novashop-marketing-assets** — Access logging is disabled.
- **CRITICAL · IAM-02 · iam-policy/LegacyAdminPolicy** — Customer-managed policy grants both `Action: "*"` and `Resource: "*"`.
- **LOW · TAG-01** — Some resources are missing governance tags.

## Governance note

This sample report demonstrates how technical configuration evidence can be translated into structured GRC findings. NIST CSF 2.0 and LGPD mappings are illustrative and must be validated against organizational scope, risk context, compensating controls, and legal interpretation.

## Author

**Michelle de Lara Ferraz Silveira Almeida**
