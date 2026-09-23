# Framework Mapping

Mappings in this project are illustrative and support control analysis. They are not legal advice, formal audit evidence, certification, or a declaration of compliance.

| Control | NIST CSF 2.0 | LGPD | Rationale |
|---|---|---|---|
| S3-01 Public access | PR.DS / PR.PS | Arts. 46, 49 | Supports protection of data and secure configuration. |
| IAM-01 MFA | PR.AA | Arts. 46, 49 | Strengthens authentication and access control. |
| CT-01 CloudTrail | DE.CM | Arts. 46, 49 | Supports monitoring and traceability. |
| SG-01 Sensitive ports | PR.PS | Art. 46 | Reduces unnecessary network exposure. |
| S3-02 Encryption | PR.DS | Art. 46 | Supports protection of stored data. |
| RDS-01 Encryption | PR.DS | Art. 46 | Supports protection of database storage. |
| LOG-01 Logging | DE.CM | Art. 46 | Supports monitoring and investigation. |
| IAM-02 Broad permissions | PR.AA | Art. 46 | Supports least privilege. |
| TAG-01 Required tags | ID.AM | Art. 46 | Supports asset ownership and governance. |

A technical control can support an LGPD security obligation without proving organizational compliance.
