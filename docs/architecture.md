# Architecture

```text
AWS Account / Mock Inventory
          |
          v
  Evidence Collection
   Boto3 / JSON
          |
          v
    Control Engine
          |
          v
 Structured Findings
       JSON
          |
          +------------------+
          |                  |
          v                  v
   Risk / Severity      Framework Mapping
                        NIST CSF 2.0 / LGPD
          |                  |
          +--------+---------+
                   v
             Markdown Report
```

The lab is read-only by design. Collection is separated from evaluation so the same controls can work with mock data, live AWS data, or future evidence sources.

Every finding includes the evidence used for the PASS/FAIL decision. Technical results still require human validation before governance, legal, audit, or compliance conclusions.
