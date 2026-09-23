from __future__ import annotations
from typing import Any, Dict, Iterable, List

Finding = Dict[str, Any]

def make_finding(control, status, resource, evidence, recommendation=None):
    return {
        "control_id": control["id"],
        "title": control["title"],
        "status": status,
        "severity": control["severity"] if status == "FAIL" else "INFO",
        "resource": resource,
        "evidence": evidence,
        "nist_csf_2_0": control.get("nist_csf_2_0", []),
        "lgpd": control.get("lgpd", []),
        "recommendation": recommendation or control.get("recommendation", ""),
    }

def check_s3_public_access(inventory, control):
    out = []
    for bucket in inventory.get("s3_buckets", []):
        pab = bucket.get("public_access_block") or {}
        all_blocked = all(pab.get(k) is True for k in (
            "BlockPublicAcls","IgnorePublicAcls","BlockPublicPolicy","RestrictPublicBuckets"
        ))
        public = bucket.get("policy_is_public", False)
        out.append(make_finding(control, "PASS" if all_blocked and not public else "FAIL",
                                f"s3://{bucket['name']}",
                                {"public_access_block": pab, "policy_is_public": public}))
    return out

def check_iam_mfa(inventory, control):
    out = []
    for user in inventory.get("iam_users", []):
        if not user.get("password_enabled", False):
            continue
        out.append(make_finding(control, "PASS" if user.get("mfa_active") else "FAIL",
                                f"user/{user['name']}",
                                {"password_enabled": True, "mfa_active": user.get("mfa_active", False)}))
    return out

def check_cloudtrail(inventory, control):
    trails = inventory.get("cloudtrails", [])
    passed = any(t.get("is_logging") for t in trails)
    return [make_finding(control, "PASS" if passed else "FAIL", "account/cloudtrail", {"trails": trails})]

def _port_range_contains(rule, port):
    start, end = rule.get("from_port"), rule.get("to_port")
    return start is not None and end is not None and start <= port <= end

def check_sensitive_ports(inventory, control):
    sensitive = {22, 3389, 3306, 5432, 1433, 27017}
    out = []
    for sg in inventory.get("security_groups", []):
        violations = []
        for rule in sg.get("ingress", []):
            if rule.get("cidr") in {"0.0.0.0/0", "::/0"}:
                exposed = sorted(p for p in sensitive if _port_range_contains(rule, p))
                if exposed:
                    violations.append({"rule": rule, "sensitive_ports": exposed})
        out.append(make_finding(control, "FAIL" if violations else "PASS",
                                f"security-group/{sg['group_id']}",
                                {"name": sg.get("name"), "violations": violations}))
    return out

def check_s3_encryption(inventory, control):
    return [make_finding(control, "PASS" if b.get("encryption_enabled") else "FAIL",
                         f"s3://{b['name']}", {"encryption_enabled": b.get("encryption_enabled", False)})
            for b in inventory.get("s3_buckets", [])]

def check_rds_encryption(inventory, control):
    return [make_finding(control, "PASS" if d.get("storage_encrypted") else "FAIL",
                         f"rds/{d['identifier']}", {"storage_encrypted": d.get("storage_encrypted", False)})
            for d in inventory.get("rds_instances", [])]

def check_s3_logging(inventory, control):
    return [make_finding(control, "PASS" if b.get("logging_enabled") else "FAIL",
                         f"s3://{b['name']}", {"logging_enabled": b.get("logging_enabled", False)})
            for b in inventory.get("s3_buckets", [])]

def _is_star(value):
    return value == "*" or (isinstance(value, list) and "*" in value)

def check_iam_star_policies(inventory, control):
    out = []
    for policy in inventory.get("iam_policies", []):
        if not policy.get("customer_managed", False):
            continue
        violations = [s for s in policy.get("statements", [])
                      if s.get("Effect") == "Allow" and _is_star(s.get("Action")) and _is_star(s.get("Resource"))]
        out.append(make_finding(control, "FAIL" if violations else "PASS",
                                f"iam-policy/{policy['name']}", {"violations": violations}))
    return out

def _tag_result(resource_type, resource_id, tags, required):
    missing = [t for t in required if not tags.get(t)]
    return resource_type, resource_id, missing, tags

def check_required_tags(inventory, control):
    required = inventory.get("required_tags", ["Owner","Environment","DataClassification"])
    rows = []
    for b in inventory.get("s3_buckets", []):
        rows.append(_tag_result("s3", b["name"], b.get("tags", {}), required))
    for d in inventory.get("rds_instances", []):
        rows.append(_tag_result("rds", d["identifier"], d.get("tags", {}), required))
    for i in inventory.get("ec2_instances", []):
        rows.append(_tag_result("ec2", i["instance_id"], i.get("tags", {}), required))
    return [make_finding(control, "FAIL" if missing else "PASS", f"{rtype}/{rid}",
                         {"required_tags": required, "missing_tags": missing, "tags": tags})
            for rtype, rid, missing, tags in rows]

CHECKS = {
    "S3-01": check_s3_public_access,
    "IAM-01": check_iam_mfa,
    "CT-01": check_cloudtrail,
    "SG-01": check_sensitive_ports,
    "S3-02": check_s3_encryption,
    "RDS-01": check_rds_encryption,
    "LOG-01": check_s3_logging,
    "IAM-02": check_iam_star_policies,
    "TAG-01": check_required_tags,
}
