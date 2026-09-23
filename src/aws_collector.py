from __future__ import annotations
import boto3
from botocore.exceptions import ClientError

REQUIRED_TAGS = ["Owner","Environment","DataClassification"]

def _tags(items):
    return {t["Key"]: t["Value"] for t in (items or [])}

def collect_s3(session):
    s3 = session.client("s3")
    out = []
    for item in s3.list_buckets().get("Buckets", []):
        name = item["Name"]
        try: pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError: pab = {}
        try: public = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]
        except ClientError: public = False
        try: s3.get_bucket_encryption(Bucket=name); enc = True
        except ClientError: enc = False
        try: log = "LoggingEnabled" in s3.get_bucket_logging(Bucket=name)
        except ClientError: log = False
        try: tags = _tags(s3.get_bucket_tagging(Bucket=name).get("TagSet"))
        except ClientError: tags = {}
        out.append({"name":name,"public_access_block":pab,"policy_is_public":public,
                    "encryption_enabled":enc,"logging_enabled":log,"tags":tags})
    return out

def collect_iam(session):
    iam = session.client("iam")
    users, policies = [], []
    for page in iam.get_paginator("list_users").paginate():
        for u in page.get("Users", []):
            name = u["UserName"]
            try: iam.get_login_profile(UserName=name); pwd = True
            except ClientError: pwd = False
            mfa = bool(iam.list_mfa_devices(UserName=name).get("MFADevices"))
            users.append({"name":name,"password_enabled":pwd,"mfa_active":mfa})
    for page in iam.get_paginator("list_policies").paginate(Scope="Local", OnlyAttached=False):
        for p in page.get("Policies", []):
            doc = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict): stmts = [stmts]
            policies.append({"name":p["PolicyName"],"customer_managed":True,"statements":stmts})
    return users, policies

def collect_cloudtrail(session):
    ct = session.client("cloudtrail")
    out = []
    for t in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
        status = ct.get_trail_status(Name=t["Name"])
        out.append({"name":t["Name"],"is_logging":status.get("IsLogging",False),"multi_region":t.get("IsMultiRegionTrail",False)})
    return out

def collect_security_groups(session, region):
    ec2 = session.client("ec2", region_name=region)
    out = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page.get("SecurityGroups", []):
            ingress=[]
            for p in sg.get("IpPermissions", []):
                for r in p.get("IpRanges", []):
                    ingress.append({"protocol":p.get("IpProtocol"),"from_port":p.get("FromPort"),"to_port":p.get("ToPort"),"cidr":r.get("CidrIp")})
                for r in p.get("Ipv6Ranges", []):
                    ingress.append({"protocol":p.get("IpProtocol"),"from_port":p.get("FromPort"),"to_port":p.get("ToPort"),"cidr":r.get("CidrIpv6")})
            out.append({"group_id":sg["GroupId"],"name":sg.get("GroupName"),"ingress":ingress})
    return out

def collect_rds(session, region):
    rds = session.client("rds", region_name=region)
    out=[]
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page.get("DBInstances", []):
            tags=_tags(rds.list_tags_for_resource(ResourceName=db["DBInstanceArn"]).get("TagList"))
            out.append({"identifier":db["DBInstanceIdentifier"],"storage_encrypted":db.get("StorageEncrypted",False),"tags":tags})
    return out

def collect_ec2(session, region):
    ec2=session.client("ec2", region_name=region)
    out=[]
    for page in ec2.get_paginator("describe_instances").paginate():
        for res in page.get("Reservations", []):
            for i in res.get("Instances", []):
                out.append({"instance_id":i["InstanceId"],"tags":_tags(i.get("Tags"))})
    return out

def collect_inventory(region="us-east-1"):
    session=boto3.Session(region_name=region)
    account=session.client("sts").get_caller_identity()["Account"]
    users, policies=collect_iam(session)
    return {
        "account_id":account, "region":region, "required_tags":REQUIRED_TAGS,
        "s3_buckets":collect_s3(session), "iam_users":users, "iam_policies":policies,
        "cloudtrails":collect_cloudtrail(session),
        "security_groups":collect_security_groups(session,region),
        "rds_instances":collect_rds(session,region),
        "ec2_instances":collect_ec2(session,region),
    }
