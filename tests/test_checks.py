import unittest
from src.checks import check_iam_mfa, check_s3_public_access, check_sensitive_ports

class TestChecks(unittest.TestCase):
    def test_mfa_fails_for_console_user_without_mfa(self):
        inventory={"iam_users":[{"name":"alice","password_enabled":True,"mfa_active":False}]}
        control={"id":"IAM-01","title":"MFA","severity":"HIGH","nist_csf_2_0":["PR.AA"],"lgpd":["Art. 46"],"recommendation":"Enable MFA."}
        self.assertEqual(check_iam_mfa(inventory,control)[0]["status"],"FAIL")

    def test_s3_public_bucket_fails(self):
        inventory={"s3_buckets":[{"name":"public","public_access_block":{},"policy_is_public":True}]}
        control={"id":"S3-01","title":"S3 public access","severity":"CRITICAL","nist_csf_2_0":["PR.DS"],"lgpd":["Art. 46"],"recommendation":"Block public access."}
        self.assertEqual(check_s3_public_access(inventory,control)[0]["status"],"FAIL")

    def test_ssh_open_to_world_fails(self):
        inventory={"security_groups":[{"group_id":"sg-test","name":"test","ingress":[{"protocol":"tcp","from_port":22,"to_port":22,"cidr":"0.0.0.0/0"}]}]}
        control={"id":"SG-01","title":"Sensitive ports","severity":"HIGH","nist_csf_2_0":["PR.PS"],"lgpd":["Art. 46"],"recommendation":"Restrict ingress."}
        self.assertEqual(check_sensitive_ports(inventory,control)[0]["status"],"FAIL")

if __name__=="__main__":
    unittest.main()
