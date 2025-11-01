# ─────────────────────────────────────────────────────────────────────────────
# MonuCloud – Code Preview (Non-Executable)
# This file is intentionally incomplete and redacted for demo purposes.
# It is NOT runnable. See the live demo at https://monucloud.com
# ─────────────────────────────────────────────────────────────────────────────

def check_sg_open(session, account_id, region):
    ec2 = session.client("ec2", region_name=region)
    res = ec2.describe_security_groups()
    for sg in res.get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            from_p = perm.get("FromPort")
            to_p = perm.get("ToPort")
            proto = perm.get("IpProtocol")
            ports = list(range(from_p or 0, (to_p or from_p or 0) + 1)) if from_p is not None else [-1]
            for ipr in perm.get("IpRanges", []):
                if ipr.get("CidrIp") == "0.0.0.0/0":
                    if not any(p in (80, 443, 8080, 8443) for p in ports):
                        yield {
                            "rule_id": "AWS-001",
                            "account_id": account_id,
                            "region": region,
                            "resource_id": sg["GroupId"],
                            "severity": "High",
                            "title": f"Security group {sg['GroupId']} allows 0.0.0.0/0 on port(s) {ports}",
                            "evidence": {"ports": ports, "protocol": proto},
                        }

if __name__ == "__main__":
    raise SystemExit("This is a non-executable code preview. See monucloud.com for the live app.")
