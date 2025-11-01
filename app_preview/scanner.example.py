# ─────────────────────────────────────────────────────────────────────────────
# MonuCloud – Code Preview (Non-Executable)
# This file is intentionally curated and partially redacted for public preview.
# It mirrors the real structure (functions & flow) without exposing internals.
# Live product: https://monucloud.com
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import subprocess
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# In the real code these come from your app layer and persistence.
# from apps.web.app import fetch_role_from_db
# from packages.cspm_core import Store
# from packages.cspm_core.DB import get_session

try:
    import boto3  # optional so the preview file can be imported safely
    from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
except Exception:  # pragma: no cover - keep preview import-safe
    boto3 = None
    ClientError = NoCredentialsError = PartialCredentialsError = Exception  # type: ignore


# --- Small public example rules (safe to ship) -------------------------------

def _example_check_ec2_sg_open(session: Any, account_id: str, region: str) -> Iterator[Dict[str, Any]]:
    """Example rule: SG open to 0.0.0.0/0 on non-web ports (preview)."""
    WEB_PORTS = {80, 443, 8080, 8443}
    try:
        ec2 = session.client("ec2", region_name=region)
        res = ec2.describe_security_groups()
    except Exception:
        res = {"SecurityGroups": []}

    for sg in res.get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            f = perm.get("FromPort")
            t = perm.get("ToPort") or f
            ports = [f] if (f is not None and t == f) else list(range(int(f or 0), int(t or 0) + 1))
            for r in perm.get("IpRanges", []):
                if r.get("CidrIp") == "0.0.0.0/0" and not any(p in WEB_PORTS for p in ports):
                    yield {
                        "rule_id": "AWS-001",
                        "account_id": account_id,
                        "region": region,
                        "resource_id": sg.get("GroupId", "sg-unknown"),
                        "severity": "High",
                        "title": f"Security group allows 0.0.0.0/0 on ports {ports}",
                        "evidence": {"ports": ports, "protocol": perm.get("IpProtocol")},
                    }


def _example_check_s3_public(session: Any, account_id: str, region: Optional[str]) -> Iterator[Dict[str, Any]]:
    """Example rule: S3 bucket public via ACL or policy (preview)."""
    import json
    try:
        s3 = session.client("s3", region_name=region) if region else session.client("s3")
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    except Exception:
        buckets = []

    def _acl_public(acl: Dict[str, Any]) -> Dict[str, bool]:
        public = {"read": False, "write": False}
        for g in acl.get("Grants", []):
            uri = (g.get("Grantee") or {}).get("URI", "")
            if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                perm = g.get("Permission")
                if perm in ("READ", "READ_ACP", "FULL_CONTROL"):
                    public["read"] = True
                if perm in ("WRITE", "WRITE_ACP", "FULL_CONTROL"):
                    public["write"] = True
        return public

    def _policy_public(doc: Dict[str, Any]) -> bool:
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for s in stmts:
            if str(s.get("Effect", "")).lower() == "allow":
                p = s.get("Principal")
                if p == "*" or (isinstance(p, dict) and p.get("AWS") == "*"):
                    return True
        return False

    for b in buckets:
        region_for_b = None
        try:
            loc = s3.get_bucket_location(Bucket=b)
            region_for_b = loc.get("LocationConstraint") or "us-east-1"
        except Exception:
            pass

        acl_pub = {"read": False, "write": False}
        pol_pub = False
        try:
            acl_pub = _acl_public(s3.get_bucket_acl(Bucket=b))
        except Exception:
            pass

        try:
            pol = s3.get_bucket_policy(Bucket=b).get("Policy")
            if pol:
                pol_pub = _policy_public(json.loads(pol))
        except Exception:
            pass

        if pol_pub or any(acl_pub.values()):
            kind = "policy" if pol_pub else "acl"
            if pol_pub and any(acl_pub.values()):
                kind = "policy & acl"
            yield {
                "rule_id": "AWS-002",
                "account_id": account_id,
                "region": region_for_b or region or "unknown",
                "resource_id": b,
                "severity": "High",
                "title": f"S3 bucket '{b}' is publicly accessible ({kind})",
                "evidence": {"policy_public": pol_pub, "acl_public": acl_pub},
            }


PUBLIC_RULES = (
    _example_check_ec2_sg_open,
    _example_check_s3_public,
)


# --- Public preview of your real functions & flow ----------------------------

def get_tool_version() -> str:
    """Preview of version stamping."""
    try:
        return subprocess.check_output(["git", "describe", "--tags", "--always"]).decode().strip()
    except Exception:
        return "unknown"


def _base_session_from_env_or_default(region: Optional[str] = None) -> Any:
    """
    In production: returns a boto3.Session from instance profile or env.
    In preview: create a best-effort session if boto3 exists, else a stub.
    """
    if boto3 is None:
        class _Stub:  # keeps preview import-safe
            def client(self, *_a, **_k): raise RuntimeError("No AWS session in preview")
        return _Stub()
    return boto3.Session(region_name=region)


def _assume_role(role_arn: str, external_id: Optional[str], region: Optional[str]) -> Any:
    """
    In production: STS AssumeRole(RoleArn, ExternalId) → boto3.Session.
    In preview: returns a base session without real STS (redacted).
    """
    # Redacted: STS call and credential vending.
    return _base_session_from_env_or_default(region)


def get_session_for_account(account_id: str, region: Optional[str] = None) -> Any:
    """
    In production:
      - fetch_role_from_db(cloud='AWS', account_id=...)
      - return _assume_role(role_arn, external_id, region)
    In preview: returns a base session.
    """
    # Redacted: fetch_role_from_db(...)
    return _base_session_from_env_or_default(region)


def run_account_scan(
    session: Any,
    account_id: str,
    regions: Iterable[str],
    scan_id: Optional[int],
    scope: str,
    cloud: str = "AWS",
) -> Tuple[int, List[str]]:
    """
    Preview of the scanning flow used by your worker:
      - iterate regions
      - run a subset of rules
      - upsert findings
      - mark missing findings as resolved

    Returns: (open_findings_count, seen_finding_uids)
    """
    # Redacted: session = get_session()
    #   with get_session() as db: Store.start_scan(...)

    open_count ='_'
