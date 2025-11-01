# ─────────────────────────────────────────────────────────────────────────────
# MonuCloud – Code Preview (Non-Executable)
# This file is intentionally incomplete and redacted for demo purposes.
# It is NOT runnable. See the live demo at https://monucloud.com
# ─────────────────────────────────────────────────────────────────────────────


from __future__ import annotations
from typing import Any, Dict, Iterator, Optional, List


RULE_ID = "AWS-002"
SEVERITY = "High"


def _is_acl_public(acl: Dict[str, Any]) -> Dict[str, bool]:
    """
    Very small heuristic: flags if the ACL grants READ/WRITE to AllUsers or AuthenticatedUsers.
    """
    public = {"read": False, "write": False}
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        perm = grant.get("Permission", "")
        if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
            if perm in ("READ", "READ_ACP", "FULL_CONTROL"):
                public["read"] = True
            if perm in ("WRITE", "WRITE_ACP", "FULL_CONTROL"):
                public["write"] = True
    return public


def _statement_allows_public(stmt: Dict[str, Any]) -> bool:
    """
    Detects statements that obviously grant public access:
    - Effect: Allow
    - Principal: "*" (or AWS:"*")
    """
    if str(stmt.get("Effect", "")).lower() != "allow":
        return False

    principal = stmt.get("Principal")
    if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
        return True
    return False


def _policy_is_public(policy_doc: Dict[str, Any]) -> bool:
    """
    Minimal public check:
    - If any statement allows Principal "*", we consider it public.
    (In real scanners it'd also evaluate Conditions and Resources.)
    """
    stmts: List[Dict[str, Any]] = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if _statement_allows_public(s):
            return True
    return False


def _get_bucket_region(s3: Any, bucket: str) -> Optional[str]:
    try:
        loc = s3.get_bucket_location(Bucket=bucket)
        region = loc.get("LocationConstraint")
        return region or "us-east-1"
    except Exception:
        return None


def check_s3_public(session: Any, account_id: str, region: Optional[str] = None) -> Iterator[Dict[str, Any]]:
    """
    Yields findings for buckets with public ACL or public bucket policy.

    Finding shape (example):
    {
        "rule_id": "AWS-002",
        "account_id": "111111111111",
        "region": "eu-north-1",
        "resource_id": "my-bucket",
        "severity": "High",
        "title": "S3 bucket 'my-bucket' is publicly accessible (policy)",
        "evidence": {"policy_public": true, "acl_public": {"read": false, "write": true}}
    }
    """
    try:
        s3 = session.client("s3", region_name=region) if region else session.client("s3")
        buckets_resp = s3.list_buckets()
        buckets = [b["Name"] for b in buckets_resp.get("Buckets", [])]
    except Exception:
        # In demo/no-credentials mode, do nothing but keep the function safe.
        buckets = []

    for bucket in buckets:
        # Resolve region per-bucket to avoid cross-region calls failing.
        bkt_region = _get_bucket_region(s3, bucket) or region

        # Public access block (PAB) – if present and fully blocking, we can skip some checks.
        pab = {}
        try:
            pab = s3.get_public_access_block(Bucket=bucket).get("PublicAccessBlockConfiguration", {})
        except Exception:
            # Missing or no permission; continue gracefully.
            pab = {}

        # Check ACL for public grants
        acl_public = {"read": False, "write": False}
        try:
            acl = s3.get_bucket_acl(Bucket=bucket)
            acl_public = _is_acl_public(acl)
        except Exception:
            pass

        # Check bucket policy for public principals
        policy_public = False
        try:
            pol_str = s3.get_bucket_policy(Bucket=bucket).get("Policy")
            if pol_str:
                # Lazy import to avoid hard dependency if json missing in odd envs
                import json  
                pol = json.loads(pol_str)
                policy_public = _policy_is_public(pol)
        except Exception:
            pass

        # Decide if bucket is public
        if policy_public or any(acl_public.values()):
            title_bits = []
            if policy_public:
                title_bits.append("policy")
            if acl_public["read"] or acl_public["write"]:
                title_bits.append("acl")
            title_kind = " & ".join(title_bits)

            yield {
                "rule_id": RULE_ID,
                "account_id": account_id,
                "region": bkt_region or "unknown",
                "resource_id": bucket,
                "severity": SEVERITY,
                "title": f"S3 bucket '{bucket}' is publicly accessible ({title_kind})",
                "evidence": {
                    "policy_public": policy_public,
                    "acl_public": acl_public,
                    "public_access_block": pab or None,
                },
            }
