# ─────────────────────────────────────────────────────────────────────────────
# MonuCloud – Code Preview (Non-Executable)
# This file is intentionally incomplete and redacted for demo purposes.
# It is NOT runnable. See the live demo at https://monucloud.com
# ─────────────────────────────────────────────────────────────────────────────


# Demo-only example "upsert" pattern
from typing import Any, Dict, Optional
from datetime import datetime, timezone

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

class DemoDB:
    def __init__(self) -> None:
        self._data: Dict[str, Dict[str, Any]] = {}

    def _key(self, rule_id: str, account_id: str, resource_id: str, region: Optional[str]) -> str:
        return "|".join([rule_id, account_id, resource_id, region or ""])

    def find(self, rule_id: str, account_id: str, resource_id: str, region: Optional[str]) -> Optional[Dict[str, Any]]:
        return self._data.get(self._key(rule_id, account_id, resource_id, region))

    def insert(self, rec: Dict[str, Any]) -> str:
        k = self._key(rec["rule_id"], rec["account_id"], rec["resource_id"], rec.get("region"))
        self._data[k] = rec
        return k

    def update(self, rec: Dict[str, Any], **fields: Any) -> None:
        rec.update(fields)

def upsert_finding(db: DemoDB, finding: Dict[str, Any]) -> str:
    existing = db.find(finding["rule_id"], finding["account_id"], finding["resource_id"], finding.get("region"))
    if existing:
        db.update(existing, last_seen=now_utc(), status="OPEN",
                  evidence=finding.get("evidence"), title=finding.get("title"))
        # return the id/key (for demo we reuse the composite key)
        return db._key(existing["rule_id"], existing["account_id"], existing["resource_id"], existing.get("region"))
    else:
        rec = {
            "rule_id": finding["rule_id"],
            "cloud": finding.get("cloud", "AWS"),
            "account_id": finding["account_id"],
            "resource_id": finding["resource_id"],
            "region": finding.get("region"),
            "severity": finding["severity"],
            "title": finding["title"],
            "evidence": finding.get("evidence", {}),
            "first_seen": now_utc(),
            "last_seen": now_utc(),
            "status": "OPEN",
        }
        return db.insert(rec)
    
if __name__ == "__main__":
    raise SystemExit("This is a non-executable code preview. See monucloud.com for the live app.")

