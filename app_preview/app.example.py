# ─────────────────────────────────────────────────────────────────────────────
# MonuCloud – Code Preview (Non-Executable)
# This file is intentionally incomplete and redacted for demo purposes.
# It is NOT runnable. See the live demo at https://monucloud.com
# ─────────────────────────────────────────────────────────────────────────────


from flask import Blueprint, request, jsonify, current_app
import csv, json, pathlib, datetime as dt
from config import DEMO_MODE, DEMO_SECRET, DEMO_ADMIN_EMAIL
# import your db/models as needed

demo_bp = Blueprint("demo", __name__, url_prefix="/admin/demo-data")

def _demo_auth():
    if not DEMO_MODE: return "Demo mode disabled", 403
    if not DEMO_SECRET: return "Demo secret not set", 403
    # simple gate: require secret header + your admin user
    if request.headers.get("X-Demo-Secret") != DEMO_SECRET:
        return "Forbidden", 403
    # if you have auth, also ensure current_user.email == DEMO_ADMIN_EMAIL
    return None

@demo_bp.route("/load", methods=["POST"])
def load_demo_data():
    auth_err = _demo_auth()
    if auth_err: return auth_err
    base = pathlib.Path(__file__).parent / "sample_data"
    # --- load accounts
    with (base / "accounts.csv").open() as f:
        for row in csv.DictReader(f):
            db_accounts.upsert(
                id=int(row["id"]),
                cloud=row["cloud"],
                account_id=row["account_id"],
                account_alias=row.get("account_alias"),
                is_demo=True,
            )
    # --- connections
    with (base / "connections.csv").open() as f:
        for row in csv.DictReader(f):
            db_connections.upsert(
                id=int(row["id"]),
                cloud=row["cloud"],
                account_id=row["account_id"],
                role_arn=row["role_arn"],
                external_id=row["external_id"],
                is_demo=True,
            )
    # --- rules
    with (base / "rules.csv").open() as f:
        for row in csv.DictReader(f):
            db_rules.upsert(
                rule_id=row["rule_id"],
                service=row["service"],
                severity=row["severity"],
                title=row["title"],
                description=row["description"],
            )
    # --- scans
    with (base / "scans.csv").open() as f:
        for row in csv.DictReader(f):
            db_scans.insert_or_update(
                scan_id=int(row["scan_id"]),
                cloud=row["cloud"],
                account_id=row["account_id"],
                started_at=dt.datetime.fromisoformat(row["started_at"].replace("Z","+00:00")),
                finished_at=dt.datetime.fromisoformat(row["finished_at"].replace("Z","+00:00")) if row["finished_at"] else None,
                status=row["status"],
                tool_version="demo",
                notes=None,
                is_demo=True,
                totals=dict(
                    total=int(row["total_findings"]),
                    critical=int(row["critical"]),
                    high=int(row["high"]),
                    medium=int(row["medium"]),
                    low=int(row["low"]),
                )
            )
    # --- findings
    with (base / "findings.json").open() as f:
        for finding in json.load(f):
            finding["is_demo"] = True
            db_findings.upsert_from_json(finding)
    db.session.commit()
    return jsonify({"ok": True})
    
@demo_bp.route("/purge", methods=["POST"])
def purge_demo_data():
    auth_err = _demo_auth()
    if auth_err: return auth_err
    # delete demo rows only
    db.session.execute("DELETE FROM findings WHERE is_demo = true;")
    db.session.execute("DELETE FROM resources WHERE is_demo = true;")
    db.session.execute("DELETE FROM scans WHERE is_demo = true;")
    db.session.execute("DELETE FROM connections WHERE is_demo = true;")
    db.session.execute("DELETE FROM accounts WHERE is_demo = true;")
    db.session.commit()
    return jsonify({"ok": True})

if __name__ == "__main__":
    raise SystemExit("This is a non-executable code preview. See monucloud.com for the live app.")

