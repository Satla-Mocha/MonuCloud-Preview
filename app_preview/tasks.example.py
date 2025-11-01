# ─────────────────────────────────────────────────────────────────────────────
# MonuCloud – Code Preview (Non-Executable)
# Celery task skeleton matching the real orchestration, without internals.
# Live product: https://monucloud.com
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Iterable, Optional

# In production these are real imports
# from celery_app import celery
# from apps.web.app import _t, create_app
# from apps.web.models import db
# from packages.cspm_core.DB import get_session
# from packages.cspm_core import Store

# Public preview scanner facade
from Scanner import get_session_for_account, run_account_scan, get_tool_version  # type: ignore


def NOW() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


STALE_AFTER = timedelta(minutes=30)


# @celery.task(name="tasks.run_full_scan", max_retries=3, default_retry_delay=10, autoretry_for=(Exception,))
def run_full_scan(account_id: str = "ALL", scope: str = "FULL") -> int:
    """
    Preview of your periodic/manual scan entrypoint.

    Production responsibilities (redacted):
      1) Close stale RUNNING scans.
      2) Insert new row into scans table (status=RUNNING, tool_version, notes=scope).
      3) Enqueue per-account jobs OR run inline for a single account.
    """
    # Redacted: app = create_app(); with app.app_context(): ...
    # Redacted: t_scans = _t("scans"); db.session.execute(...); db.session.commit()
    job_id = 0  # placeholder PK from scans.insert(...)
    # Redacted: If account_id == "ALL": enqueue run_full_scan_for_job for each connected account.
    # Else: directly call run_full_scan_for_job(job_id, account_id)
    return job_id


# @celery.task(name="tasks.run_full_scan_for_job", max_retries=3, default_retry_delay=5, rate_limit="12/m")
def run_full_scan_for_job(job_id: int, account_id: str, scope: str = "FULL") -> int:
    """
    Preview of the worker that performs the actual scan.

    Production responsibilities (redacted):
      - Look up regions for the account (or use defaults).
      - Build AWS session via AssumeRole + ExternalId.
      - Stream findings into the store (upsert); mark missing as resolved.
      - Update scan row status to SUCCESS/ERROR.
    """
    # Example preview behavior
    regions: Iterable[str] = ("eu-north-1", "us-east-1")

    # Build session (preview: base env session)
    session = get_session_for_account(account_id, region=None)

    # Run the subset of public rules and collect results
    open_count, seen = run_account_scan(
        session=session,
        account_id=account_id,
        regions=regions,
        scan_id=job_id,
        scope=scope,
        cloud="AWS",
    )

    # Redacted: persist open_count totals into scans.totals; mark SUCCESS
    return job_id


# @celery.on_after_finalize.connect
def setup_periodic_tasks(sender, **kwargs) -> None:  # pragma: no cover
    """
    In production: register beat schedules, e.g. hourly full scan.
    """
    # sender.add_periodic_task(
    #     crontab(minute=0),
    #     run_full_scan.s("ALL", "FULL"),
    #     name="hourly-full-scan",
    # )
    return


if __name__ == "__main__":
    raise SystemExit("This is a non-executable preview file. See https://monucloud.com")
