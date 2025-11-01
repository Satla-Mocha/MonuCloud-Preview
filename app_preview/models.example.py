# ─────────────────────────────────────────────────────────────────────────────
# MonuCloud – Code Preview (Non-Executable)
# This file is intentionally curated for public preview. It is NOT your prod schema.
# See the live app at https://monucloud.com
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

from datetime import date, datetime
from typing import Optional

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Date, DateTime, Enum, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

db = SQLAlchemy()

# ----------------------------
# Users & Accounts
# ----------------------------

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # One user can connect many AWS accounts
    accounts: Mapped[list["AwsAccount"]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan",
        lazy=True,
    )

    # Helper methods typically live here 


class AwsAccount(db.Model):
    """
    Connected AWS account for a user. Stores cross-account role + External ID.
    NOTE: __tablename__ intentionally matches FindingSnapshot's historical FK.
    """
    __tablename__ = "aws_account"

    id: Mapped[int] = mapped_column(primary_key=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Optional human-friendly alias shown in UI (e.g., "dev", "prod")
    account_alias: Mapped[str] = mapped_column(String(128), nullable=False, default="My AWS")

    # Cross-account auth (read-only role) + External ID
    role_arn: Mapped[str] = mapped_column(String(512), nullable=False)
    external_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    account_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)  # 12-digit AWS ID
    default_region: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Demo tagging lets you safely load/purge preview data
    is_demo: Mapped[bool] = mapped_column(default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    owner: Mapped["User"] = relationship(back_populates="accounts")
    snapshots: Mapped[list["FindingSnapshot"]] = relationship(
        back_populates="account",
        cascade="all, delete-orphan",
        lazy=True,
    )


# ----------------------------
# Rule catalog & findings
# ----------------------------

class Rule(db.Model):
    """
    Public rule catalog entry (subset shown in README). The actual rule logic lives
    in scanner modules; this is metadata for UI, severity, and enabling.
    """
    __tablename__ = "rules"

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g., "AWS-001"
    service: Mapped[str] = mapped_column(String(64), nullable=False)    # EC2, S3, IAM, ...
    severity: Mapped[str] = mapped_column(
        Enum("Critical", "High", "Medium", "Low", name="severity_enum"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)


class Resource(db.Model):
    """
    Optional resource inventory for linking findings to concrete assets.
    """
    __tablename__ = "resources"

    resource_pk: Mapped[int] = mapped_column(primary_key=True)
    account_pk: Mapped[int] = mapped_column(ForeignKey("aws_account.id", ondelete="CASCADE"), index=True)
    cloud: Mapped[str] = mapped_column(String(16), nullable=False, default="AWS")
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g., "ec2:security-group"
    resource_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    region: Mapped[Optional[str]] = mapped_column(String(64))
    properties = mapped_column(db.JSON, nullable=True)  # JSONB in Postgres (db.JSON is ORM-agnostic)

    is_demo: Mapped[bool] = mapped_column(default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint("account_pk", "resource_type", "resource_id", "region", name="uq_resource_identity"),
    )


class Finding(db.Model):
    """
    Current-state finding (deduplicated). Time-series lives in FindingSnapshot.
    Idempotency is provided by a unique key (rule_id, account_pk, resource_id, region).
    """
    __tablename__ = "findings"

    finding_id: Mapped[int] = mapped_column(primary_key=True)  # in prod you may prefer UUIDs
    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.rule_id", ondelete="RESTRICT"), index=True)
    account_pk: Mapped[int] = mapped_column(ForeignKey("aws_account.id", ondelete="CASCADE"), index=True)

    cloud: Mapped[str] = mapped_column(String(16), nullable=False, default="AWS")
    resource_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    region: Mapped[Optional[str]] = mapped_column(String(64))

    severity: Mapped[str] = mapped_column(
        Enum("Critical", "High", "Medium", "Low", name="severity_enum"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence = mapped_column(db.JSON, nullable=True)  # service-specific evidence (ports, policy snippet, etc.)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    status: Mapped[str] = mapped_column(
        Enum("OPEN", "RESOLVED", "SUPPRESSED", name="finding_status_enum"), nullable=False, default="OPEN"
    )

    is_demo: Mapped[bool] = mapped_column(default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint("rule_id", "account_pk", "resource_id", "region", name="uq_finding_identity"),
    )


class FindingSnapshot(db.Model):
    """
    Daily rollup per (account, rule_id). Used to draw time-series charts efficiently.
    Insert one row per rule per day with open_count (and optional suppressed_count).
    """
    __tablename__ = "finding_snapshot"

    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("aws_account.id", ondelete="CASCADE"), nullable=False)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    open_count: Mapped[int] = mapped_column(nullable=False, default=0)
    suppressed_count: Mapped[int] = mapped_column(nullable=False, default=0)

    account: Mapped["AwsAccount"] = relationship(back_populates="snapshots")

    __table_args__ = (
        UniqueConstraint("account_id", "snapshot_date", "rule_id", name="uq_snap_unique"),
    )

    @staticmethod
    def upsert(account_id: int, when: date, rule_id: str, open_count: int, suppressed_count: int = 0) -> "FindingSnapshot":
        """
        Simplified preview upsert for the README; prod version may use ON CONFLICT.
        """
        rec = FindingSnapshot.query.filter_by(
            account_id=account_id, snapshot_date=when, rule_id=rule_id
        ).one_or_none()
        if rec is None:
            rec = FindingSnapshot(
                account_id=account_id,
                snapshot_date=when,
                rule_id=rule_id,
                open_count=open_count,
                suppressed_count=suppressed_count,
            )
            db.session.add(rec)
        else:
            rec.open_count = open_count
            rec.suppressed_count = suppressed_count
        return rec


# ----------------------------
# Scan jobs & audit trail
# ----------------------------

class Scan(db.Model):
    """
    Records each scan execution (manual or scheduled).
    """
    __tablename__ = "scans"

    scan_id: Mapped[int] = mapped_column(primary_key=True)
    account_pk: Mapped[Optional[int]] = mapped_column(ForeignKey("aws_account.id", ondelete="SET NULL"), index=True)
    cloud: Mapped[str] = mapped_column(String(16), nullable=False, default="AWS")

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    status: Mapped[str] = mapped_column(
        Enum("RUNNING", "SUCCESS", "FAILED", name="scan_status_enum"), nullable=False, default="RUNNING"
    )
    tool_version: Mapped[Optional[str]] = mapped_column(String(32))
    notes: Mapped[Optional[str]] = mapped_column(Text)

    totals = mapped_column(db.JSON, nullable=True)  # {"total":12,"critical":1,"high":4,"medium":5,"low":2}

    is_demo: Mapped[bool] = mapped_column(default=False, nullable=False)


class RemediationLog(db.Model):
    """
    Preview of automated remediation tracking (kept minimal/safe).
    """
    __tablename__ = "remediation_actions"

    action_id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.finding_id", ondelete="CASCADE"), index=True)
    action_type: Mapped[str] = mapped_column(
        Enum("DRY_RUN", "AUTO", "FIX", name="remediation_action_type_enum"),
        nullable=False,
        default="DRY_RUN",
    )
    status: Mapped[str] = mapped_column(
        Enum("PENDING", "SUCCESS", "FAILED", name="remediation_status_enum"),
        nullable=False,
        default="PENDING",
    )
    details = mapped_column(db.JSON, nullable=True)  # request/response, diff, etc.
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Guardrail for previews/demos
    is_demo: Mapped[bool] = mapped_column(default=False, nullable=False)