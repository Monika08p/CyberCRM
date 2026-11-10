"""
models.py
---------
SQLAlchemy ORM models for the 5 core tables:
  Users, Customers, ActivityLogs, Alerts, RiskScores
"""

from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db


class User(db.Model, UserMixin):
    """Employee / Admin accounts with Role-Based Access Control."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="employee")  # 'admin' or 'employee'
    is_active_account = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # Live cumulative risk score shown on dashboards (Feature 4: "Display live risk score")
    live_risk_score = db.Column(db.Integer, default=0)
    is_suspicious = db.Column(db.Boolean, default=False)

    # Bumped whenever an admin "revokes" this user's active session(s).
    # The login session stores the value seen at login time; a mismatch
    # on any later request forces an automatic logout (see app.py).
    session_version = db.Column(db.Integer, default=0)

    # Relationships
    logs = db.relationship("ActivityLog", backref="user", lazy="dynamic",
                            cascade="all, delete-orphan")
    alerts = db.relationship("Alert", backref="user", lazy="dynamic",
                              cascade="all, delete-orphan")
    risk_scores = db.relationship("RiskScore", backref="user", lazy="dynamic",
                                   cascade="all, delete-orphan")

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    def is_admin(self):
        return self.role == "admin"

    def risk_level(self):
        """Translate the live cumulative score into a human alert level."""
        from flask import current_app
        cfg = current_app.config
        score = self.live_risk_score
        if score >= cfg["RISK_LEVEL_HIGH"]:
            return "Critical"
        elif score >= cfg["RISK_LEVEL_MEDIUM"]:
            return "High"
        elif score >= cfg["RISK_LEVEL_LOW"]:
            return "Medium"
        return "Low"

    def display_risk_score(self):
        """Risk score capped at 100 for on-screen gauges (Feature 9)."""
        return min(self.live_risk_score or 0, 100)

    def is_privileged(self):
        """A 'privileged user' for monitoring purposes = an admin account.
        Kept as its own method so a future privileged sub-role can hook
        in here without touching every call site."""
        return self.role == "admin"

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Customer(db.Model):
    """CRM customer records."""
    __tablename__ = "customers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    company = db.Column(db.String(120), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Customer {self.name}>"


class ActivityLog(db.Model):
    """Every user action is logged here (Feature 3: Activity Monitoring)."""
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    # e.g. login, logout, view_customer, edit_customer, delete_customer, export_data, failed_login
    target_type = db.Column(db.String(50), nullable=True)   # e.g. 'customer'
    target_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<ActivityLog {self.action} by user {self.user_id} @ {self.timestamp}>"


class Alert(db.Model):
    """Suspicious activity alerts (Feature 6: Alert System)."""
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    alert_type = db.Column(db.String(80), nullable=False)
    level = db.Column(db.String(20), nullable=False)  # Low, Medium, High, Critical
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    resolved = db.Column(db.Boolean, default=False)

    # Which SecurityIncident (if any) this alert has been correlated into.
    incident_id = db.Column(db.Integer, db.ForeignKey("security_incidents.id"), nullable=True)

    def __repr__(self):
        return f"<Alert {self.level}: {self.alert_type} (user {self.user_id})>"


class RiskScore(db.Model):
    """Historical risk-score events, used to compute live score & trend charts."""
    __tablename__ = "risk_scores"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    points = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<RiskScore +{self.points} ({self.reason}) user {self.user_id}>"


class AuditEvent(db.Model):
    """
    Tamper-Evident Audit Trail (SHA-256 hash chaining).

    Every security-sensitive / privileged action (role changes, account
    creation, suspensions, alert resolution, incident actions, approval
    decisions, etc.) is written here in addition to the normal
    ActivityLog. Each row's `current_hash` is SHA-256 of its own fields
    PLUS the previous row's `current_hash`, forming a chain:

        Event 1 -> Hash A
        Event 2 + Hash A -> Hash B
        Event 3 + Hash B -> Hash C  ...

    If any stored field of an old event is edited directly in the
    database, recomputing its hash will no longer match `current_hash`
    (and every later event's chain link breaks too) — see
    utils/audit.py:verify_audit_chain().
    """
    __tablename__ = "audit_events"
    # AUTOINCREMENT: ids are never reused, even if rows are lost, so a lost event's
    # id can never be handed to a different, newer event (which would clash with
    # the archived copy).
    __table_args__ = {"sqlite_autoincrement": True}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(60), nullable=False)
    # e.g. LOGIN, LOGOUT, ROLE_CHANGE, USER_CREATE, ACCOUNT_SUSPEND,
    # ACCOUNT_ACTIVATE, ALERT_RESOLVE, INCIDENT_STATUS_CHANGE,
    # SESSION_REVOKE, PRIVILEGE_REVOKED, AUDIT_TAMPER_ATTEMPT,
    # APPROVAL_REQUEST, APPROVAL_DECISION, BULK_EXPORT
    target_type = db.Column(db.String(50), nullable=True)
    target_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.String(255), nullable=True)
    risk_level = db.Column(db.String(20), default="INFO")  # INFO/LOW/MEDIUM/HIGH/CRITICAL
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    previous_hash = db.Column(db.String(64), nullable=False)
    current_hash = db.Column(db.String(64), nullable=False)

    actor = db.relationship("User", foreign_keys=[user_id])

    def __repr__(self):
        return f"<AuditEvent #{self.id} {self.action} by user {self.user_id}>"


class SecurityIncident(db.Model):
    """
    A Security Incident groups multiple correlated Alerts for the same
    user into a single case an admin can investigate and resolve
    (Feature 5/6: Event Correlation + Incident Management).
    """
    __tablename__ = "security_incidents"

    id = db.Column(db.Integer, primary_key=True)
    incident_code = db.Column(db.String(20), unique=True, nullable=True)  # e.g. INC-001
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # Low/Medium/High/Critical
    risk_score = db.Column(db.Integer, default=0)  # snapshot at creation time (capped at 100)
    status = db.Column(db.String(30), default="OPEN")
    # OPEN, UNDER_INVESTIGATION, CONTAINED, RESOLVED, FALSE_POSITIVE
    investigator_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    resolution_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    suspect = db.relationship("User", foreign_keys=[user_id])
    investigator = db.relationship("User", foreign_keys=[investigator_id])
    alerts = db.relationship("Alert", backref="incident", lazy="dynamic")

    def __repr__(self):
        return f"<SecurityIncident {self.incident_code} ({self.status})>"


class ApprovalRequest(db.Model):
    """
    Dual-authorization workflow for critical security actions (Feature 8).
    A requesting admin cannot also be the approver of their own request.
    """
    __tablename__ = "approval_requests"

    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50), nullable=False)  # e.g. SUSPEND_PRIVILEGED_ACCOUNT
    target_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    requested_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    decided_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    reason = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), default="PENDING")  # PENDING/APPROVED/REJECTED
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    decided_at = db.Column(db.DateTime, nullable=True)

    target_user = db.relationship("User", foreign_keys=[target_user_id])
    requested_by = db.relationship("User", foreign_keys=[requested_by_id])
    decided_by = db.relationship("User", foreign_keys=[decided_by_id])

    def __repr__(self):
        return f"<ApprovalRequest {self.action_type} -> user {self.target_user_id} ({self.status})>"


# ==========================================================================
# APPEND-ONLY PROTECTION FOR EVIDENCE TABLES
# ==========================================================================
# No application code - for ANY role, admins included - may UPDATE or DELETE
# an AuditEvent or an ActivityLog row. These listeners enforce that on the
# server side (not just by hiding buttons): any attempt through the ORM raises
# an error before it reaches the database, so the original evidence stays
# intact. This also stops the User -> ActivityLog "delete-orphan" cascade from
# silently wiping a user's activity history if a user is ever deleted.
# (Someone editing the .db file directly, outside the app, is not stopped by
# this - that is what the hash chain and the separate archive are for.)
from sqlalchemy import event as _sa_event
from sqlalchemy.orm import Session as _Session


class AuditImmutableError(Exception):
    """Raised when code tries to modify or delete an audit event."""


class ActivityLogImmutableError(AuditImmutableError):
    """Raised when code tries to modify or delete an activity-log row."""


_PROTECTED = {AuditEvent: AuditImmutableError, ActivityLog: ActivityLogImmutableError}


def _make_guard(error_cls, verb):
    def guard(mapper, connection, target):
        raise error_cls(f"{mapper.class_.__name__} records are append-only and cannot be {verb}.")
    return guard


for _model, _err in _PROTECTED.items():
    _sa_event.listen(_model, "before_update", _make_guard(_err, "modified"))
    _sa_event.listen(_model, "before_delete", _make_guard(_err, "deleted"))


@_sa_event.listens_for(_Session, "do_orm_execute")
def _block_bulk_evidence_changes(state):
    # Also catches bulk statements such as AuditEvent.query.delete()
    if state.is_update or state.is_delete:
        for mapper in state.all_mappers:
            if mapper.class_ in _PROTECTED:
                raise _PROTECTED[mapper.class_](
                    f"{mapper.class_.__name__} records are append-only; "
                    f"bulk update/delete is not allowed.")
