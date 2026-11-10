"""
utils/detection.py
--------------------
Rule-Based Insider Threat Detection + Alert System.

Every time a new activity is logged, this module inspects the recent
window of ActivityLog rows for that user against a fixed set of
security rules. When a rule threshold is crossed it:

  1. Awards the risk points defined for that rule (utils.risk_engine),
     so the score shown on screen always matches the reason for it.
  2. Raises an Alert — unless a similar unresolved alert for the same
     user was already raised recently (duplicate-alert prevention).

Rules implemented:
  - Multiple failed login attempts        -> +30
  - Login outside office hours            -> +15
  - Excessive customer viewing (1 minute) -> +20
  - Multiple customer deletions           -> +50
  - Bulk data export                      -> +40
  - Unauthorized / suspicious access      -> +80
"""

from datetime import datetime, timedelta
from flask import current_app, request
from extensions import db
from models import ActivityLog, Alert, AuditEvent
from utils.risk_engine import award_points
from utils.incidents import correlate_and_create_incident


def _duplicate_alert_exists(user, alert_type):
    """
    Duplicate-alert prevention: if an unresolved alert of the same type
    was already raised for this user within the configured dedupe
    window, skip creating another one (and skip re-awarding points).
    """
    cfg = current_app.config
    window_start = datetime.utcnow() - timedelta(minutes=cfg["ALERT_DEDUPE_WINDOW_MIN"])
    existing = Alert.query.filter(
        Alert.user_id == user.id,
        Alert.alert_type == alert_type,
        Alert.resolved.is_(False),
        Alert.timestamp >= window_start,
    ).first()
    return existing is not None


def _raise_alert(user, alert_type, level, message, reason=None):
    """
    Create an Alert for a detected rule violation, awarding the matching
    risk points at the same time so score and alert never disagree.
    Returns the Alert if one was created, or None if suppressed as a
    duplicate.
    """
    if _duplicate_alert_exists(user, alert_type):
        return None

    if reason:
        award_points(user, reason)

    alert = Alert(user_id=user.id, alert_type=alert_type, level=level,
                   message=message, timestamp=datetime.utcnow())
    db.session.add(alert)
    db.session.commit()

    # Feature 5/6: try to correlate this new alert (plus any other recent
    # unresolved ones for this user) into a Security Incident.
    correlate_and_create_incident(user)

    return alert


def check_excessive_views(user):
    """Rule: excessive customer viewing within a 1-minute window -> +20."""
    cfg = current_app.config
    window_start = datetime.utcnow() - timedelta(minutes=1)
    count = ActivityLog.query.filter(
        ActivityLog.user_id == user.id,
        ActivityLog.action == "view_customer",
        ActivityLog.timestamp >= window_start,
    ).count()

    if count >= cfg["MAX_VIEWS_PER_MINUTE"]:
        return _raise_alert(
            user, "Excessive Record Viewing", "Medium",
            f"{user.username} viewed {count} customer records within 1 minute.",
            reason="excessive_viewing",
        )
    return None


def check_failed_logins(user):
    """Rule: multiple failed login attempts -> +30."""
    cfg = current_app.config
    window_start = datetime.utcnow() - timedelta(minutes=cfg["FAILED_LOGIN_WINDOW_MIN"])
    count = ActivityLog.query.filter(
        ActivityLog.user_id == user.id,
        ActivityLog.action == "failed_login",
        ActivityLog.timestamp >= window_start,
    ).count()

    if count >= cfg["MAX_FAILED_LOGINS"]:
        _raise_alert(
            user, "Multiple Failed Logins", "High",
            f"{count} failed login attempts for '{user.username}' "
            f"within {cfg['FAILED_LOGIN_WINDOW_MIN']} minutes.",
            reason="failed_login_pattern",
        )
    return count


def is_account_locked(user):
    """
    Temporary login restriction: if the failed-login rule threshold has
    been crossed very recently, block further login attempts for a
    short cooldown window (derived from real ActivityLog data, no extra
    DB column required).
    """
    cfg = current_app.config
    window_start = datetime.utcnow() - timedelta(minutes=cfg["ACCOUNT_LOCK_WINDOW_MIN"])
    count = ActivityLog.query.filter(
        ActivityLog.user_id == user.id,
        ActivityLog.action == "failed_login",
        ActivityLog.timestamp >= window_start,
    ).count()
    return count >= cfg["ACCOUNT_LOCK_THRESHOLD"]


def check_office_hours(user):
    """Rule: login outside configured office hours -> +15."""
    cfg = current_app.config
    now = datetime.now()
    if now.hour < cfg["OFFICE_HOUR_START"] or now.hour >= cfg["OFFICE_HOUR_END"]:
        _raise_alert(
            user, "Off-Hours Login", "Low",
            f"{user.username} logged in at {now.strftime('%H:%M')}, "
            f"outside office hours ({cfg['OFFICE_HOUR_START']}:00-{cfg['OFFICE_HOUR_END']}:00).",
            reason="off_hours_login",
        )
        return True
    return False


def check_multiple_deletes(user):
    """Rule: multiple customer deletions in a short window -> +50."""
    cfg = current_app.config
    window_start = datetime.utcnow() - timedelta(minutes=cfg["DELETE_WINDOW_MIN"])
    count = ActivityLog.query.filter(
        ActivityLog.user_id == user.id,
        ActivityLog.action == "delete_customer",
        ActivityLog.timestamp >= window_start,
    ).count()

    if count >= cfg["MAX_DELETES_PER_WINDOW"]:
        _raise_alert(
            user, "Multiple Delete Operations", "Critical",
            f"{user.username} deleted {count} customer records within "
            f"{cfg['DELETE_WINDOW_MIN']} minutes.",
            reason="multiple_deletes",
        )
    return count


def check_bulk_export(user, row_count):
    """Rule: bulk export of customer data -> +40."""
    cfg = current_app.config
    if row_count >= cfg["BULK_EXPORT_ROW_THRESHOLD"]:
        # Security-sensitive: also record it in the tamper-evident audit chain
        from utils.audit import log_audit_event
        log_audit_event(user, "BULK_EXPORT", target_type="customer",
                        details=f"{user.username} exported {row_count} customer records.",
                        risk_level="HIGH")
        _raise_alert(
            user, "Bulk Data Export", "High",
            f"{user.username} exported {row_count} customer records in a single export.",
            reason="bulk_export",
        )
        return True
    return False


def flag_unauthorized_access(user, resource):
    """Rule: unauthorized/suspicious access to a restricted resource -> +80."""
    _raise_alert(
        user, "Unauthorized Access Attempt", "Critical",
        f"{user.username} attempted to access restricted resource: {resource}.",
        reason="unauthorized_access",
    )


# ==========================================================================
# PRIVILEGED USER RULE ENGINE (Feature 2)
# "Privileges determine what a user is allowed to do, but privileges do
# not make the user's activity invisible to security monitoring."
# Every function below applies EQUALLY to any user who holds admin
# privileges — including the account currently signed in as admin.
# ==========================================================================

def check_role_change(admin_user, target_user, new_role):
    """Rule 1 — Privilege escalation: an admin promotes a user to ADMIN -> +30 High."""
    if new_role == "admin":
        _raise_alert(
            admin_user, "Privilege Escalation", "High",
            f"{admin_user.username} changed {target_user.username}'s role to ADMIN.",
            reason="role_change",
        )
    check_multiple_privilege_changes(admin_user)


def check_multiple_privilege_changes(admin_user):
    """Rule 2 — Several role changes by the same admin in a short window -> +40 High."""
    cfg = current_app.config
    window_start = datetime.utcnow() - timedelta(minutes=cfg["PRIVILEGE_CHANGE_WINDOW_MIN"])
    count = AuditEvent.query.filter(
        AuditEvent.user_id == admin_user.id,
        AuditEvent.action == "ROLE_CHANGE",
        AuditEvent.timestamp >= window_start,
    ).count()
    if count >= cfg["MAX_PRIVILEGE_CHANGES"]:
        _raise_alert(
            admin_user, "Multiple Privilege Changes", "High",
            f"{admin_user.username} changed {count} user roles within "
            f"{cfg['PRIVILEGE_CHANGE_WINDOW_MIN']} minutes.",
            reason="multiple_privilege_changes",
        )


def check_new_admin_account(admin_user):
    """Rule 3 — An admin directly creates another admin account -> +50 Critical."""
    _raise_alert(
        admin_user, "New Privileged Account Created", "Critical",
        f"{admin_user.username} created a new administrator account.",
        reason="create_admin_account",
    )
    check_mass_account_modification(admin_user)


def check_mass_account_modification(admin_user):
    """Rule 4 — Many accounts touched (create/suspend/activate/role-change)
    by the same admin in a short window -> +40 High."""
    cfg = current_app.config
    window_start = datetime.utcnow() - timedelta(minutes=cfg["MASS_MODIFICATION_WINDOW_MIN"])
    count = AuditEvent.query.filter(
        AuditEvent.user_id == admin_user.id,
        AuditEvent.action.in_(cfg["ACCOUNT_MODIFYING_ACTIONS"]),
        AuditEvent.timestamp >= window_start,
    ).count()
    if count >= cfg["MAX_ACCOUNT_MODIFICATIONS"]:
        _raise_alert(
            admin_user, "Mass Account Modification", "High",
            f"{admin_user.username} modified {count} accounts within "
            f"{cfg['MASS_MODIFICATION_WINDOW_MIN']} minutes.",
            reason="mass_account_modification",
        )


def check_admin_off_hours(admin_user, action_label):
    """Rule 5 — Sensitive administrative action performed outside office
    hours -> +20 Medium."""
    cfg = current_app.config
    now = datetime.now()
    if now.hour < cfg["OFFICE_HOUR_START"] or now.hour >= cfg["OFFICE_HOUR_END"]:
        _raise_alert(
            admin_user, "Off-Hours Administrative Action", "Medium",
            f"{admin_user.username} performed '{action_label}' at "
            f"{now.strftime('%H:%M')}, outside office hours.",
            reason="off_hours_admin_action",
        )
        return True
    return False


def check_rapid_alert_resolution(admin_user):
    """Rule 7 — Suspicious alert manipulation: an admin resolves several
    alerts unusually fast (could be covering their tracks) -> +40 High."""
    cfg = current_app.config
    window_start = datetime.utcnow() - timedelta(minutes=cfg["RAPID_ALERT_RESOLUTION_WINDOW_MIN"])
    count = AuditEvent.query.filter(
        AuditEvent.user_id == admin_user.id,
        AuditEvent.action == "ALERT_RESOLVE",
        AuditEvent.timestamp >= window_start,
    ).count()
    if count >= cfg["MAX_ALERTS_RESOLVED_RAPIDLY"]:
        _raise_alert(
            admin_user, "Suspicious Alert Manipulation", "High",
            f"{admin_user.username} resolved {count} alerts within "
            f"{cfg['RAPID_ALERT_RESOLUTION_WINDOW_MIN']} minutes.",
            reason="rapid_alert_resolution",
        )


def flag_audit_tampering_attempt(admin_user, event_id):
    """Rule 8 — Attempted modification/deletion of audit evidence -> +50
    Critical. The route that calls this NEVER actually performs the
    deletion — evidence is never silently destroyed. `event_id` may be None
    when the attempt targets the whole trail (e.g. "clear all")."""
    event_id = event_id if event_id is not None else "ALL"
    _raise_alert(
        admin_user, "Audit Tampering Attempt", "Critical",
        f"{admin_user.username} attempted to modify/delete audit event {'#' if str(event_id).isdigit() else ''}{event_id}.",
        reason="audit_tampering_attempt",
    )
