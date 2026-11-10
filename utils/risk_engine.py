"""
utils/risk_engine.py
---------------------
Feature 4: Risk Score Engine.

Every meaningful action produces a RiskScore entry. The user's
`live_risk_score` (shown on dashboards in real time) is the running
sum of all their RiskScore points. This module is intentionally kept
separate from detection.py: risk_engine.py only ASSIGNS points,
detection.py decides whether a PATTERN of actions should raise an Alert.
"""

from datetime import datetime
from flask import current_app
from extensions import db
from models import RiskScore, User


def award_points(user: User, reason: str, points: int = None):
    """
    Create a RiskScore record for `user` and bump their live_risk_score.

    :param reason: short machine key, e.g. 'login_success', 'failed_login',
                    'view_customer', 'bulk_view', 'export', 'delete_customer',
                    'unauthorized_access', 'off_hours_login', 'edit_customer', 'logout'
    :param points: override the configured point value if given
    """
    cfg = current_app.config["RISK_POINTS"]
    if points is None:
        points = cfg.get(reason, 0)

    entry = RiskScore(user_id=user.id, points=points, reason=reason,
                       timestamp=datetime.utcnow())
    db.session.add(entry)

    user.live_risk_score = (user.live_risk_score or 0) + points

    # Flag the user as suspicious once they cross the "High" threshold
    high_threshold = current_app.config["RISK_LEVEL_HIGH"]
    if user.live_risk_score >= high_threshold:
        user.is_suspicious = True

    db.session.commit()
    return entry


def get_live_score(user: User) -> int:
    """Return the current cumulative risk score for a user."""
    return user.live_risk_score or 0


def reset_score(user: User):
    """Admin utility: reset a user's live risk score back to 0 (e.g. after review)."""
    user.live_risk_score = 0
    user.is_suspicious = False
    db.session.commit()


# Human-readable labels for each machine-readable RiskScore reason, used
# on the User Investigation page.
REASON_LABELS = {
    "login_success": "Successful Login",
    "logout": "Logout",
    "view_customer": "Customer Record Viewed",
    "edit_customer": "Customer Record Edited",
    "failed_login": "Failed Login Attempt",
    "failed_login_pattern": "Multiple Failed Logins",
    "off_hours_login": "Off-Hours Login",
    "excessive_viewing": "Excessive Customer Viewing",
    "multiple_deletes": "Multiple Customer Deletions",
    "bulk_export": "Bulk Data Export",
    "unauthorized_access": "Unauthorized Access Attempt",
    # Privileged / admin insider-threat rules
    "role_change": "Privilege Escalation (Role Change to Admin)",
    "multiple_privilege_changes": "Multiple Privilege Changes",
    "create_admin_account": "New Privileged Account Created",
    "mass_account_modification": "Mass Account Modification",
    "off_hours_admin_action": "Off-Hours Administrative Action",
    "rapid_alert_resolution": "Suspicious Alert Manipulation",
    "audit_tampering_attempt": "Audit Tampering Attempt",
}

# The subset of reasons that represent an actual RULE VIOLATION (as
# opposed to routine baseline activity). Used to explain *why* a user's
# risk score is what it is.
VIOLATION_REASONS = {
    "failed_login_pattern", "off_hours_login", "excessive_viewing",
    "multiple_deletes", "bulk_export", "unauthorized_access",
    "role_change", "multiple_privilege_changes", "create_admin_account",
    "mass_account_modification", "off_hours_admin_action",
    "rapid_alert_resolution", "audit_tampering_attempt",
}


def get_risk_reasons(user: User):
    """
    Summarize why a user has the risk score they do: group their
    RiskScore history by reason, keeping only rule-violation reasons,
    and return them ordered by total points contributed (highest first).
    Used by the Investigate User page.
    """
    from models import RiskScore
    rows = (db.session.query(RiskScore.reason, db.func.sum(RiskScore.points),
                              db.func.count(RiskScore.id))
            .filter(RiskScore.user_id == user.id,
                    RiskScore.reason.in_(VIOLATION_REASONS))
            .group_by(RiskScore.reason)
            .order_by(db.func.sum(RiskScore.points).desc())
            .all())
    return [
        {"reason": reason, "label": REASON_LABELS.get(reason, reason),
         "total_points": int(total or 0), "occurrences": count}
        for reason, total, count in rows
    ]
