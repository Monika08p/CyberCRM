"""
utils/helpers.py
------------------
Single entry point `log_activity()` used throughout the app. Every route
that performs a monitored action calls this function, which:

  1. Writes an ActivityLog row (activity monitoring)
  2. Awards baseline risk points via risk_engine (rule-based scoring)
  3. Runs relevant pattern checks via detection.py, which raises Alerts
     and awards additional rule-violation points when a threshold is
     crossed.

Keeping this logic in one place guarantees no action is logged without
also being scored and screened for insider-threat patterns.
"""

from datetime import datetime
from flask import request
from extensions import db
from models import ActivityLog
from utils import risk_engine, detection


def log_activity(user, action, target_type=None, target_id=None, details=None):
    """
    Record an activity, score it, and run pattern-based threat detection.

    :param action: one of 'login', 'failed_login', 'logout', 'view_customer',
                    'create_customer', 'edit_customer', 'delete_customer', 'export_data'
    """
    entry = ActivityLog(
        user_id=user.id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
        ip_address=request.remote_addr if request else None,
        timestamp=datetime.utcnow(),
    )
    db.session.add(entry)
    db.session.commit()

    # ---- Risk scoring (base points per action) ----
    action_to_reason = {
        "login": "login_success",
        "failed_login": "failed_login",
        "logout": "logout",
        "view_customer": "view_customer",
        "create_customer": "edit_customer",   # same baseline points as an edit
        "edit_customer": "edit_customer",
        "delete_customer": "delete_customer",
        "export_data": "export",
    }
    reason = action_to_reason.get(action)
    if reason:
        risk_engine.award_points(user, reason)

    # ---- Pattern-based insider threat detection ----
    if action == "view_customer":
        detection.check_excessive_views(user)
    elif action == "failed_login":
        detection.check_failed_logins(user)
    elif action == "delete_customer":
        detection.check_multiple_deletes(user)

    return entry
