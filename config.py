"""
config.py
---------
Central configuration for CyberCRM Guardian.
Holds every threshold and point value used by the Rule-Based Risk Engine
and Insider Threat Detection module, so the whole security policy can be
tuned from a single place.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # --- Flask / Security core ---
    SECRET_KEY = os.environ.get("SECRET_KEY", "cybercrm-guardian-dev-secret-key")
    # DATABASE_URL can point at a different SQLite file (used by the test
    # script so it never touches the real development database).
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "instance", "cybercrm.db"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ==================================================================
    # AUDIT RETENTION & ARCHIVE
    # ==================================================================
    # How long audit evidence must be kept. In this academic version NOTHING
    # is auto-deleted when the period passes; the value is shown on the Audit
    # Integrity page (set AUDIT_RETENTION_DAYS=60 to demo a shorter policy).
    AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "365"))

    # Separate, append-only archive of every audit event (JSON Lines), kept
    # OUTSIDE instance/cybercrm.db so the evidence survives if the DB is lost.
    # In production point this at protected / WORM storage (see README).
    AUDIT_BACKUP_DIR = os.environ.get(
        "AUDIT_BACKUP_DIR", os.path.join(BASE_DIR, "audit_backups"))

    # --- Office hours (24h clock) used for "login outside office hours" detection ---
    OFFICE_HOUR_START = 9   # 9 AM
    OFFICE_HOUR_END = 18    # 6 PM

    # ==================================================================
    # RULE-BASED RISK ENGINE — point values
    # ==================================================================
    # Two categories, kept intentionally separate so the scoring logic
    # never conflicts between files:
    #
    #  1) BASELINE points — small values awarded for routine, everyday
    #     actions. They accumulate over time but do not, by themselves,
    #     raise a security alert.
    #
    #  2) RULE VIOLATION points — the points explicitly attached to a
    #     detected suspicious PATTERN. These are the values that are
    #     also shown next to the Alert that gets raised, so the score
    #     and the alert always agree with each other.
    RISK_POINTS = {
        # --- Baseline / routine activity ---
        "login_success": 5,
        "logout": 1,
        "view_customer": 1,
        "edit_customer": 3,
        "failed_login": 5,        # per single failed attempt
        "delete_customer": 8,     # baseline points for a single delete
        "export": 5,              # baseline points for a single export

        # --- Rule violations (each one also raises a matching Alert) ---
        "failed_login_pattern": 30,   # Multiple failed login attempts
        "off_hours_login": 15,        # Login outside office hours
        "excessive_viewing": 20,      # Excessive customer viewing in a short period
        "multiple_deletes": 50,       # Multiple customer deletions
        "bulk_export": 40,            # Bulk data export
        "unauthorized_access": 80,    # Unauthorized / suspicious access

        # --- Privileged / admin insider-threat rules (Feature 2) ---
        "role_change": 30,                  # Rule 1: promote a user to ADMIN
        "multiple_privilege_changes": 40,   # Rule 2: several role changes in a short time
        "create_admin_account": 50,         # Rule 3: brand-new admin account created
        "mass_account_modification": 40,    # Rule 4: many accounts touched quickly
        "off_hours_admin_action": 20,       # Rule 5: sensitive admin op outside office hours
        "rapid_alert_resolution": 40,       # Rule 7: alerts resolved suspiciously fast
        "audit_tampering_attempt": 50,      # Rule 8: attempted to alter audit evidence
    }

    # ==================================================================
    # INSIDER THREAT DETECTION — rule thresholds
    # ==================================================================
    MAX_VIEWS_PER_MINUTE = 10        # "excessive customer viewing"
    MAX_FAILED_LOGINS = 3            # within FAILED_LOGIN_WINDOW_MIN minutes
    FAILED_LOGIN_WINDOW_MIN = 10
    MAX_DELETES_PER_WINDOW = 3       # "multiple delete operations"
    DELETE_WINDOW_MIN = 15
    BULK_EXPORT_ROW_THRESHOLD = 20   # rows exported at once counts as "bulk"

    # Temporary login restriction after repeated failed attempts.
    ACCOUNT_LOCK_THRESHOLD = 5
    ACCOUNT_LOCK_WINDOW_MIN = 10

    # How long (minutes) an unresolved alert of the same type for the same
    # user suppresses a duplicate alert from being created again.
    ALERT_DEDUPE_WINDOW_MIN = 30

    # ==================================================================
    # PRIVILEGED USER RULE ENGINE (Feature 2) — thresholds
    # ==================================================================
    PRIVILEGE_CHANGE_WINDOW_MIN = 30     # window for "multiple privilege changes"
    MAX_PRIVILEGE_CHANGES = 2            # 2+ role changes by the same admin -> alert

    MASS_MODIFICATION_WINDOW_MIN = 15    # window for "mass account modification"
    MAX_ACCOUNT_MODIFICATIONS = 4        # 4+ account-touching actions -> alert

    RAPID_ALERT_RESOLUTION_WINDOW_MIN = 5
    MAX_ALERTS_RESOLVED_RAPIDLY = 3      # 3+ alerts resolved within the window -> alert

    # ==================================================================
    # EVENT CORRELATION / INCIDENT MANAGEMENT (Feature 5 & 6)
    # ==================================================================
    CORRELATION_WINDOW_MIN = 60          # look-back window to group alerts
    INCIDENT_ALERT_THRESHOLD = 2         # 2+ unresolved alerts in the window -> incident

    # Actions considered "account-touching" for mass-modification detection
    # and for the Privileged Activity feed.
    PRIVILEGED_ACTIONS = (
        "LOGIN", "LOGOUT", "ROLE_CHANGE", "USER_CREATE", "ACCOUNT_SUSPEND",
        "ACCOUNT_ACTIVATE", "ALERT_RESOLVE", "SESSION_REVOKE",
        "PRIVILEGE_REVOKED", "AUDIT_TAMPER_ATTEMPT", "INCIDENT_STATUS_CHANGE",
        "APPROVAL_REQUEST", "APPROVAL_DECISION", "BULK_EXPORT",
    )
    ACCOUNT_MODIFYING_ACTIONS = (
        "ROLE_CHANGE", "USER_CREATE", "ACCOUNT_SUSPEND", "ACCOUNT_ACTIVATE",
        "PRIVILEGE_REVOKED",
    )

    # --- Risk level thresholds based on cumulative live risk score ---
    # 0-30 Low, 31-60 Medium, 61-80 High, 81+ Critical (Feature 9)
    RISK_LEVEL_LOW = 31
    RISK_LEVEL_MEDIUM = 61
    RISK_LEVEL_HIGH = 81

    # --- Customer form validation ---
    CUSTOMER_MAX_LEN = {
        "name": 120,
        "email": 120,
        "phone": 30,
        "company": 120,
        "address": 255,
        "notes": 2000,
    }
