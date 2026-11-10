"""
routes/admin.py
-----------------
Admin Dashboard, User Management, Alerts, Activity Logs, and the
User Investigation workflow (Detect -> Alert -> Investigate -> Response).

Privileged-user monitoring lives here too: creating users, changing
roles, suspending/activating accounts, and resolving alerts are all
security-sensitive admin actions, so each one is written to the
tamper-evident AuditEvent chain (utils/audit.py) IN ADDITION to the
normal ActivityLog, and checked against the privileged-user rule
engine (utils/detection.py) — "privileges do not make the user's
activity invisible to security monitoring."
"""

from datetime import datetime, timedelta
from flask import (Blueprint, render_template, redirect, url_for, flash,
                    request, jsonify, current_app)
from flask_login import login_required, current_user

from extensions import db
from models import User, ActivityLog, Alert, RiskScore, Customer, ApprovalRequest
from utils.decorators import admin_required
from utils.risk_engine import reset_score, get_risk_reasons
from utils.audit import log_audit_event
from utils import detection

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# Activities considered inherently sensitive, shown in the "Recent
# Suspicious Activity" feed on the dashboard (real ActivityLog rows,
# not a separate/fake data source).
SUSPICIOUS_ACTIONS = ("failed_login", "delete_customer", "export_data")


def _is_ajax():
    return request.headers.get("X-Requested-With") == "XMLHttpRequest"


def _safe_redirect(default_endpoint, **default_kwargs):
    """Redirect back to a 'next' form field if it's a safe relative path,
    otherwise fall back to the given endpoint (used so actions triggered
    from the Investigate page return the admin to that same page)."""
    next_url = request.form.get("next")
    if next_url and next_url.startswith("/"):
        return redirect(next_url)
    return redirect(url_for(default_endpoint, **default_kwargs))


def _block_self_investigation():
    """Feature 7 — a privileged user must not be able to act on their
    own account's security response. Returns a Flask response if
    blocked, else None."""
    target_id = request.view_args.get("user_id")
    if target_id == current_user.id and current_user.is_admin():
        message = ("Self-investigation restricted: a privileged user cannot "
                   "independently take security action against their own account.")
        if _is_ajax():
            return jsonify(success=False, message=message), 403
        flash(message, "danger")
        return _safe_redirect("admin.users")
    return None


@admin_bp.route("/dashboard")
@login_required
@admin_required
def dashboard():
    from models import SecurityIncident
    from utils.audit import verify_audit_chain

    total_users = User.query.filter_by(role="employee").count()
    active_users = User.query.filter_by(role="employee", is_active_account=True).count()
    suspended_users = User.query.filter(User.is_active_account.is_(False)).count()
    total_alerts = Alert.query.filter_by(resolved=False).count()
    total_customers = Customer.query.count()
    privileged_users = User.query.filter_by(role="admin").count()

    all_accounts = User.query.all()
    high_critical_users = sum(1 for u in all_accounts if u.risk_level() in ("High", "Critical"))

    highest_risk_users = (User.query
                           .order_by(User.live_risk_score.desc())
                           .limit(5).all())

    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(8).all()
    recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    recent_suspicious = (ActivityLog.query.filter(ActivityLog.action.in_(SUSPICIOUS_ACTIONS))
                          .order_by(ActivityLog.timestamp.desc()).limit(8).all())

    critical_incidents = SecurityIncident.query.filter_by(severity="Critical").filter(
        SecurityIncident.status.in_(["OPEN", "UNDER_INVESTIGATION"])).count()
    recent_incidents = SecurityIncident.query.order_by(SecurityIncident.created_at.desc()).limit(5).all()

    # Privileged Activity feed — audit events performed by admin accounts
    privileged_activity = (ActivityLog.query.join(User, ActivityLog.user_id == User.id)
                            .filter(User.role == "admin")
                            .order_by(ActivityLog.timestamp.desc()).limit(6).all())

    from models import AuditEvent
    privileged_audit_feed = AuditEvent.query.order_by(AuditEvent.timestamp.desc()).limit(6).all()

    audit_summary = verify_audit_chain()

    # counts by alert level for the "Alert Statistics" chart
    alert_stats = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for level, count in (db.session.query(Alert.level, db.func.count(Alert.id))
                          .group_by(Alert.level).all()):
        alert_stats[level] = count

    # daily activity for the last 7 days
    daily_labels, daily_counts = [], []
    for i in range(6, -1, -1):
        day = datetime.utcnow().date() - timedelta(days=i)
        day_start = datetime.combine(day, datetime.min.time())
        day_end = day_start + timedelta(days=1)
        count = ActivityLog.query.filter(
            ActivityLog.timestamp >= day_start, ActivityLog.timestamp < day_end
        ).count()
        daily_labels.append(day.strftime("%b %d"))
        daily_counts.append(count)

    # --- Risk Overview: overall organization risk score + breakdown ---
    employees = User.query.filter_by(role="employee").all()
    if employees:
        overall_risk_score = round(
            sum(u.live_risk_score or 0 for u in employees) / len(employees)
        )
    else:
        overall_risk_score = 0

    risk_level_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for u in employees:
        risk_level_counts[u.risk_level()] = risk_level_counts.get(u.risk_level(), 0) + 1

    app_cfg = current_app.config
    if overall_risk_score >= app_cfg["RISK_LEVEL_HIGH"]:
        overall_risk_level = "Critical"
    elif overall_risk_score >= app_cfg["RISK_LEVEL_MEDIUM"]:
        overall_risk_level = "High"
    elif overall_risk_score >= app_cfg["RISK_LEVEL_LOW"]:
        overall_risk_level = "Medium"
    else:
        overall_risk_level = "Low"
    overall_risk_pct = min(100, round((overall_risk_score / max(app_cfg["RISK_LEVEL_HIGH"], 1)) * 100))

    # --- Risk trend: total risk points awarded per day, last 7 days ---
    risk_trend_labels, risk_trend_values = [], []
    for i in range(6, -1, -1):
        day = datetime.utcnow().date() - timedelta(days=i)
        day_start = datetime.combine(day, datetime.min.time())
        day_end = day_start + timedelta(days=1)
        total_points = db.session.query(db.func.sum(RiskScore.points)).filter(
            RiskScore.timestamp >= day_start, RiskScore.timestamp < day_end
        ).scalar() or 0
        risk_trend_labels.append(day.strftime("%b %d"))
        risk_trend_values.append(int(total_points))

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        active_users=active_users,
        suspended_users=suspended_users,
        high_critical_users=high_critical_users,
        total_alerts=total_alerts,
        total_customers=total_customers,
        privileged_users=privileged_users,
        critical_incidents=critical_incidents,
        recent_incidents=recent_incidents,
        privileged_activity=privileged_activity,
        privileged_audit_feed=privileged_audit_feed,
        audit_summary=audit_summary,
        highest_risk_users=highest_risk_users,
        recent_alerts=recent_alerts,
        recent_logs=recent_logs,
        recent_suspicious=recent_suspicious,
        alert_stats=alert_stats,
        daily_labels=daily_labels,
        daily_counts=daily_counts,
        overall_risk_score=overall_risk_score,
        overall_risk_level=overall_risk_level,
        overall_risk_pct=overall_risk_pct,
        risk_level_counts=risk_level_counts,
        risk_trend_labels=risk_trend_labels,
        risk_trend_values=risk_trend_values,
    )


@admin_bp.route("/users")
@login_required
@admin_required
def users():
    all_users = User.query.order_by(User.live_risk_score.desc()).all()
    return render_template("admin_users.html", users=all_users)


@admin_bp.route("/users/new", methods=["POST"])
@login_required
@admin_required
def new_user():
    """Feature 1 (User creation) + Rule 3 (new privileged account)."""
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""
    role = request.form.get("role") or "employee"
    if role not in ("admin", "employee"):
        role = "employee"

    if not username or not email or len(password) < 6:
        message = "Username, email, and a password of at least 6 characters are required."
        flash(message, "danger")
        if _is_ajax():
            return jsonify(success=False, message=message), 400
        return _safe_redirect("admin.users")

    if User.query.filter((User.username == username) | (User.email == email)).first():
        message = "A user with that username or email already exists."
        flash(message, "danger")
        if _is_ajax():
            return jsonify(success=False, message=message), 400
        return _safe_redirect("admin.users")

    new_account = User(username=username, email=email, role=role, is_active_account=True)
    new_account.set_password(password)
    db.session.add(new_account)
    db.session.commit()

    risk = "CRITICAL" if role == "admin" else "MEDIUM"
    log_audit_event(current_user, "USER_CREATE", target_type="user", target_id=new_account.id,
                     details=f"{current_user.username} created user '{username}' with role {role}.",
                     risk_level=risk)
    detection.check_admin_off_hours(current_user, "Create User Account")

    if role == "admin":
        detection.check_new_admin_account(current_user)
    else:
        detection.check_mass_account_modification(current_user)

    message = f"User '{username}' created."
    flash(message, "success")
    if _is_ajax():
        return jsonify(success=True, message=message, user_id=new_account.id)
    return _safe_redirect("admin.users")


@admin_bp.route("/users/<int:user_id>/investigate")
@login_required
@admin_required
def investigate_user(user_id):
    """Detect -> Alert -> Investigate: full picture of one user for the
    admin to review before deciding on a response."""
    from models import SecurityIncident
    user = User.query.get_or_404(user_id)

    reasons = get_risk_reasons(user)
    recent_logs = (ActivityLog.query.filter_by(user_id=user.id)
                   .order_by(ActivityLog.timestamp.desc()).limit(20).all())
    login_history = (ActivityLog.query.filter_by(user_id=user.id, action="login")
                      .order_by(ActivityLog.timestamp.desc()).limit(10).all())
    alerts = (Alert.query.filter_by(user_id=user.id)
              .order_by(Alert.timestamp.desc()).all())
    incidents = (SecurityIncident.query.filter_by(user_id=user.id)
                 .order_by(SecurityIncident.created_at.desc()).all())
    suspicious_count = sum(r["occurrences"] for r in reasons)

    self_investigation = (user.id == current_user.id and user.is_admin())

    return render_template(
        "investigate_user.html",
        user=user,
        reasons=reasons,
        recent_logs=recent_logs,
        login_history=login_history,
        alerts=alerts,
        incidents=incidents,
        suspicious_count=suspicious_count,
        self_investigation=self_investigation,
    )


@admin_bp.route("/users/<int:user_id>/change-role", methods=["POST"])
@login_required
@admin_required
def change_role(user_id):
    """Rule 1 — Privilege escalation monitoring."""
    blocked = _block_self_investigation()
    if blocked:
        return blocked

    user = User.query.get_or_404(user_id)
    new_role = request.form.get("new_role")
    if new_role not in ("admin", "employee"):
        message = "Invalid role."
        flash(message, "danger")
        return (jsonify(success=False, message=message), 400) if _is_ajax() else _safe_redirect("admin.users")

    old_role = user.role
    user.role = new_role
    db.session.commit()

    log_audit_event(current_user, "ROLE_CHANGE", target_type="user", target_id=user.id,
                     details=f"{current_user.username} changed {user.username}'s role: {old_role} -> {new_role}.",
                     risk_level="HIGH" if new_role == "admin" else "MEDIUM")
    detection.check_admin_off_hours(current_user, "Role Change")
    detection.check_role_change(current_user, user, new_role)
    detection.check_mass_account_modification(current_user)

    message = f"{user.username}'s role changed to {new_role}."
    flash(message, "warning")
    if _is_ajax():
        return jsonify(success=True, message=message, new_role=new_role)
    return _safe_redirect("admin.users")


@admin_bp.route("/users/<int:user_id>/reset-score", methods=["POST"])
@login_required
@admin_required
def reset_user_score(user_id):
    user = User.query.get_or_404(user_id)
    old_score = user.live_risk_score
    reset_score(user)
    # Resetting a score changes how a user's risk looks, so it is audited too.
    log_audit_event(current_user, "RISK_SCORE_RESET", target_type="user", target_id=user.id,
                     details=f"{current_user.username} reset risk score of '{user.username}' "
                             f"from {old_score} to 0.", risk_level="MEDIUM")
    message = f"Risk score reset for {user.username}."
    flash(message, "info")
    if _is_ajax():
        return jsonify(success=True, message=message)
    return _safe_redirect("admin.users")


@admin_bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@login_required
@admin_required
def toggle_active(user_id):
    blocked = _block_self_investigation()
    if blocked:
        return blocked

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        message = "You cannot suspend your own account."
        flash(message, "danger")
        if _is_ajax():
            return jsonify(success=False, message=message), 400
        return _safe_redirect("admin.users")

    is_suspend_action = user.is_active_account  # currently active -> this call suspends

    # Feature 8 — Dual authorization: suspending a PRIVILEGED (admin)
    # account is a critical operation and requires a second, different
    # admin to approve it rather than happening immediately.
    if is_suspend_action and user.is_privileged():
        existing = ApprovalRequest.query.filter_by(
            action_type="SUSPEND_PRIVILEGED_ACCOUNT", target_user_id=user.id, status="PENDING"
        ).first()
        if not existing:
            req = ApprovalRequest(action_type="SUSPEND_PRIVILEGED_ACCOUNT",
                                   target_user_id=user.id, requested_by_id=current_user.id,
                                   reason=f"Requested by {current_user.username}")
            db.session.add(req)
            db.session.commit()
            log_audit_event(current_user, "APPROVAL_REQUEST", target_type="user", target_id=user.id,
                             details=f"{current_user.username} requested suspension of privileged "
                                     f"account '{user.username}' — pending second-admin approval.",
                             risk_level="HIGH")
        message = ("This is a privileged account. Suspension requires approval from a "
                   "different administrator — request submitted.")
        flash(message, "warning")
        if _is_ajax():
            return jsonify(success=True, message=message, pending_approval=True)
        return _safe_redirect("admin.users")

    user.is_active_account = not user.is_active_account
    db.session.commit()
    state = "activated" if user.is_active_account else "suspended"
    action_key = "ACCOUNT_ACTIVATE" if user.is_active_account else "ACCOUNT_SUSPEND"

    if user.is_privileged() or current_user.is_privileged():
        log_audit_event(current_user, action_key, target_type="user", target_id=user.id,
                         details=f"{current_user.username} {state} account '{user.username}'.",
                         risk_level="HIGH" if action_key == "ACCOUNT_SUSPEND" else "INFO")
        detection.check_admin_off_hours(current_user, f"Account {state.capitalize()}")
        detection.check_mass_account_modification(current_user)

    message = f"User {user.username} {state}."
    flash(message, "warning")
    if _is_ajax():
        return jsonify(success=True, message=message, is_active=user.is_active_account)
    return _safe_redirect("admin.users")


@admin_bp.route("/users/<int:user_id>/revoke-session", methods=["POST"])
@login_required
@admin_required
def revoke_session(user_id):
    """Response action: force this user's active session(s) to log out
    on their next request, without suspending the account."""
    blocked = _block_self_investigation()
    if blocked:
        return blocked

    user = User.query.get_or_404(user_id)
    user.session_version = (user.session_version or 0) + 1
    db.session.commit()

    log_audit_event(current_user, "SESSION_REVOKE", target_type="user", target_id=user.id,
                     details=f"{current_user.username} revoked active session(s) for '{user.username}'.",
                     risk_level="MEDIUM")

    message = f"Active session revoked for {user.username}."
    flash(message, "warning")
    if _is_ajax():
        return jsonify(success=True, message=message)
    return _safe_redirect("admin.users")


@admin_bp.route("/users/<int:user_id>/disable-privileged", methods=["POST"])
@login_required
@admin_required
def disable_privileged(user_id):
    """Response action: immediately demote an admin account back to
    employee (least privilege) without suspending it outright."""
    blocked = _block_self_investigation()
    if blocked:
        return blocked

    user = User.query.get_or_404(user_id)
    if not user.is_privileged():
        message = "This account does not hold privileged access."
        flash(message, "info")
        return (jsonify(success=False, message=message), 400) if _is_ajax() else _safe_redirect("admin.users")

    user.role = "employee"
    user.session_version = (user.session_version or 0) + 1  # force re-login with new role
    db.session.commit()

    log_audit_event(current_user, "PRIVILEGE_REVOKED", target_type="user", target_id=user.id,
                     details=f"{current_user.username} revoked privileged access for '{user.username}'.",
                     risk_level="HIGH")

    message = f"Privileged access revoked for {user.username}."
    flash(message, "warning")
    if _is_ajax():
        return jsonify(success=True, message=message)
    return _safe_redirect("admin.users")


@admin_bp.route("/alerts")
@login_required
@admin_required
def alerts():
    level_filter = request.args.get("level")
    status_filter = request.args.get("status")  # 'open' or 'resolved'
    user_filter = request.args.get("user_id", type=int)

    query = Alert.query
    if level_filter:
        query = query.filter_by(level=level_filter)
    if status_filter == "open":
        query = query.filter_by(resolved=False)
    elif status_filter == "resolved":
        query = query.filter_by(resolved=True)
    if user_filter:
        query = query.filter_by(user_id=user_filter)

    all_alerts = query.order_by(Alert.timestamp.desc()).all()
    all_users = User.query.order_by(User.username).all()
    return render_template("alerts.html", alerts=all_alerts, level_filter=level_filter,
                            status_filter=status_filter, user_filter=user_filter,
                            users=all_users)


@admin_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
@admin_required
def resolve_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.resolved = True
    db.session.commit()

    # Rule 7 — resolving alerts is itself security-sensitive (an insider
    # admin could resolve alerts fast to cover their tracks), so it goes
    # through the audit chain and the rapid-resolution rule too.
    log_audit_event(current_user, "ALERT_RESOLVE", target_type="alert", target_id=alert.id,
                     details=f"{current_user.username} resolved alert #{alert.id} "
                             f"({alert.alert_type}) for user {alert.user.username}.",
                     risk_level="INFO")
    detection.check_rapid_alert_resolution(current_user)

    message = "Alert marked as resolved."
    flash(message, "success")
    if _is_ajax():
        return jsonify(success=True, message=message, alert_id=alert.id)
    return _safe_redirect("admin.alerts")


@admin_bp.route("/logs")
@login_required
@admin_required
def logs():
    user_filter = request.args.get("user_id", type=int)
    query = ActivityLog.query
    if user_filter:
        query = query.filter_by(user_id=user_filter)
    all_logs = query.order_by(ActivityLog.timestamp.desc()).limit(300).all()
    all_users = User.query.order_by(User.username).all()
    return render_template("logs.html", logs=all_logs, users=all_users,
                            user_filter=user_filter)
