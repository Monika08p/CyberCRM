"""
routes/auth.py
----------------
User Authentication (Employee & Admin login) + Role-Based Access Control.
Every login attempt (success or failure) is logged and scored, and feeds
the "multiple failed logins" / "login outside office hours" rules.
"""

from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from extensions import db
from models import User
from utils.helpers import log_activity
from utils import detection
from utils.audit import log_audit_event

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        # --- Suspended account: block immediately with a clear message ---
        if user and not user.is_active_account:
            flash("This account has been suspended. Please contact your administrator.", "danger")
            return redirect(url_for("auth.login"))

        # --- Temporary lockout after repeated recent failed attempts ---
        if user and detection.is_account_locked(user):
            flash("Too many failed login attempts. Please try again in a few minutes.", "danger")
            return redirect(url_for("auth.login"))

        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            # Stamp this browser session with the user's current session
            # version, so an admin "Revoke Session" action (which bumps
            # session_version) forces this exact session to log out.
            from flask import session
            session["session_version"] = user.session_version or 0
            db.session.commit()

            log_activity(user, "login", details="Successful login")
            detection.check_office_hours(user)

            # Feature 1: privileged users are monitored too — every admin
            # login becomes a tamper-evident audit event, not just a
            # normal ActivityLog row.
            if user.is_privileged():
                log_audit_event(user, "LOGIN", target_type="user", target_id=user.id,
                                 details=f"Admin '{user.username}' logged in.",
                                 risk_level="INFO")
                detection.check_admin_off_hours(user, "Admin Login")

            flash(f"Welcome back, {user.username}!", "success")
            if user.is_admin():
                return redirect(url_for("admin.dashboard"))
            return redirect(url_for("dashboard.index"))

        # --- Failed login handling ---
        if user:
            log_activity(user, "failed_login",
                         details=f"Failed login attempt for '{username}'")
        flash("Invalid username or password.", "danger")
        return redirect(url_for("auth.login"))

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    log_activity(current_user, "logout", details="User logged out")
    if current_user.is_privileged():
        log_audit_event(current_user, "LOGOUT", target_type="user", target_id=current_user.id,
                         details=f"Admin '{current_user.username}' logged out.",
                         risk_level="INFO")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
