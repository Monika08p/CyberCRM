"""
routes/settings.py
--------------------
Account settings: view profile info and change password. This is a real,
database-backed feature (not a placeholder page) so the "Settings" nav
item has genuine functionality behind it.
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user

from extensions import db
from utils.helpers import log_activity
from utils.audit import log_audit_event

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not current_user.check_password(current_password):
            flash("Current password is incorrect.", "danger")
        elif len(new_password) < 6:
            flash("New password must be at least 6 characters long.", "danger")
        elif new_password != confirm_password:
            flash("New password and confirmation do not match.", "danger")
        else:
            current_user.set_password(new_password)
            db.session.commit()
            log_activity(current_user, "settings_update", details="Password changed")
            if current_user.is_privileged():
                # Never record the password itself - only the fact that it changed.
                log_audit_event(current_user, "PASSWORD_CHANGE", target_type="user",
                                 target_id=current_user.id,
                                 details=f"{current_user.username} changed their own password.",
                                 risk_level="MEDIUM")
            flash("Password updated successfully.", "success")

        return redirect(url_for("settings.index"))

    return render_template("settings.html")
