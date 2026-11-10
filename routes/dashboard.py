"""
routes/dashboard.py
---------------------
Feature 2: CRM Dashboard (landing page after login) for employees.
Shows customer count, the user's own live risk score, and recent
personal activity.
"""

from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

from models import Customer, ActivityLog, RiskScore

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    if current_user.is_admin():
        return redirect(url_for("admin.dashboard"))

    total_customers = Customer.query.count()
    my_recent_activity = (ActivityLog.query
                           .filter_by(user_id=current_user.id)
                           .order_by(ActivityLog.timestamp.desc())
                           .limit(10).all())

    # last 10 risk events for a small trend sparkline
    my_risk_history = (RiskScore.query
                        .filter_by(user_id=current_user.id)
                        .order_by(RiskScore.timestamp.desc())
                        .limit(15).all())
    my_risk_history = list(reversed(my_risk_history))

    return render_template(
        "dashboard.html",
        total_customers=total_customers,
        recent_activity=my_recent_activity,
        risk_history=my_risk_history,
    )
