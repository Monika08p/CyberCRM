"""
routes/reports.py
-------------------
Reports - Daily Report, Weekly Report, Risk Report.
Pure Python aggregation over SQLAlchemy query results (no pandas).
"""

import io
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from flask import Blueprint, render_template, Response
from flask_login import login_required

from models import ActivityLog, Alert, User
from utils.decorators import admin_required

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


def _activity_summary(since):
    """
    Build a per-user x per-action count table from real ActivityLog rows.
    Returns (summary_rows, action_columns) where summary_rows is a list of
    dicts like {'user': 'jsmith', 'login': 3, 'view_customer': 5, ...}
    """
    logs = ActivityLog.query.filter(ActivityLog.timestamp >= since).all()
    if not logs:
        return [], []

    counts = defaultdict(lambda: defaultdict(int))
    actions_seen = set()
    for log in logs:
        counts[log.user.username][log.action] += 1
        actions_seen.add(log.action)

    action_columns = sorted(actions_seen)
    summary = []
    for username, action_counts in sorted(counts.items()):
        row = {"user": username}
        for col in action_columns:
            row[col] = action_counts.get(col, 0)
        summary.append(row)
    return summary, action_columns


@reports_bp.route("/daily")
@login_required
@admin_required
def daily_report():
    since = datetime.combine(datetime.utcnow().date(), datetime.min.time())
    summary, action_columns = _activity_summary(since)
    return render_template("reports.html", report_type="Daily", summary=summary,
                            action_columns=action_columns, since=since)


@reports_bp.route("/weekly")
@login_required
@admin_required
def weekly_report():
    since = datetime.utcnow() - timedelta(days=7)
    summary, action_columns = _activity_summary(since)
    return render_template("reports.html", report_type="Weekly", summary=summary,
                            action_columns=action_columns, since=since)


@reports_bp.route("/risk")
@login_required
@admin_required
def risk_report():
    users = User.query.filter_by(role="employee").order_by(
        User.live_risk_score.desc()
    ).all()

    rows = []
    for u in users:
        alert_count = Alert.query.filter_by(user_id=u.id, resolved=False).count()
        rows.append({
            "username": u.username,
            "live_risk_score": u.live_risk_score,
            "risk_level": u.risk_level(),
            "is_suspicious": u.is_suspicious,
            "is_active_account": u.is_active_account,
            "open_alerts": alert_count,
            "last_login": u.last_login,
        })

    return render_template("reports.html", report_type="Risk", risk_rows=rows)


def _csv_response(filename, header, rows):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(header)
    for row in rows:
        writer.writerow(row)
    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


@reports_bp.route("/daily/export")
@login_required
@admin_required
def export_daily_report():
    since = datetime.combine(datetime.utcnow().date(), datetime.min.time())
    summary, action_columns = _activity_summary(since)
    header = ["User"] + action_columns
    rows = [[r["user"]] + [r[c] for c in action_columns] for r in summary]
    return _csv_response("daily_report.csv", header, rows)


@reports_bp.route("/weekly/export")
@login_required
@admin_required
def export_weekly_report():
    since = datetime.utcnow() - timedelta(days=7)
    summary, action_columns = _activity_summary(since)
    header = ["User"] + action_columns
    rows = [[r["user"]] + [r[c] for c in action_columns] for r in summary]
    return _csv_response("weekly_report.csv", header, rows)


@reports_bp.route("/risk/export")
@login_required
@admin_required
def export_risk_report():
    users = User.query.filter_by(role="employee").order_by(
        User.live_risk_score.desc()
    ).all()
    rows = []
    for u in users:
        alert_count = Alert.query.filter_by(user_id=u.id, resolved=False).count()
        rows.append([
            u.username, u.live_risk_score, u.risk_level(),
            "Yes" if u.is_suspicious else "No",
            "Suspended" if not u.is_active_account else "Active",
            alert_count,
            u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "Never",
        ])
    header = ["Username", "Live Risk Score", "Risk Level", "Suspicious",
              "Account Status", "Open Alerts", "Last Login"]
    return _csv_response("risk_report.csv", header, rows)
