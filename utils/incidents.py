"""
utils/incidents.py
--------------------
Security Event Correlation + Incident Management (Feature 5 & 6).

Pure rules-and-thresholds correlation — no ML. Whenever a new Alert is
raised for a user, `correlate_and_create_incident()` checks whether
that user now has enough *unresolved* alerts within a short rolling
window to justify grouping them into one Security Incident, instead of
leaving the admin to review a pile of unrelated-looking alerts.
"""

from datetime import datetime, timedelta
from flask import current_app
from extensions import db
from models import Alert, SecurityIncident

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def correlate_and_create_incident(user):
    """
    Look at this user's recent unresolved alerts. If there are enough of
    them (INCIDENT_ALERT_THRESHOLD) within CORRELATION_WINDOW_MIN, group
    them into a SecurityIncident (reusing an already-OPEN one for this
    user if it exists, so a burst of activity doesn't spawn many
    incidents).
    """
    cfg = current_app.config
    window_start = datetime.utcnow() - timedelta(minutes=cfg["CORRELATION_WINDOW_MIN"])

    recent_unresolved = (Alert.query
                          .filter(Alert.user_id == user.id, Alert.resolved.is_(False),
                                  Alert.timestamp >= window_start)
                          .order_by(Alert.timestamp.asc()).all())

    if len(recent_unresolved) < cfg["INCIDENT_ALERT_THRESHOLD"]:
        return None

    unlinked = [a for a in recent_unresolved if a.incident_id is None]
    existing_open = (SecurityIncident.query
                      .filter(SecurityIncident.user_id == user.id,
                              SecurityIncident.status.in_(["OPEN", "UNDER_INVESTIGATION"]))
                      .order_by(SecurityIncident.id.desc()).first())

    if not unlinked and existing_open:
        return existing_open
    if not unlinked and not existing_open:
        return None

    severity = max((a.level for a in recent_unresolved), key=lambda lv: SEVERITY_RANK.get(lv, 0))
    title = ("Privileged Insider Incident" if user.is_privileged()
             else "Suspicious Insider Activity")

    if existing_open:
        incident = existing_open
        # A fresh, higher-severity alert can escalate an already-open incident.
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(incident.severity, 0):
            incident.severity = severity
        incident.risk_score = user.display_risk_score()
    else:
        incident = SecurityIncident(
            user_id=user.id, title=title, severity=severity,
            risk_score=user.display_risk_score(), status="OPEN",
            created_at=datetime.utcnow(),
        )
        db.session.add(incident)
        db.session.flush()  # assign incident.id before we build the code
        incident.incident_code = f"INC-{incident.id:03d}"

    for a in unlinked:
        a.incident_id = incident.id

    db.session.commit()
    return incident


def user_can_investigate(admin_user, incident):
    """Feature 7 — Prevent self-investigation: a privileged user cannot
    be the investigator/approver of an incident raised against their
    own account."""
    return admin_user.id != incident.user_id
