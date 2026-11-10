"""
routes/security.py
--------------------
Security Operations — kept as its own blueprint, separate from normal
CRM/admin routes (Security Requirement #7: "Separate normal CRM
operations from security administration").

Covers:
  - Security Incident list/detail/response (Feature 5, 6, 11, 12)
  - Audit Integrity verification page (Feature 4)
  - Privileged Activity feed (Feature 1)
  - Dual-authorization Approvals queue (Feature 8)

Self-investigation restriction (Feature 7) is enforced on every
response/decision route in this file.
"""

from datetime import datetime
from flask import (Blueprint, render_template, redirect, url_for, flash, request,
                    jsonify, current_app, send_from_directory, abort)
from flask_login import login_required, current_user

from extensions import db
from models import User, Alert, ActivityLog, SecurityIncident, AuditEvent, ApprovalRequest
from utils.decorators import admin_required
from utils.audit import verify_audit_chain, log_audit_event
from utils.incidents import user_can_investigate
from utils import detection
from utils import audit_archive

security_bp = Blueprint("security", __name__, url_prefix="/security")


def _is_ajax():
    return request.headers.get("X-Requested-With") == "XMLHttpRequest"


# ==========================================================================
# SECURITY INCIDENTS (Feature 6 & 11 & 12)
# ==========================================================================

@security_bp.route("/incidents")
@login_required
@admin_required
def incidents():
    status_filter = request.args.get("status")
    severity_filter = request.args.get("severity")

    query = SecurityIncident.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    if severity_filter:
        query = query.filter_by(severity=severity_filter)

    all_incidents = query.order_by(SecurityIncident.created_at.desc()).all()
    return render_template("incidents.html", incidents=all_incidents,
                            status_filter=status_filter, severity_filter=severity_filter)


@security_bp.route("/incidents/<int:incident_id>")
@login_required
@admin_required
def incident_detail(incident_id):
    incident = SecurityIncident.query.get_or_404(incident_id)
    related_alerts = (Alert.query.filter_by(incident_id=incident.id)
                       .order_by(Alert.timestamp.asc()).all())

    # Timeline: merge related alerts + the suspect's recent activity
    # logs into one time-ordered picture (Feature 11).
    recent_activity = (ActivityLog.query.filter_by(user_id=incident.user_id)
                        .order_by(ActivityLog.timestamp.desc()).limit(25).all())

    self_investigation = not user_can_investigate(current_user, incident)

    return render_template("incident_detail.html", incident=incident,
                            related_alerts=related_alerts,
                            recent_activity=recent_activity,
                            self_investigation=self_investigation)


@security_bp.route("/incidents/<int:incident_id>/action", methods=["POST"])
@login_required
@admin_required
def incident_action(incident_id):
    """Feature 12 — controlled response actions on an incident.
    Feature 7 — blocked if the current admin IS the suspect."""
    incident = SecurityIncident.query.get_or_404(incident_id)

    if not user_can_investigate(current_user, incident):
        message = ("Self-investigation restricted: you cannot act on an incident "
                   "involving your own account. Another administrator must respond.")
        flash(message, "danger")
        if _is_ajax():
            return jsonify(success=False, message=message), 403
        return redirect(url_for("security.incident_detail", incident_id=incident.id))

    action_type = request.form.get("action_type")
    notes = (request.form.get("notes") or "").strip()
    suspect = incident.suspect

    if incident.investigator_id is None:
        incident.investigator_id = current_user.id

    if action_type == "under_investigation":
        incident.status = "UNDER_INVESTIGATION"
        message = "Incident marked as Under Investigation."
    elif action_type == "contained":
        incident.status = "CONTAINED"
        message = "Incident marked as Contained."
    elif action_type == "resolve":
        incident.status = "RESOLVED"
        incident.resolved_at = datetime.utcnow()
        incident.resolution_notes = notes or incident.resolution_notes
        message = "Incident resolved."
    elif action_type == "false_positive":
        incident.status = "FALSE_POSITIVE"
        incident.resolved_at = datetime.utcnow()
        incident.resolution_notes = notes or "Marked as false positive."
        message = "Incident marked as a false positive."
    elif action_type == "note":
        incident.resolution_notes = ((incident.resolution_notes or "") +
                                      f"\n[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')} "
                                      f"{current_user.username}] {notes}")
        message = "Investigation note added."
    else:
        message = "Unknown action."
        flash(message, "danger")
        return redirect(url_for("security.incident_detail", incident_id=incident.id))

    db.session.commit()
    log_audit_event(current_user, "INCIDENT_STATUS_CHANGE", target_type="incident",
                     target_id=incident.id,
                     details=f"{current_user.username} set incident {incident.incident_code} "
                             f"to {action_type} for user {suspect.username}."
                             + (f" Notes: {notes}" if notes else ""),
                     risk_level="INFO")

    flash(message, "success")
    if _is_ajax():
        return jsonify(success=True, message=message, status=incident.status)
    return redirect(url_for("security.incident_detail", incident_id=incident.id))


# ==========================================================================
# PRIVILEGED ACTIVITY FEED (Feature 1)
# ==========================================================================

@security_bp.route("/privileged-activity")
@login_required
@admin_required
def privileged_activity():
    admin_ids = [u.id for u in User.query.filter_by(role="admin").all()]

    audit_events = (AuditEvent.query.order_by(AuditEvent.timestamp.desc()).limit(200).all())
    activity_logs = (ActivityLog.query.filter(ActivityLog.user_id.in_(admin_ids))
                      .order_by(ActivityLog.timestamp.desc()).limit(100).all()
                      if admin_ids else [])

    return render_template("privileged_activity.html", audit_events=audit_events,
                            activity_logs=activity_logs)


# ==========================================================================
# AUDIT INTEGRITY (Feature 3 & 4)
# ==========================================================================

@security_bp.route("/audit")
@login_required
@admin_required
def audit_integrity():
    summary = verify_audit_chain()
    recent_events = AuditEvent.query.order_by(AuditEvent.id.desc()).limit(100).all()
    backup = audit_archive.get_backup_summary()

    actions = [r[0] for r in db.session.query(AuditEvent.action).distinct().order_by(AuditEvent.action)]
    target_types = [r[0] for r in db.session.query(AuditEvent.target_type)
                    .filter(AuditEvent.target_type.isnot(None)).distinct().order_by(AuditEvent.target_type)]
    return render_template(
        "audit_integrity.html", summary=summary, events=recent_events, backup=backup,
        retention_days=current_app.config["AUDIT_RETENTION_DAYS"],
        evidence_files=audit_archive.list_evidence_files(),
        users=User.query.order_by(User.username).all(),
        actions=actions, target_types=target_types)


# ---- verification / backup buttons -------------------------------------

@security_bp.route("/audit/verify", methods=["POST"])
@login_required
@admin_required
def audit_verify():
    """[Verify Audit Chain] / [Verify Backup] buttons."""
    what = request.form.get("what")
    # Audit-management actions are themselves audited.
    log_audit_event(current_user, "AUDIT_VERIFY", target_type="audit_archive" if what == "backup" else "audit_chain",
                     details=f"{current_user.username} ran '{'backup' if what == 'backup' else 'chain'}' "
                             f"integrity verification.", risk_level="INFO")
    if what == "backup":
        report = audit_archive.verify_audit_backup()
        if report["status"] == "VALID":
            flash(f"Backup VALID: {len(report['files'])} archive file(s), "
                  f"{report['archived_events']} events verified.", "success")
        elif report["status"] == "EMPTY":
            flash("No backup exists yet. Click 'Create Backup' first.", "warning")
        else:
            problems = "; ".join(f"{f['name']}: {', '.join(f['issues'])}"
                                  for f in report["files"] if f["issues"])
            flash(f"Backup COMPROMISED - {problems}", "danger")
    else:
        result = verify_audit_chain()
        if result["chain_status"] == "VALID":
            flash(f"Audit chain VALID: all {result['total']} events verified.", "success")
        else:
            flash(f"Audit chain COMPROMISED: {result['tampered']} event(s) failed, "
                  f"first affected event #{result['first_tampered_id']}.", "danger")
    return redirect(url_for("security.audit_integrity"))


@security_bp.route("/audit/backup", methods=["POST"])
@login_required
@admin_required
def audit_backup():
    """[Create Backup] - archive every audit event not yet in audit_backups/."""
    try:
        result = audit_archive.create_backup()
    except OSError:
        current_app.logger.exception("Audit backup failed")
        flash("Backup failed: the archive folder is not writable.", "danger")
        return redirect(url_for("security.audit_integrity"))
    log_audit_event(current_user, "AUDIT_BACKUP_CREATE", target_type="audit_archive",
                     details=f"{current_user.username} created an audit backup: "
                             f"{result['written']} new event(s) archived, "
                             f"{result['skipped']} already archived.",
                     risk_level="INFO")
    flash(f"Backup created: {result['written']} new event(s) archived, "
          f"{result['skipped']} already archived (no duplicates).", "success")
    return redirect(url_for("security.audit_integrity"))


# ---- evidence export ----------------------------------------------------

@security_bp.route("/audit/export", methods=["POST"])
@login_required
@admin_required
def audit_export_evidence():
    """[Export Evidence] - structured JSON + SHA-256 checksum + custody metadata."""
    f = request.form
    try:
        result = audit_archive.export_evidence(
            current_user, date_from=f.get("date_from") or None,
            date_to=f.get("date_to") or None, user_id=f.get("user_id") or None,
            action=f.get("action") or None, target_type=f.get("target_type") or None)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("security.audit_integrity"))
    except OSError:
        current_app.logger.exception("Evidence export failed")
        flash("Evidence export failed: could not write the evidence file.", "danger")
        return redirect(url_for("security.audit_integrity"))

    log_audit_event(current_user, "EVIDENCE_EXPORT", target_type="audit_evidence",
                     details=f"{current_user.username} exported {result['count']} audit "
                             f"record(s) to {result['filename']} (SHA-256 {result['sha256']}).",
                     risk_level="INFO")
    flash(f"Evidence exported successfully. Records: {result['count']}. "
          f"SHA-256: {result['sha256']}", "success")
    return redirect(url_for("security.audit_integrity"))


@security_bp.route("/audit/evidence/<filename>")
@login_required
@admin_required
def audit_download_evidence(filename):
    # Only files we generated; the regex also blocks path traversal.
    if not audit_archive.EVIDENCE_NAME_RE.match(filename):
        abort(404)
    log_audit_event(current_user, "EVIDENCE_DOWNLOAD", target_type="audit_evidence",
                     details=f"{current_user.username} downloaded {filename}.", risk_level="INFO")
    return send_from_directory(audit_archive.evidence_dir(), filename, as_attachment=True)


# ---- append-only enforcement -------------------------------------------

def _block_audit_modification(event_id, attempted):
    """
    Shared handler for EVERY attempt to change or delete audit evidence.
    The audit table is never touched: we only (1) raise the existing
    Rule-8 alert/risk points and (2) append an AUDIT_TAMPER_ATTEMPT event.
    """
    detection.flag_audit_tampering_attempt(current_user, event_id)
    target = f"audit event #{event_id}" if event_id is not None else "the entire audit trail"
    log_audit_event(current_user, "AUDIT_TAMPER_ATTEMPT", target_type="audit_event",
                     target_id=event_id,
                     details=f"{current_user.username} attempted to {attempted} {target}. "
                             f"Request blocked; evidence intact.",
                     risk_level="CRITICAL")
    message = ("Blocked: audit evidence is append-only and cannot be modified or deleted. "
               "This attempt has been logged and flagged.")
    flash(message, "danger")
    if _is_ajax():
        return jsonify(success=False, message=message), 403
    return redirect(url_for("security.audit_integrity"))


@security_bp.route("/audit/<int:event_id>/delete", methods=["POST"])
@login_required
@admin_required
def audit_delete_blocked(event_id):
    return _block_audit_modification(event_id, "delete")


@security_bp.route("/audit/<int:event_id>/edit", methods=["POST"])
@login_required
@admin_required
def audit_edit_blocked(event_id):
    return _block_audit_modification(event_id, "modify")


@security_bp.route("/audit/clear", methods=["POST"])
@login_required
@admin_required
def audit_clear_blocked():
    return _block_audit_modification(None, "clear")


@security_bp.route("/audit/<int:event_id>/tamper-attempt", methods=["POST"])
@login_required
@admin_required
def audit_tamper_attempt(event_id):
    """Kept for backward compatibility with the earlier security-test button."""
    return _block_audit_modification(event_id, "modify/delete")


# ==========================================================================
# DUAL AUTHORIZATION — APPROVALS (Feature 8)
# ==========================================================================

@security_bp.route("/approvals")
@login_required
@admin_required
def approvals():
    pending = (ApprovalRequest.query.filter_by(status="PENDING")
               .order_by(ApprovalRequest.created_at.desc()).all())
    history = (ApprovalRequest.query.filter(ApprovalRequest.status != "PENDING")
               .order_by(ApprovalRequest.decided_at.desc()).limit(20).all())
    return render_template("approvals.html", pending=pending, history=history)


@security_bp.route("/approvals/<int:approval_id>/decide", methods=["POST"])
@login_required
@admin_required
def decide_approval(approval_id):
    approval = ApprovalRequest.query.get_or_404(approval_id)
    decision = request.form.get("decision")  # 'approve' or 'reject'

    if approval.status != "PENDING":
        message = "This request has already been decided."
        flash(message, "info")
        return redirect(url_for("security.approvals"))

    # A requesting admin cannot approve their own request (two-person rule).
    if approval.requested_by_id == current_user.id:
        message = "You cannot approve your own request. A different administrator must review it."
        flash(message, "danger")
        if _is_ajax():
            return jsonify(success=False, message=message), 403
        return redirect(url_for("security.approvals"))

    approval.decided_by_id = current_user.id
    approval.decided_at = datetime.utcnow()

    if decision == "approve":
        approval.status = "APPROVED"
        if approval.action_type == "SUSPEND_PRIVILEGED_ACCOUNT":
            target = approval.target_user
            target.is_active_account = False
            db.session.commit()
            log_audit_event(current_user, "ACCOUNT_SUSPEND", target_type="user",
                             target_id=target.id,
                             details=f"{current_user.username} approved and executed suspension "
                                     f"of privileged account '{target.username}' "
                                     f"(requested by {approval.requested_by.username}).",
                             risk_level="HIGH")
        message = "Request approved and action executed."
    else:
        approval.status = "REJECTED"
        message = "Request rejected."

    db.session.commit()
    log_audit_event(current_user, "APPROVAL_DECISION", target_type="approval_request",
                     target_id=approval.id,
                     details=f"{current_user.username} {approval.status.lower()} approval "
                             f"request #{approval.id} ({approval.action_type}).",
                     risk_level="INFO")

    flash(message, "success")
    if _is_ajax():
        return jsonify(success=True, message=message, status=approval.status)
    return redirect(url_for("security.approvals"))
