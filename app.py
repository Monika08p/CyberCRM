"""
app.py
-------
CyberCRM Guardian: Smart Protection Against Insider Attacks
Main application factory & entry point.

Run with:  python app.py
Then visit http://127.0.0.1:5000
Default credentials are created by seed.py (see README.md).
"""

import os
from flask import Flask, render_template
from flask_login import current_user

from config import Config
from extensions import db, login_manager


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure instance folder exists (holds the SQLite DB file)
    os.makedirs(os.path.join(app.root_path, "instance"), exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)

    # --- Register blueprints ---
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.customers import customers_bp
    from routes.admin import admin_bp
    from routes.reports import reports_bp
    from routes.settings import settings_bp
    from routes.security import security_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(customers_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(security_bp)

    from models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # --- Session revocation enforcement (Response action: "Revoke Session") ---
    # An admin can bump a user's `session_version`; every request compares
    # the browser session's stamped version against the current one and
    # forces an immediate logout on mismatch.
    @app.before_request
    def _enforce_session_revocation():
        from flask import session
        from flask_login import logout_user
        if current_user.is_authenticated:
            stamped = session.get("session_version")
            if stamped is not None and stamped != (current_user.session_version or 0):
                from flask import flash
                logout_user()
                session.clear()
                flash("Your session was revoked by an administrator. Please log in again.", "warning")

    # --- Error handlers ---
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403,
                                message="Access denied. This incident has been logged."), 403

    # Safety net: if ANY code path tries to update/delete an AuditEvent, the model
    # layer raises AuditImmutableError. Roll back, keep the evidence untouched,
    # and record the attempt (Rule 8) instead of showing a raw error.
    from models import AuditImmutableError

    @app.errorhandler(AuditImmutableError)
    def audit_immutable(e):
        db.session.rollback()
        if current_user.is_authenticated:
            from utils import detection
            from utils.audit import log_audit_event
            detection.flag_audit_tampering_attempt(current_user, None)
            log_audit_event(current_user, "AUDIT_TAMPER_ATTEMPT", target_type="audit_event",
                             details=f"{current_user.username} attempted to modify/delete audit "
                                     f"evidence. Blocked; evidence intact.",
                             risk_level="CRITICAL")
        return render_template("error.html", code=403,
                                message="Audit and activity evidence is append-only and cannot be "
                                        "modified or deleted."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404,
                                message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(e):
        db.session.rollback()
        return render_template("error.html", code=500,
                                message="Something went wrong on our end. Please try again."), 500

    # --- Context processor: make live risk score & notifications available in every template ---
    @app.context_processor
    def inject_globals():
        from models import Alert, SecurityIncident, ApprovalRequest

        live_score = 0
        notifications = []
        open_alerts_count = 0
        open_incidents_count = 0
        pending_approvals_count = 0
        if current_user.is_authenticated:
            live_score = current_user.live_risk_score or 0
            if current_user.is_admin():
                notifications = (Alert.query.filter_by(resolved=False)
                                  .order_by(Alert.timestamp.desc()).limit(5).all())
                open_alerts_count = Alert.query.filter_by(resolved=False).count()
                open_incidents_count = SecurityIncident.query.filter(
                    SecurityIncident.status.in_(["OPEN", "UNDER_INVESTIGATION"])).count()
                pending_approvals_count = ApprovalRequest.query.filter_by(status="PENDING").count()
            else:
                notifications = (Alert.query.filter_by(user_id=current_user.id, resolved=False)
                                  .order_by(Alert.timestamp.desc()).limit(5).all())
                open_alerts_count = Alert.query.filter_by(
                    user_id=current_user.id, resolved=False).count()
        return dict(app_name="CyberCRM Guardian", my_live_score=live_score,
                    nav_notifications=notifications, open_alerts_count=open_alerts_count,
                    open_incidents_count=open_incidents_count,
                    pending_approvals_count=pending_approvals_count)

    with app.app_context():
        db.create_all()
        # If the app/process stopped between an audit commit and its archive
        # write, copy any events still missing to the archive now.
        from utils import audit_archive
        audit_archive.startup_catchup()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
