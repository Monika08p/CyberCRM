"""
seed.py
--------
Run once to initialize the database with demo data:
  - 1 admin account
  - 4 employee accounts
  - 15 sample customers
  - a spread of historical activity logs / risk scores / alerts so the
    dashboards and charts have something to show immediately.

Usage:
    python seed.py
"""

import random
from datetime import datetime, timedelta

from app import create_app
from extensions import db
from models import User, Customer, ActivityLog, Alert, RiskScore
from utils.risk_engine import award_points
from utils.audit import log_audit_event
from utils.incidents import correlate_and_create_incident

app = create_app()

SAMPLE_CUSTOMERS = [
    ("Acme Logistics", "contact@acmelogistics.com", "555-0101", "Acme Logistics Inc."),
    ("Nova Retail Group", "info@novaretail.com", "555-0102", "Nova Retail Group"),
    ("BluePeak Finance", "hello@bluepeak.com", "555-0103", "BluePeak Finance"),
    ("Sierra Health Systems", "admin@sierrahealth.com", "555-0104", "Sierra Health"),
    ("Orion Manufacturing", "sales@orionmfg.com", "555-0105", "Orion Manufacturing"),
    ("Cedar Grove Realty", "office@cedargrove.com", "555-0106", "Cedar Grove Realty"),
    ("Vantage Media Co.", "contact@vantagemedia.com", "555-0107", "Vantage Media"),
    ("Redwood Legal Partners", "info@redwoodlegal.com", "555-0108", "Redwood Legal"),
    ("Falcon Freight", "ops@falconfreight.com", "555-0109", "Falcon Freight"),
    ("Harbor Point Insurance", "quotes@harborpoint.com", "555-0110", "Harbor Point Ins."),
    ("Ironclad Security", "support@ironclad.com", "555-0111", "Ironclad Security"),
    ("Maple Street Bakery Supply", "orders@maplesupply.com", "555-0112", "Maple Supply"),
    ("Zenith Software Labs", "team@zenithlabs.com", "555-0113", "Zenith Labs"),
    ("Golden Gate Consulting", "hi@ggconsulting.com", "555-0114", "Golden Gate Consulting"),
    ("Summit Energy Partners", "info@summitenergy.com", "555-0115", "Summit Energy"),
]


def seed():
    with app.app_context():
        db.drop_all()
        db.create_all()

        # The database was just reset, so audit ids start from 1 again. Move any
        # previous audit archive aside (NOT deleted) so old evidence is kept and
        # the new archive starts consistent with the new database.
        import glob, os, shutil
        from utils.audit_archive import backup_dir
        old = [f for f in glob.glob(os.path.join(backup_dir(), "audit_*.jsonl*"))]
        if old:
            parked = os.path.join(backup_dir(), f"replaced_by_reseed_{datetime.utcnow():%Y%m%d_%H%M%S}")
            os.makedirs(parked)
            for f in old:
                shutil.move(f, parked)
            print(f"Previous audit archive moved to {parked}")

        # --- Users ---
        admin = User(username="admin", email="admin@cybercrm.local", role="admin")
        admin.set_password("Admin@123")
        db.session.add(admin)

        # A second admin account so the demo can show dual-authorization
        # (one admin cannot approve their own critical request) and
        # self-investigation restriction (an admin cannot resolve an
        # incident raised against their OWN account).
        admin2 = User(username="admin2", email="admin2@cybercrm.local", role="admin")
        admin2.set_password("Admin@123")
        db.session.add(admin2)

        employees_data = [
            ("jsmith", "jsmith@cybercrm.local"),
            ("mrodriguez", "mrodriguez@cybercrm.local"),
            ("akhan", "akhan@cybercrm.local"),
            ("tnguyen", "tnguyen@cybercrm.local"),
        ]
        employees = []
        for uname, email in employees_data:
            u = User(username=uname, email=email, role="employee")
            u.set_password("Employee@123")
            db.session.add(u)
            employees.append(u)

        db.session.commit()

        # --- Customers ---
        customers = []
        for name, email, phone, company in SAMPLE_CUSTOMERS:
            c = Customer(name=name, email=email, phone=phone, company=company,
                         address="123 Business Ave, Springfield")
            db.session.add(c)
            customers.append(c)
        db.session.commit()

        # --- Demo activity spread across last 10 days ---
        now = datetime.utcnow()

        def log(user, action, ts, target=None):
            entry = ActivityLog(user_id=user.id, action=action, target_type="customer",
                                target_id=target.id if target else None,
                                timestamp=ts, details=f"Demo: {action}")
            db.session.add(entry)

        for day_offset in range(10, -1, -1):
            base_day = now - timedelta(days=day_offset)
            for u in employees:
                # normal daily login
                login_time = base_day.replace(hour=random.randint(8, 17), minute=random.randint(0, 59))
                log(u, "login", login_time)
                award_points(u, "login_success")

                # some normal customer views
                for _ in range(random.randint(1, 5)):
                    c = random.choice(customers)
                    view_time = login_time + timedelta(minutes=random.randint(1, 90))
                    log(u, "view_customer", view_time, c)
                    award_points(u, "view_customer")

                log(u, "logout", login_time + timedelta(hours=random.randint(1, 6)))

        # One employee ("mrodriguez") behaves anomalously to demonstrate detection.
        # Kept RECENT (not backdated by days) so the real incident-correlation
        # window (utils/incidents.py: CORRELATION_WINDOW_MIN, checked against
        # the actual current time) picks these alerts up when it runs below —
        # exactly like it would for genuinely live suspicious activity.
        risky_user = employees[1]
        anomaly_day = now - timedelta(minutes=45)

        # burst of views within a minute
        for i in range(12):
            log(risky_user, "view_customer", anomaly_day + timedelta(seconds=i * 4),
                random.choice(customers))
        award_points(risky_user, "excessive_viewing")
        db.session.add(Alert(user_id=risky_user.id, alert_type="Excessive Record Viewing",
                             level="Medium", timestamp=anomaly_day,
                             message=f"{risky_user.username} viewed 12 customer records within 1 minute."))

        # multiple deletes
        for i in range(3):
            c = customers[i]
            log(risky_user, "delete_customer", anomaly_day + timedelta(minutes=i * 2), c)
            award_points(risky_user, "delete_customer")
        award_points(risky_user, "multiple_deletes")
        db.session.add(Alert(user_id=risky_user.id, alert_type="Multiple Delete Operations",
                             level="Critical", timestamp=anomaly_day,
                             message=f"{risky_user.username} deleted 3 customer records within 15 minutes."))

        # bulk export
        log(risky_user, "export_data", anomaly_day + timedelta(minutes=10))
        award_points(risky_user, "export")
        award_points(risky_user, "bulk_export")
        db.session.add(Alert(user_id=risky_user.id, alert_type="Bulk Data Export",
                             level="High", timestamp=anomaly_day,
                             message=f"{risky_user.username} exported 25 customer records in a single export."))

        # off-hours login
        off_hours_time = anomaly_day - timedelta(minutes=2)
        log(risky_user, "login", off_hours_time)
        award_points(risky_user, "off_hours_login")
        db.session.add(Alert(user_id=risky_user.id, alert_type="Off-Hours Login",
                             level="Low", timestamp=off_hours_time,
                             message=f"{risky_user.username} logged in at "
                                     f"{off_hours_time.strftime('%H:%M')}, outside office hours."))

        # Reuse the existing incident-correlation logic (utils/incidents.py)
        # instead of hardcoding an incident — this groups risky_user's
        # unresolved alerts above into one real SecurityIncident and links
        # each Alert.incident_id, exactly as it would during live app use.
        db.session.commit()
        correlate_and_create_incident(risky_user)

        # failed logins for another user
        target_user = employees[2]
        for i in range(3):
            log(target_user, "failed_login", anomaly_day + timedelta(minutes=i))
            award_points(target_user, "failed_login")
        award_points(target_user, "failed_login_pattern")
        db.session.add(Alert(user_id=target_user.id, alert_type="Multiple Failed Logins",
                             level="High", timestamp=anomaly_day,
                             message=f"3 failed login attempts for '{target_user.username}' within 10 minutes."))
        db.session.commit()
        correlate_and_create_incident(target_user)  # no-op here: only 1 alert, below the threshold

        risky_user.last_login = anomaly_day
        target_user.last_login = anomaly_day
        db.session.commit()

        # --- Seed a few tamper-evident audit events so the Audit
        # Integrity page and Privileged Activity feed aren't empty on
        # first login. ---
        log_audit_event(admin, "LOGIN", target_type="user", target_id=admin.id,
                         details="Admin 'admin' logged in.", risk_level="INFO")
        log_audit_event(admin, "USER_CREATE", target_type="user", target_id=employees[0].id,
                         details=f"admin created user '{employees[0].username}' with role employee.",
                         risk_level="MEDIUM")
        log_audit_event(admin2, "LOGIN", target_type="user", target_id=admin2.id,
                         details="Admin 'admin2' logged in.", risk_level="INFO")

        print("Database seeded successfully!")
        print("-------------------------------------------------")
        print("Admin login:     username='admin'       password='Admin@123'")
        print("Admin login:     username='admin2'       password='Admin@123'  (2nd admin, for dual-auth demo)")
        print("Employee login:  username='jsmith'      password='Employee@123'")
        print("Employee login:  username='mrodriguez'  password='Employee@123'  (flagged as risky)")
        print("Employee login:  username='akhan'       password='Employee@123'  (has failed login alert)")
        print("Employee login:  username='tnguyen'     password='Employee@123'")
        print("-------------------------------------------------")


if __name__ == "__main__":
    seed()
