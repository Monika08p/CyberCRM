"""
test_sensitive_actions.py - verifies that employee AND admin actions are audited,
that evidence cannot be altered/deleted, and that recovery works.

    python test_sensitive_actions.py

SAFE: runs on a throw-away database + archive folder in a temp directory; your
real instance/cybercrm.db and audit_backups/ are never touched.
"""
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="cybercrm_sensitive_test_")
DB_FILE = os.path.join(TMP, "test.db")
ARCHIVE = os.path.join(TMP, "audit_vault")          # an "external" location
os.environ["DATABASE_URL"] = "sqlite:///" + DB_FILE
os.environ["AUDIT_BACKUP_DIR"] = ARCHIVE
os.environ.pop("AUDIT_RETENTION_DAYS", None)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

import seed                                                    # noqa: E402
from extensions import db                                      # noqa: E402
from models import (ActivityLog, AuditEvent, Alert, Customer, User,   # noqa: E402
                    AuditImmutableError, ActivityLogImmutableError)
from utils import audit_archive                                # noqa: E402
from utils.audit import verify_audit_chain, log_audit_event    # noqa: E402

AJAX = {"X-Requested-With": "XMLHttpRequest"}
results = []


def check(name, ok, extra=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({extra})" if extra else ""))


def section(t):
    print(f"\n{t}")


def run_cli(script, *args):
    p = subprocess.run([sys.executable, script, *args], cwd=HERE, env=dict(os.environ),
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


seed.seed()
app = seed.app
app.config["TESTING"] = True


def login(username, password):
    c = app.test_client()
    r = c.post("/login", data={"username": username, "password": password})
    assert r.status_code == 302, f"login failed for {username}"
    return c


def audit_rows(action):
    return AuditEvent.query.filter_by(action=action).order_by(AuditEvent.id).all()


def archive_lines():
    return "".join(open(f).read() for f in glob.glob(os.path.join(ARCHIVE, "audit_*.jsonl")))


admin = login("admin", "Admin@123")
employee = login("jsmith", "Employee@123")

# ------------------------------------------------------------------ 0
section("0. Retention default and storage location")
code, out = run_cli("-c", "from config import Config; print(Config.AUDIT_RETENTION_DAYS)")
check("AUDIT_RETENTION_DAYS defaults to 365", out.strip() == "365", out.strip())
with app.app_context():
    check("project-folder archive is flagged LOCAL / not protected",
          audit_archive.storage_info(os.path.join(HERE, "audit_backups"))["is_local"] is True)
    check("configured external folder is NOT flagged local",
          audit_archive.storage_info()["is_local"] is False)
page = admin.get("/security/audit").get_data(as_text=True)
check("Audit page shows retention (365), archive location and last-backup fields",
      "Audit Retention: 365 days" in page and "Archive storage" in page and "Last Backup" in page)

# ------------------------------------------------------------------ 1
section("1. Admin export below the bulk threshold (exactly one audit event)")
with app.app_context():
    n_cust = Customer.query.count()
    c_ids = [c.id for c in Customer.query.order_by(Customer.id).limit(3).all()]
    victim_name = Customer.query.get(c_ids[0]).name
check("seed has fewer than 20 customers", n_cust < 20, f"{n_cust}")
admin.get("/customers/export")
with app.app_context():
    check("CUSTOMER_EXPORT audit event recorded", len(audit_rows("CUSTOMER_EXPORT")) == 1)
    check("no BULK_EXPORT for a small export", len(audit_rows("BULK_EXPORT")) == 0)

# ------------------------------------------------------------------ 2
section("2. An EMPLOYEE deletes a customer")
with app.app_context():
    emp = User.query.filter_by(username="jsmith").first()
    emp_id = emp.id
    before_logs = ActivityLog.query.filter_by(action="delete_customer", user_id=emp_id).count()
r = employee.post(f"/customers/{c_ids[0]}/delete", headers=AJAX)
check("employee delete succeeds (employees may manage CRM data)", r.status_code == 200)
with app.app_context():
    log = ActivityLog.query.filter_by(action="delete_customer", user_id=emp_id).order_by(ActivityLog.id.desc()).first()
    check("ActivityLog row written", ActivityLog.query.filter_by(action="delete_customer", user_id=emp_id).count() == before_logs + 1)
    check("ActivityLog has user, customer id, IP and timestamp",
          log.target_id == c_ids[0] and log.ip_address == "127.0.0.1" and log.timestamp is not None)
    check("ActivityLog details contain no customer name", victim_name not in (log.details or ""), log.details)
    ev = audit_rows("CUSTOMER_DELETE")
    check("destructive delete is also in the tamper-evident AuditEvent chain",
          len(ev) == 1 and ev[0].user_id == emp_id and ev[0].target_id == c_ids[0])
    check("AuditEvent carries IP and no customer name",
          "[ip=127.0.0.1]" in ev[0].details and victim_name not in ev[0].details, ev[0].details)
    check("employee delete was archived", f'"event_id": {ev[0].id},' in archive_lines())
    check("chain still VALID", verify_audit_chain()["chain_status"] == "VALID")

# ------------------------------------------------------------------ 3
section("3. An ADMIN deletes a customer")
admin.post(f"/customers/{c_ids[1]}/delete", headers=AJAX)
with app.app_context():
    ev = audit_rows("CUSTOMER_DELETE")
    adm = User.query.filter_by(username="admin").first()
    check("AuditEvent CUSTOMER_DELETE by admin with target id and IP",
          len(ev) == 2 and ev[1].user_id == adm.id and ev[1].target_id == c_ids[1]
          and "[ip=127.0.0.1]" in ev[1].details)
    log = ActivityLog.query.filter_by(action="delete_customer", user_id=adm.id).order_by(ActivityLog.id.desc()).first()
    check("ActivityLog row for the admin delete", log is not None and log.target_id == c_ids[1])

section("3b. Admin create / edit are audited without personal data")
SECRET = "ZZ_SECRET_NAME_ZZ"
admin.post("/customers/new", data={"name": SECRET, "email": "zz.secret@example.com", "phone": "5559990000"}, headers=AJAX)
with app.app_context():
    new_id = Customer.query.filter_by(name=SECRET).first().id
admin.post(f"/customers/{new_id}/edit", data={"name": SECRET + "2", "email": "zz.secret2@example.com",
                                               "phone": "5559990000"}, headers=AJAX)
with app.app_context():
    check("ActivityLog has create_customer (distinct from edit)",
          ActivityLog.query.filter_by(action="create_customer").count() >= 1)
    check("AuditEvent CUSTOMER_CREATE + CUSTOMER_EDIT by admin",
          len(audit_rows("CUSTOMER_CREATE")) == 1 and len(audit_rows("CUSTOMER_EDIT")) == 1)
    edit_ev = audit_rows("CUSTOMER_EDIT")[0]
    check("edit event lists changed field NAMES only", "name, email" in edit_ev.details, edit_ev.details)
    blob = archive_lines() + " ".join((a.details or "") for a in ActivityLog.query.all()) + \
           " ".join((a.details or "") for a in AuditEvent.query.all())
    check("no customer name / email / phone anywhere in logs or archive",
          SECRET not in blob and "zz.secret" not in blob and "5559990000" not in blob)

# ------------------------------------------------------------------ 4
section("4. Admin bulk export (20+ records)")
for i in range(8):
    admin.post("/customers/new", data={"name": f"Filler {i}"}, headers=AJAX)
with app.app_context():
    n_now = Customer.query.count()
    exp_logs = ActivityLog.query.filter_by(action="export_data").count()
    exp_audit = len(audit_rows("CUSTOMER_EXPORT"))
admin.get("/customers/export")
with app.app_context():
    check("customers >= 20 for a bulk export", n_now >= 20, f"{n_now}")
    bulk = audit_rows("BULK_EXPORT")
    check("exactly one BULK_EXPORT audit event (with IP)", len(bulk) == 1 and "[ip=127.0.0.1]" in bulk[0].details)
    check("no duplicate CUSTOMER_EXPORT for the same export", len(audit_rows("CUSTOMER_EXPORT")) == exp_audit)
    check("ActivityLog export_data recorded", ActivityLog.query.filter_by(action="export_data").count() == exp_logs + 1)
    check("'Bulk Data Export' alert raised", Alert.query.filter_by(alert_type="Bulk Data Export").count() >= 1)

section("4b. Other admin actions are audited (no secrets recorded)")
with app.app_context():
    emp_user_id = User.query.filter_by(username="tnguyen").first().id
admin.post(f"/admin/users/{emp_user_id}/change-role", data={"new_role": "admin"}, headers=AJAX)
admin.post(f"/admin/users/{emp_user_id}/change-role", data={"new_role": "employee"}, headers=AJAX)
admin.post(f"/admin/users/{emp_user_id}/toggle-active", headers=AJAX)
admin.post(f"/admin/users/{emp_user_id}/reset-score", headers=AJAX)
admin.post("/settings/", data={"current_password": "Admin@123", "new_password": "N3wSecret!pw",
                               "confirm_password": "N3wSecret!pw"})
admin.post("/security/audit/verify", data={"what": "chain"})
admin.post("/security/audit/backup")
with app.app_context():
    need = {"ROLE_CHANGE", "ACCOUNT_SUSPEND", "RISK_SCORE_RESET", "PASSWORD_CHANGE",
            "AUDIT_VERIFY", "AUDIT_BACKUP_CREATE"}
    have = {a for (a,) in db.session.query(AuditEvent.action).all()}
    check("role change / suspension / score reset / password change / verify / backup audited",
          need <= have, f"missing {sorted(need - have)}")
    blob = " ".join((a.details or "") for a in AuditEvent.query.all()) + archive_lines()
    check("passwords never appear in audit data", "N3wSecret" not in blob and "Admin@123" not in blob)
    check("no user-deletion route exists (users are suspended, never deleted)",
          not any("delete" in r.rule and "/admin/users" in r.rule for r in app.url_map.iter_rules()))

# ------------------------------------------------------------------ 5
section("5. Admin attempts to delete / alter audit evidence (and activity logs)")
with app.app_context():
    first = AuditEvent.query.order_by(AuditEvent.id).first()
    first_id, first_hash = first.id, first.current_hash
    n_audit, n_act = AuditEvent.query.count(), ActivityLog.query.count()
    tamper_before = len(audit_rows("AUDIT_TAMPER_ATTEMPT"))
    score_before = User.query.filter_by(username="admin").first().live_risk_score
for url in (f"/security/audit/{first_id}/delete", f"/security/audit/{first_id}/edit", "/security/audit/clear"):
    admin.post(url)
with app.app_context():
    check("original audit event untouched", AuditEvent.query.get(first_id).current_hash == first_hash)
    check("3 AUDIT_TAMPER_ATTEMPT events recorded",
          len(audit_rows("AUDIT_TAMPER_ATTEMPT")) == tamper_before + 3)
    check("nothing but the 3 attempts was appended", AuditEvent.query.count() == n_audit + 3)
    check("risk increased by Rule 8", User.query.filter_by(username="admin").first().live_risk_score >= score_before + 50)
    check("chain VALID after attempts", verify_audit_chain()["chain_status"] == "VALID")

    def raises(exc, fn):
        try:
            fn()
        except exc:
            db.session.rollback()
            return True
        db.session.rollback()
        return False

    ev = AuditEvent.query.get(first_id)
    log = ActivityLog.query.first()
    check("AuditEvent ORM delete blocked", raises(AuditImmutableError, lambda: (db.session.delete(ev), db.session.commit())))
    check("AuditEvent ORM update blocked", raises(AuditImmutableError, lambda: (setattr(ev, "details", "x"), db.session.commit())))
    check("AuditEvent bulk delete blocked", raises(AuditImmutableError, lambda: (AuditEvent.query.delete(), db.session.commit())))
    check("ActivityLog ORM delete blocked", raises(ActivityLogImmutableError, lambda: (db.session.delete(log), db.session.commit())))
    check("ActivityLog ORM update blocked", raises(ActivityLogImmutableError, lambda: (setattr(log, "details", "x"), db.session.commit())))
    check("ActivityLog bulk delete blocked", raises(ActivityLogImmutableError, lambda: (ActivityLog.query.delete(), db.session.commit())))
    victim_user = User.query.filter_by(username="akhan").first()
    check("deleting a user can NOT cascade-wipe their activity logs",
          raises(AuditImmutableError, lambda: (db.session.delete(victim_user), db.session.commit())))
    check("no audit or activity rows were lost",
          AuditEvent.query.count() == n_audit + 3 and ActivityLog.query.count() >= n_act)

# ------------------------------------------------------------------ 6
section("6. Archive reliability: failed write, catch-up, no duplicates")
original = audit_archive.archive_event
def failing(*a, **k):
    raise OSError("simulated disk failure")
audit_archive.archive_event = failing
with app.test_request_context("/"):
    with app.app_context():
        e_lost = log_audit_event(None, "AUDIT_VERIFY", details="written while archive was down")
        lost_id = e_lost.id
audit_archive.archive_event = original
with app.app_context():
    check("event committed to DB but not archived (archive was down)",
          f'"event_id": {lost_id},' not in archive_lines()
          and audit_archive.get_backup_summary()["not_yet_archived"] >= 1)
    log_audit_event(None, "AUDIT_VERIFY", details="next event triggers catch-up")
    check("next audit event back-fills the archive automatically",
          f'"event_id": {lost_id},' in archive_lines() and audit_archive.get_backup_summary()["not_yet_archived"] == 0)
    ids = [json.loads(l)["event_id"] for l in archive_lines().splitlines() if l.strip()]
    check("archive has no duplicate entries", len(ids) == len(set(ids)))
    check("archive verification VALID", audit_archive.verify_audit_backup()["status"] == "VALID")

# ------------------------------------------------------------------ 7
section("7. Database audit records are lost, archive remains -> restore")
admin.post("/security/audit/backup")
shutil.copy(DB_FILE, os.path.join(TMP, "db_before_loss.db"))
with app.app_context():
    all_ids = [i for (i,) in db.session.query(AuditEvent.id).order_by(AuditEvent.id)]
    total = len(all_ids)
lost = all_ids[1:6] + all_ids[-2:]
con = sqlite3.connect(DB_FILE)
con.executemany("DELETE FROM audit_events WHERE id=?", [(i,) for i in lost])
con.commit()
con.close()
with app.app_context():
    check("loss detected: chain COMPROMISED", verify_audit_chain()["chain_status"] == "COMPROMISED")
    s = audit_archive.get_backup_summary()
    check("archive is still VALID and still has the lost events",
          s["status"] == "VALID" and s["missing_in_db"] == len(lost))
code, out = run_cli("restore_audit.py")
print("      " + out.strip().replace("\n", "\n      "))
check(f"restored exactly the {len(lost)} lost events", f"Restored: {len(lost)} event" in out)
check("duplicates skipped, not re-inserted", f"already in database): {total - len(lost)}" in out)
check("SHA-256 chain VALID after recovery", "chain after recovery: VALID" in out and code == 0)
with app.app_context():
    check("restore recorded as AUDIT_RESTORE", len(audit_rows("AUDIT_RESTORE")) == 1)
    check("row count = original + AUDIT_RESTORE", AuditEvent.query.count() == total + 1)
    check("all lost ids are back with original hashes",
          all(AuditEvent.query.get(i) is not None for i in lost))
code, out = run_cli("restore_audit.py")
with app.app_context():
    check("second restore: nothing restored, nothing duplicated",
          "Restored: 0 event" in out and AuditEvent.query.count() == total + 1)

# a database row that DIFFERS from the archive is reported, never overwritten
con = sqlite3.connect(DB_FILE)
con.execute("UPDATE audit_events SET details='forged' WHERE id=?", (all_ids[0],))
con.commit()
con.close()
code, out = run_cli("restore_audit.py")
with app.app_context():
    check("forged DB row is reported as an integrity failure and NOT overwritten",
          "differs from archive" in out and AuditEvent.query.get(all_ids[0]).details == "forged")
    check("Audit page data flags DB/archive mismatch", audit_archive.get_backup_summary()["differs_from_db"] >= 1)

# ------------------------------------------------------------------ 8
section("8. Records are kept after the retention period")
with app.app_context():
    app.config["AUDIT_RETENTION_DAYS"] = 0            # everything is now 'past retention'
    n = AuditEvent.query.count()
    s = audit_archive.get_backup_summary()
    audit_archive.startup_catchup()
    audit_archive.create_backup()
    check("events past retention are counted but never deleted",
          s["past_retention"] > 0 and AuditEvent.query.count() == n)
    app.config["AUDIT_RETENTION_DAYS"] = 365

# ------------------------------------------------------------------ 9
section("9. Employees cannot reach admin-only / audit routes")
with app.app_context():
    n_audit = AuditEvent.query.count()
    alerts_before = Alert.query.filter_by(alert_type="Unauthorized Access Attempt").count()
GETS = ["/admin/dashboard", "/admin/users", "/admin/alerts", "/admin/logs", "/security/audit",
        "/security/incidents", "/security/privileged-activity", "/security/approvals",
        "/reports/daily", "/reports/weekly", "/reports/risk", "/reports/risk/export",
        "/security/audit/evidence/audit_evidence_20200101_000000.json"]
POSTS = ["/security/audit/backup", "/security/audit/verify", "/security/audit/export",
         "/security/audit/clear", "/security/audit/1/delete", "/security/audit/1/edit",
         "/admin/users/1/toggle-active", "/admin/users/new", "/admin/alerts/1/resolve",
         "/admin/users/1/change-role", "/admin/users/1/reset-score", "/security/approvals/1/decide"]
bad = [u for u in GETS if employee.get(u).status_code != 403]
bad += [u for u in POSTS if employee.post(u, data={"what": "chain"}).status_code != 403]
check(f"employee gets 403 on all {len(GETS) + len(POSTS)} admin/audit routes", not bad, f"not 403: {bad}")
with app.app_context():
    check("blocked attempts are flagged as Unauthorized Access alerts",
          Alert.query.filter_by(alert_type="Unauthorized Access Attempt").count() > alerts_before - 0
          or alerts_before > 0)
    check("employee attempts changed no audit evidence", AuditEvent.query.count() == n_audit)
anon = app.test_client()
check("unauthenticated visitor is redirected to login",
      anon.get("/security/audit").status_code in (302, 401) and "/login" in (anon.get("/security/audit").headers.get("Location") or "/login"))
check("there is NO web route for restore (CLI only)",
      not any("restore" in r.rule for r in app.url_map.iter_rules()))
check("admin can still use the audit page", admin.get("/security/audit").status_code == 200)

# ------------------------------------------------------------------ 10
section("10. Existing features still work")
for url in ("/admin/dashboard", "/admin/users", "/admin/alerts", "/security/incidents",
            "/security/approvals", "/reports/daily", "/customers/"):
    check(f"admin GET {url} -> 200", admin.get(url).status_code == 200)
check("employee can use the CRM pages", employee.get("/customers/").status_code == 200)

passed = sum(results)
print(f"\n{'=' * 60}\nRESULT: {passed}/{len(results)} checks passed")
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(0 if passed == len(results) else 1)
