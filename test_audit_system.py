"""
test_audit_system.py - end-to-end checks for the audit retention / backup system.

    python test_audit_system.py

SAFE: it runs against a throw-away database and archive folder in a temp
directory (via DATABASE_URL / AUDIT_BACKUP_DIR). Your real
instance/cybercrm.db and audit_backups/ are never touched.
"""
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="cybercrm_audit_test_")
DB_FILE = os.path.join(TMP, "test.db")
ARCHIVE = os.path.join(TMP, "audit_backups")
os.environ["DATABASE_URL"] = "sqlite:///" + DB_FILE
os.environ["AUDIT_BACKUP_DIR"] = ARCHIVE
os.environ["AUDIT_RETENTION_DAYS"] = "60"          # demo value (test J)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

import seed                                         # noqa: E402  (uses the env above)
from extensions import db                           # noqa: E402
from models import (AuditEvent, ActivityLog, Alert, User, Customer,   # noqa: E402
                    SecurityIncident, ApprovalRequest, AuditImmutableError)
from utils import audit_archive                     # noqa: E402
from utils.audit import verify_audit_chain          # noqa: E402

results = []


def check(name, ok, extra=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({extra})" if extra else ""))


def section(title):
    print(f"\n{title}")


seed.seed()
app = seed.app
app.config["TESTING"] = True
client = app.test_client()


def audit_count():
    with app.app_context():
        return AuditEvent.query.count()


def run_cli(script, *args):
    env = dict(os.environ)
    p = subprocess.run([sys.executable, script, *args], cwd=HERE, env=env,
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


# ---------------------------------------------------------------- A
section("A. Normal audit event creation (admin demo actions)")
r = client.post("/login", data={"username": "admin", "password": "Admin@123"})
check("admin login succeeds", r.status_code == 302)
with app.app_context():
    login_evt = AuditEvent.query.filter_by(action="LOGIN").order_by(AuditEvent.id.desc()).first()
    check("LOGIN written to AuditEvent", login_evt is not None)
    cust = Customer.query.first()
    cust_id = cust.id
    emp = User.query.filter_by(username="jsmith").first()
    emp_id = emp.id
    admin2_id = User.query.filter_by(username="admin2").first().id

before_view = 0
with app.app_context():
    before_view = ActivityLog.query.filter_by(action="view_customer").count()
client.get(f"/customers/{cust_id}")
r = client.post(f"/customers/{cust_id}/edit",
                data={"name": "Edited By Test", "email": "edited.test@example.com",
                      "phone": "5551234567", "company": "TestCo", "address": "1 Test St", "notes": ""},
                headers={"X-Requested-With": "XMLHttpRequest"})
check("edit customer works", r.status_code == 200)
for i in range(7):   # make >=20 customers so the export counts as BULK
    client.post("/customers/new", data={"name": f"Bulk Filler {i}"},
                headers={"X-Requested-With": "XMLHttpRequest"})
victim = None
with app.app_context():
    victim = Customer.query.filter_by(name="Bulk Filler 0").first().id
r = client.post(f"/customers/{victim}/delete", headers={"X-Requested-With": "XMLHttpRequest"})
check("delete customer works", r.status_code == 200)
for i in range(1, 3):   # keep >= 20 customers after the delete
    client.post("/customers/new", data={"name": f"Bulk Filler B{i}"},
                headers={"X-Requested-With": "XMLHttpRequest"})
r = client.get("/customers/export")
check("bulk export works", r.status_code == 200)
r = client.post(f"/admin/users/{emp_id}/toggle-active", headers={"X-Requested-With": "XMLHttpRequest"})
check("suspend user works", r.status_code == 200)
client.post(f"/admin/users/{emp_id}/toggle-active", headers={"X-Requested-With": "XMLHttpRequest"})  # re-activate
client.post(f"/admin/users/{emp_id}/revoke-session", headers={"X-Requested-With": "XMLHttpRequest"})

with app.app_context():
    acts = {a for (a,) in db.session.query(ActivityLog.action).all()}
    check("ActivityLog has view/edit/delete/export",
          {"view_customer", "edit_customer", "delete_customer", "export_data"} <= acts)
    check("no duplicate ActivityLog row for one view",
          ActivityLog.query.filter_by(action="view_customer").count() == before_view + 1)
    audit_actions = {a for (a,) in db.session.query(AuditEvent.action).all()}
    need = {"LOGIN", "USER_CREATE", "ACCOUNT_SUSPEND", "ACCOUNT_ACTIVATE", "SESSION_REVOKE", "BULK_EXPORT"}
    check("AuditEvent has LOGIN/ACCOUNT_SUSPEND/ACTIVATE/SESSION_REVOKE/BULK_EXPORT",
          need <= audit_actions, f"missing: {sorted(need - audit_actions)}")

# ---------------------------------------------------------------- B
section("B. Audit chain verification")
with app.app_context():
    chain = verify_audit_chain()
check("SHA-256 chain is VALID", chain["chain_status"] == "VALID", f"{chain['total']} events")

# ---------------------------------------------------------------- auto-archive
with app.app_context():
    s = audit_archive.get_backup_summary()
check("every new event was auto-archived", s["not_yet_archived"] == 0,
      f"archived {s['archived_events']}")

# ---------------------------------------------------------------- C / D / E
section("C. Backup creation  D. Backup verification  E. Duplicate prevention")
r = client.post("/security/audit/backup")
check("[Create Backup] button works", r.status_code == 302)
files = glob.glob(os.path.join(ARCHIVE, "audit_*.jsonl"))
check("archive .jsonl + .sha256 exist", bool(files) and all(os.path.exists(f + ".sha256") for f in files))
with app.app_context():
    rep = audit_archive.verify_audit_backup()
check("backup verifies VALID", rep["status"] == "VALID")
with app.app_context():
    again = audit_archive.create_backup()
    n_db = AuditEvent.query.count()
    lines = sum(1 for f in files for _ in open(f))
check("second backup writes 0 new records", again["written"] == 0)
with app.app_context():
    ev = AuditEvent.query.first()
    check("archiving an already-archived event is refused", audit_archive.archive_event(ev) is False)
check("archive lines == unique events (no duplicates)", lines == n_db, f"{lines} lines / {n_db} events")
rec = json.loads(open(files[0]).readline())
check("archive record has all required fields", set(audit_archive.REQUIRED_FIELDS) <= set(rec))

# ---------------------------------------------------------------- F
section("F. Evidence export")
pre = audit_count()
r = client.post("/security/audit/export", data={"date_from": "2020-01-01", "date_to": "2099-12-31",
                                                "action": "", "user_id": "", "target_type": "user"},
                follow_redirects=True)
html = r.get_data(as_text=True)
check("export message shows record count + SHA-256",
      "Evidence exported successfully" in html and "SHA-256:" in html)
ev_files = glob.glob(os.path.join(ARCHIVE, "evidence", "audit_evidence_*.json"))
check("evidence .json + .sha256 created", len(ev_files) == 1 and os.path.exists(ev_files[0] + ".sha256"))
doc = json.load(open(ev_files[0]))
meta = doc["chain_of_custody"]
check("custody metadata complete",
      all(k in meta for k in ("export_timestamp_utc", "exported_by", "date_range", "filters_used",
                              "record_count", "source_system")) and meta["exported_by"]["username"] == "admin")
check("record_count matches records", meta["record_count"] == len(doc["records"]) > 0)
check("records contain required fields",
      all(k in doc["records"][0] for k in ("timestamp", "user", "action", "target", "details",
                                           "risk_level", "previous_hash", "current_hash")))
stored = open(ev_files[0] + ".sha256").read().split()[0]
check("evidence checksum matches file", stored == audit_archive.sha256_file(ev_files[0]))
bad = client.post("/security/audit/export", data={"date_from": "2099-01-01", "date_to": "2020-01-01"},
                  follow_redirects=True)
check("invalid date range rejected", "must not be after" in bad.get_data(as_text=True))

# ---------------------------------------------------------------- G / H
section("G. Audit deletion blocking  H. Tamper attempt logging")
with app.app_context():
    target_id = AuditEvent.query.order_by(AuditEvent.id.asc()).first().id
    target_hash = AuditEvent.query.get(target_id).current_hash
    count_before = AuditEvent.query.count()
    score_before = User.query.filter_by(username="admin").first().live_risk_score
r = client.post(f"/security/audit/{target_id}/delete")
check("delete route returns redirect and blocks", r.status_code == 302)
client.post(f"/security/audit/{target_id}/edit")
client.post("/security/audit/clear")
with app.app_context():
    still = AuditEvent.query.get(target_id)
    check("original audit event still exists unchanged", still is not None and still.current_hash == target_hash)
    attempts = AuditEvent.query.filter_by(action="AUDIT_TAMPER_ATTEMPT").count()
    check("AUDIT_TAMPER_ATTEMPT recorded for delete/edit/clear", attempts == 3, f"{attempts}")
    check("only tamper-attempt events were appended",
          AuditEvent.query.count() == count_before + 3)
    score_after = User.query.filter_by(username="admin").first().live_risk_score
    check("risk score increased (Rule 8, +50)", score_after >= score_before + 50,
          f"{score_before} -> {score_after}")
    check("'Audit Tampering Attempt' alert raised",
          Alert.query.filter_by(alert_type="Audit Tampering Attempt").count() >= 1)
    check("chain still VALID after attempts", verify_audit_chain()["chain_status"] == "VALID")

    # server-side ORM guard (not just hidden buttons)
    def raises(fn):
        try:
            fn()
        except AuditImmutableError:
            db.session.rollback()
            return True
        db.session.rollback()
        return False

    ev = AuditEvent.query.get(target_id)

    def do_delete():
        db.session.delete(ev)
        db.session.commit()

    def do_update():
        ev.details = "changed"
        db.session.commit()

    def do_bulk_delete():
        AuditEvent.query.delete()
        db.session.commit()
    check("ORM delete blocked", raises(do_delete))
    check("ORM update blocked", raises(do_update))
    check("ORM bulk delete blocked", raises(do_bulk_delete))
    check("nothing was lost by the attempts", AuditEvent.query.count() == count_before + 3)

# employee cannot reach any audit route
client.get("/logout")
client.post("/login", data={"username": "tnguyen", "password": "Employee@123"})
for url in (f"/security/audit/{target_id}/delete", "/security/audit/clear", "/security/audit/backup"):
    check(f"employee blocked from {url}", client.post(url).status_code == 403)
client.get("/logout")
client.post("/login", data={"username": "admin", "password": "Admin@123"})

# ---------------------------------------------------------------- J
section("J. Retention display")
page = client.get("/security/audit").get_data(as_text=True)
check("page shows 'Audit Retention: 60 days'", "Audit Retention: 60 days" in page)
check("page shows Archived Events / Last Backup / Backup Status / Audit Chain",
      all(t in page for t in ("Archived Events", "Last Backup", "Backup Status", "Audit Chain")))
check("page has the 4 buttons", all(t in page for t in
      ("Verify Audit Chain", "Verify Backup", "Create Backup", "Export Evidence")))
check("no page link/form can delete an audit event except the always-blocked simulator",
      "/security/audit/clear" not in page)

# ---------------------------------------------------------------- I
section("I. Audit recovery (simulated database loss)")
client.post("/security/audit/backup")      # archive the tamper-attempt events too
db_backup = os.path.join(TMP, "test_before_loss.db")
shutil.copy(DB_FILE, db_backup)             # backup BEFORE touching anything
with app.app_context():
    total = AuditEvent.query.count()
    ids = [i for (i,) in db.session.query(AuditEvent.id).order_by(AuditEvent.id).all()]
lost = ids[2:5] + ids[-2:]                  # a middle block + the tail
con = sqlite3.connect(DB_FILE)              # raw SQL = "database loss" outside the app
con.executemany("DELETE FROM audit_events WHERE id=?", [(i,) for i in lost])
con.commit()
con.close()
with app.app_context():
    broken = verify_audit_chain()
    check("loss is detected (chain COMPROMISED)", broken["chain_status"] == "COMPROMISED")
    check("page flags archived events missing from DB",
          audit_archive.get_backup_summary()["missing_in_db"] == len(lost))
code, out = run_cli("restore_audit.py", "--dry-run")
check("dry run reports the missing events and changes nothing",
      f"Would restore: {len(lost)}" in out and audit_count() == total - len(lost))
code, out = run_cli("restore_audit.py")
print("      " + out.strip().replace("\n", "\n      "))
check("restore reports restored count", f"Restored: {len(lost)} event" in out)
check("restore reports skipped duplicates", f"Skipped duplicates (already in database): {total - len(lost)}" in out)
check("chain is VALID after recovery", "chain after recovery: VALID" in out and code == 0)
check("row count fully recovered (+1 AUDIT_RESTORE event recording the restore)",
      audit_count() == total + 1)
with app.app_context():
    check("restore itself was recorded as AUDIT_RESTORE",
          AuditEvent.query.filter_by(action="AUDIT_RESTORE").count() == 1)
code, out = run_cli("restore_audit.py")
check("running restore again creates no duplicates",
      "Restored: 0 event" in out and audit_count() == total + 1)

# archive tampering is detected and rejected
arch = sorted(glob.glob(os.path.join(ARCHIVE, "audit_*.jsonl")))[0]
orig = open(arch).read()
with open(arch, "a") as f:
    f.write(json.dumps({"event_id": 99999, "forged": True}) + "\n")
with app.app_context():
    check("modified archive file -> backup COMPROMISED",
          audit_archive.verify_audit_backup()["status"] == "COMPROMISED")
code, out = run_cli("backup_audit.py", "--verify")
check("backup_audit.py --verify reports COMPROMISED", "COMPROMISED" in out and code == 1)
code, out = run_cli("restore_audit.py")
check("restore rejects the modified archive file", "checksum mismatch" in out)
open(arch, "w").write(orig)
with app.app_context():
    check("original archive restored -> VALID again",
          audit_archive.verify_audit_backup()["status"] == "VALID")
code, out = run_cli("backup_audit.py")
check("backup_audit.py CLI runs (no duplicates)", "0 new event(s) archived" in out and code == 0)

# ---------------------------------------------------------------- K
section("K. Existing features still work")
with app.app_context():
    check("security incident INC-001 exists with linked alerts",
          SecurityIncident.query.count() >= 1 and Alert.query.filter(Alert.incident_id.isnot(None)).count() >= 4)
    check("alerts/risk score exist", Alert.query.count() > 0 and
          User.query.filter_by(username="mrodriguez").first().live_risk_score > 0)
for url in ("/admin/dashboard", "/admin/users", "/admin/alerts", "/admin/logs", "/security/incidents",
            "/security/privileged-activity", "/security/approvals", "/reports/daily", "/reports/risk",
            "/customers/", "/security/audit"):
    check(f"GET {url} -> 200", client.get(url).status_code == 200)
r = client.post(f"/admin/users/{admin2_id}/toggle-active", headers={"X-Requested-With": "XMLHttpRequest"})
with app.app_context():
    check("dual authorization still creates a PENDING approval",
          ApprovalRequest.query.filter_by(status="PENDING").count() == 1)

passed, total_checks = sum(results), len(results)
print(f"\n{'=' * 60}\nRESULT: {passed}/{total_checks} checks passed")
print(f"(temp files in {TMP})")
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(0 if passed == total_checks else 1)
