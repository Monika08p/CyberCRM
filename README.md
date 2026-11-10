# CyberCRM Guardian
### Rule-Based Insider Threat Detection with Privileged User Monitoring, Risk Scoring, Incident Correlation and Tamper-Evident Auditing

A cybersecurity-focused CRM monitoring system built with Flask. It detects
insider threats — from **both employees and administrators** — using a
**purely rule-based** detection engine (no ML, no blockchain), correlates
related alerts into Security Incidents, and keeps a tamper-evident audit
trail of every privileged action.

> **Core principle:** *Privileges determine what a user is allowed to do,
> but privileges do not make the user's activity invisible to security
> monitoring.*

---

## 1. Architecture

```
Login
  ↓
User Activity  (employee OR admin)
  ↓
Activity Log  +  Tamper-Evident Audit Log (privileged actions)
  ↓
Rule-Based Detection Engine  (employee rules + privileged-user rules)
  ↓
Risk Score  (capped display at 100)
  ↓
Risk Level  (Low / Medium / High / Critical)
  ↓
Security Alert
  ↓
Event Correlation  (2+ unresolved alerts for the same user, 60-min window)
  ↓
Security Incident  (OPEN → UNDER_INVESTIGATION → CONTAINED → RESOLVED / FALSE_POSITIVE)
  ↓
Investigation  (self-investigation blocked for the suspect's own account)
  ↓
Response  (Suspend* / Revoke Session / Disable Privileged Access / Reset Score)
  ↓
Resolution

* Suspending a PRIVILEGED account requires a second, different admin's
  approval (dual authorization / two-person rule).
```

### Folder structure (new/changed files only)
```
cybercrm_guardian/
├── config.py                 # + privileged rule points & thresholds, updated risk levels
├── models.py                 # + AuditEvent, SecurityIncident, ApprovalRequest, Alert.incident_id, User.session_version
├── app.py                    # + security blueprint, session-revocation enforcement
├── seed.py                   # + 2nd admin account, seeded audit events
├── routes/
│   ├── admin.py                 # + create user, change role, revoke session, disable privileged, dual-auth on suspend
│   └── security.py              # NEW — Incidents, Audit Integrity, Privileged Activity, Approvals
├── utils/
│   ├── audit.py                  # NEW — SHA-256 hash-chained tamper-evident audit log
│   ├── incidents.py               # NEW — alert correlation into Security Incidents
│   ├── detection.py                # + 7 privileged-user rules (Rules 1-8, minus Rule 6 which is generic)
│   └── risk_engine.py               # + reason labels for the new rules
└── templates/
    ├── incidents.html, incident_detail.html, audit_integrity.html,
    │   privileged_activity.html, approvals.html                       # NEW
    ├── admin_dashboard.html            # + Privileged Users / Critical Incidents / Audit chain status cards
    ├── admin_users.html                # + Add User modal, privileged badges
    └── investigate_user.html           # + self-investigation banner, role change, revoke session, disable privileged
```

---

## 2. Database changes

| Table | Change |
|---|---|
| `users` | + `session_version` (int) — bumped by "Revoke Session"; a mismatch between the browser session and this value forces logout |
| `alerts` | + `incident_id` (FK, nullable) — which Security Incident this alert was correlated into |
| `audit_events` | **NEW** — the tamper-evident hash chain (see below) |
| `security_incidents` | **NEW** — correlated cases: code, suspect, severity, risk score, status, investigator, resolution notes |
| `approval_requests` | **NEW** — dual-authorization queue: action type, target, requester, decider, status |

No existing table was removed or renamed. Since this is SQLite in
development, the schema change is applied by **deleting
`instance/cybercrm.db` and re-running `python seed.py`** (see Setup).

---

## 3. Security rules implemented

### Existing employee/general rules (unchanged, and already apply to admins too since they check the acting user generically)
| Rule | Points | Severity |
|---|---|---|
| Multiple failed logins (3+/10min) | +30 | High |
| Off-hours login | +15 | Low |
| Excessive record viewing (10+/min) | +20 | Medium |
| Multiple deletions (3+/15min) | +50 | Critical |
| Bulk data export (20+ records) | +40 | High |
| Unauthorized access attempt | +80 | Critical |

### New privileged-user rules (Feature 2)
| # | Rule | Trigger | Points | Severity |
|---|---|---|---|---|
| 1 | Privilege Escalation | Admin promotes a user to ADMIN | +30 | High |
| 2 | Multiple Privilege Changes | 2+ role changes by the same admin in 30 min | +40 | High |
| 3 | New Privileged Account | Admin directly creates another admin account | +50 | Critical |
| 4 | Mass Account Modification | 4+ account-touching actions in 15 min | +40 | High |
| 5 | Off-Hours Admin Action | Sensitive admin op outside office hours | +20 | Medium |
| 6 | Bulk Export (admin) | Reuses the generic bulk-export rule above | +40 | High |
| 7 | Suspicious Alert Manipulation | 3+ alerts resolved within 5 min | +40 | High |
| 8 | Audit Tampering Attempt | Any attempt to modify/delete audit evidence | +50 | Critical |

All thresholds live in `config.py` (`PRIVILEGE_CHANGE_WINDOW_MIN`,
`MAX_PRIVILEGE_CHANGES`, `MASS_MODIFICATION_WINDOW_MIN`,
`MAX_ACCOUNT_MODIFICATIONS`, `RAPID_ALERT_RESOLUTION_WINDOW_MIN`,
`MAX_ALERTS_RESOLVED_RAPIDLY`, `BULK_EXPORT_ROW_THRESHOLD`, etc.) —
nothing is hard-coded inside the rule functions themselves.

### Risk levels (Feature 9)
```
0–30     Low
31–60    Medium
61–80    High
81–100+  Critical      (raw score keeps accumulating; on-screen gauges
                         cap the DISPLAYED number at 100 via
                         User.display_risk_score())
```

---

## 4. Tamper-Evident Audit Logging (Feature 3 & 4)

Every privileged/security-sensitive action (login, logout, role change,
user creation, suspend/activate, alert resolution, incident actions,
approval decisions, session revocation, privilege revocation) is written
to `AuditEvent` using **SHA-256 hash chaining** — not blockchain, not ML:

```
Event 1                → current_hash = SHA256(fields_1 + "0"*64)
Event 2 (prev=Hash 1)   → current_hash = SHA256(fields_2 + Hash 1)
Event 3 (prev=Hash 2)   → current_hash = SHA256(fields_3 + Hash 2)
...
```

`utils/audit.py:verify_audit_chain()` recomputes every hash from the
currently stored field values. If any field of an old row is edited
directly in the database, its recomputed hash no longer matches the
stored one — and because each hash feeds the next, every event after it
is flagged too, exactly like a real tamper-evident log. This was
verified by directly editing a row with raw SQL — see Testing below.

The **Audit Integrity** page (`/security/audit`) shows Total / Verified
/ Tampered event counts, chain status (VALID / COMPROMISED), and the
first affected event if tampering is found. A "security test" button
lets you demonstrate Rule 8 safely — it **never actually modifies any
evidence**, it only raises the Critical alert that a real tampering
attempt would.

---

## 5. Event Correlation & Incident Management (Feature 5 & 6)

`utils/incidents.py:correlate_and_create_incident()` runs every time a
new alert is raised. If a user now has 2+ *unresolved* alerts within a
60-minute window, they're grouped into one `SecurityIncident` (reusing
an already-open incident for that user rather than creating duplicates).

Incident statuses: `OPEN → UNDER_INVESTIGATION → CONTAINED → RESOLVED`
or `FALSE_POSITIVE`. Each incident tracks its investigator and
resolution notes.

---

## 6. Self-Investigation Restriction & Dual Authorization (Feature 7 & 8)

- **Self-investigation restriction**: every response route (`toggle-active`,
  `change-role`, `revoke-session`, `disable-privileged`, and the incident
  action route) checks whether the target account is the acting admin's
  own — if so, the action is refused with a clear "SELF-INVESTIGATION
  RESTRICTED" message, enforced server-side (not just a hidden button).
- **Dual authorization**: suspending a **privileged (admin)** account
  doesn't happen immediately — it creates a pending `ApprovalRequest`.
  A *different* admin must review and approve it at `/security/approvals`;
  the system explicitly rejects an approval decided by the same admin
  who requested it.

---

## 7. Setup & Run

```bash
cd cybercrm_guardian
pip install -r requirements.txt

# Schema changed in this version (new tables/columns) — reset the DB:
rm -f instance/cybercrm.db
python seed.py

python app.py
```
Open **http://127.0.0.1:5000**

### Demo accounts
| Username | Password | Role |
|---|---|---|
| admin | Admin@123 | Admin |
| admin2 | Admin@123 | Admin (2nd admin — needed for dual-auth / self-investigation demo) |
| jsmith | Employee@123 | Employee |
| mrodriguez | Employee@123 | Employee (seeded with rule violations) |
| akhan | Employee@123 | Employee (seeded failed-login alert) |
| tnguyen | Employee@123 | Employee |

---

## 8. Test cases (all executed against a live server during development)

| # | Scenario | Result |
|---|---|---|
| 1 | Normal employee login/activity | Low risk, no alert ✅ |
| 2 | Suspicious employee (bulk viewing/deletes/export) | Alerts raised, existing rules unaffected ✅ |
| 3 | Normal admin login | No alert, logged to AuditEvent only ✅ |
| 4 | **Privilege escalation** — admin promotes employee to admin | "Privilege Escalation" alert, +30 ✅ |
| 5 | **New admin account created** | "New Privileged Account Created" alert, +50 Critical ✅ |
| 6 | **Bulk export by admin** (22 records) | "Bulk Data Export" alert, +40 ✅ |
| 7 | **Audit tampering — safe demo route** | Alert raised, chain stays VALID (route never writes) ✅ |
| 8 | **Audit tampering — real DB edit via raw SQL** | Chain correctly reports COMPROMISED, names exact event # ✅ |
| 9 | **Event correlation** | 2+ alerts for `admin` auto-grouped into `INC-001 "Privileged Insider Incident"`, Critical ✅ |
| 10 | **Self-investigation restriction** | Admin blocked from suspending/investigating their own account, server-enforced ✅ |
| 11 | **Dual authorization** | Suspend-admin request created; requester's own approval attempt rejected (403); a different admin's approval executes the suspension ✅ |
| 12 | **Session revocation** | Revoked user's very next request is force-logged-out with a clear message ✅ |
| 13 | RBAC on new Security blueprint | Employee gets 403 on all `/security/*` routes ✅ |
| 14 | All pages / static assets | Every route returns 200, no 500s, zero raw tracebacks ✅ |

---

## 9. Demo procedure (Scenario 3 — malicious administrator, the key demo)

1. Log in as `admin`.
2. **Users → Change Role** an employee to `admin` (or use the investigate page). → Privilege Escalation alert.
3. **Customers → Add ~10 more** (to cross the 20-record bulk threshold), then **Export CSV**. → Bulk Data Export alert.
4. **Security → Audit Integrity** → click the small warning-triangle "security test" button on any event. → Audit Tampering Attempt alert (nothing is actually modified).
5. **Security → Incidents** → a new `INC-00X "Privileged Insider Incident"`, Critical, has appeared automatically.
6. Open it → try to act on it *if you're still logged in as the same admin* → **blocked**, "SELF-INVESTIGATION RESTRICTED".
7. Log out, log in as `admin2` → open the same incident → respond: Suspend / Revoke Session / mark Resolved.
8. If suspending a privileged account: it goes to **Security → Approvals** as PENDING instead of executing immediately — a third admin (or `admin` logging back in) can see it's awaiting someone *other than the requester*.

---

## 10. Viva talking points

- "This is fully rule-based — every alert traces to one named rule and a
  fixed point value in `config.py`. There's no model, no training data."
- "The system doesn't blindly trust the admin role — the same detection
  functions that watch employees (excessive viewing, deletes, off-hours
  login) run against admin accounts too, plus eight extra rules specific
  to privileged actions."
- "Tamper-evidence is a classic SHA-256 hash chain, not blockchain — I
  can prove it works by editing a row directly with SQL and showing the
  Audit Integrity page immediately flags it."
- "Self-investigation restriction and dual authorization exist because
  the biggest weakness of 'admin monitors everyone' is 'who monitors the
  admin' — those two features directly answer that."

---

## 11. Limitations

- Single "admin" role is used as the stand-in for "privileged user" —
  there's no finer-grained RBAC (e.g. a separate "security officer" role
  distinct from "admin who also does CRM work").
- Event correlation is a simple count-within-window rule, not a graph/
  causality engine — sufficient for a final-year project, not for a
  production SIEM.
- Session revocation relies on the next request hitting `before_request`
  — a user mid-download or on a very long-polling request would not be
  interrupted until their next navigation.
- SQLite + `db.drop_all()/create_all()` in `seed.py` means schema
  upgrades require a full reset in this dev setup; a production system
  would use real migrations (e.g. Alembic).

## 12. Future enhancements

- A dedicated "Security Officer" role distinct from "Admin" so day-to-day
  CRM admin work and security response are held by different people by
  design, not just by convention.
- Export the audit chain (or a signed digest of it) to external
  write-once storage so verification doesn't rely solely on the same
  database the attacker might have access to.
- IP-address / device fingerprint correlation for the incident timeline.
- Alembic migrations instead of full DB resets.

---

## 13. Audit Log Retention, Backup & Recovery

The SHA-256 chain (section 4) *detects* tampering, but if `instance/cybercrm.db`
is deleted the evidence is gone. So audit events are also kept in a **separate,
append-only archive**.

```
User/Admin Action -> ActivityLog / AuditEvent -> SHA-256 hash chain -> Primary DB
                 -> Separate archive (audit_backups/*.jsonl + .sha256)
                 -> Integrity check -> Evidence export / Recovery
```

| Piece | Where | What it does |
|---|---|---|
| Retention setting | `config.py` `AUDIT_RETENTION_DAYS` (env var, default 365) | Shown on the Audit Integrity page. **Nothing is auto-deleted** in this academic version. Try `AUDIT_RETENTION_DAYS=60 python app.py`. |
| Append-only guard | `models.py` (`AuditImmutableError`) | Any ORM update/delete/bulk-delete of an `AuditEvent` is refused on the **server side**. |
| Tamper handling | `routes/security.py` | Edit/delete/clear routes never touch the table; they record `AUDIT_TAMPER_ATTEMPT` and apply the existing Rule 8 (+50, Critical alert). |
| Automatic archive | `utils/audit_archive.py` | Every committed audit event is appended to `audit_backups/audit_YYYY-MM-DD.jsonl` (structured JSON: id, timestamp, user id + name, action, target, details, risk level, previous/current hash). Already-archived ids are skipped. |
| File checksums | `audit_*.jsonl.sha256` | SHA-256 of each archive file; `verify_audit_backup()` reports **VALID / COMPROMISED** (it also recomputes every record hash and chain link). |
| Manual backup | `python backup_audit.py` (`--verify` to only check) | Archives anything missing; safe to repeat. |
| Recovery | `python restore_audit.py` (`--dry-run` to preview) | Inserts only events missing from the DB, preserving ids, timestamps and hashes; rejects archive files with a bad checksum; never overwrites existing rows; reports restored / skipped / integrity failures, then re-verifies the chain. |
| Evidence export | Audit Integrity page -> **Export Evidence** | Filter by date range, user, action, target type. Writes `audit_backups/evidence/audit_evidence_YYYYMMDD_HHMMSS.json` + `.sha256`, with chain-of-custody metadata (export time, exported by, range, filters, record count, source system, chain status). The exact SHA-256 is shown to the admin. |

### What is audited, and where

| Action | `ActivityLog` (all users) | `AuditEvent` (tamper-evident chain + archive) |
|---|---|---|
| Customer view | `view_customer` | - (high volume; watched by the excessive-viewing rule) |
| Customer create | `create_customer` | `CUSTOMER_CREATE` - admins |
| Customer edit | `edit_customer` | `CUSTOMER_EDIT` - admins (lists changed field *names* only) |
| Customer delete | `delete_customer` | `CUSTOMER_DELETE` - **every role** (destructive) |
| Customer export | `export_data` | `BULK_EXPORT` (20+ rows, any role) or `CUSTOMER_EXPORT` (admins, smaller) - exactly one event per export |
| Login / logout / failed login | yes | `LOGIN` / `LOGOUT` - admins |
| User creation, role change, suspend / activate, session revoke, privilege revoke, risk-score reset, own password change | - | `USER_CREATE`, `ROLE_CHANGE`, `ACCOUNT_SUSPEND`, `ACCOUNT_ACTIVATE`, `SESSION_REVOKE`, `PRIVILEGE_REVOKED`, `RISK_SCORE_RESET`, `PASSWORD_CHANGE` |
| Alert resolve, incident status, approval request/decision | - | `ALERT_RESOLVE`, `INCIDENT_STATUS_CHANGE`, `APPROVAL_REQUEST`, `APPROVAL_DECISION` |
| Audit management | - | `AUDIT_VERIFY`, `AUDIT_BACKUP_CREATE`, `EVIDENCE_EXPORT`, `EVIDENCE_DOWNLOAD`, `AUDIT_RESTORE`, `AUDIT_TAMPER_ATTEMPT` |

Every record stores who, when, target id, action and the request **IP address**
(`ActivityLog.ip_address`; for `AuditEvent` it is appended to `details` as `[ip=...]`
so the hash covers it - it is the socket address, proxy headers are not trusted).
**Passwords and customer personal data (names, e-mails, phones, addresses) are never
written to either log** - only IDs and field names.

Users are never deleted in this application (accounts are suspended), so there is no
user-deletion route. Even if one were added later, `User -> ActivityLog` has a
delete cascade, which the model-layer guard now blocks so activity history cannot be
wiped that way.

### Who can do what
Evidence is **append-only for every role, admins included**: no route and no ORM call can update
or delete an `AuditEvent` **or an `ActivityLog` row** (blocked in `models.py`; attempts through
the routes are recorded as `AUDIT_TAMPER_ATTEMPT` with the existing Rule 8). All
admin, audit, backup, evidence and report routes use `@admin_required`, so employees
get HTTP 403 (and an "Unauthorized Access" alert); restore is a command-line tool only - there is no
web route for it. `ActivityLog` is protected from the application but, unlike `AuditEvent`, is
not hash-chained, which is why admin-level and destructive actions are mirrored into `AuditEvent`.

### Reliable archiving
Each committed audit event is copied to the archive right after the commit. If that write fails the
failure is remembered and the **next audit event, the next app start, or `python backup_audit.py`**
back-fills everything missing. Duplicates are impossible (existing ids are skipped, writes are
locked across processes). The Audit page also compares the database with the archive and warns if
events are un-archived, missing from the database, or *differ* between the two.
`AuditEvent` ids use SQLite `AUTOINCREMENT`, so a lost event's id is never reused by a newer event
(new databases). After a database loss, **run `restore_audit.py` before using the app again**.

### Where the archive lives (read this)
The default `audit_backups/` is a folder next to the app. **That is NOT protected against anyone who
has full operating-system access to the machine** (they can edit or delete the database, the archive
and its checksum files together). The Audit page says so while the archive is local. It protects
against accidental loss/corruption and against changes made through the application; it is
not tamper-proof and not a legally compliant evidence store.

**Configure an external, restricted location** (no code change, no cloud credentials):
```bash
# Linux/macOS: a separate volume or mount, writable only by the service account
sudo mkdir -p /mnt/audit_vault && sudo chown auditsvc:auditsvc /mnt/audit_vault && sudo chmod 700 /mnt/audit_vault
export AUDIT_BACKUP_DIR=/mnt/audit_vault      # Windows (PowerShell): $env:AUDIT_BACKUP_DIR="D:\audit_vault"
python app.py
```
Use a path on a different disk/server share, owned by an account that is **not** the web admin or
developer account. `python backup_audit.py` and `python restore_audit.py` honour the same variable
(or `--dir`).

**Production (immutable / WORM):** keep the app's archive folder on restricted storage, then
replicate it with a scheduled job to a protected system with object-lock/WORM retention
(e.g. S3 Object Lock in compliance mode, Azure immutable blob, or a write-once appliance), with
write-only credentials for the replication job, no delete permission for administrators, encryption at
rest, access logging, regular restore tests, and a reviewed deletion process after
`AUDIT_RETENTION_DAYS`. Verification (`backup_audit.py --verify`) can then be run against the replica.
Do not point the live app directly at an append-only/WORM directory: it rewrites the small `.sha256` files.

### Commands
```bash
python seed.py                 # (re)creates demo data; a previous archive is moved aside, not deleted
python app.py                  # run the app -> Security > Audit Integrity
python backup_audit.py         # manual backup           (python backup_audit.py --verify  = check only)
python restore_audit.py        # recover missing events  (python restore_audit.py --dry-run = preview)
python test_audit_system.py       # 71 checks: retention, backup, evidence export, recovery (throw-away DB)
python test_sensitive_actions.py  # 72 checks: employee/admin auditing, evidence protection, recovery, access control
```

### Demo for review
1. Log in as `admin`; edit a customer, delete a customer, export customers (needs 20+ rows for the *bulk* rule), suspend a user.
2. **Security > Audit Integrity** -> **Create Backup**; note *Last Backup* and *Backup Status: VALID*.
3. Click the small warning icon on an event ("simulate delete attempt") -> it is blocked, an `AUDIT_TAMPER_ATTEMPT` event appears, the original row is still there.
4. **Export Evidence** -> note *Records* and the *SHA-256* in the message; the files are in `audit_backups/evidence/`.
5. Recovery: stop the app, delete a few rows from `audit_events` with a SQLite tool (copy the DB first!), run `python restore_audit.py`, and watch the chain return to VALID.

### Limitations & production note
* A checksum file next to an archive detects modification, but someone able to rewrite *both* can forge a pair; the per-record hash chain is re-checked for that reason. SHA-256 does **not** make storage impossible to attack - it makes modification detectable.
* The local `audit_backups/` folder is **not** equivalent to legally compliant evidence storage, and the evidence export does not by itself guarantee court admissibility; it preserves traceability and integrity.
* Someone with direct file access to the SQLite file can still edit it outside the app; the archive and chain exist to catch and recover from that. Without external storage, someone with full OS access can alter the database *and* the local archive.
* Because the restore tool refuses to overwrite, a database row that was forged *and* has a valid-looking hash is reported ("differs from archive"), not silently replaced - an administrator decides.
* For production, move archives to a separate protected system with restricted write/delete permissions, immutable/WORM (object-lock) retention, access logging, encryption, regular backups and a controlled retention policy (including a reviewed deletion process after `AUDIT_RETENTION_DAYS`).
