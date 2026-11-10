"""
utils/audit_archive.py
------------------------
Separate, append-only archive of the audit trail (long-term retention).

Why: the SHA-256 hash chain in the AuditEvent table can DETECT tampering,
but if instance/cybercrm.db is deleted or corrupted the evidence itself is
gone. So every audit event is also written to a structured JSON Lines file
OUTSIDE the database:

    audit_backups/
        audit_2026-10-08.jsonl          <- one JSON object per audit event
        audit_2026-10-08.jsonl.sha256   <- SHA-256 checksum of that file
        evidence/                       <- exported evidence files + checksums

Rules this module follows
  * Append-only: records are only ever appended; a record whose event_id is
    already in the file is skipped (no duplicates).
  * Structured data: each line is a JSON record (not a screenshot/HTML).
  * Each archive file has a .sha256 sidecar so modification can be DETECTED.

Honest limitation: a checksum next to the file detects accidental or casual
modification. Someone who can rewrite BOTH the file and its checksum can still
forge a consistent pair. That is why the per-record hash chain is also
re-verified, and why production archives belong on protected/WORM storage.
"""

import contextlib
import glob
import hashlib
import json
import os
import re
import threading
from datetime import datetime, timedelta

from flask import current_app

from extensions import db
from models import AuditEvent

_lock = threading.Lock()
_archive_failed = False   # set when an archive write failed; triggers a catch-up

REQUIRED_FIELDS = (
    "event_id", "timestamp", "user_id", "username", "action", "target_type",
    "target_id", "details", "risk_level", "previous_hash", "current_hash",
)
ARCHIVE_NAME_RE = re.compile(r"^audit_\d{4}-\d{2}-\d{2}\.jsonl$")
EVIDENCE_NAME_RE = re.compile(r"^audit_evidence_\d{8}_\d{6}\.json(\.sha256)?$")


# --------------------------------------------------------------------------
# paths / small helpers
# --------------------------------------------------------------------------

def backup_dir(directory=None):
    path = directory or current_app.config["AUDIT_BACKUP_DIR"]
    os.makedirs(path, exist_ok=True)
    return path


def evidence_dir(directory=None):
    path = os.path.join(backup_dir(directory), "evidence")
    os.makedirs(path, exist_ok=True)
    return path


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_checksum(path):
    """Write '<sha256>  <filename>' (sha256sum-compatible) next to the file."""
    digest = sha256_file(path)
    tmp = path + ".sha256.tmp"
    with open(tmp, "w") as f:
        f.write(f"{digest}  {os.path.basename(path)}\n")
    os.replace(tmp, path + ".sha256")
    return digest


def _read_checksum(path):
    try:
        with open(path + ".sha256") as f:
            return f.read().split()[0].strip().lower()
    except (OSError, IndexError):
        return None


@contextlib.contextmanager
def _process_lock(directory=None):
    """Lock shared with other processes (e.g. `python backup_audit.py` while the
    web app is running) so two writers cannot append the same event twice."""
    handle = open(os.path.join(backup_dir(directory), ".archive.lock"), "a+")
    try:
        try:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX)
        except ImportError:                      # Windows
            try:
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            except Exception:                    # noqa: BLE001 - best effort only
                pass
        yield
    finally:
        handle.close()                           # closing releases the lock


def event_to_record(event):
    """Structured archive record for one AuditEvent (all required fields)."""
    return {
        "event_id": event.id,
        "timestamp": event.timestamp.isoformat(),
        "user_id": event.user_id,
        "username": event.actor.username if event.actor else None,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "details": event.details,
        "risk_level": event.risk_level,
        "previous_hash": event.previous_hash,
        "current_hash": event.current_hash,
    }


COMPARED_FIELDS = ("user_id", "action", "target_type", "target_id", "details",
                   "risk_level", "previous_hash", "current_hash")


def record_matches_event(rec, event):
    """True if the archived record and the database row hold the same content."""
    if rec["timestamp"] != event.timestamp.isoformat():
        return False
    return all(rec[f] == getattr(event, f) for f in COMPARED_FIELDS)


def record_format_errors(rec):
    """Return a list of problems with an archive record's structure."""
    if not isinstance(rec, dict):
        return ["record is not a JSON object"]
    missing = [k for k in REQUIRED_FIELDS if k not in rec]
    errors = [f"missing field '{k}'" for k in missing]
    if not missing:
        try:
            datetime.fromisoformat(rec["timestamp"])
        except (TypeError, ValueError):
            errors.append("invalid timestamp")
        if not isinstance(rec["event_id"], int):
            errors.append("event_id is not an integer")
    return errors


def record_hash_valid(rec):
    """Recompute the record's SHA-256 from its own fields + previous_hash."""
    from utils.audit import _compute_hash  # local import avoids a cycle
    try:
        expected = _compute_hash(rec["user_id"], rec["action"], rec["target_type"],
                                  rec["target_id"], rec["details"],
                                  datetime.fromisoformat(rec["timestamp"]),
                                  rec["previous_hash"])
    except (KeyError, TypeError, ValueError):
        return False
    return expected == rec["current_hash"]


# --------------------------------------------------------------------------
# reading the archive
# --------------------------------------------------------------------------

def list_archive_files(directory=None):
    d = backup_dir(directory)
    return sorted(p for p in glob.glob(os.path.join(d, "audit_*.jsonl"))
                  if ARCHIVE_NAME_RE.match(os.path.basename(p)))


def read_archive_file(path):
    """
    Parse one archive file. Returns:
      {name, records, checksum ('OK'|'MISSING'|'MISMATCH'), errors:[...]}
    Never raises on bad content - problems are reported in `errors`.
    """
    result = {"name": os.path.basename(path), "path": path, "records": [],
              "checksum": "OK", "errors": []}
    stored = _read_checksum(path)
    if stored is None:
        result["checksum"] = "MISSING"
        result["errors"].append("checksum file missing")
    elif stored != sha256_file(path):
        result["checksum"] = "MISMATCH"
        result["errors"].append("file SHA-256 does not match its checksum file "
                                "(file was modified)")
    try:
        with open(path, encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    result["errors"].append(f"line {line_no}: invalid JSON")
                    continue
                problems = record_format_errors(rec)
                if problems:
                    result["errors"].append(f"line {line_no}: " + "; ".join(problems))
                    continue
                result["records"].append(rec)
    except OSError as exc:
        result["errors"].append(f"cannot read file: {exc}")
    return result


def _ids_in_file(path):
    ids = set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    ids.add(json.loads(line)["event_id"])
                except (ValueError, KeyError, TypeError):
                    continue
    except OSError:
        pass
    return ids


# --------------------------------------------------------------------------
# writing the archive
# --------------------------------------------------------------------------

def archive_event(event, directory=None):
    """
    Append one committed AuditEvent to its day's archive file.
    Returns True if written, False if it was already archived.
    Raises on I/O errors (callers that must not fail wrap this).
    """
    record = event_to_record(event)
    path = os.path.join(backup_dir(directory),
                        f"audit_{event.timestamp:%Y-%m-%d}.jsonl")
    with _lock, _process_lock(directory):
        if record["event_id"] in _ids_in_file(path):
            return False
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        _write_checksum(path)
    return True


def archive_with_catchup(event, directory=None):
    """
    Archive one committed event WITHOUT ever raising into the caller.
    If an earlier write failed, first back-fill everything that is missing.
    """
    global _archive_failed
    try:
        if _archive_failed:
            create_backup(directory)          # also archives `event` (it is in the DB)
            _archive_failed = False
        else:
            archive_event(event, directory)
    except Exception:  # noqa: BLE001 - archiving must never break the user's action
        _archive_failed = True
        current_app.logger.exception("Audit archive write failed for event %s "
                                      "(will be retried automatically)", event.id)


def startup_catchup(directory=None):
    """Called when the app starts: archive any committed events that are missing
    (e.g. the process crashed between the DB commit and the archive write)."""
    try:
        return create_backup(directory)["written"]
    except Exception:  # noqa: BLE001
        current_app.logger.exception("Startup audit archive catch-up failed")
        return 0


def archived_event_ids(directory=None):
    ids = set()
    for path in list_archive_files(directory):
        ids |= _ids_in_file(path)
    return ids


def create_backup(directory=None):
    """
    Export every audit event that is not yet in the archive.
    Safe to run repeatedly - already archived events are skipped.
    """
    already = archived_event_ids(directory)
    written = skipped = 0
    for event in AuditEvent.query.order_by(AuditEvent.id.asc()).all():
        if event.id in already:
            skipped += 1
        elif archive_event(event, directory):
            written += 1
        else:
            skipped += 1
    return {"written": written, "skipped": skipped,
            "total_in_db": written + skipped,
            "files": len(list_archive_files(directory))}


# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------

def verify_audit_backup(directory=None):
    """
    Check every archive file: checksum matches, every line parses, every
    record's own SHA-256 recomputes, and consecutive records still link.
    status: VALID | COMPROMISED | EMPTY (no backup created yet)
    """
    files = list_archive_files(directory)
    report_files, all_records = [], []
    problems = 0

    for path in files:
        parsed = read_archive_file(path)
        bad_hash = [r["event_id"] for r in parsed["records"] if not record_hash_valid(r)]
        issues = list(parsed["errors"])
        if bad_hash:
            issues.append("record hash mismatch for event(s): "
                          + ", ".join(map(str, bad_hash)))
        seen, dups = set(), set()
        for r in parsed["records"]:
            (dups if r["event_id"] in seen else seen).add(r["event_id"])
        if dups:
            issues.append("duplicate event ids: " + ", ".join(map(str, sorted(dups))))
        problems += len(issues)
        report_files.append({"name": parsed["name"], "records": len(parsed["records"]),
                             "status": "VALID" if not issues else "COMPROMISED",
                             "issues": issues})
        all_records.extend(parsed["records"])

    # chain linkage across the whole archive (consecutive ids must link)
    warnings = []
    by_id = {}
    for r in all_records:
        by_id.setdefault(r["event_id"], r)
    ordered = [by_id[k] for k in sorted(by_id)]
    for prev, cur in zip(ordered, ordered[1:]):
        if cur["event_id"] == prev["event_id"] + 1:
            if cur["previous_hash"] != prev["current_hash"]:
                problems += 1
                report_files.append({"name": "(chain)", "records": 0,
                                     "status": "COMPROMISED",
                                     "issues": [f"chain link broken between events "
                                                f"{prev['event_id']} and {cur['event_id']}"]})
        else:
            warnings.append(f"gap in archive between events "
                            f"{prev['event_id']} and {cur['event_id']}")

    if not files:
        status = "EMPTY"
    else:
        status = "COMPROMISED" if problems else "VALID"
    return {"status": status, "files": report_files, "warnings": warnings,
            "archived_events": len(by_id), "checked_at": datetime.utcnow()}


def last_backup_time(directory=None):
    files = list_archive_files(directory)
    if not files:
        return None
    return datetime.utcfromtimestamp(max(os.path.getmtime(p) for p in files))


def storage_info(directory=None):
    """Where the archive lives and how well that location can be trusted."""
    path = os.path.abspath(backup_dir(directory))
    app_root = os.path.abspath(current_app.root_path)
    is_local = os.path.commonpath([path, app_root]) == app_root
    return {"path": path,
            "kind": "LOCAL (inside the project folder)" if is_local
                    else "CONFIGURED EXTERNAL LOCATION",
            "is_local": is_local,
            "writable": os.access(path, os.W_OK)}


def get_backup_summary(directory=None):
    """Numbers for the Audit Integrity page."""
    report = verify_audit_backup(directory)
    db_events = {e.id: e for e in AuditEvent.query.all()}
    db_ids = set(db_events)
    archived = archived_event_ids(directory)
    archive_recs = {}
    for path in list_archive_files(directory):
        for rec in read_archive_file(path)["records"]:
            archive_recs.setdefault(rec["event_id"], rec)
    differs = sum(1 for i, rec in archive_recs.items()
                  if i in db_events and not record_matches_event(rec, db_events[i]))
    cutoff = datetime.utcnow() - timedelta(days=current_app.config["AUDIT_RETENTION_DAYS"])
    return {
        "status": report["status"],
        "files": report["files"],
        "warnings": report["warnings"],
        "archived_events": len(archived),
        "not_yet_archived": len(db_ids - archived),
        "missing_in_db": len(archived - db_ids),
        "differs_from_db": differs,
        "storage": storage_info(directory),
        "last_backup": last_backup_time(directory),
        "past_retention": AuditEvent.query.filter(AuditEvent.timestamp < cutoff).count(),
    }


# --------------------------------------------------------------------------
# evidence export (with chain-of-custody metadata)
# --------------------------------------------------------------------------

def _parse_day(value, end_of_day=False):
    if not value:
        return None
    day = datetime.strptime(value, "%Y-%m-%d")
    return day + timedelta(days=1) - timedelta(microseconds=1) if end_of_day else day


def export_evidence(exported_by, date_from=None, date_to=None, user_id=None,
                    action=None, target_type=None, directory=None):
    """
    Write a structured evidence file for the selected audit events plus a
    .sha256 checksum file. Returns {filename, path, sha256, count}.
    Raises ValueError for invalid filter input.
    """
    from utils.audit import verify_audit_chain
    try:
        start = _parse_day(date_from)
        end = _parse_day(date_to, end_of_day=True)
    except ValueError:
        raise ValueError("Dates must be in YYYY-MM-DD format.")
    if start and end and start > end:
        raise ValueError("'From' date must not be after 'To' date.")

    query = AuditEvent.query
    if start:
        query = query.filter(AuditEvent.timestamp >= start)
    if end:
        query = query.filter(AuditEvent.timestamp <= end)
    if user_id:
        query = query.filter(AuditEvent.user_id == int(user_id))
    if action:
        query = query.filter(AuditEvent.action == action)
    if target_type:
        query = query.filter(AuditEvent.target_type == target_type)
    events = query.order_by(AuditEvent.id.asc()).all()

    now = datetime.utcnow()
    chain = verify_audit_chain()
    document = {
        "chain_of_custody": {
            "export_timestamp_utc": now.isoformat(),
            "exported_by": {"user_id": exported_by.id, "username": exported_by.username},
            "date_range": {"from": date_from or None, "to": date_to or None},
            "filters_used": {"user_id": int(user_id) if user_id else None,
                              "action": action or None,
                              "target_type": target_type or None},
            "record_count": len(events),
            "source_system": "CyberCRM Guardian audit database "
                              f"({os.path.basename(current_app.config['SQLALCHEMY_DATABASE_URI'])})",
            "hash_algorithm": "SHA-256",
            "audit_chain_status_at_export": chain["chain_status"],
            "evidence_file_sha256": "see companion .sha256 file (a file cannot "
                                    "contain its own checksum)",
            "note": "This export preserves traceability and lets integrity be "
                    "re-checked. It does not by itself guarantee legal "
                    "admissibility.",
        },
        "records": [{
            "event_id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "user": e.actor.username if e.actor else None,
            "user_id": e.user_id,
            "action": e.action,
            "target": f"{e.target_type}#{e.target_id}" if e.target_type else None,
            "target_type": e.target_type,
            "target_id": e.target_id,
            "details": e.details,
            "risk_level": e.risk_level,
            "previous_hash": e.previous_hash,
            "current_hash": e.current_hash,
        } for e in events],
    }

    filename = f"audit_evidence_{now:%Y%m%d_%H%M%S}.json"
    path = os.path.join(evidence_dir(directory), filename)
    n = 1
    while os.path.exists(path):  # two exports in the same second
        filename = f"audit_evidence_{now:%Y%m%d_%H%M%S}_{n}.json"
        path = os.path.join(evidence_dir(directory), filename)
        n += 1
    with open(path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2, ensure_ascii=False)
    digest = _write_checksum(path)
    return {"filename": filename, "path": path, "sha256": digest, "count": len(events)}


def list_evidence_files(directory=None, limit=5):
    d = evidence_dir(directory)
    files = sorted((p for p in glob.glob(os.path.join(d, "audit_evidence_*.json"))),
                   key=os.path.getmtime, reverse=True)[:limit]
    return [{"filename": os.path.basename(p),
             "created": datetime.utcfromtimestamp(os.path.getmtime(p)),
             "sha256": _read_checksum(p)} for p in files]
