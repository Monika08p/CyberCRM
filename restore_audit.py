"""
restore_audit.py - recover missing audit events from the archive.

    python restore_audit.py              # restore into the database
    python restore_audit.py --dry-run    # show what WOULD happen, change nothing
    python restore_audit.py --dir PATH   # read a different archive folder

Safety rules
  * Existing database rows are NEVER modified or overwritten.
  * Only events whose id is missing from the database are inserted
    (duplicates are skipped and counted).
  * Original ids, timestamps, previous_hash and current_hash are preserved.
  * Archive files whose SHA-256 checksum does not match are rejected
    (reported as integrity failures); malformed records and records whose
    own hash does not recompute are skipped and reported too.
  * Afterwards the full SHA-256 audit chain is verified.
"""
import argparse
import sys
from datetime import datetime

from app import create_app
from extensions import db
from models import AuditEvent
from utils import audit_archive
from utils.audit import verify_audit_chain


def main():
    ap = argparse.ArgumentParser(description="Restore missing audit events from the archive.")
    ap.add_argument("--dir", help="archive folder (default: audit_backups/)")
    ap.add_argument("--dry-run", action="store_true", help="report only, change nothing")
    args = ap.parse_args()

    app = create_app()
    with app.app_context():
        files = audit_archive.list_archive_files(args.dir)
        if not files:
            print("No archive files found - nothing to restore.")
            sys.exit(1)

        integrity_failures = []
        candidates = {}
        for path in files:
            parsed = audit_archive.read_archive_file(path)
            if parsed["checksum"] == "MISMATCH":
                integrity_failures.append(f"{parsed['name']}: checksum mismatch - file rejected")
                continue
            if parsed["checksum"] == "MISSING":
                print(f"warning: {parsed['name']} has no checksum file; "
                      f"verifying each record's own hash instead")
            for err in parsed["errors"]:
                if "checksum" not in err:
                    integrity_failures.append(f"{parsed['name']}: {err}")
            for rec in parsed["records"]:
                if not audit_archive.record_hash_valid(rec):
                    integrity_failures.append(
                        f"{parsed['name']}: event {rec['event_id']} hash does not "
                        f"recompute - skipped")
                    continue
                candidates.setdefault(rec["event_id"], rec)

        existing = {e.id: e for e in AuditEvent.query.all()}
        restored = skipped = conflicts = 0
        for event_id in sorted(candidates):
            rec = candidates[event_id]
            if event_id in existing:
                if audit_archive.record_matches_event(rec, existing[event_id]):
                    skipped += 1
                else:
                    conflicts += 1
                    integrity_failures.append(
                        f"event {event_id}: database copy differs from archive (content changed) - "
                        f"database row left untouched")
                continue
            restored += 1
            if not args.dry_run:
                db.session.add(AuditEvent(
                    id=rec["event_id"], user_id=rec["user_id"], action=rec["action"],
                    target_type=rec["target_type"], target_id=rec["target_id"],
                    details=rec["details"], risk_level=rec["risk_level"],
                    timestamp=datetime.fromisoformat(rec["timestamp"]),
                    previous_hash=rec["previous_hash"], current_hash=rec["current_hash"]))
        if not args.dry_run:
            db.session.commit()

        label = "Would restore" if args.dry_run else "Restored"
        print(f"{label}: {restored} event(s)")
        print(f"Skipped duplicates (already in database): {skipped}")
        print(f"Integrity failures: {len(integrity_failures)}")
        for item in integrity_failures:
            print(f"  - {item}")

        if restored and not args.dry_run:
            # Record that evidence was restored (appended AFTER the restored events,
            # so the chain stays intact; it is archived like any other event).
            from utils.audit import log_audit_event
            log_audit_event(None, "AUDIT_RESTORE", target_type="audit_archive",
                            details=f"Restored {restored} audit event(s) from the archive via "
                                    f"restore_audit.py ({skipped} already present, "
                                    f"{len(integrity_failures)} integrity failure(s)).",
                            risk_level="HIGH")

        chain = verify_audit_chain()
        print(f"SHA-256 audit chain after recovery: {chain['chain_status']} "
              f"({chain['verified']}/{chain['total']} events verified)")
        sys.exit(0 if (chain["chain_status"] == "VALID" and not integrity_failures) else 1)


if __name__ == "__main__":
    main()
