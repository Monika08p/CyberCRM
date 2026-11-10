"""
backup_audit.py - manual audit backup.

    python backup_audit.py              # archive every audit event not yet archived
    python backup_audit.py --verify     # only verify the existing archive
    python backup_audit.py --dir PATH   # use a different archive folder

Exports audit events to append-only JSON Lines files in audit_backups/
(one file per day + a .sha256 checksum file). Events already in the archive
are skipped, so running it repeatedly never creates duplicates.
"""
import argparse
import sys

from app import create_app
from utils import audit_archive


def main():
    ap = argparse.ArgumentParser(description="Back up the CyberCRM Guardian audit trail.")
    ap.add_argument("--dir", help="archive folder (default: audit_backups/)")
    ap.add_argument("--verify", action="store_true", help="verify only, do not write")
    args = ap.parse_args()

    app = create_app()
    with app.app_context():
        if not args.verify:
            result = audit_archive.create_backup(args.dir)
            print(f"Backup complete: {result['written']} new event(s) archived, "
                  f"{result['skipped']} already archived "
                  f"({result['total_in_db']} events in database, {result['files']} archive file(s)).")

        report = audit_archive.verify_audit_backup(args.dir)
        print(f"Backup integrity: {report['status']} "
              f"({report['archived_events']} archived event(s))")
        for f in report["files"]:
            line = f"  {f['name']}: {f['status']} ({f['records']} record(s))"
            print(line)
            for issue in f["issues"]:
                print(f"      - {issue}")
        for w in report["warnings"]:
            print(f"  warning: {w}")
        sys.exit(1 if report["status"] == "COMPROMISED" else 0)


if __name__ == "__main__":
    main()
