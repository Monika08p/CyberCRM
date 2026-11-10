"""
utils/audit.py
----------------
Tamper-Evident Audit Trail (Feature 3 & 4).

Every security-sensitive / privileged action is written to AuditEvent
using SHA-256 hash chaining (NOT blockchain, NOT ML — just a classic
tamper-evident log):

    Event 1                -> current_hash = SHA256(fields_1 + "0"*64)
    Event 2 (prev=Hash 1)   -> current_hash = SHA256(fields_2 + Hash1)
    Event 3 (prev=Hash 2)   -> current_hash = SHA256(fields_3 + Hash2)
    ...

`verify_audit_chain()` walks the whole table, recomputing each event's
hash from its *currently stored* fields and the *previous event's*
hash. If anyone edits a field of an old row directly in the database
(bypassing the app), the recomputed hash will no longer equal the
stored `current_hash` — and because each hash feeds the next, every
later event is also flagged, exactly like a real tamper-evident chain.

Retention / backup: every committed event is also appended to a separate
archive (utils/audit_archive.py) so evidence survives loss of the database.
Audit rows are APPEND-ONLY: models.py blocks any ORM update/delete of an
AuditEvent (see AuditImmutableError).
"""

import hashlib
from datetime import datetime
from flask import request, has_request_context
from extensions import db
from models import AuditEvent

GENESIS_HASH = "0" * 64


def _compute_hash(user_id, action, target_type, target_id, details, timestamp, previous_hash):
    """Deterministic SHA-256 over an event's own fields + the previous hash."""
    payload = "|".join([
        str(user_id), str(action), str(target_type), str(target_id),
        str(details), timestamp.isoformat(), previous_hash,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _client_ip():
    """IP of the current request, if there is one (not trusted proxy headers)."""
    return request.remote_addr if has_request_context() else None


def log_audit_event(user, action, target_type=None, target_id=None,
                     details=None, risk_level="INFO"):
    """
    Append a new event to the tamper-evident audit chain.
    Used for privileged / security-sensitive actions (role changes,
    account creation, suspensions, customer data changes by admins, alert
    resolution, incident actions, audit management, etc).

    The requesting IP address (when available) is appended to `details` as
    "[ip=...]" so it is covered by the SHA-256 hash and copied to the archive.
    Callers must never put passwords or unnecessary personal data in `details`.
    """
    ip = _client_ip()
    if ip:
        suffix = f" [ip={ip}]"
        details = (details or "")[:255 - len(suffix)] + suffix
    elif details:
        details = details[:255]

    last = AuditEvent.query.order_by(AuditEvent.id.desc()).first()
    previous_hash = last.current_hash if last else GENESIS_HASH
    timestamp = datetime.utcnow()

    user_id = user.id if user else None
    current_hash = _compute_hash(user_id, action, target_type, target_id,
                                  details, timestamp, previous_hash)

    event = AuditEvent(
        user_id=user_id, action=action, target_type=target_type,
        target_id=target_id, details=details, risk_level=risk_level,
        timestamp=timestamp, previous_hash=previous_hash,
        current_hash=current_hash,
    )
    db.session.add(event)
    db.session.commit()

    # Long-term retention: copy the committed event to the separate append-only
    # archive (audit_backups/*.jsonl). It runs AFTER the commit so a failed
    # file write can never roll back or block the real action. If it fails, the
    # failure is remembered and the next audit event (or the next app start,
    # or `python backup_audit.py`) catches the archive up, so nothing is
    # silently left out. Duplicates are impossible: archive_event() skips ids
    # that are already archived.
    from utils import audit_archive
    audit_archive.archive_with_catchup(event)
    return event


def verify_audit_chain():
    """
    Recompute the entire hash chain from scratch and compare against
    what's stored. Returns a dict summarizing chain integrity, used by
    the Audit Integrity page.

    A single tampered row breaks the chain from that point forward
    (by design — that's what makes the tampering evident).
    """
    events = AuditEvent.query.order_by(AuditEvent.id.asc()).all()
    total = len(events)
    tampered_ids = []
    first_tampered = None
    expected_prev = GENESIS_HASH

    for e in events:
        expected_hash = _compute_hash(e.user_id, e.action, e.target_type,
                                       e.target_id, e.details, e.timestamp,
                                       expected_prev)
        is_ok = (e.previous_hash == expected_prev) and (e.current_hash == expected_hash)
        if not is_ok:
            tampered_ids.append(e.id)
            if first_tampered is None:
                first_tampered = e.id
        # Continue the chain using the EXPECTED hash (not the possibly
        # tampered stored one) so a single edit cascades and correctly
        # flags every subsequent event as unverifiable too.
        expected_prev = expected_hash

    verified = total - len(tampered_ids)
    return {
        "total": total,
        "verified": verified,
        "tampered": len(tampered_ids),
        "tampered_ids": tampered_ids,
        "first_tampered_id": first_tampered,
        "chain_status": "COMPROMISED" if tampered_ids else "VALID",
        "checked_at": datetime.utcnow(),
    }
