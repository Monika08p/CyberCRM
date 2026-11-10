"""
utils/validators.py
---------------------
Rule-based validation for CRM customer records. Kept in one place so
add_customer / edit_customer never diverge on what counts as valid data.
"""

import re
from flask import current_app
from models import Customer

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^[0-9+\-\s()]{7,20}$")


def validate_customer(data, exclude_id=None):
    """
    Validate customer form data.

    :param data: dict with keys name, email, phone, company, address, notes
    :param exclude_id: when editing, the customer's own id (so duplicate
                        email check doesn't flag the record against itself)
    :return: list of human-readable error strings (empty = valid)
    """
    errors = []
    max_len = current_app.config["CUSTOMER_MAX_LEN"]

    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    phone = (data.get("phone") or "").strip()
    company = (data.get("company") or "").strip()
    address = (data.get("address") or "").strip()
    notes = (data.get("notes") or "").strip()

    # --- Required fields ---
    if not name:
        errors.append("Customer name is required.")

    # --- Max length checks ---
    if len(name) > max_len["name"]:
        errors.append(f"Name must be {max_len['name']} characters or fewer.")
    if len(email) > max_len["email"]:
        errors.append(f"Email must be {max_len['email']} characters or fewer.")
    if len(phone) > max_len["phone"]:
        errors.append(f"Phone number must be {max_len['phone']} characters or fewer.")
    if len(company) > max_len["company"]:
        errors.append(f"Company must be {max_len['company']} characters or fewer.")
    if len(address) > max_len["address"]:
        errors.append(f"Address must be {max_len['address']} characters or fewer.")
    if len(notes) > max_len["notes"]:
        errors.append(f"Notes must be {max_len['notes']} characters or fewer.")

    # --- Email format ---
    if email and not EMAIL_RE.match(email):
        errors.append("Please enter a valid email address.")

    # --- Phone format (digits, spaces, +, -, parentheses only) ---
    if phone and not PHONE_RE.match(phone):
        errors.append("Please enter a valid phone number.")

    # --- Duplicate email check (case-insensitive) ---
    if email and EMAIL_RE.match(email):
        query = Customer.query.filter(Customer.email.ilike(email))
        if exclude_id:
            query = query.filter(Customer.id != exclude_id)
        if query.first():
            errors.append("A customer with this email already exists.")

    return errors
