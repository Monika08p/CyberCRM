"""
routes/customers.py
---------------------
Feature 2: CRM Dashboard - Customer records (list / view / edit / delete)
Feature 3: Every action here is logged via log_activity()
Feature 5/6: Bulk export triggers insider-threat detection
"""

import io
import csv
from flask import (Blueprint, render_template, redirect, url_for, flash,
                    request, Response, jsonify)
from flask_login import login_required, current_user

from extensions import db
from models import Customer
from utils.helpers import log_activity
from utils import detection
from utils.audit import log_audit_event
from utils.validators import validate_customer

customers_bp = Blueprint("customers", __name__, url_prefix="/customers")


def _is_ajax():
    """True when the request was made via fetch()/XHR from the modal UI."""
    return request.headers.get("X-Requested-With") == "XMLHttpRequest"


CUSTOMER_FIELDS = ("name", "email", "phone", "company", "address", "notes")


def _audit_customer(action, customer_id, details, risk_level, *, admin_only):
    """
    Mirror a sensitive customer operation into the tamper-evident AuditEvent
    chain (the ActivityLog row is always written separately by log_activity).
    admin_only=True  -> only privileged users (create / edit by admins)
    admin_only=False -> every role (destructive deletes)
    Details carry the customer ID and field NAMES only - never customer
    names, e-mails, phone numbers or any other personal values.
    """
    if admin_only and not current_user.is_privileged():
        return
    log_audit_event(current_user, action, target_type="customer", target_id=customer_id,
                    details=details, risk_level=risk_level)


@customers_bp.route("/")
@login_required
def list_customers():
    search = request.args.get("q", "").strip()
    sort = request.args.get("sort", "name")
    query = Customer.query
    if search:
        like = f"%{search}%"
        query = query.filter(
            (Customer.name.ilike(like)) |
            (Customer.email.ilike(like)) |
            (Customer.company.ilike(like))
        )
    sort_columns = {
        "name": Customer.name.asc(),
        "company": Customer.company.asc(),
        "created": Customer.created_at.desc(),
    }
    customers = query.order_by(sort_columns.get(sort, Customer.name.asc())).all()
    return render_template("customers.html", customers=customers, search=search, sort=sort)


@customers_bp.route("/<int:customer_id>")
@login_required
def view_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    log_activity(current_user, "view_customer", target_type="customer",
                 target_id=customer.id, details=f"Viewed customer #{customer.id}")
    return render_template("customer_detail.html", customer=customer)


@customers_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_customer():
    if request.method == "POST":
        errors = validate_customer(request.form)
        if errors:
            if _is_ajax():
                return jsonify(success=False, message=errors[0], errors=errors), 400
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("customers.list_customers"))

        customer = Customer(
            name=request.form.get("name").strip(),
            email=(request.form.get("email") or "").strip() or None,
            phone=(request.form.get("phone") or "").strip() or None,
            company=(request.form.get("company") or "").strip() or None,
            address=(request.form.get("address") or "").strip() or None,
            notes=(request.form.get("notes") or "").strip() or None,
        )
        db.session.add(customer)
        db.session.commit()
        log_activity(current_user, "create_customer", target_type="customer",
                     target_id=customer.id, details=f"Created customer #{customer.id}")
        _audit_customer("CUSTOMER_CREATE", customer.id,
                        f"{current_user.username} created customer #{customer.id}.",
                        "MEDIUM", admin_only=True)
        flash("Customer added successfully.", "success")

        if _is_ajax():
            return jsonify(success=True, message="Customer added successfully.",
                            customer_id=customer.id)
        return redirect(url_for("customers.list_customers"))
    return render_template("customer_form.html", customer=None)


@customers_bp.route("/<int:customer_id>/edit", methods=["GET", "POST"])
@login_required
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    if request.method == "POST":
        errors = validate_customer(request.form, exclude_id=customer.id)
        if errors:
            if _is_ajax():
                return jsonify(success=False, message=errors[0], errors=errors), 400
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("customers.list_customers"))

        new_values = {f: (request.form.get(f) or "").strip() or None for f in CUSTOMER_FIELDS}
        changed = [f for f in CUSTOMER_FIELDS if getattr(customer, f) != new_values[f]]
        for field in CUSTOMER_FIELDS:
            setattr(customer, field, new_values[field])
        db.session.commit()
        changed_txt = ", ".join(changed) if changed else "no fields changed"
        log_activity(current_user, "edit_customer", target_type="customer",
                     target_id=customer.id,
                     details=f"Edited customer #{customer.id} (fields: {changed_txt})")
        _audit_customer("CUSTOMER_EDIT", customer.id,
                        f"{current_user.username} edited customer #{customer.id} "
                        f"(fields: {changed_txt}).", "MEDIUM", admin_only=True)
        flash("Customer updated successfully.", "success")

        if _is_ajax():
            return jsonify(success=True, message="Customer updated successfully.",
                            customer_id=customer.id)
        return redirect(url_for("customers.view_customer", customer_id=customer.id))
    return render_template("customer_form.html", customer=customer)


@customers_bp.route("/<int:customer_id>/delete", methods=["POST"])
@login_required
def delete_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    name = customer.name          # only used for the on-screen confirmation, never logged
    db.session.delete(customer)
    db.session.commit()
    log_activity(current_user, "delete_customer", target_type="customer",
                 target_id=customer_id, details=f"Deleted customer #{customer_id}")
    # Deleting data is destructive, so it is tamper-evidently audited for EVERY role.
    _audit_customer("CUSTOMER_DELETE", customer_id,
                    f"{current_user.username} ({current_user.role}) deleted customer #{customer_id}.",
                    "HIGH", admin_only=False)
    flash(f"Customer '{name}' deleted successfully.", "warning")

    if _is_ajax():
        return jsonify(success=True, message=f"Customer '{name}' deleted successfully.")
    return redirect(url_for("customers.list_customers"))


@customers_bp.route("/export")
@login_required
def export_customers():
    """Export all customers as CSV. Bulk exports trigger a High alert."""
    customers = Customer.query.all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Name", "Email", "Phone", "Company", "Address"])
    for c in customers:
        writer.writerow([c.id, c.name, c.email, c.phone, c.company, c.address])

    log_activity(current_user, "export_data", target_type="customer",
                 details=f"Exported {len(customers)} customer records")
    # A bulk export is written to the audit chain as BULK_EXPORT by the rule
    # engine (any role). A smaller export is audited here for admins, so each
    # export produces exactly ONE audit event.
    is_bulk = bool(detection.check_bulk_export(current_user, len(customers)))
    if not is_bulk:
        _audit_customer("CUSTOMER_EXPORT", None,
                        f"{current_user.username} exported {len(customers)} customer records.",
                        "MEDIUM", admin_only=True)
    if current_user.is_privileged():
        detection.check_admin_off_hours(current_user, "Bulk Customer Export")

    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=customers_export.csv"
    return response
