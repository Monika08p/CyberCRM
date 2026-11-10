"""
utils/decorators.py
---------------------
`@admin_required` enforces Role-Based Access Control (Feature 1) on
admin-only routes. Non-admin attempts are logged as "Unauthorized
Access" and scored 80 points (Feature 4/5).
"""

from functools import wraps
from flask import abort, request
from flask_login import current_user
from utils import detection


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.is_admin():
            detection.flag_unauthorized_access(current_user, request.path)
            abort(403)
        return view_func(*args, **kwargs)
    return wrapped
