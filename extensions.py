"""
extensions.py
-------------
Instantiates Flask extensions separately from app.py to avoid circular
imports between models.py, routes/*.py and app.py.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access CyberCRM Guardian."
login_manager.login_message_category = "warning"
