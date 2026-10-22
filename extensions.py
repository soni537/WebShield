"""Shared Flask extensions — instantiated here, initialised in app.py."""
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = "dashboard.index"  # No auth system; redirect to home
login_manager.login_message_category = "info"
