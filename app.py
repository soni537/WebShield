"""
app.py — Flask application factory and entry point.
"""

from __future__ import annotations

import logging
import os

from flask import Flask

from config import get_config
from extensions import db, csrf, login_manager


def create_app(config_class=None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Load configuration
    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)

    # Initialise extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)

    # Register blueprints
    from routes.dashboard import dashboard_bp
    from routes.scans import scans_bp
    from routes.reports import reports_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(reports_bp)

    # Exempt JSON API endpoints from CSRF (they use JSON body, not form)
    csrf.exempt(scans_bp)

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Create DB tables on first run
    with app.app_context():
        try:
            db.create_all()
            logging.getLogger(__name__).info("Database tables verified/created.")
        except Exception as exc:
            db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
            safe_uri = db_uri.split("@")[-1] if "@" in db_uri else db_uri
            logging.getLogger(__name__).warning(
                "Database initialization failed for target '%s': %s. "
                "If MySQL is not installed or credentials in .env are not configured, "
                "set DATABASE_URL=sqlite:///webshield_dev.db for local standalone execution.",
                safe_uri,
                exc,
            )

    # User loader for Flask-Login
    from models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Jinja2 globals
    from scanner.scoring import score_label, score_colour
    app.jinja_env.globals.update(
        score_label=score_label,
        score_colour=score_colour,
    )

    return app


if __name__ == "__main__":
    flask_app = create_app()
    # Never run with debug=True in production.
    # Use a proper WSGI server (gunicorn/waitress) for production.
    flask_app.run(
        host="127.0.0.1",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
