"""
tests/conftest.py — Pytest fixtures and test environment setup.

Ensures background scan tasks finish cleanly before database teardown,
preventing SQLite OperationalErrors / table-dropped race conditions.
"""

import pytest

from config import TestingConfig
from scanner.task_runner import wait_for_all_scans


@pytest.fixture
def app():
    from app import create_app
    application = create_app(TestingConfig)
    with application.app_context():
        from extensions import db
        db.create_all()
        yield application
        # Ensure any background scan threads have finished before teardown
        wait_for_all_scans(timeout=5.0)
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()
