"""
scanner/task_runner.py — Manages execution of background scanning tasks.

Provides:
- Thread lifecycle tracking to prevent database teardown race conditions.
- Configurable synchronous execution for testing (SYNC_SCANS=True).
- Reliable mocking option for test suites (MOCK_BACKGROUND_SCANS=True).
- Graceful shutdown / wait helper (wait_for_all_scans).
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from flask import Flask

from scanner.orchestrator import run_scan

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_active_threads: set[threading.Thread] = set()


def dispatch_scan(scan_id: int, target_url: str, app: Flask) -> Optional[threading.Thread]:
    """
    Dispatch a scan task according to application configuration.

    - If app.config['MOCK_BACKGROUND_SCANS'] is True: does not run the scan.
    - If app.config['SYNC_SCANS'] is True: runs the scan synchronously.
    - Otherwise: spawns and tracks a background thread.
    """
    if app.config.get("MOCK_BACKGROUND_SCANS", False):
        logger.debug("MOCK_BACKGROUND_SCANS enabled; skipping scan execution for scan %s", scan_id)
        return None

    if app.config.get("SYNC_SCANS", False):
        logger.debug("SYNC_SCANS enabled; running scan %s synchronously", scan_id)
        run_scan(scan_id, target_url, app)
        return None

    def _worker():
        cur_thread = threading.current_thread()
        try:
            run_scan(scan_id, target_url, app)
        except Exception as exc:
            logger.exception("Uncaught exception in scan worker for scan %s: %s", scan_id, exc)
        finally:
            with _lock:
                _active_threads.discard(cur_thread)

    t = threading.Thread(
        target=_worker,
        name=f"WebShield-Scan-{scan_id}",
        daemon=True,
    )
    with _lock:
        _active_threads.add(t)
    t.start()
    return t


def wait_for_all_scans(timeout: float = 10.0) -> None:
    """
    Wait for all active background scan threads to finish.
    Used during test database teardown or application shutdown.
    """
    with _lock:
        threads = list(_active_threads)

    deadline = timeout
    for t in threads:
        if t.is_alive():
            t.join(timeout=max(0.1, deadline))
        with _lock:
            _active_threads.discard(t)


def get_active_scan_count() -> int:
    """Return the number of currently active scan threads."""
    with _lock:
        # Prune dead threads
        dead = {t for t in _active_threads if not t.is_alive()}
        _active_threads.difference_update(dead)
        return len(_active_threads)
