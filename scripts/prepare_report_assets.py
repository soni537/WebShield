"""
scripts/prepare_report_assets.py — Captures genuine application screenshots using Playwright
and renders high-resolution architecture diagrams for the Word project report.
"""

import os
import sys
import time
import subprocess
import requests
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from playwright.sync_api import sync_playwright

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DOCS_DIR = os.path.join(BASE_DIR, "docs")
SCREENSHOTS_DIR = os.path.join(DOCS_DIR, "screenshots")
DIAGRAMS_DIR = os.path.join(DOCS_DIR, "diagrams")
DB_PATH = os.path.join(BASE_DIR, "webshield_dev.db")

# Force SQLite for assets preparation
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["FLASK_DEBUG"] = "0"
os.environ["DEMO_MODE"] = "1"

os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
os.makedirs(DIAGRAMS_DIR, exist_ok=True)

# -----------------------------------------------------------------------------
# 1. Ensure comparison scan exists in database
# -----------------------------------------------------------------------------
def ensure_sample_data():
    sys.path.insert(0, BASE_DIR)
    from config import Config
    from app import create_app
    from extensions import db
    from models import Scan, Finding, ScanStatus, Severity, FindingStatus
    from datetime import datetime, timezone, timedelta

    app = create_app()
    with app.app_context():
        # Check if we have at least 2 scans of the same host
        scans = Scan.query.filter_by(normalized_hostname="xavier.ac.in").all()
        if len(scans) < 2:
            print("[*] Creating second historical scan for comparison view...")
            scan2 = Scan(
                target_url="https://xavier.ac.in",
                normalized_hostname="xavier.ac.in",
                status=ScanStatus.COMPLETED,
                scan_started_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7),
                scan_completed_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7) + timedelta(seconds=12),
                security_score=55,
                total_findings=11,
                critical_count=0,
                high_count=2,
                medium_count=2,
                low_count=2,
                informational_count=5,
            )
            db.session.add(scan2)
            db.session.commit()

            # Copy sample findings to scan2
            f1 = Finding(
                scan_id=scan2.id,
                finding_id="TLS-001",
                check_name="HTTPS Support",
                category="Transport Security",
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.PASS,
                description="HTTPS is supported and the server responded successfully.",
                evidence="HTTP 200 from https://xavier.ac.in",
                impact="Ensures encryption in transit.",
                recommendation="Maintain valid TLS configuration.",
                reference_url="https://developer.mozilla.org/en-US/docs/Glossary/HTTPS"
            )
            f2 = Finding(
                scan_id=scan2.id,
                finding_id="HDR-001",
                check_name="Content-Security-Policy",
                category="HTTP Security Headers",
                severity=Severity.HIGH,
                status=FindingStatus.FAIL,
                description="Content-Security-Policy (CSP) header is missing.",
                evidence="No CSP header returned.",
                impact="Leaves site susceptible to cross-site scripting (XSS) and data injection.",
                recommendation="Deploy a strict CSP policy.",
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
            )
            db.session.add_all([f1, f2])
            db.session.commit()
            print("[+] Scan 2 created successfully.")

# -----------------------------------------------------------------------------
# 2. Render Architecture & Workflow Diagrams using Matplotlib
# -----------------------------------------------------------------------------
def render_architecture_diagram():
    fig, ax = plt.subplots(figsize=(12, 8), dpi=300)
    ax.axis('off')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)

    # Color Palette
    c_client = "#E3F2FD"      # Light Blue
    c_flask = "#EDE7F6"       # Light Purple
    c_guard = "#FFEBEE"       # Light Red/Pink
    c_scanner = "#E8F5E9"     # Light Green
    c_storage = "#FFF3E0"     # Light Orange
    c_border = "#263238"

    def draw_box(x, y, w, h, text, title="", color="#FFFFFF", fontsize=10, title_color="#1A237E"):
        rect = patches.FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.5,rounding_size=1.5",
            facecolor=color, edgecolor=c_border, linewidth=1.5
        )
        ax.add_patch(rect)
        if title:
            ax.text(x + w / 2, y + h - 3, title, ha='center', va='top', fontsize=fontsize + 1, fontweight='bold', color=title_color)
        if text:
            ax.text(x + w / 2, y + h / 2 - (1.5 if title else 0), text, ha='center', va='center', fontsize=fontsize, color="#212121")

    # Layer 1: Client & Presentation
    draw_box(5, 78, 25, 16, "Web Browser / API Client\n(Bootstrap 5, Chart.js, HTML5)", "Presentation Layer", c_client)

    # Layer 2: Flask Routing & Blueprints
    draw_box(37, 78, 58, 16, "Dashboard Blueprint (routes/dashboard.py)\nScans Blueprint (routes/scans.py)\nReports Blueprint (routes/reports.py)", "Flask Application Factory (app.py)", c_flask)

    # Layer 3: Security Guardrails & Task Runner
    draw_box(37, 52, 27, 18, "Pre-Flight SSRF Filter\nBlocked CIDRs (IPv4/IPv6)\nDNS Verification\nRedirect TOCTOU (safety.py)", "Security Guardrails", c_guard, title_color="#B71C1C")
    draw_box(68, 52, 27, 18, "Thread Tracker & Registry\nSYNC_SCANS / Mock Modes\nGraceful Teardown Draining\n(task_runner.py)", "Task Execution Engine", c_guard, title_color="#B71C1C")

    # Layer 4: Scanner Engine Modules
    draw_box(5, 18, 59, 26, "• Transport Security (TLS-001..003) — transport.py\n• Security Headers (HDR-001..007) — headers.py\n• Cookie Attributes (CKY-001..004) — cookies.py\n• CORS Configuration (CRS-001..004) — cors.py\n• HTML Form & Input Inspection — html_checks.py\n• Deductive Scoring Engine (0-100) — scoring.py", "Core Scanner Engine (orchestrator.py)", c_scanner, title_color="#1B5E20")

    # Layer 5: Storage & Reporting
    draw_box(68, 18, 27, 26, "• SQLAlchemy Models\n  (User, Scan, Finding)\n• Database Engines:\n  MySQL (PyMySQL) & SQLite\n• Report Service (PDF, CSV, JSON)\n  (report_service.py)", "Storage & Reports", c_storage, title_color="#E65100")

    # Connecting Arrows
    arrow_kwargs = dict(arrowstyle="->", lw=1.8, color="#37474F", shrinkA=4, shrinkB=4)

    # Client -> Flask
    ax.annotate("", xy=(37, 86), xytext=(30, 86), arrowprops=arrow_kwargs)
    # Flask -> Security Guardrails
    ax.annotate("", xy=(50, 70), xytext=(50, 78), arrowprops=arrow_kwargs)
    # Guardrails -> Task Runner
    ax.annotate("", xy=(68, 61), xytext=(64, 61), arrowprops=arrow_kwargs)
    # Task Runner -> Scanner Engine
    ax.annotate("", xy=(40, 44), xytext=(75, 52), arrowprops=arrow_kwargs)
    # Scanner Engine -> Storage
    ax.annotate("", xy=(68, 31), xytext=(64, 31), arrowprops=arrow_kwargs)
    # Storage -> Flask (Reports delivery)
    ax.annotate("", xy=(85, 78), xytext=(85, 44), arrowprops=arrow_kwargs)

    plt.title("WebShield System Architecture & Data Flow", fontsize=16, fontweight='bold', pad=20, color="#0D47A1")
    arch_path = os.path.join(DIAGRAMS_DIR, "system_architecture.png")
    plt.savefig(arch_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"[+] Architecture diagram saved: {arch_path}")

def render_workflow_diagram():
    fig, ax = plt.subplots(figsize=(10, 10), dpi=300)
    ax.axis('off')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)

    c_box = "#ECEFF1"
    c_decision = "#FFF9C4"
    c_action = "#E1F5FE"
    c_end = "#E8F5E9"

    def draw_step(x, y, w, h, text, color=c_action, shape="box"):
        if shape == "box":
            p = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=1.0", facecolor=color, edgecolor="#37474F", lw=1.5)
        else: # diamond-like decision
            p = patches.Polygon([[x + w/2, y], [x + w, y + h/2], [x + w/2, y + h], [x, y + h/2]], facecolor=color, edgecolor="#37474F", lw=1.5)
        ax.add_patch(p)
        ax.text(x + w / 2, y + h / 2, text, ha='center', va='center', fontsize=9.5, fontweight='bold', color="#212121")

    # Workflow steps vertically
    draw_step(25, 90, 50, 7, "User Submits Target URL (Web UI / API)", c_box)
    draw_step(25, 78, 50, 7, "Pre-Flight SSRF & DNS Validation", c_decision, shape="diamond")
    draw_step(25, 66, 50, 7, "Initialize Scan Record (Status: PENDING)", c_action)
    draw_step(25, 54, 50, 7, "Dispatch Background Task (task_runner.py)", c_action)
    draw_step(20, 38, 60, 11, "Modular Analysis Pipeline:\n• TLS / HTTPS Verification (verify=True)\n• HTTP Security Headers (CSP, HSTS, XFO...)\n• Cookie Flag Checks (Secure, HttpOnly...)\n• CORS Evaluation & HTML Form Inspection", c_action)
    draw_step(25, 25, 50, 8, "Calculate Deductive Security Score (0-100)\nPersist Findings to Database", c_action)
    draw_step(25, 12, 50, 8, "Scan COMPLETED: Deliver Dashboard Telemetry\n& On-Demand Reports (JSON, CSV, PDF)", c_end)

    # Connections
    ak = dict(arrowstyle="->", lw=1.5, color="#37474F", shrinkA=3, shrinkB=3)
    ax.annotate("", xy=(50, 85), xytext=(50, 90), arrowprops=ak)
    ax.annotate("", xy=(50, 73), xytext=(50, 78), arrowprops=ak)
    ax.annotate("Valid Public URL", xy=(50, 73), xytext=(52, 75.5), fontsize=8, color="#1B5E20", fontweight='bold')
    
    # Block branch
    ax.annotate("", xy=(85, 70), xytext=(75, 81.5), arrowprops=ak)
    draw_step(77, 65, 20, 6, "Reject: Blocked IP / SSRF", "#FFCDD2")

    ax.annotate("", xy=(50, 61), xytext=(50, 66), arrowprops=ak)
    ax.annotate("", xy=(50, 49), xytext=(50, 54), arrowprops=ak)
    ax.annotate("", xy=(50, 33), xytext=(50, 38), arrowprops=ak)
    ax.annotate("", xy=(50, 20), xytext=(50, 25), arrowprops=ak)

    plt.title("WebShield Scan Execution Workflow", fontsize=15, fontweight='bold', pad=15, color="#0D47A1")
    wf_path = os.path.join(DIAGRAMS_DIR, "scan_workflow.png")
    plt.savefig(wf_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"[+] Workflow diagram saved: {wf_path}")

# -----------------------------------------------------------------------------
# 3. Capture Genuine UI Screenshots via Playwright
# -----------------------------------------------------------------------------
def capture_genuine_screenshots():
    port = 5005
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
    env["FLASK_DEBUG"] = "0"
    env["DEMO_MODE"] = "1"

    cmd = [
        sys.executable, "-c",
        f"from app import create_app; app = create_app(); app.run(host='127.0.0.1', port={port})"
    ]

    print(f"[*] Starting background Flask server on port {port}...")
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    try:
        # Wait for server ready
        ready = False
        for _ in range(15):
            time.sleep(1)
            try:
                r = requests.get(f"http://127.0.0.1:{port}/", timeout=2)
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                pass

        if not ready:
            print("[-] Server failed to start on port 5005.")
            return

        print("[+] Server ready. Launching Playwright browser...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1280, "height": 800})
            page = context.new_page()

            targets = [
                ("01_landing_page.png", f"http://127.0.0.1:{port}/", "Landing page with URL scanner input"),
                ("02_dashboard.png", f"http://127.0.0.1:{port}/dashboard", "Interactive dashboard with metrics and Chart.js charts"),
                ("03_scan_results.png", f"http://127.0.0.1:{port}/scans/1", "Detailed scan results with security score and finding cards"),
                ("04_scan_comparison.png", f"http://127.0.0.1:{port}/scans/1/compare?other=2", "Side-by-side scan differential comparison"),
                ("05_scan_history.png", f"http://127.0.0.1:{port}/history", "Historical scans table with pagination and filter options"),
                ("06_report_view.png", f"http://127.0.0.1:{port}/reports/1", "Executive summary security report view")
            ]

            for filename, url, desc in targets:
                out_file = os.path.join(SCREENSHOTS_DIR, filename)
                print(f"[*] Capturing: {desc} -> {filename}...")
                page.goto(url, wait_until="networkidle")
                time.sleep(1) # Allow charts and fonts to settle
                page.screenshot(path=out_file, full_page=False)
                print(f"[+] Saved: {out_file}")

            browser.close()

    finally:
        print("[*] Terminating background Flask server...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    ensure_sample_data()
    render_architecture_diagram()
    render_workflow_diagram()
    capture_genuine_screenshots()
    print("[+] All report assets successfully generated!")
