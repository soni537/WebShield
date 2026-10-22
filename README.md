# WebShield — Automated Web Security Scanner

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.0.3-green.svg)](https://palletsprojects.com/p/flask/)
[![Tests](https://img.shields.io/badge/tests-110%20passed-brightgreen.svg)](https://pytest.org/)
[![Database](https://img.shields.io/badge/database-MySQL%20%7C%20SQLite-orange.svg)](https://www.sqlalchemy.org/)

WebShield is a lightweight, automated web application security posture scanner designed to evaluate authorized web targets for critical transport security misconfigurations, missing HTTP defense headers, insecure cookie attributes, permissive Cross-Origin Resource Sharing (CORS) rules, and insecure HTML practices.

WebShield produces categorized findings with actionable remediation advice, computes an aggregate security score (0–100), presents historical scan telemetry through an interactive dashboard, and exports audit-ready reports in JSON, CSV, and PDF formats.

---

## Table of Contents

- [1. Overview & Problem Statement](#1-overview--problem-statement)
- [2. System Architecture](#2-system-architecture)
- [3. Features](#3-features)
- [4. Security Checks Explained](#4-security-checks-explained)
- [5. Technology Stack](#5-technology-stack)
- [6. System Requirements](#6-system-requirements)
- [7. Project Directory Structure](#7-project-directory-structure)
- [8. Installation & Setup](#8-installation--setup)
- [9. Database Configuration](#9-database-configuration)
- [10. Environment Variables](#10-environment-variables)
- [11. Running the Application](#11-running-the-application)
- [12. How to Use WebShield](#12-how-to-use-webshield)
- [13. REST API Reference](#13-rest-api-reference)
- [14. Testing & Quality Assurance](#14-testing--quality-assurance)
- [15. Security & Ethical Use](#15-security--ethical-use)
- [16. Troubleshooting](#16-troubleshooting)
- [17. Limitations & Future Enhancements](#17-limitations--future-enhancements)
- [18. Academic Project Information](#18-academic-project-information)
- [19. License & Contribution](#19-license--contribution)

---

## 1. Overview & Problem Statement

Modern web security requires defense-in-depth. While backend application logic flaws often receive the most attention, a significant proportion of real-world breaches and browser-side attacks (including Cross-Site Scripting, Clickjacking, MIME confusion, and Session Hijacking) stem from baseline misconfigurations:

- **Missing or weak HTTP security headers** that leave browser security controls disabled.
- **Insecure cookie attributes** (`HttpOnly`, `Secure`, `SameSite`) that expose session identifiers to client-side scripts and cross-site requests.
- **Permissive CORS headers** allowing arbitrary third-party domains to read authenticated responses.
- **Missing HTTPS or plaintext fallback forms** exposing credentials in transit.

**WebShield** solves this challenge by providing security engineers, system administrators, and developers with a non-destructive, automated assessment engine that checks externally visible HTTP and transport configurations without requiring active credential brute-forcing or invasive payload exploitation.

### Target Users & Use Cases
- **Security Engineering Students & Researchers:** Studying passive security assessment and security posture metrics.
- **Developers & DevSecOps:** Validating staging or production server hardening before release.
- **System Administrators:** Auditing web server headers (Nginx, Apache, Caddy, Cloudflare) against industry standards (OWASP, NIST).

---

## 2. System Architecture

WebShield is structured into modular layers separating the presentation interface, routing logic, asynchronous scan orchestration, modular security analyzers, and report generation.


flowchart TD
    Client["Web Browser / API Client"] -->|HTTP / JSON| FlaskApp["Flask Web Application - app.py"]

    subgraph Routing["Routing and Controllers"]
        FlaskApp --> DashBP["Dashboard Blueprint - routes/dashboard.py"]
        FlaskApp --> ScanBP["Scans Blueprint - routes/scans.py"]
        FlaskApp --> ReportBP["Reports Blueprint - routes/reports.py"]
    end

    subgraph Guardrails["Task Management and Security"]
        ScanBP --> SSRF["SSRF Validation - scanner/safety.py"]
        ScanBP --> TaskRunner["Background Task Runner - scanner/task_runner.py"]
    end

    subgraph Scanner["Scanner Engine"]
        TaskRunner --> Orchestrator["Scan Orchestrator - scanner/orchestrator.py"]
        Orchestrator --> ModTLS["Transport and TLS - scanner/transport.py"]
        Orchestrator --> ModHDR["Security Headers - scanner/headers.py"]
        Orchestrator --> ModCKY["Cookie Attributes - scanner/cookies.py"]
        Orchestrator --> ModCORS["CORS Analyzer - scanner/cors.py"]
        Orchestrator --> ModHTML["HTML Inspection - scanner/html_checks.py"]
        Orchestrator --> Scoring["Scoring Engine - scanner/scoring.py"]
    end

    subgraph Storage["Storage and Export"]
        Orchestrator --> DB["SQLAlchemy Database - MySQL or SQLite"]
        ReportBP --> DB
        ReportBP --> ReportSvc["Report Service - services/report_service.py"]
        ReportSvc --> ExportPDF["PDF Export - ReportLab"]
        ReportSvc --> ExportCSV["CSV Exporter"]
        ReportSvc --> ExportJSON["JSON Exporter"]
    end


## 3. Features

### Core Capabilities
- **Non-Destructive Scanning:** Evaluates target endpoints using standard HTTP requests (`GET`, `HEAD`, `OPTIONS`) without exploiting vulnerabilities or injecting destructive payloads.
- **Multi-Module Analysis:**
  - Transport Layer Security (TLS/HTTPS verification, HTTP-to-HTTPS redirect validation).
  - Seven critical HTTP defense headers.
  - Session and tracking cookie security attributes.
  - Cross-Origin Resource Sharing (CORS) origin reflections and credential flags.
  - HTML form action inspection and password field autocomplete observations.
- **Deductive Scoring Model:** Calculates a 0–100 security score with qualitative health bands (*Excellent*, *Good*, *Fair*, *Poor*, *Critical*).
- **Interactive UI & Visualization:** Bootstrap 5 dark-themed interface with Chart.js score history and finding severity distributions.
- **Scan Comparison:** Side-by-side differential inspection of historical scans for the same hostname.
- **Multi-Format Export Engine:** On-demand generation of structured JSON, spreadsheet-ready CSV, and formal executive PDF reports.
- **Managed Threading & Reliability:** Background execution engine tracking scan threads with clean lifecycle synchronization to prevent database race conditions.
- **Robust SSRF Protection:** Pre-flight DNS resolution, IPv4/IPv6 private/reserved address filtering, hex/integer notation validation, and per-hop redirect verification.

---

## 4. Security Checks Explained

WebShield assigns a unique identifier (`finding_id`) to every observation. Findings reflect configuration state rather than confirmed exploitability.

### 4.1 Transport Security (`scanner/transport.py`)

| Check ID | Name | Default Severity | Description & Significance |
| :--- | :--- | :---: | :--- |
| **TLS-001** | HTTPS Support | High | Confirms the server responds over HTTPS with a valid TLS certificate recognized by standard system trust stores. |
| **TLS-002** | HTTP-to-HTTPS Redirect | Medium | Verifies that plaintext HTTP requests are immediately redirected (301/308) to encrypted HTTPS endpoints. |
| **TLS-003** | TLS Certificate Validity | High | Evaluates certificate expiration, domain matching, and certificate authority trustworthiness. |

### 4.2 HTTP Security Headers (`scanner/headers.py`)

| Check ID | Name | Default Severity | Description & Significance |
| :--- | :--- | :---: | :--- |
| **HDR-001** | Content-Security-Policy | High | Checks for `Content-Security-Policy` and flags dangerous directives such as `'unsafe-inline'` or `'unsafe-eval'`. Prevents XSS and unauthorized script execution. |
| **HDR-002** | Strict-Transport-Security | High | Validates `Strict-Transport-Security` (HSTS) on HTTPS responses, ensuring a sufficient `max-age` (minimum 6 months / 15,552,000s) to prevent SSL-stripping MITM attacks. |
| **HDR-003** | X-Content-Type-Options | Medium | Checks for `X-Content-Type-Options: nosniff`. Prevents MIME-confusion attacks and executable payload sniffing. |
| **HDR-004** | X-Frame-Options | Medium | Checks for `X-Frame-Options` (`DENY` or `SAMEORIGIN`) to prevent Clickjacking. Recognizes when superseded by CSP `frame-ancestors`. |
| **HDR-005** | Referrer-Policy | Low | Checks for `Referrer-Policy` to avoid leaking sensitive URLs or authentication tokens in HTTP `Referer` headers. |
| **HDR-006** | Permissions-Policy | Informational | Verifies whether browser hardware APIs (camera, microphone, geolocation) are restricted. |
| **HDR-007** | Server Version Leak | Informational | Flags verbose `Server` or `X-Powered-By` headers that disclose exact underlying web server and framework versions. |

### 4.3 Cookie Security Flags (`scanner/cookies.py`)

| Check ID | Name | Default Severity | Description & Significance |
| :--- | :--- | :---: | :--- |
| **CKY-001** | Cookie Missing `Secure` Flag | Medium | Ensures cookies transmitted over HTTPS carry the `Secure` flag, preventing plaintext transmission over HTTP. |
| **CKY-002** | Cookie Missing `HttpOnly` Flag | Medium | Identifies session tokens lacking `HttpOnly`, which leaves them vulnerable to theft via Cross-Site Scripting (XSS). |
| **CKY-003** | Insecure or Missing `SameSite` | Low | Inspects `SameSite` attribute (`Strict`, `Lax`, or `None`). Flags `SameSite=None` without `Secure` and cookies omitting `SameSite`. |
| **CKY-004** | Persistent Cookie Observation | Informational | Observes session cookies configured with long expiration times (`Max-Age` / `Expires`). |

### 4.4 CORS Configuration (`scanner/cors.py`)

| Check ID | Name | Default Severity | Description & Significance |
| :--- | :--- | :---: | :--- |
| **CRS-001** | Wildcard Origin with Credentials | High | Detects `Access-Control-Allow-Origin: *` paired with `Access-Control-Allow-Credentials: true`, a severe browser violation that allows arbitrary websites to read authenticated responses. |
| **CRS-002** | Arbitrary Reflected Origin | High | Tests whether sending a test origin header causes the server to dynamically echo that origin back in `Access-Control-Allow-Origin`. |
| **CRS-003** | Overly Permissive Methods | Medium | Identifies wildcard or high-risk HTTP method allowances (`PUT`, `DELETE`) exposed broadly. |
| **CRS-004** | Missing `Vary: Origin` | Low | Checks if dynamic CORS responses include `Vary: Origin` to prevent HTTP cache poisoning. |

### 4.5 HTML Security Observations (`scanner/html_checks.py`)

| Check ID | Name | Default Severity | Description & Significance |
| :--- | :--- | :---: | :--- |
| **HTML-001** | Form Submits Over Plaintext HTTP | Medium | Flags `<form>` elements whose `action` attribute submits data over unencrypted HTTP. |
| **HTML-002** | Password Field Submitted Insecurely | High | Identifies forms containing `<input type="password">` that transmit credentials over plaintext HTTP. |
| **HTML-003** | Mixed Content / Insecure Resources | Medium | Inspects `src` attributes of scripts, stylesheets, and images for unencrypted HTTP inclusions on HTTPS pages. |
| **HTML-004** | Meta Security Tag Fallbacks | Informational | Inspects `<meta http-equiv>` tags that supply client-side CSP or Referrer fallbacks. |
| **HTML-005** | Autocomplete on Sensitive Inputs | Informational | Observes password inputs lacking `autocomplete="off"` or `autocomplete="new-password"`. |

---

## 5. Technology Stack

- **Application Framework:** Python 3.10+ / [Flask 3.0.3](https://flask.palletsprojects.com/)
- **Database ORM:** [Flask-SQLAlchemy 3.1.1](https://flask-sqlalchemy.palletsprojects.com/) / [SQLAlchemy 2.0+](https://www.sqlalchemy.org/)
- **Database Engines:** [PyMySQL 1.1.1](https://pymysql.readthedocs.io/) (MySQL production & staging), SQLite (standalone local development & testing)
- **Forms & CSRF:** [Flask-WTF 1.2.1](https://flask-wtf.readthedocs.io/) / WTForms 3.1.2
- **Session Management:** [Flask-Login 0.6.3](https://flask-login.readthedocs.io/)
- **HTTP Client & Parsing:** [Requests 2.32.3](https://requests.readthedocs.io/), [BeautifulSoup4 4.12.3](https://www.crummy.com/software/BeautifulSoup/), [lxml 5.2.2](https://lxml.de/)
- **PDF Generation:** [ReportLab 4.2.2](https://www.reportlab.com/)
- **Front-End Styling:** [Bootstrap 5.3.3](https://getbootstrap.com/), [Bootstrap Icons 1.11.3](https://icons.getbootstrap.com/), Google Fonts (Inter, JetBrains Mono)
- **Data Visualization:** [Chart.js 4.4.3](https://www.chartjs.org/)
- **Testing Framework:** [pytest 8.2.2](https://docs.pytest.org/), [pytest-mock 3.14.0](https://pytest-mock.readthedocs.io/)

---

## 6. System Requirements

- **Operating System:** Windows 10/11, Windows Server 2019+, Ubuntu 20.04+, Debian 11+, or macOS 12+
- **Python:** Python 3.10, 3.11, 3.12, or 3.13 (3.13 tested and verified)
- **Package Manager:** `pip` (Python package manager)
- **Database Engine (Choose One):**
  - **SQLite:** Built-in with Python, zero installation required. Ideal for development and demonstration.
  - **MySQL / MariaDB:** MySQL 8.0+ or MariaDB 10.4+ for multi-user production environments.

---

## 7. Project Directory Structure

```text
D:\WebShield\
├── app.py                     # Flask application factory and entry point
├── config.py                  # Environment-driven configuration (Dev, Prod, Test)
├── extensions.py              # Shared SQLAlchemy, CSRF, and LoginManager instances
├── models.py                  # User, Scan, and Finding ORM models
├── conftest.py                # Root test configuration (sys.path initialization)
├── pytest.ini                 # Pytest runner settings and local tempdir config
├── requirements.txt           # Python package dependencies
├── .env.example               # Template for local environment variables
├── .gitignore                 # Version control exclusions
│
├── scanner/                   # Core Security Scanning Engine
│   ├── __init__.py            # Package exports (run_scan, dispatch_scan, etc.)
│   ├── safety.py              # SSRF protection, IP/DNS validation, redirect checks
│   ├── transport.py           # HTTPS, TLS certificate, and redirect analysis
│   ├── headers.py             # HTTP security header checks (CSP, HSTS, XFO, etc.)
│   ├── cookies.py             # Cookie attribute inspection (Secure, HttpOnly, etc.)
│   ├── cors.py                # Cross-Origin Resource Sharing analysis
│   ├── html_checks.py         # BeautifulSoup HTML inspection (forms, inputs, mixed content)
│   ├── scoring.py             # Security score deduction algorithm and thresholds
│   ├── orchestrator.py        # Pipeline coordinator running checks and saving results
│   └── task_runner.py         # Managed background thread execution and synchronization
│
├── routes/                    # Flask Blueprint Controllers
│   ├── __init__.py
│   ├── dashboard.py           # Landing page, dashboard statistics, history, health
│   ├── scans.py               # Scan submission, status API, results UI, comparison
│   └── reports.py             # Report viewing and JSON/CSV/PDF download dispatch
│
├── services/                  # Business Logic Services
│   ├── __init__.py
│   └── report_service.py      # PDF (ReportLab), CSV, and JSON report generator
│
├── static/                    # Front-End Static Assets
│   ├── css/
│   │   └── style.css          # Custom styling, dark mode tokens, and score badges
│   └── js/
│       └── dashboard.js       # Chart.js initialization and client-side interactions
│
├── templates/                 # Jinja2 HTML Templates
│   ├── base.html              # Base layout with navbar, alerts, footer, and CDN links
│   ├── index.html             # Landing page with URL scan submission form
│   ├── dashboard.html         # Aggregate telemetry, score chart, and recent scans
│   ├── scan_results.html      # Detailed scan findings grouped by severity
│   ├── scan_history.html      # Paginated and searchable scan history table
│   ├── compare.html           # Side-by-side scan differential comparison
│   └── reports.html           # Print-friendly executive summary report
│
├── tests/                     # Automated Test Suite (110 passing tests)
│   ├── conftest.py            # Test fixtures and background thread draining
│   ├── test_safety.py         # SSRF, IPv4, IPv6, CIDR, and DNS test suite
│   ├── test_headers.py        # Header scanner module unit tests
│   ├── test_cookies.py        # Cookie attribute scanner unit tests
│   ├── test_cors.py           # CORS analyzer unit tests
│   ├── test_reports.py        # JSON, CSV, and PDF generation tests
│   ├── test_api.py            # Route integration and API endpoint tests
│   └── test_e2e_lifecycle.py  # Live simulated server end-to-end lifecycle tests
│
└── scripts/
    └── verify_app_live.py     # Live server diagnostic validation script
```

---

## 8. Installation & Setup

Follow these steps to set up and run WebShield on **Windows PowerShell**.

### Step 1: Open the Project Directory
Open Windows PowerShell and navigate to the project directory:
```powershell
cd D:\WebShield
```

### Step 2: Create and Activate a Virtual Environment
Create an isolated Python virtual environment:
```powershell
python -m venv .venv
```
Activate the virtual environment:
```powershell
.\.venv\Scripts\Activate.ps1
```

> **PowerShell Execution Policy Note:** If script execution is blocked on your system, enable it for the current process:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .\.venv\Scripts\Activate.ps1
> ```

*(For Linux / macOS bash users):*
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Upgrade pip and Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure the Environment File
Copy the provided `.env.example` file to create your active `.env`:
```powershell
Copy-Item .env.example .env
```
Open `.env` in your text editor and adjust settings as needed (see [Database Configuration](#9-database-configuration) and [Environment Variables](#10-environment-variables)).

---

## 9. Database Configuration

WebShield uses SQLAlchemy with support for both **SQLite** and **MySQL**.

### Automatic Table Creation
When WebShield starts (`app.py`), it automatically calls `db.create_all()` inside an application context. If tables (`users`, `scans`, `findings`) do not exist, they are created automatically.

---

### Option A: SQLite (Quickest / Zero-Setup)

SQLite requires no external server installation and stores all data in a single local file. This is the recommended option for local evaluation, grading, and testing.

1. Open `.env` and set:
   ```ini
   DATABASE_URL=sqlite:///d:/WebShield/webshield_dev.db
   ```
   *(Or in PowerShell for your current terminal session)*:
   ```powershell
   $env:DATABASE_URL = "sqlite:///d:/WebShield/webshield_dev.db"
   ```
2. Start the application. The `webshield_dev.db` file will be created automatically.

---

### Option B: MySQL / MariaDB (Production & Staging)

For multi-user production environments with a running MySQL server:

1. **Log in to MySQL as administrator:**
   ```powershell
   mysql -u root -p
   ```

2. **Execute the initialization SQL script:**
   ```sql
   -- Create database with UTF-8 support
   CREATE DATABASE webshield CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

   -- Create a dedicated application user
   CREATE USER 'webshield_user'@'localhost' IDENTIFIED BY 'StrongPasswordHere123!';

   -- Grant permissions to the application database only
   GRANT ALL PRIVILEGES ON webshield.* TO 'webshield_user'@'localhost';
   FLUSH PRIVILEGES;
   EXIT;
   ```

3. **Configure `.env` with your credentials:**
   ```ini
   DB_HOST=localhost
   DB_PORT=3306
   DB_NAME=webshield
   DB_USER=webshield_user
   DB_PASSWORD=StrongPasswordHere123!
   ```
   Alternatively, you can provide the complete connection URI via `DATABASE_URL`:
   ```ini
   DATABASE_URL=mysql+pymysql://webshield_user:StrongPasswordHere123!@localhost:3306/webshield
   ```

---

## 10. Environment Variables

All settings are managed via environment variables and loaded automatically via `python-dotenv`:

| Variable Name | Required? | Default Value | Description |
| :--- | :---: | :--- | :--- |
| `SECRET_KEY` | Recommended | `dev-only-insecure-key-change-me` | Cryptographic secret key used by Flask for session signing and CSRF tokens. Set to a random 32+ character string in production. |
| `FLASK_ENV` | Optional | `development` | Selects config class: `development`, `production`, or `testing`. |
| `FLASK_DEBUG` | Optional | `0` | Enables Flask interactive debug mode (`1` for dev, `0` for production). |
| `DATABASE_URL` | Optional | *(Computed from DB_*)* | Direct database connection URI. E.g. `sqlite:///d:/WebShield/webshield_dev.db` or `mysql+pymysql://...`. Overrides individual `DB_*` variables if set. |
| `DB_HOST` | Optional | `localhost` | MySQL server hostname or IP address. |
| `DB_PORT` | Optional | `3306` | MySQL server network port. |
| `DB_NAME` | Optional | `webshield` | Name of the database schema. |
| `DB_USER` | Optional | `root` | Database username. |
| `DB_PASSWORD` | Optional | `""` | Database user password. |
| `SCANNER_TIMEOUT` | Optional | `15` | Per-request network timeout (in seconds) applied to all target probes. |
| `SCANNER_MAX_RESPONSE_SIZE`| Optional | `5242880` (5 MB) | Maximum bytes read from a target response. Prevents memory exhaustion attacks. |
| `SCANNER_MAX_REQUESTS_PER_SCAN` | Optional | `20` | Maximum network requests allowed for a single scan execution. |
| `RATE_LIMIT_PER_MINUTE` | Optional | `10` | Maximum scan initiations allowed per client IP address in a 60-second window. |
| `SCAN_ALLOWLIST` | Optional | `""` (Empty = Permissive) | Comma-separated list of hostnames allowed for scanning (e.g., `example.com,test.com`). If empty, scans are open to any valid public domain. |
| `DEMO_MODE` | Optional | `0` | When set to `1`, fallback simulation can be used when remote hosts are offline. |

---

## 11. Running the Application

### Starting with Standalone SQLite (Recommended for Testing)
In your activated Windows PowerShell window:
```powershell
$env:DATABASE_URL = "sqlite:///d:/WebShield/webshield_dev.db"
python app.py
```

### Starting with Configured `.env` (MySQL or Config File)
```powershell
python app.py
```

### Accessing the Web Application
Open your browser and navigate to:
```text
http://127.0.0.1:5000/
```

### Stopping the Server
Press `Ctrl + C` in the PowerShell terminal to gracefully terminate the application server.

> **Production Notice:** `python app.py` starts the Werkzeug development server. For production environments, run behind a production WSGI server such as Waitress (on Windows) or Gunicorn (on Linux):
> ```powershell
> pip install waitress
> waitress-serve --port=5000 app:create_app
> ```

---

## 12. How to Use WebShield

### 1. Initiate a Scan
1. Open the landing page (`http://127.0.0.1:5000/`).
2. Enter the full URL of the website you are authorized to assess (e.g. `https://example.com`).
3. Click **Start Security Scan**.
4. The application validates the URL against SSRF rules, registers the scan as `pending`, and immediately transitions to the real-time scan status screen (`/scans/<scan_id>`).

### 2. View Real-Time Status & Results
- Once the background engine finishes executing checks, the page refreshes to reveal:
  - **Overall Security Score:** A numerical score (0–100) and color-coded badge.
  - **Telemetry Summary:** Total findings categorized by severity (*Critical*, *High*, *Medium*, *Low*, *Informational*).
  - **Findings Table:** Detailed cards for each check displaying the finding ID, description, recorded technical evidence, security impact, remediation guidance, and official reference links.

### 3. Review Analytics Dashboard
Click **Dashboard** in the top navigation bar (`/dashboard`):
- View aggregate scan count and findings statistics across all targets.
- Inspect the **Score History Trend** line chart and the **Findings by Severity** distribution doughnut chart.
- Quick-access table showing the 10 most recent scans.

### 4. Search and Filter History
Click **History** (`/history`):
- Browse paginated scan records.
- Filter historical scans by target URL substring or status (*Completed*, *Failed*, *Running*).

### 5. Compare Scans
1. Navigate to a completed scan's results page.
2. Click **Compare Scan** (`/scans/<scan_id>/compare`).
3. Select an earlier scan of the same domain from the dropdown.
4. Review side-by-side findings comparison to verify whether security remediation was effective.

### 6. Export Reports
Navigate to the report screen (`/reports/<scan_id>`) or download directly:
- **JSON:** Machine-readable report for CI/CD integration (`/reports/<scan_id>/export/json`).
- **CSV:** Tabular export suitable for Excel or data analysis (`/reports/<scan_id>/export/csv`).
- **PDF:** Formal, professionally formatted executive security report with score badges, finding summaries, and evidence blocks (`/reports/<scan_id>/export/pdf`).

---

## 13. REST API Reference

WebShield provides a RESTful JSON API alongside its web interface. JSON API endpoints are exempted from CSRF requirements for automated integration.

### Summary of Endpoints

| HTTP Method | Endpoint | Description | Expected Status |
| :--- | :--- | :--- | :---: |
| `GET` | `/` | Web landing page and scan submission form | `200 OK` |
| `GET` | `/dashboard` | Interactive analytics dashboard | `200 OK` |
| `GET` | `/history` | Paginated scan history web view | `200 OK` |
| `GET` | `/health` | System and database health status check | `200 OK` |
| `POST` | `/scans/new` | Web form scan initiation (form URL-encoded) | `302 Found` |
| `GET` | `/scans/<scan_id>` | Scan results and detailed findings web view | `200 OK` |
| `GET` | `/scans/<scan_id>/compare` | Side-by-side scan comparison view | `200 OK` |
| `POST` | `/scans/api/scan` | API scan submission (`{"url": "https://..."}`) | `202 Accepted` / `422` |
| `GET` | `/scans/api/scan/<scan_id>` | API scan status and score summary | `200 OK` / `404` |
| `GET` | `/scans/api/scan/<scan_id>/findings` | API list of findings for a completed scan | `200 OK` / `409` |
| `GET` | `/scans/api/history` | Paginated API scan history list | `200 OK` |
| `GET` | `/reports/<scan_id>` | HTML executive summary report view | `200 OK` |
| `GET` | `/reports/<scan_id>/export/<fmt>` | Download report (`fmt`: `json`, `csv`, or `pdf`) | `200 OK` / `400` |

### API Usage Examples

#### 1. Submit a New Scan via API
```bash
curl -X POST http://127.0.0.1:5000/scans/api/scan \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
```
**Response (`202 Accepted`):**
```json
{
  "scan_id": 1,
  "status": "pending"
}
```

#### 2. Query Scan Status & Results
```bash
curl http://127.0.0.1:5000/scans/api/scan/1
```
**Response (`200 OK`):**
```json
{
  "id": 1,
  "target_url": "https://example.com",
  "normalized_hostname": "example.com",
  "status": "completed",
  "security_score": 37,
  "total_findings": 13,
  "critical_count": 0,
  "high_count": 2,
  "medium_count": 3,
  "low_count": 1,
  "informational_count": 7,
  "scan_started_at": "2026-10-22T09:19:35",
  "scan_completed_at": "2026-10-22T09:19:36",
  "duration_seconds": 1.35
}
```

---

## 14. Testing & Quality Assurance

WebShield maintains a comprehensive automated test suite powered by `pytest` covering unit checks, SSRF boundary conditions, report builders, route APIs, and end-to-end scanner execution.

### Running the Complete Test Suite
In Windows PowerShell from the project root:
```powershell
python -m pytest tests/ -v
```

### Verified Test Results
```text
============================= test session starts =============================
platform win32 -- Python 3.13.1, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\WebShield, configfile: pytest.ini
collected 110 items

tests/test_api.py .....................                                  [ 19%]
tests/test_cookies.py ........                                           [ 26%]
tests/test_cors.py .........                                             [ 34%]
tests/test_e2e_lifecycle.py ...                                          [ 37%]
tests/test_headers.py ....................                               [ 55%]
tests/test_reports.py ......                                             [ 60%]
tests/test_safety.py ............................................        [100%]

======================= 110 passed, 2 warnings in 6.87s =======================
```
*Note on warnings:* The 2 captured warnings originate from external third-party packages (the standard Requests/urllib3 environment notice on Python 3.13 and ReportLab's internal `ast.NameConstant` backward-compatibility check). WebShield project code executes with zero warnings and zero thread race conditions.

### Test Categories
1. **SSRF & Network Safety (`tests/test_safety.py`):** 44 test cases validating IPv4 CIDR blocks, IPv6 ranges, link-local metadata addresses, cloud metadata endpoints, decimal/hex IP representations, and redirect destination policies.
2. **Security Headers (`tests/test_headers.py`):** 20 tests validating individual header presence, weak values, and fallback precedence.
3. **Cookie Security (`tests/test_cookies.py`):** 8 tests validating flags across HTTP and HTTPS schemes.
4. **CORS Security (`tests/test_cors.py`):** 9 tests testing wildcard origins, reflected origins, credentials combinations, and `Vary: Origin` headers.
5. **Report Exports (`tests/test_reports.py`):** 6 tests validating JSON structure, CSV syntax, and valid binary PDF generation.
6. **API & Route Integration (`tests/test_api.py`):** 20 integration tests verifying HTTP status codes, error handling, input validation, and history pagination.
7. **End-to-End Lifecycle (`tests/test_e2e_lifecycle.py`):** 3 live tests that spawn an ephemeral HTTP server on `127.0.0.1`, run a full scan cycle, verify database persistence of findings, and validate exported reports.

---

## 15. Security & Ethical Use

> [!IMPORTANT]
> **Ethical Scanner Policy:** WebShield is designed strictly for authorized, defensive security evaluations. You must **only scan websites you own or have explicit written permission to test**.

### Built-in SSRF Protection & Defense-in-Depth
To prevent Server-Side Request Forgery (SSRF) and avoid unintended scanning of internal networks:
1. **Scheme Restrictions:** Only `http` and `https` schemes are accepted. Protocols like `file://`, `gopher://`, `ftp://`, or `data:` are blocked.
2. **Blocked Hostnames:** Cloud metadata hostnames (`metadata.google.internal`, `metadata.goog`) are explicitly denied.
3. **Private & Reserved IPv4 Filtering:** Prohibits scanning loopback (`127.0.0.0/8`), private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local / cloud metadata (`169.254.0.0/16`), carrier-grade NAT (`100.64.0.0/10`), multicast (`224.0.0.0/4`), and broadcast (`255.255.255.255/32`).
4. **IPv6 Matching:** Prohibits loopback (`::1`), link-local (`fe80::/10`), unique local (`fc00::/7`), and multicast (`ff00::/8`).
5. **Encoding Protection:** Detects and parses raw integer and hexadecimal IP representations (e.g. `2130706433` or `0x7f000001`) before DNS resolution.
6. **Pre-Flight DNS Resolution:** Resolves target hostnames prior to connecting; if any returned IP falls within a prohibited range, the scan is blocked immediately.
7. **Redirect Verification:** All redirects are intercepted and re-validated against SSRF filters at every hop.
8. **Resource Caps:** Enforces strict timeouts (`SCANNER_TIMEOUT=15`) and streaming response caps (`SCANNER_MAX_RESPONSE_SIZE=5242880` bytes) to prevent resource exhaustion attacks.
9. **Strict TLS Verification:** All outbound HTTPS checks strictly enforce valid TLS certificates using standard system CA trust bundles (`verify=True`).

---

## 16. Troubleshooting

### 1. `OperationalError: (1045, "Access denied for user 'root'@'localhost'")`
- **Cause:** MySQL is running on port 3306 but the credentials in `.env` do not match your MySQL server password.
- **Solution:** 
  - Update `DB_USER` and `DB_PASSWORD` in `.env` to match your MySQL server credentials.
  - Or switch to SQLite by setting `DATABASE_URL=sqlite:///d:/WebShield/webshield_dev.db`.

### 2. `Address already in use` or Port 5000 Conflict
- **Cause:** Another process (e.g., AirPlay, previous Flask instance) is using port 5000.
- **Solution:** Check what is running or start WebShield on a different port:
  ```powershell
  python -c "from app import create_app; create_app().run(port=5050)"
  ```

### 3. `URL validation failed: Resolved address ... is in blocked range`
- **Cause:** Attempted to scan `localhost`, `127.0.0.1`, a private LAN address (e.g., `192.168.1.1`), or an AWS/GCP metadata address.
- **Solution:** WebShield's SSRF protection intentionally blocks local and private networks. Target a valid, public Internet-facing domain.

### 4. PowerShell `Script Execution Blocked`
- **Cause:** Windows PowerShell execution policy restricts running activation scripts.
- **Solution:** Execute:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\.venv\Scripts\Activate.ps1
  ```

### 5. PDF Generation Error (`reportlab` module issue)
- **Cause:** Missing or corrupted ReportLab library.
- **Solution:** Reinstall the package:
  ```powershell
  pip install --force-reinstall reportlab==4.2.2
  ```

---

## 17. Limitations & Future Enhancements

### Genuine Current Limitations
- **Single Page Scope:** Scans the designated URL target; does not recursively crawl all internal links across the domain.
- **Static DOM Inspection:** Uses BeautifulSoup for HTML inspection. Dynamic single-page applications (React, Angular, Vue) requiring heavy client-side JavaScript execution to render DOM forms may omit some client-side HTML checks.
- **In-Memory Rate Limiting:** The per-IP rate limiter uses an in-memory dictionary; production deployments across multiple worker processes would benefit from Redis.
- **Informative Scoring:** The 0–100 score is a heuristic benchmark of defense configuration and does not represent an absolute guarantee of exploit immunity.

### Planned Future Enhancements
- [ ] **Recursive Site Crawler:** Configurable depth crawler to discover and audit multiple sub-pages.
- [ ] **Headless Browser Integration:** Optional Playwright/Selenium driver to execute JavaScript and evaluate dynamically generated forms and cookies.
- [ ] **Scheduled Automated Scans:** Cron-based continuous monitoring with email/webhook change alerts.
- [ ] **Role-Based Access Control (RBAC):** Multi-tenant team authentication with scan access control.
- [ ] **Custom Scan Profiles:** Selectable audit profiles (e.g. *Headers Only*, *OWASP Top 10 Focus*, *Strict Compliance*).

---

## 18. Academic Project Information

This software was developed as a final-year engineering capstone project in Cybersecurity and Web Engineering.

| Project Attribute | Details |
| :--- | :--- |
| **Project Title** | WebShield — Automated Web Security Scanner |
| **Project Type** | Final-Year B.Tech / B.E. Capstone Engineering Project |
| **Domain** | Cybersecurity, Web Application Security, DevSecOps |
| **Academic Year** | 2025 – 2026 |
| **Department** | Computer Science & Engineering / Information Security |
| **Institution** | *[Insert College / University Name]* |
| **Project Guide** | *[Insert Guide / Supervisor Name]* |
| **Student Team** | *[Insert Student Names & Roll Numbers]* |

---

## 19. License & Contribution

### License
No formal open-source license has been specified yet for this repository. All rights are reserved by the original project authors.

### Contributions
Academic and peer review contributions are welcome:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/NewCheck`).
3. Ensure all tests pass (`python -m pytest tests/ -v`).
4. Submit a descriptive Pull Request.
