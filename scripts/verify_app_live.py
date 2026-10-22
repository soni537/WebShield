"""
scripts/verify_app_live.py — Standalone script to test live Flask server endpoints.
"""

import os
import sys
import time
import subprocess
import requests

SERVER_PORT = 5005
BASE_URL = f"http://127.0.0.1:{SERVER_PORT}"
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "live_verify.db"))

env = os.environ.copy()
env["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
env["FLASK_DEBUG"] = "0"
env["DEMO_MODE"] = "1"
env["SCAN_ALLOWLIST"] = "example.com"

# Launch Flask app on port 5005
cmd = [
    sys.executable,
    "-c",
    f"from app import create_app; app = create_app(); app.run(host='127.0.0.1', port={SERVER_PORT})",
]

print(f"[*] Starting Flask test server on port {SERVER_PORT} with database {DB_PATH}...")
proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

try:
    # Wait for server to become ready
    ready = False
    for attempt in range(15):
        time.sleep(1)
        try:
            r = requests.get(f"{BASE_URL}/", timeout=2)
            if r.status_code == 200:
                ready = True
                print(f"[+] Server is up and responding (attempt {attempt + 1})")
                break
        except Exception:
            pass

    if not ready:
        stdout, stderr = proc.communicate(timeout=2)
        print("[-] Server failed to start:")
        print("STDOUT:", stdout)
        print("STDERR:", stderr)
        sys.exit(1)

    print("\n--- 1. Testing Landing Page (/) ---")
    r = requests.get(f"{BASE_URL}/")
    print(f"Status: {r.status_code}, 'WebShield' in body: {'WebShield' in r.text}")
    assert r.status_code == 200

    print("\n--- 2. Testing Dashboard (/dashboard) ---")
    r = requests.get(f"{BASE_URL}/dashboard")
    print(f"Status: {r.status_code}, 'Dashboard' in body: {'Dashboard' in r.text}")
    assert r.status_code == 200

    print("\n--- 3. Testing History (/history) ---")
    r = requests.get(f"{BASE_URL}/history")
    print(f"Status: {r.status_code}")
    assert r.status_code == 200

    print("\n--- 4. Testing API Scan Submission (/scans/api/scan) ---")
    r = requests.post(f"{BASE_URL}/scans/api/scan", json={"url": "https://example.com"})
    print(f"Status: {r.status_code}, Body: {r.text}")
    assert r.status_code in (202, 422)
    scan_id = r.json().get("scan_id") if r.status_code == 202 else None

    if scan_id:
        print(f"\n--- 5. Testing API Scan Status (/scans/api/scan/{scan_id}) ---")
        time.sleep(2)
        r = requests.get(f"{BASE_URL}/scans/api/scan/{scan_id}")
        print(f"Status: {r.status_code}, Body: {r.text}")
        assert r.status_code == 200

        print(f"\n--- 6. Testing Results Page (/scans/{scan_id}) ---")
        r = requests.get(f"{BASE_URL}/scans/{scan_id}")
        print(f"Status: {r.status_code}, 'Scan' in body: {'Scan' in r.text}")
        assert r.status_code == 200

        print(f"\n--- 7. Testing Report Page (/reports/{scan_id}) ---")
        r = requests.get(f"{BASE_URL}/reports/{scan_id}")
        print(f"Status: {r.status_code}")
        assert r.status_code == 200

        print(f"\n--- 8. Testing JSON Report Export (/reports/{scan_id}/export/json) ---")
        r = requests.get(f"{BASE_URL}/reports/{scan_id}/export/json")
        print(f"Status: {r.status_code}, Content-Type: {r.headers.get('Content-Type')}")
        assert r.status_code == 200

        print(f"\n--- 9. Testing CSV Report Export (/reports/{scan_id}/export/csv) ---")
        r = requests.get(f"{BASE_URL}/reports/{scan_id}/export/csv")
        print(f"Status: {r.status_code}, Content-Type: {r.headers.get('Content-Type')}")
        assert r.status_code == 200

        print(f"\n--- 10. Testing PDF Report Export (/reports/{scan_id}/export/pdf) ---")
        r = requests.get(f"{BASE_URL}/reports/{scan_id}/export/pdf")
        print(f"Status: {r.status_code}, Content-Type: {r.headers.get('Content-Type')}, Bytes: {len(r.content)}")
        assert r.status_code == 200

    print("\n--- 11. Testing API History (/scans/api/history) ---")
    r = requests.get(f"{BASE_URL}/scans/api/history")
    print(f"Status: {r.status_code}, Body: {r.text[:200]}")
    assert r.status_code == 200

    print("\n[+] ALL LIVE ENDPOINT CHECKS SUCCEEDED!")

finally:
    print("[*] Terminating test server...")
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except Exception:
            pass
