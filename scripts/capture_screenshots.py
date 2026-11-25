"""Capture validation & security screenshots of the running app (Component 8).

Drives the real website in a headless copy of the installed Google Chrome,
enters invalid input, and saves what the app shows to docs/screenshots/.

    .venv/bin/python scripts/capture_screenshots.py      (app must be running)
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "screenshots"
URL = "http://127.0.0.1:8765/"
PW = "Rvce@2026"
done: list[tuple[str, str]] = []


def api(path, body=None, token=None, method=None):
    req = urllib.request.Request("http://127.0.0.1:8765/api" + path, method=method or ("POST" if body is not None else "GET"),
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.load(e)


def shot(page, name, caption, target=None):
    path = OUT / f"{name}.png"
    if target is not None:
        target.scroll_into_view_if_needed()
        target.screenshot(path=str(path))
    else:
        page.screenshot(path=str(path))
    done.append((path.name, caption))
    print("saved", path.name)


def login(page, user, pw=PW):
    page.evaluate("() => { try { localStorage.clear() } catch (e) {} }")
    page.goto(URL)
    page.fill("#lu", user)
    page.fill("#lp", pw)
    page.click("#loginForm button")
    page.wait_for_selector("#app:not([hidden])", timeout=15000)
    page.wait_for_timeout(800)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    admin_tok = api("/login", {"username": "admin.iyer", "password": PW})["token"]
    incidents = api("/incidents", token=admin_tok)
    new_inc = next(i["incident_id"] for i in incidents if i["status"] == "New")
    owned = next(i for i in incidents if i["analyst"] == "analyst.rao")["incident_id"]

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        ctx = browser.new_context(viewport={"width": 1366, "height": 860}, device_scale_factor=2)
        page = ctx.new_page()
        page.goto(URL)
        page.wait_for_selector("#loginForm")
        card = page.locator("#loginForm")

        # 1. login: required fields
        page.click("#loginForm button")
        page.wait_for_timeout(300)
        shot(page, "01_login_required_fields", "Login form: submitting empty fields is rejected in the browser", card)

        # 2. login: wrong password
        page.fill("#lu", "analyst.rao"); page.fill("#lp", "wrong-password")
        page.click("#loginForm button"); page.wait_for_timeout(1200)
        shot(page, "02_login_wrong_password", "Login form: wrong password rejected by the server (scrypt hash check)", card)

        # 3. login: lockout after repeated failures (throw-away username)
        page.fill("#lu", "demo.attacker")
        for _ in range(6):
            page.fill("#lp", "guess"); page.click("#loginForm button"); page.wait_for_timeout(500)
        shot(page, "03_login_lockout", "Brute-force protection: 5 failures in 5 minutes lock the account", card)

        # 4. admin: add-user form validation
        login(page, "admin.iyer")
        page.evaluate("() => { store.set('adminSub','users'); show('admin'); }")
        page.wait_for_selector("#uf")
        page.fill("#u_name", "Bad Name!"); page.fill("#u_mail", "not-an-email")
        page.select_option("#u_role", "Analyst"); page.fill("#u_dept", "S"); page.fill("#u_pw", "abc")
        page.click("#uf button"); page.wait_for_timeout(400)
        shot(page, "04_add_user_validation", "Admin › Add user: username, email, department and password-strength rules",
             page.locator("#uf").locator("xpath=.."))

        # 5. admin: register-device validation
        page.evaluate("() => { store.set('adminSub','devices'); admin(); }")
        page.wait_for_selector("#df")
        page.fill("#d_host", "-bad host-"); page.fill("#d_ip", "999.10.1.300"); page.fill("#d_mac", "zz:11")
        page.fill("#d_os", ""); page.fill("#d_crit", "9")
        page.click("#df button"); page.wait_for_timeout(400)
        shot(page, "05_device_validation", "Admin › Register device: hostname, IPv4, MAC, OS and criticality (1–5) checks",
             page.locator("#df").locator("xpath=.."))

        # 6. server-side validation: the API rejects bad data even if the browser checks are bypassed
        resp = page.evaluate("""async () => {
            const r = await fetch('/api/admin/users', {method:'POST', headers:{'Content-Type':'application/json',
                      Authorization:'Bearer ' + TOKEN}, body: JSON.stringify({username:'x', email:'nope', role:'Hacker', department:''})});
            return {status: r.status, body: await r.json()};
        }""")
        page.set_content(f"""<html><body style="background:#0f1420;color:#e6ebf5;font:15px ui-monospace,monospace;padding:28px">
            <h2 style="font-family:system-ui">Server-side validation (browser checks bypassed with a direct API call)</h2>
            <p style="font-family:system-ui;color:#8d99b5">POST /api/admin/users with username 'x', email 'nope', role 'Hacker', empty department</p>
            <p><b>HTTP {resp['status']} Unprocessable Entity</b></p>
            <pre style="background:#171e2e;padding:16px;border-radius:10px;white-space:pre-wrap">{json.dumps(resp['body'], indent=2)[:2200]}</pre></body></html>""")
        shot(page, "06_server_side_validation", "Server-side validation: the API rejects invalid data even when the web form is bypassed")
        page.goto(URL); page.wait_for_selector("#app:not([hidden])")

        # 7. incident: closing without a reason / notes too short
        page.evaluate(f"async () => {{ show('incidents'); await new Promise(r => setTimeout(r, 500)); await incidentDetail({new_inc}); }}")
        page.wait_for_selector("#ns")
        page.select_option("#ns", "False Positive"); page.fill("#nsNote", "")
        page.click("#sts"); page.wait_for_timeout(400)
        page.evaluate("() => window.scrollTo(0, 0)")
        shot(page, "07_reason_required", "Incident workflow: marking False Positive without a written reason is refused")
        page.fill("#anotes", "ok"); page.click("#actForm button"); page.wait_for_timeout(300)
        shot(page, "08_action_notes_validation", "Record action: notes shorter than 3 characters are rejected",
             page.locator("#actForm").locator("xpath=.."))

        # 9. Ask AI: destructive request neutralised
        page.evaluate("() => show('ask')")
        page.wait_for_selector("#q")
        page.fill("#q", "drop table users")
        page.click("#qf button")
        page.wait_for_function("() => !document.querySelector('#ans').innerText.includes('Thinking')", timeout=120000)
        page.wait_for_timeout(300)
        shot(page, "09_ask_ai_sql_injection_blocked", "Ask AI: 'drop table users' → only a harmless read-only query runs",
             page.locator("#tab-ask .card"))

        # 10. raw-log integrity
        page.evaluate(f"async () => {{ show('incidents'); await new Promise(r => setTimeout(r, 500)); await incidentDetail({owned}); }}")
        page.wait_for_selector("a.raw")
        page.click("a.raw"); page.wait_for_selector("#modal:not([hidden])"); page.wait_for_timeout(500)
        shot(page, "10_raw_log_integrity", "Evidence integrity: SHA-256 of the MongoDB raw log re-checked → verified",
             page.locator(".modalCard"))
        page.click("#mclose")

        # 11. security self-test
        page.evaluate("() => { store.set('adminSub','selftest'); show('admin'); }")
        page.wait_for_selector("#st"); page.click("#st")
        page.wait_for_selector("#stOut h2", timeout=180000); page.wait_for_timeout(500)
        shot(page, "11_security_self_test", "Security self-test: 13 attacks on the system, all blocked",
             page.locator("#adm .card"))

        # 12. role-based access: another analyst cannot work rao's incident
        login(page, "analyst.menon")
        page.evaluate(f"async () => {{ show('incidents'); await new Promise(r => setTimeout(r, 500)); await incidentDetail({owned}); }}")
        page.wait_for_timeout(800)
        shot(page, "12_role_based_access", "Access control: analyst.menon cannot change, annotate or take over analyst.rao's incident",
             page.locator("#tab-incidents .card").first)

        browser.close()

    md = ["# Validation & security screenshots (Component 8)", "",
          "Captured from the running app by `scripts/capture_screenshots.py`.", ""]
    for f, cap in done:
        md += [f"### {cap}", "", f"![{cap}]({f})", ""]
    (OUT / "README.md").write_text("\n".join(md))
    print(f"{len(done)} screenshots in {OUT}")


if __name__ == "__main__":
    sys.exit(main())
