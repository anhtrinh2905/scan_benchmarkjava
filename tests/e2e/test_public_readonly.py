"""C-013 done-evidence: the deployed URL answers an anonymous visitor.

Streamlit ships an empty HTML shell and fills it over a websocket, so `curl` can neither
see a password form nor prove its absence. Only a real browser can. This script opens the
public URL in a fresh context (no storage, no cookies), types no password anywhere, and
reports what an anonymous visitor actually gets.

Updated when Run Scan was removed from the read-only nav. Two things moved with it:

* **Results is now the landing page**, so it is probed at `/` rather than `/results`.
  Streamlit serves the default page at `/` and ignores its `url_path`, so on the deploy
  `/results` is the one URL that does not resolve — by design, and nothing published
  points at it. `/security-report` is the link README and the week-3 report hand out, so
  it is probed by name here to keep that promise under test.
* **Section 4 inverts.** It used to assert the Run Scan page refuses; there is no Run Scan
  page on the deploy now, so it asserts the page and its controls are absent entirely.
  What keeps the instance safe is still `scan_runner`'s refusal to spawn, not the missing
  nav entry — this section checks the nav, and the seam has its own guard.
"""
import sys

from playwright.sync_api import sync_playwright

URL = "https://scan-benchmarkjava-production.up.railway.app"
SHOTS = "/tmp/c013"


def body(page) -> str:
    return page.locator("body").inner_text()


def main() -> int:
    failures = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        # No storage_state: this context has never authenticated to anything.
        page = browser.new_context().new_page()

        page.goto(URL, wait_until="networkidle", timeout=90_000)
        page.wait_for_timeout(9_000)
        landing = body(page)
        page.screenshot(path=f"{SHOTS}_1_landing.png", full_page=True)

        if "not configured for public access" in landing:
            print("STALE BUILD: old code is still serving (it now refuses, as designed).")
            return 2

        print("=== 1. Landing, anonymous, zero authentication steps ===")
        for probe in ("Access password", "Enter the access password", "Continue"):
            hit = probe.lower() in landing.lower()
            print(f"  prompt {probe!r:32}: {'PRESENT <-- BAD' if hit else 'absent'}")
            if hit:
                failures.append(f"password prompt {probe!r} still rendered")
        pw_inputs = page.locator("input[type=password]").count()
        print(f"  input[type=password] count     : {pw_inputs}")
        if pw_inputs:
            failures.append("a password input exists in the DOM")

        print("\n=== 2. The landing page IS Results, with real data ===")
        for marker in ("scorecard", "deepseek"):
            hit = marker in landing.lower()
            print(f"  {marker!r:14} on landing     : {'yes' if hit else 'NO <-- BAD'}")
            if not hit:
                failures.append(f"landing page missing {marker!r}")

        print("\n=== 3. /security-report resolves by name (README hands out this link) ===")
        page.goto(f"{URL}/security-report", wait_until="networkidle", timeout=90_000)
        page.wait_for_timeout(9_000)
        report = body(page)
        page.screenshot(path=f"{SHOTS}_3_security_report.png", full_page=True)
        for marker in ("Security Report", "Tổng quan", "Ma trận"):
            hit = marker.lower() in report.lower()
            print(f"  {marker!r:16} present       : {'yes' if hit else 'NO <-- BAD'}")
            if not hit:
                failures.append(f"Security Report missing {marker!r}")
        if "page not found" in report.lower():
            failures.append("/security-report 404'd — the published deep link is dead")

        print("\n=== 4. Knowledge Base answers a real query, anonymous ===")
        page.goto(f"{URL}/knowledge-base", wait_until="networkidle", timeout=90_000)
        page.wait_for_timeout(9_000)
        box = page.locator("input[type=text]").first
        box.fill("sql injection")
        # Enter alone leaves this form unsubmitted; the button is the only real path.
        page.get_by_role("button", name="Search").first.click()
        page.wait_for_timeout(12_000)
        kb = body(page)
        page.screenshot(path=f"{SHOTS}_4_kb.png", full_page=True)
        got_hit = "score" in kb.lower() and "no results" not in kb.lower()
        print(f"  real KB hit for 'sql injection': {'yes' if got_hit else 'NO <-- BAD'}")
        if not got_hit:
            failures.append("KB returned no hit")

        print("\n=== 5. The write path is not merely refused — it is not built ===")
        page.goto(URL, wait_until="networkidle", timeout=90_000)
        page.wait_for_timeout(9_000)
        nav_entry = page.get_by_role("link", name="Run Scan").count()
        print(f"  'Run Scan' nav entries          : {nav_entry}")
        if nav_entry:
            failures.append("a Run Scan nav entry is still rendered")

        start_buttons = page.get_by_role("button", name="Start scan").count()
        print(f"  'Start scan' controls in the DOM: {start_buttons}")
        if start_buttons:
            failures.append("a Start scan control is reachable")

        page.goto(f"{URL}/run", wait_until="networkidle", timeout=90_000)
        page.wait_for_timeout(9_000)
        run = body(page)
        page.screenshot(path=f"{SHOTS}_5_run.png", full_page=True)
        reachable = page.get_by_role("button", name="Start scan").count()
        print(f"  'Start scan' at /run            : {reachable}")
        if reachable:
            failures.append("/run still exposes a Start scan control")
        print(f"  /run body starts with           : {run.strip().splitlines()[0][:60]!r}")

        browser.close()

    print()
    if failures:
        print("FAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("PASS: anonymous visitor reads everything, and there is nothing to run.")
    print(f"Screenshots: {SHOTS}_1_landing.png .. {SHOTS}_5_run.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
