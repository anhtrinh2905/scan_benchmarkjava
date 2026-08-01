"""C-013 done-evidence: the deployed URL answers an anonymous visitor.

Streamlit ships an empty HTML shell and fills it over a websocket, so `curl` can neither
see a password form nor prove its absence. Only a real browser can. This script opens the
public URL in a fresh context (no storage, no cookies), types no password anywhere, and
reports what an anonymous visitor actually gets on each of the three pages.
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

        print("\n=== 2. Results renders real data to an anonymous visitor ===")
        page.goto(f"{URL}/results", wait_until="networkidle", timeout=90_000)
        page.wait_for_timeout(9_000)
        results = body(page)
        page.screenshot(path=f"{SHOTS}_2_results.png", full_page=True)
        for marker in ("scorecard", "deepseek"):
            hit = marker in results.lower()
            print(f"  {marker!r:14} on Results     : {'yes' if hit else 'NO <-- BAD'}")
            if not hit:
                failures.append(f"Results missing {marker!r}")

        print("\n=== 3. Knowledge Base answers a real query, anonymous ===")
        page.goto(f"{URL}/knowledge-base", wait_until="networkidle", timeout=90_000)
        page.wait_for_timeout(9_000)
        box = page.locator("input[type=text]").first
        box.fill("sql injection")
        # Enter alone leaves this form unsubmitted; the button is the only real path.
        page.get_by_role("button", name="Search").first.click()
        page.wait_for_timeout(12_000)
        kb = body(page)
        page.screenshot(path=f"{SHOTS}_3_kb.png", full_page=True)
        got_hit = "score" in kb.lower() and "no results" not in kb.lower()
        print(f"  real KB hit for 'sql injection': {'yes' if got_hit else 'NO <-- BAD'}")
        if not got_hit:
            failures.append("KB returned no hit")

        print("\n=== 4. Opening the read gate must NOT have opened the write path ===")
        page.goto(f"{URL}/run", wait_until="networkidle", timeout=90_000)
        page.wait_for_timeout(9_000)
        run = body(page)
        page.screenshot(path=f"{SHOTS}_4_run.png", full_page=True)
        refused = "not available on this instance" in run.lower()
        print(f"  Run Scan states it is unavailable: {'yes' if refused else 'NO <-- BAD'}")
        if not refused:
            failures.append("Run Scan page does not refuse")
        start_buttons = page.get_by_role("button", name="Start scan").count()
        print(f"  'Start scan' controls in the DOM : {start_buttons}")
        if start_buttons:
            failures.append("a Start scan control is reachable")

        browser.close()

    print()
    if failures:
        print("FAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("PASS: anonymous visitor reads everything, and still cannot run anything.")
    print(f"Screenshots: {SHOTS}_1_landing.png .. {SHOTS}_4_run.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
