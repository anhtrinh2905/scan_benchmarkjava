"""C-013 done-evidence: the deployed URL answers an anonymous visitor.

Streamlit ships an empty HTML shell and fills it over a websocket, so `curl` can neither
see a password form nor prove its absence. Only a real browser can. This script opens the
public URL in a fresh context (no storage, no cookies), types no password anywhere, and
reports what an anonymous visitor actually gets.

Updated when Run Scan was removed from the read-only nav. Two things moved with it:

* **The landing page is probed at `/`.** Streamlit serves the default page at `/` and
  ignores its `url_path`, so exactly one page cannot be linked to by name — by design, and
  nothing published points at the name it loses.
* **Section 5 inverts.** It used to assert the Run Scan page refuses; there is no Run Scan
  page on the deploy now, so it asserts the page and its controls are absent entirely.
  What keeps the instance safe is still `scan_runner`'s refusal to spawn, not the missing
  nav entry — this section checks the nav, and the seam has its own guard.

Updated again for C-021, which reorganized the nav. **Security Report is now the default
page**, so it is what `/` serves and `/security-report` is the URL that no longer resolves.
That is a real, chosen cost: the published deep link moved to the site root, in README and
in the week-3 report, and section 2 below probes the root for report markers rather than
scorecard ones. Results was renamed **Comparison** and now answers at `/comparison`, which
section 3 checks — a rename that leaves a dead nav entry is worse than no rename.
"""
import sys

from playwright.sync_api import sync_playwright

URL = "https://scan-benchmarkjava-production.up.railway.app"
SHOTS = "/tmp/c013"


def body(page) -> str:
    return page.locator("body").inner_text()


def wait_for_text(page, needle: str, timeout_ms: int = 45_000) -> bool:
    """Poll the rendered body until `needle` shows up, or give up.

    Streamlit fills the page over a websocket in several deltas, so a fixed sleep races the
    render: the same healthy page passed at 21s and failed at 9s, which reads as a broken
    deploy when it is a broken assertion. Waiting for the thing we are asserting on removes
    the race in the only direction that matters — a marker that never arrives still fails."""
    waited = 0
    while waited < timeout_ms:
        if needle.lower() in body(page).lower():
            return True
        page.wait_for_timeout(1_500)
        waited += 1_500
    return False


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

        print("\n=== 2. The landing page IS the Security Report, on its Hỏi đáp tab ===")
        # The root is the published link now, so what it serves is the promise under test.
        # `Danh sách phát hiện` is on this list deliberately: it is the heading that proves
        # the findings list came along into the Q&A tab instead of staying a third tab.
        for marker in ("Security Report", "Hỏi đáp", "Danh sách phát hiện"):
            hit = wait_for_text(page, marker)
            print(f"  {marker!r:22} on landing : {'yes' if hit else 'NO <-- BAD'}")
            if not hit:
                failures.append(f"landing page missing {marker!r}")

        tabs = [
            page.get_by_role("tab").nth(i).inner_text()
            for i in range(page.get_by_role("tab").count())
        ]
        print(f"  tab order                     : {tabs}")
        if tabs[:2] != ["Hỏi đáp", "Tổng quan"]:
            failures.append(f"tab order is {tabs}, expected Hỏi đáp then Tổng quan")
        selected = page.get_by_role("tab").nth(0).get_attribute("aria-selected")
        print(f"  'Hỏi đáp' selected on open    : {selected}")
        if selected != "true":
            failures.append("Hỏi đáp is not the tab a visitor lands on")

        # A suggested question is prebaked, so it must answer without a model round trip —
        # which is also the only way this assertion can pass on an instance with no key.
        suggestion = page.get_by_role("button", name="Thống kê theo CWE, loại lỗi nào nhiều nhất?")
        if suggestion.count():
            suggestion.first.click()
            instant = wait_for_text(page, "Trả lời dựng sẵn", 30_000)
            print(f"  prebaked answer served        : {'yes' if instant else 'NO <-- BAD'}")
            if not instant:
                failures.append("a suggested question did not serve its prebaked answer")
            for stat in ("token", "mô hình"):
                if stat not in body(page):
                    failures.append(f"answer does not report {stat!r}")
        else:
            failures.append("no suggested-question buttons rendered")
        page.screenshot(path=f"{SHOTS}_2_security_report.png", full_page=True)

        print("\n=== 3. /comparison resolves under its new name, with real data ===")
        page.goto(f"{URL}/comparison", wait_until="networkidle", timeout=90_000)
        page.wait_for_timeout(9_000)
        # Structural markers, not a model name. The old check looked for 'deepseek', which
        # really asserted which run the page preselects — and that changes: a redeploy
        # rewrites file mtimes, so the run at the top of the list is not stable across
        # builds. A scorecard with a precision table in it is what "real data" means, on
        # whichever run got picked.
        for marker in ("Comparison", "scorecard", "precision", "recall"):
            hit = wait_for_text(page, marker)
            print(f"  {marker!r:14} at /comparison : {'yes' if hit else 'NO <-- BAD'}")
            if not hit:
                failures.append(f"/comparison missing {marker!r}")
        page.screenshot(path=f"{SHOTS}_3_comparison.png", full_page=True)
        if "page not found" in body(page).lower():
            failures.append("/comparison 404'd — the renamed page has no URL")

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
