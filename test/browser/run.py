"""End-to-end browser test for the turnstile handler.

Drives real Chromium through the challenge against Cloudflare's live
siteverify, using the public testing keys. Requires Chromium and network
access to challenges.cloudflare.com.

    pip install playwright && playwright install chromium
    xcaddy build v2.11.9 --with github.com/perennialtech/caddy-turnstile=../..
    ./caddy run --config Caddyfile &
    python3 run.py
"""

import time

from playwright.sync_api import sync_playwright

PASS = "https://localhost:18443"
FAIL = "https://localhost:18444"


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL: " + msg)
    print("ok:", msg)


def clearance_jar(ctx, origin):
    # Cookies are scoped to the hostname, NOT the port. PASS and FAIL both
    # use localhost, so the successful policy's cookie will still be here.
    return {
        c["name"]: c["value"]
        for c in ctx.cookies(origin)
        if c["name"].startswith("turnstile_clearance_")
    }


def require_unchanged_clearances(before, after):
    # Check both new names and existing names with modified values; a
    # failed verifier must never mint a clearance under *any* namespace.
    changes = [name for name, value in after.items() if before.get(name) != value]
    if changes:
        raise AssertionError(f"unexpected clearance cookie(s): {changes}")


with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    console, seq = [], []
    page.on("console", lambda m: console.append(m.text))
    page.on("response", lambda r: seq.append((r.request.method, r.status)) if r.url.startswith(PASS) else None)

    page.goto(PASS + "/deep/page?x=1&y=2")
    page.get_by_text("protected content").wait_for(timeout=45000)
    check(page.url == PASS + "/deep/page?x=1&y=2", "returned to the original URL")
    check(seq == [("GET", 403), ("POST", 303), ("GET", 200)], f"challenge, verify, redirect: {seq}")
    check(not [m for m in console if "Content Security Policy" in m], "no CSP violations under a strict site policy")

    cookies = [c for c in ctx.cookies(PASS) if c["name"].startswith("turnstile_clearance")]
    check(len(cookies) == 1 and cookies[0]["name"].startswith("turnstile_clearance_"), "one clearance cookie")
    c = cookies[0]
    check(c["httpOnly"] and c["secure"] and c["sameSite"] == "Lax", "cookie attributes")
    days = (c["expires"] - time.time()) / 86400
    check(29.9 < days <= 30, f"cookie lasts 30 days ({days:.2f})")

    r = page.goto(PASS + "/another")
    check(r.status == 200, "second visit goes straight through")

    before_fail = clearance_jar(ctx, FAIL)
    check(bool(before_fail), "existing pass cookie is visible on failure origin (same hostname)")
    page2 = ctx.new_page()
    page2.goto(FAIL + "/somewhere?z=9")
    page2.get_by_text("couldn't verify").wait_for(timeout=45000)
    check(page2.get_attribute("a", "href") == "/somewhere?z=9", "failure page links back to the original URL")
    check("ts-" in page2.inner_text("body"), "failure page shows a block ID")
    require_unchanged_clearances(before_fail, clearance_jar(ctx, FAIL))
    print("ok: no new or changed clearance after a failed verification")

    # Negative control: deliberately put a bogus clearance into this origin
    # and prove the exact assertion above catches it.
    ctx.add_cookies([{"name": "turnstile_clearance_negative_probe", "value": "unexpected", "url": FAIL}])
    try:
        require_unchanged_clearances(before_fail, clearance_jar(ctx, FAIL))
    except AssertionError:
        print("ok: negative control catches an unexpected clearance")
    else:
        raise AssertionError("negative control did not detect an issued clearance")

    browser.close()
print("all browser checks passed")
