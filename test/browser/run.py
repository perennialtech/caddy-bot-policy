"""End-to-end browser test for the turnstile handler.

Drives real Chromium through the challenge against Cloudflare's live
siteverify, using the public testing keys. Not run in CI: it needs Chromium
and network access to challenges.cloudflare.com.

    pip install playwright && playwright install chromium
    xcaddy build --with github.com/perennialtech/caddy-bot-policy=../..
    ./caddy run --config Caddyfile &
    python3 run.py
"""

import ssl
import time
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

PASS = "https://localhost:18443"
FAIL = "https://localhost:18444"


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL: " + msg)
    print("ok:", msg)


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

    cookies = [c for c in ctx.cookies(PASS) if c["name"].startswith("bp_clearance")]
    check([c["name"] for c in cookies] == ["bp_clearance_t"], "one TCP-bound clearance cookie")
    c = cookies[0]
    check(c["httpOnly"] and c["secure"] and c["sameSite"] == "Lax", "cookie attributes")
    days = (c["expires"] - time.time()) / 86400
    check(29.9 < days <= 30, f"cookie lasts 30 days ({days:.2f})")

    r = page.goto(PASS + "/another")
    check(r.status == 200, "second visit goes straight through")

    # Replay the bound cookie from Python's TLS stack: different JA4.
    tls = ssl.create_default_context()
    tls.check_hostname, tls.verify_mode = False, ssl.CERT_NONE
    req = urllib.request.Request(PASS + "/another", headers={"Cookie": f"{c['name']}={c['value']}"})
    try:
        status = urllib.request.urlopen(req, context=tls).status
    except urllib.error.HTTPError as e:
        status = e.code
    check(status == 403, f"bound cookie replayed from another TLS stack is refused ({status})")

    page2 = ctx.new_page()
    page2.goto(FAIL + "/somewhere?z=9")
    page2.get_by_text("couldn't verify").wait_for(timeout=45000)
    check(page2.get_attribute("a", "href") == "/somewhere?z=9", "failure page links back to the original URL")
    check("ts-" in page2.inner_text("body"), "failure page shows a block ID")
    check(not [x for x in ctx.cookies(FAIL) if x["name"] == "bp_clearance"], "no clearance after a failed verification")

    browser.close()
print("all browser checks passed")
