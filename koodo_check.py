#!/usr/bin/env python3
"""Koodo single-account login check (own account only).

What it does:
  - opens YOUR long koodo-login-v2 URL in a real Chromium (playwright)
  - fills YOUR identifier + password ONCE, reads the DOM verdict
  - verdicts: success | wrong_pass | otp_required | blocked | unknown

What it does NOT do:
  - no combo list, no bulk, no retry storm (single check per run)
  - no password guessing, no bypass, no OTP solve

Why browser (not requests):
  - the login is JS + OAuth via auth-gateway.koodomobile.com
    (client_id, response_type=code, redirect to proxy.digital.koodomobile.com)
  - plain HTTP fetch returns empty; need real DOM + event waits

Usage:
  set KOODO_USER=you@example.com
  set KOODO_PASS=yourpassword
  python koodo_check.py --headed --shot koodo.png --dump-html koodo.html
  python koodo_check.py --user you@example.com --pass-env KOODO_PASS --out result.json

Needs: pip install playwright && playwright install chrome
"""

import argparse
import getpass
import json
import os
import sys
import time

DEFAULT_URL = (
    "https://www.koodomobile.com/koodo-login-v2?service_type=koodo&acr=ci-loa3"
    "&goto=https%3A%2F%2Fauth-gateway.koodomobile.com%2Fas%2Fauthorization.oauth2"
    "%3Fclient_id%3D214aa452-c949-4895-9a9f-5e8b18d9a9a1%26response_type%3Dcode"
    "%26scope%3Dprofileinfohighdetail%2520customerinfo%2520securitymgmt"
    "%26redirect_uri%3Dhttps%253A%252F%252Fproxy.digital.koodomobile.com"
    "%252Foauth2%252Fcallback%26acr_values%3Dci-loa3%26from%3Dlogin"
)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

STEALTH_JS = """() => {
  Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
  window.chrome = window.chrome || {runtime: {}};
  Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
  Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
}"""

USER_SELECTORS = [
    "[data-testid=login-form-email-input]",
    "#idtoken1",
    "input[type=email]",
    "input[name=identifier]",
    "input[name=username]",
    "input[id*=user i]",
    "input[id*=email i]",
    "input[id*=login i]",
    "input[type=text]",
]

PASS_SELECTORS = [
    "[data-testid=login-form-password-input]",
    "#idtoken2",
    "input[type=password][name=Passwd]",
    "input[type=password]",
]

NEXT_SELECTORS = [
    "[data-testid=login-form-submit-button]",
    "#login-form button[type=submit]",
    "#identifierNext",
    "button[type=submit]",
    "input[type=submit]",
    "button:has-text('Next')",
    "button:has-text('Continue')",
    "button:has-text('Sign in')",
    "button:has-text('Log in')",
]

PASS_NEXT_SELECTORS = [
    "#passwordNext",
    "button[type=submit]",
    "input[type=submit]",
    "button:has-text('Next')",
    "button:has-text('Sign in')",
    "button:has-text('Verify')",
]

BLOCKED_MARKERS = (
    "verify you're not a robot",
    "confirm you're not a robot",
    "unusual traffic",
    "type the text you hear or see",
    "recaptcha",
    "access denied",
    "rejected",
)

WRONG_PASS_MARKERS = (
    "wrong password",
    "incorrect password",
    "password is incorrect",
    "invalid password",
    "couldn't sign you in",
    "check your password",
)

OTP_MARKERS = (
    "one-time passcode",
    "one time passcode",
    "verification code",
    "verify it's you",
    "2-step",
    "two-step",
    "enter the code",
    "text message",
    "authenticator",
)

SUCCESS_URL_HINTS = (
    "proxy.digital.koodomobile.com/oauth2/callback",
    "code=",
    "my account",
    "overview",
)

SUCCESS_TEXT_HINTS = (
    "my account",
    "overview",
    "current plan",
    "pay bill",
    "log out",
    "logout",
    "sign out",
)


def first_visible(pg, selectors, timeout_each=8000):
    """Return (selector, locator) for first selector that becomes visible."""
    for sel in selectors:
        try:
            loc = pg.locator(sel).first
            loc.wait_for(state="visible", timeout=timeout_each)
            return sel, loc
        except Exception:
            continue
    return None, None


def body_text(pg):
    try:
        return pg.evaluate(
            "() => document.body ? document.body.innerText : ''"
        ) or ""
    except Exception:
        try:
            return pg.inner_text("body") or ""
        except Exception:
            return ""


def classify(pg):
    url = ""
    try:
        url = pg.url or ""
    except Exception:
        pass
    low_url = url.lower()
    low = body_text(pg).lower().replace("\n", " ")

    if "rejected" in low_url or "challenge" in low_url:
        return "blocked", "url shows rejected/challenge"
    if any(m in low for m in BLOCKED_MARKERS):
        return "blocked", "anti-bot / challenge text present"
    if any(m in low for m in OTP_MARKERS):
        return "otp_required", "second-factor / passcode screen detected"
    if any(m in low for m in WRONG_PASS_MARKERS):
        return "wrong_pass", "password-error text detected"
    if any(h in low_url for h in SUCCESS_URL_HINTS):
        return "success", "oauth callback / code in url: %s" % url[:160]
    if any(h in low for h in SUCCESS_TEXT_HINTS):
        return "success", "account dashboard text detected"
    # visible password field but no error yet = still on password stage
    try:
        n = pg.locator("input[type=password]").count()
        for i in range(n):
            try:
                if pg.locator("input[type=password]").nth(i).is_visible():
                    return "unknown", "still on password stage, no verdict text"
            except Exception:
                pass
    except Exception:
        pass
    return "unknown", "no decisive signal"


def check(user, password, url, headless, timeout_ms=60000,
          shot=None, dump_html=None):
    from playwright.sync_api import sync_playwright

    t0 = time.time()
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(
                channel="chrome", headless=headless,
                args=["--disable-blink-features=AutomationControlled",
                      "--disable-infobars"])
        except Exception:
            browser = p.chromium.launch(
                headless=headless,
                args=["--disable-blink-features=AutomationControlled"])
        ctx = browser.new_context(user_agent=UA, locale="en-US",
                                  viewport={"width": 1366, "height": 768})
        ctx.add_init_script(STEALTH_JS)
        pg = ctx.new_page()
        try:
            pg.goto(url, timeout=timeout_ms)
            # 1. identifier stage
            sel, box = first_visible(pg, USER_SELECTORS, timeout_each=15000)
            if not box:
                v, why = classify(pg)
                return finish(pg, v if v != "unknown" else "blocked",
                              "no identifier field: %s" % why, t0,
                              shot, dump_html)
            pg.wait_for_timeout(600)
            box.fill(user)
            pg.wait_for_timeout(500)
            nsel, nxt = first_visible(pg, NEXT_SELECTORS, timeout_each=5000)
            if nxt:
                try:
                    nxt.click()
                except Exception:
                    box.press("Enter")
            else:
                box.press("Enter")

            # 2. wait for either password field or a verdict
            psel, pwd = first_visible(pg, PASS_SELECTORS, timeout_each=20000)
            if not pwd:
                # maybe identifier error, OTP directly, or block
                pg.wait_for_timeout(3000)
                v, why = classify(pg)
                return finish(pg, v, "post-identifier: %s" % why, t0,
                              shot, dump_html)
            pg.wait_for_timeout(600)
            pwd.fill(password)
            pg.wait_for_timeout(500)
            _, pnext = first_visible(pg, PASS_NEXT_SELECTORS, timeout_each=5000)
            if pnext:
                try:
                    pnext.click()
                except Exception:
                    pwd.press("Enter")
            else:
                pwd.press("Enter")

            # 3. verdict poll (event-based, up to 25s)
            end = time.time() + 25
            last = ("unknown", "no signal yet")
            while time.time() < end:
                v, why = classify(pg)
                if v != "unknown":
                    return finish(pg, v, why, t0, shot, dump_html)
                last = (v, why)
                time.sleep(0.5)
            return finish(pg, last[0], last[1], t0, shot, dump_html)
        finally:
            try:
                browser.close()
            except Exception:
                pass


def finish(pg, verdict, reason, t0, shot, dump_html):
    rec = {"verdict": verdict, "reason": reason,
           "url": "", "elapsed_s": round(time.time() - t0, 1)}
    try:
        rec["url"] = pg.url or ""
    except Exception:
        pass
    if shot:
        try:
            pg.screenshot(path=shot, full_page=False)
            rec["screenshot"] = shot
        except Exception as e:
            rec["screenshot_error"] = type(e).__name__
    if dump_html:
        try:
            with open(dump_html, "w", encoding="utf-8") as f:
                f.write(pg.content() or "")
            rec["html"] = dump_html
        except Exception as e:
            rec["html_error"] = type(e).__name__
    return rec


def main(argv):
    ap = argparse.ArgumentParser(description="Koodo single-account login check.")
    ap.add_argument("--url", default=DEFAULT_URL, help="login start URL")
    ap.add_argument("--user", default=os.environ.get("KOODO_USER", ""))
    ap.add_argument("--pass-env", default="KOODO_PASS",
                    help="env var holding the password (default KOODO_PASS)")
    ap.add_argument("--headed", action="store_true",
                    help="show browser window (default headless)")
    ap.add_argument("--shot", default="koodo.png")
    ap.add_argument("--dump-html", default=None)
    ap.add_argument("--out", default=None, help="JSON output path")
    ap.add_argument("--timeout", type=int, default=60)
    a = ap.parse_args(argv)

    user = (a.user or "").strip()
    if not user:
        print("missing user: --user you@example.com or set KOODO_USER")
        return 2
    password = os.environ.get(a.pass_env, "")
    if not password:
        try:
            password = getpass.getpass("password for %s: " % user)
        except Exception:
            password = ""
    if not password:
        print("missing password: set %s or type it at prompt" % a.pass_env)
        return 2

    print("[*] opening koodo login (single check, one submit)...")
    rec = check(user, password, a.url, headless=not a.headed,
                timeout_ms=a.timeout * 1000,
                shot=a.shot, dump_html=a.dump_html)
    rec["user"] = user
    print("%s -> %s (%s) [%.1fs]" % (user, rec["verdict"].upper(),
                                     rec["reason"], rec["elapsed_s"]))
    if rec.get("url"):
        print("url: %s" % rec["url"][:220])
    if rec.get("screenshot"):
        print("shot: %s" % rec["screenshot"])
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)
        print("-> %s" % a.out)
    if rec["verdict"] == "otp_required":
        print("[*] akun valid tapi butuh kode OTP — cek SMS/authenticator lo")
    elif rec["verdict"] == "blocked":
        print("[*] kena challenge/blok — tunggu 10-30 mnt, jangan retry beruntun")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
