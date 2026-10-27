#!/usr/bin/env python3
"""Koodo direct-API probe (own single account, reverse-engineering helper).

Why this exists:
  - browser version works but heavy. direct API is faster IF we know schema.
  - network capture shows real endpoints:
      POST https://auth-gateway.koodomobile.com/v1/flows/login?acr=ci-loa3 -> 401 (flow init)
      GET  https://proxy.digital.koodomobile.com/authentication/status -> 200
  - exact JSON schema is inside JS chunks (cix-authentication-mfe), not in HTML,
    so this probe sends ONE minimal attempt and PRINTS the raw server reply
    (flow descriptor / callbacks / next step) so you can refine it with your
    own HAR. No guessing loop, no bulk.

Usage:
  python koodo_api_check.py --user you@example.com --status-only
  set KOODO_PASS=xxx & python koodo_api_check.py --user you@example.com --send --out api.json

Verdicts: init_ok | need_schema (server wants different fields) | blocked | error
Never sends password unless --send is passed.
"""

import argparse
import getpass
import json
import os
import sys
import urllib.request
import urllib.error
import http.cookiejar

FLOW_URL = "https://auth-gateway.koodomobile.com/v1/flows/login?acr=ci-loa3"
STATUS_URL = "https://proxy.digital.koodomobile.com/authentication/status"
LOGIN_PAGE = ("https://www.koodomobile.com/koodo-login-v2"
              "?service_type=koodo&acr=ci-loa3")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def build_opener():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    op.addheaders = [("User-Agent", UA),
                     ("Accept", "application/json, text/plain, */*")]
    return op, jar


def req(op, method, url, payload=None, extra=None, timeout=20):
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("User-Agent", UA)
    r.add_header("Accept", "application/json, text/plain, */*")
    r.add_header("Origin", "https://www.koodomobile.com")
    r.add_header("Referer", LOGIN_PAGE)
    if payload is not None:
        r.add_header("Content-Type", "application/json")
    for k, v in (extra or {}).items():
        r.add_header(k, v)
    try:
        with op.open(r, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, None
    except Exception as e:
        return 0, "", "%s: %s" % (type(e).__name__, str(e)[:120])


def redact(text, secret):
    if secret and text:
        return text.replace(secret, "***")
    return text


def main(argv):
    ap = argparse.ArgumentParser(description="Koodo direct-API probe.")
    ap.add_argument("--user", default=os.environ.get("KOODO_USER", ""))
    ap.add_argument("--pass-env", default="KOODO_PASS")
    ap.add_argument("--status-only", action="store_true",
                    help="only GET status + GET login page, send nothing")
    ap.add_argument("--send", action="store_true",
                    help="actually POST credentials once")
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)

    op, jar = build_opener()
    log = {"flow_url": FLOW_URL, "steps": []}

    # 1. warm cookies via login page (no password)
    s, b, err = req(op, "GET", LOGIN_PAGE)
    log["steps"].append({"step": "get_login_page", "http": s,
                         "cookies": len(list(jar)),
                         "err": err, "snippet": b[:300]})
    print("[1] GET login page -> %s (%d cookies)" % (s, len(list(jar))))

    # 2. status endpoint (no password)
    s, b, err = req(op, "GET", STATUS_URL)
    log["steps"].append({"step": "get_status", "http": s,
                         "err": err, "body": b[:2000]})
    print("[2] GET status -> %s" % s)
    print("    %s" % (b[:400].replace("\n", " ") or err or "(empty)"))

    # 3. flow init WITHOUT credentials (learn schema, burns nothing)
    s, b, err = req(op, "POST", FLOW_URL, payload={})
    log["steps"].append({"step": "post_empty_init", "http": s,
                         "err": err, "body": b[:4000]})
    print("[3] POST empty init -> %s (expect 401/400 + flow descriptor)" % s)
    print("    %s" % (b[:600].replace("\n", " ") or err or "(empty)"))

    if a.status_only or not a.send:
        print("[*] stopped before credentials (pass --send to try once)")
        if a.out:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(log, f, ensure_ascii=False, indent=2)
            print("-> %s" % a.out)
        return 0

    user = (a.user or "").strip()
    if not user:
        print("missing --user"); return 2
    pw = os.environ.get(a.pass_env, "")
    if not pw:
        pw = getpass.getpass("password for %s: " % user)
    if not pw:
        print("missing password"); return 2

    # 4. ONE credentialed attempt, minimal schema.
    # If server replies need_schema, paste the reply + your HAR and we adapt.
    payload = {"username": user, "password": pw,
               "service_type": "koodo", "acr": "ci-loa3"}
    s, b, err = req(op, "POST", FLOW_URL, payload=payload)
    safe = redact(b, pw)
    verdict = "unknown"
    low = safe.lower()
    if s == 401 and ("callback" in low or "flow" in low or "next" in low):
        verdict = "need_schema"
    elif s in (429, 403):
        verdict = "blocked"
    elif s == 200 and ("token" in low or "success" in low or "code" in low):
        verdict = "init_ok"
    log["steps"].append({"step": "post_credentials_once", "http": s,
                         "verdict": verdict, "err": err,
                         "body": safe[:4000]})
    log["verdict"] = verdict
    print("[4] POST credentials once -> %s => %s" % (s, verdict))
    print("    %s" % (safe[:800].replace("\n", " ") or err or "(empty)"))
    if verdict == "need_schema":
        print("[*] server wants different fields. buka DevTools > Network, "
              "login manual sekali, klik POST v1/flows/login > Payload, "
              "paste JSON-nya ke gue, gue cocokin skemanya.")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(log, f, ensure_ascii=False, indent=2)
        print("-> %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
