#!/usr/bin/env python3
"""Email hygiene checker + local dashboard (email-only, no password checks).

Checks per email (legitimate hygiene signals only):
  - syntax (regex + length + consecutive dots)
  - disposable domain
  - role-based prefix (info@, admin@, ...)
  - MX records (DNS only, no SMTP connection)

Usage:
  python hygiene_dashboard.py list.txt --out results.jsonl --serve --port 8901
  python hygiene_dashboard.py --test
"""
import argparse
import asyncio
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from html import escape

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.dev", "guerrillamail.com", "10minutemail.com",
    "temp-mail.org", "yopmail.com", "sharklasers.com", "trashmail.com",
    "fakeinbox.com", "throwawaymail.com", "maildrop.cc", "getnada.com",
    "dispostable.com", "mailnesia.com", "tempr.email", "tmpmail.net",
    "moakt.com", "linshiyouxiang.net", "emailondeck.com",
}

ROLE_PREFIXES = (
    "admin", "info", "support", "sales", "billing", "contact", "help",
    "noreply", "no-reply", "postmaster", "webmaster", "abuse", "hostmaster",
    "marketing", "team", "office", "hr", "jobs", "newsletter",
)

RESULTS = []


def check_syntax(email):
    if not email or not EMAIL_RE.match(email):
        return False, "invalid_syntax"
    local, _, _ = email.rpartition("@")
    if len(local) > 64 or len(email) > 254:
        return False, "too_long"
    if ".." in email:
        return False, "consecutive_dots"
    return True, "ok"


def is_disposable(email):
    return email.rpartition("@")[2].lower() in DISPOSABLE_DOMAINS


def is_role_based(email):
    return email.rpartition("@")[0].lower() in ROLE_PREFIXES


def check_mx(domain):
    if not HAS_DNS:
        return False, "dnspython_missing", []
    try:
        answers = dns.resolver.resolve(domain, "MX")
        records = sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
        if not records:
            return False, "no_mx_records", []
        return True, "ok", [h for _, h in records]
    except Exception as e:
        return False, f"dns_error:{type(e).__name__}", []


def check_one(email):
    email = email.strip()
    r = {"email": email, "valid": False, "status": "invalid", "reason": "", "notes": []}
    ok, reason = check_syntax(email)
    if not ok:
        r["reason"] = reason
        return r
    if is_disposable(email):
        r["reason"] = "disposable_domain"
        r["notes"].append("disposable")
        return r
    if is_role_based(email):
        r["notes"].append("role_based")
    domain = email.rpartition("@")[2].lower()
    ok, reason, mx = check_mx(domain)
    if not ok:
        r["reason"] = reason
        return r
    r["valid"] = True
    r["status"] = "likely_valid"
    r["reason"] = "syntax_ok_mx_found"
    r["notes"].append(f"mx:{mx[0]}" if mx else "mx:found")
    return r


async def run_batch(emails, concurrency=10):
    sem = asyncio.Semaphore(concurrency)

    async def one(e):
        async with sem:
            return await asyncio.to_thread(check_one, e)

    return list(await asyncio.gather(*[one(e) for e in emails]))


def load_emails(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        out = []
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "@" in line:
                out.append(line.split()[0])
        return out


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Email hygiene dashboard</title>
<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;padding:0 1em}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:6px 8px;font-size:14px}
.ok{color:green}.bad{color:#a00}.cards{display:flex;gap:1em;margin:1em 0}
.card{border:1px solid #ccc;border-radius:8px;padding:0.8em 1.2em}</style></head>
<body><h1>Email hygiene dashboard</h1><div class="cards">
<div class="card"><b>Total</b><br>TOTAL</div>
<div class="card"><b>Likely valid</b><br>VALID</div>
<div class="card"><b>Invalid</b><br>INVALID</div></div>
<table><tr><th>Email</th><th>Status</th><th>Reason</th><th>Notes</th></tr>ROWS</table>
<p><a href="/api/results">JSON API</a></p></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/api/results":
            body = json.dumps(RESULTS, ensure_ascii=False, indent=1).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        total = len(RESULTS)
        valid = sum(1 for r in RESULTS if r["valid"])
        rows = "".join(
            "<tr><td>{}</td><td class='{}'>{}</td><td>{}</td><td>{}</td></tr>".format(
                escape(r["email"]), "ok" if r["valid"] else "bad",
                escape(r["status"]), escape(r["reason"]), escape(",".join(r["notes"])))
            for r in RESULTS[:2000])
        body = PAGE.replace("TOTAL", str(total)).replace("VALID", str(valid)) \
            .replace("INVALID", str(total - valid)).replace("ROWS", rows).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("listfile", nargs="?", help="text file, one email per line")
    ap.add_argument("--out", default="hygiene_results.jsonl")
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=8901)
    ap.add_argument("--test", action="store_true")
    a = ap.parse_args()

    global RESULTS
    if a.test or not a.listfile:
        emails = ["user@gmail.com", "bad-email", "admin@mailinator.com",
                  "info@example.com", "nonexistent@randomdomain123.xyz"]
    else:
        emails = load_emails(a.listfile)
    RESULTS = asyncio.run(run_batch(emails, a.concurrency))
    for r in RESULTS:
        mark = "OK " if r["valid"] else "X  "
        print(f"{mark}{r['email']} -> {r['status']} ({r['reason']})")
    with open(a.out, "w", encoding="utf-8") as f:
        for r in RESULTS:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\n{sum(1 for r in RESULTS if r['valid'])}/{len(RESULTS)} likely valid -> {a.out}")
    if a.serve:
        srv = HTTPServer(("127.0.0.1", a.port), Handler)
        print(f"Dashboard: http://127.0.0.1:{a.port}/  (Ctrl+C to stop)")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
