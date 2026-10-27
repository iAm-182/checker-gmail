#!/usr/bin/env python3
"""Hosted entrypoint for the hygiene dashboard (Botkeep apps profile).

Run:  python dashboard_app.py
Listens on 0.0.0.0:$PORT (falls back to 8901 locally).
Checks the bundled sample list (or sample.txt) once at startup, then serves.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hygiene_dashboard as H
from http.server import HTTPServer

SAMPLES = [
    "user@gmail.com",
    "bad-email",
    "admin@mailinator.com",
    "info@example.com",
    "nonexistent@randomdomain123.xyz",
]


def main() -> int:
    list_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.txt")
    if os.path.exists(list_path):
        emails = H.load_emails(list_path)
        print(f"[*] loaded {len(emails)} addresses from sample.txt", flush=True)
    else:
        emails = SAMPLES
        print(f"[*] using {len(emails)} built-in samples", flush=True)

    H.RESULTS = asyncio.run(H.run_batch(emails, 10))
    ok = sum(1 for r in H.RESULTS if r["valid"])
    print(f"[*] checked {len(H.RESULTS)} ({ok} likely valid)", flush=True)

    port = int(os.environ.get("PORT", "8901"))
    srv = HTTPServer(("0.0.0.0", port), H.Handler)
    print(f"[*] dashboard live on 0.0.0.0:{port}/", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
