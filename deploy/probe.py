#!/usr/bin/env python3
"""Port-25 egress probe for Botkeep (or any host).

Run:  python probe.py
Reads: console output. OPEN + 220 banner = SMTP probing possible here.
       BLOCKED/timeout       = port 25 egress is filtered on this host.
Stdlib only, no dependencies, exits 0 either way (result is the printout).
"""
import socket

TARGETS = [
    "gmail-smtp-in.l.google.com",
    "aspmx.l.google.com",
    "smtp.gmail.com",
]

for host in TARGETS:
    try:
        s = socket.create_connection((host, 25), timeout=8)
        s.settimeout(8)
        try:
            banner = s.recv(256).decode(errors="replace").strip()
        except Exception:
            banner = "<no banner>"
        print(f"OPEN    {host}:25  banner={banner!r}", flush=True)
        try:
            s.close()
        except Exception:
            pass
    except Exception as e:
        print(f"BLOCKED {host}:25  {type(e).__name__}: {str(e)[:90]}", flush=True)

print("probe done", flush=True)
