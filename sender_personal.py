"""Personal bulk-mail sender (offline clone of "Sasa Sender V2" workflow).

Single-file, stdlib-only (tkinter GUI). No network calls except the SMTP
servers YOU configure. No telemetry, no persistence, no phone-home.

SMTP file format (one per line, like Sasa):
    host port user pass
Separators accepted: spaces, ':' or '|'.  Lines starting with '#' skipped.
Example:
    smtp.gmail.com 587 you@gmail.com appPassword

Recipient file format: one email per line, '#' comments skipped.

Run GUI:  python sender_personal.py
Run CLI:  python sender_personal.py --cli --smtp smtp.txt --list emails.txt
              --subject "Hi" --body-file msg.html --html --report out.txt
Test SMTP only: python sender_personal.py --cli --smtp smtp.txt --test-only
From checker:   python sender_personal.py --cli --smtp smtp.txt \
              --from-checker results.jsonl --subject Hi --body hello
Dry run:        python sender_personal.py --cli --smtp smtp.txt --list emails.txt
              --subject Hi --body hello --dry-run
"""

import argparse
import datetime
import json
import os
import queue
import random
import smtplib
import ssl
import sys
import tempfile
import threading
import time
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from email.message import EmailMessage
from email.utils import formataddr, parseaddr

APP_TITLE = "Personal Sender V2 (offline)"
X_MAILER = "PersonalSender/2.0"

# --------------------------------------------------------------------------
# Pure logic (importable / unit-testable, no GUI here)
# --------------------------------------------------------------------------

def parse_smtp_line(line):
    """Parse one SMTP line -> dict(host,port,user,pass) or None.

    Accepts 'host port user pass', 'host:port:user:pass', 'host|port|user|pass'.
    Password may contain spaces (space form) or ':' (colon form).
    """
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    if "|" in line:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            return None
        host, port_s, user = parts[0], parts[1], parts[2]
        pw = "|".join(parts[3:])
    elif line.count(":") >= 3 and " " not in line:
        parts = [p.strip() for p in line.split(":")]
        if len(parts) < 4:
            return None
        host, port_s, user = parts[0], parts[1], parts[2]
        pw = ":".join(parts[3:])
    else:
        parts = line.split()
        if len(parts) < 4:
            return None
        host, port_s, user = parts[0], parts[1], parts[2]
        pw = " ".join(parts[3:])
    try:
        port = int(port_s)
    except ValueError:
        return None
    if not host or not user or not pw or not (1 <= port <= 65535):
        return None
    return {"host": host, "port": port, "user": user, "pass": pw}


def load_smtp_file(path):
    """Return (servers, bad_count)."""
    servers, bad = [], 0
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for raw in f:
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            rec = parse_smtp_line(s)
            if rec:
                servers.append(rec)
            else:
                bad += 1
    return servers, bad


def load_email_file(path):
    """Return (emails, bad_count). Keeps order, dedupes case-insensitively."""
    emails, bad, seen = [], 0, set()
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for raw in f:
            s = raw.strip().lstrip("\ufeff")
            if not s or s.startswith("#"):
                continue
            _name, addr = parseaddr(s)
            addr = addr.strip()
            if "@" not in addr or " " in addr or "." not in addr.split("@")[-1]:
                bad += 1
                continue
            key = addr.lower()
            if key in seen:
                continue
            seen.add(key)
            emails.append(addr)
    return emails, bad


def load_checker_emails(path, statuses=("valid", "likely")):
    """Read email_checker.py JSONL output, keep rows whose status is in
    `statuses`. Returns (emails, kept_counts, skipped_counts).

    Row shape: {"email":..., "valid":bool, "status":str, "reason":..., ...}.
    """
    wanted = set(s.strip().lower() for s in statuses if s.strip())
    emails, seen = [], set()
    kept, skipped = {}, {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            addr = str(row.get("email", "")).strip()
            status = str(row.get("status", "")).strip().lower()
            if "@" not in addr:
                continue
            if status in wanted:
                key = addr.lower()
                if key not in seen:
                    seen.add(key)
                    emails.append(addr)
                kept[status] = kept.get(status, 0) + 1
            else:
                skipped[status or "?"] = skipped.get(status or "?", 0) + 1
    return emails, kept, skipped


def pick_smtp(servers, mode, counter):
    """Rotation picker. mode: 'sequential' | 'random'."""
    if not servers:
        return None
    if mode == "random":
        return random.choice(servers)
    return servers[counter % len(servers)]


def build_message(smtp_user, recipient, subject, body, is_html,
                  display_name="", spoof_mode="none", spoof_email="",
                  attachments=()):
    """Build the EmailMessage. Envelope sender is always the SMTP user
    (return-path); spoofing only touches From / Reply-To headers."""
    msg = EmailMessage()
    from_addr = smtp_user
    if spoof_mode == "direct" and spoof_email:
        from_addr = spoof_email
    msg["From"] = formataddr((display_name or "", from_addr))
    msg["To"] = recipient
    msg["Subject"] = subject if subject else "(no subject)"
    if spoof_mode == "reply" and spoof_email:
        msg["Reply-To"] = spoof_email
    msg["X-Mailer"] = X_MAILER
    if is_html:
        msg.set_content(_html_to_text(body))
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)
    for path in attachments or ():
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            msg.add_attachment(data, maintype="application",
                               subtype="octet-stream",
                               filename=os.path.basename(path))
        except OSError:
            pass
    return msg


def _html_to_text(html):
    import re
    text = re.sub(r"(?i)<br\s*/?>", "\n", html)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    for ent, ch in (("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"),
                     ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'")):
        text = text.replace(ent, ch)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _connect(host, port, timeout):
    """SSL/TLS auto: 465 -> implicit SSL, else STARTTLS with plain fallback."""
    if port == 465:
        ctx = ssl.create_default_context()
        s = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        s.ehlo()
        return s, "SSL"
    s = smtplib.SMTP(host, port, timeout=timeout)
    s.ehlo()
    try:
        ctx = ssl.create_default_context()
        s.starttls(context=ctx)
        s.ehlo()
        return s, "STARTTLS"
    except smtplib.SMTPException:
        return s, "plain"


def smtp_test(server, timeout=15):
    """Connect + EHLO + TLS + LOGIN only. Returns (ok, info)."""
    try:
        s, mode = _connect(server["host"], server["port"], timeout)
        try:
            s.login(server["user"], server["pass"])
        finally:
            try:
                s.quit()
            except smtplib.SMTPException:
                pass
        return True, "login ok (%s)" % mode
    except smtplib.SMTPAuthenticationError as e:
        return False, "auth failed: %s" % _short_exc(e)
    except Exception as e:  # noqa: BLE001 - report any transport error
        return False, "%s: %s" % (type(e).__name__, _short_exc(e))


def smtp_send(server, msg, timeout=25):
    """Send one message. Envelope-from = SMTP user. Returns (ok, info)."""
    try:
        s, _mode = _connect(server["host"], server["port"], timeout)
        try:
            s.login(server["user"], server["pass"])
            s.send_message(msg, from_addr=server["user"])
        finally:
            try:
                s.quit()
            except smtplib.SMTPException:
                pass
        return True, "sent via %s" % server["host"]
    except smtplib.SMTPRecipientsRefused as e:
        return False, "recipient refused: %s" % _short_exc(e)
    except smtplib.SMTPSenderRefused as e:
        return False, "sender refused: %s" % _short_exc(e)
    except smtplib.SMTPAuthenticationError:
        return False, "auth failed"
    except Exception as e:  # noqa: BLE001 - report any transport error
        return False, "%s: %s" % (type(e).__name__, _short_exc(e))


def _short_exc(e, limit=140):
    text = str(e).replace("\n", " ").strip()
    return text[:limit] if text else type(e).__name__


def build_report(results, elapsed_s):
    """results: list of dict(email, ok, info, smtp). Returns report text."""
    sent = sum(1 for r in results if r["ok"])
    failed = len(results) - sent
    rate = (100.0 * sent / len(results)) if results else 0.0
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "PERSONAL SENDER V2 - REPORT",
        "Generated: %s" % stamp,
        "",
        "SUMMARY",
        "Sent: %d    Failed: %d    Total: %d" % (sent, failed, len(results)),
        "Success rate: %.1f%%    Elapsed: %.1fs" % (rate, elapsed_s),
        "",
        "DETAILS",
    ]
    for r in results:
        mark = "OK " if r["ok"] else "FAIL"
        lines.append("%s %s -> %s [%s]" % (mark, r["email"], r["info"], r["smtp"]))
    return "\n".join(lines) + "\n"

# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

class SenderApp:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.geometry("980x820")

        self.smtp_servers = []
        self.email_list = []
        self.attachments = []
        self.results = []
        self.sending = False
        self.stop_event = threading.Event()
        self.ui_queue = queue.Queue()
        self.start_ts = 0.0

        self._build_smtp_section(root)
        self._build_recipients_section(root)
        self._build_message_section(root)
        self._build_action_bar(root)
        self._build_status_section(root)
        root.after(200, self._pump_queue)

    # -- layout ---------------------------------------------------------
    def _build_smtp_section(self, root):
        box = ttk.LabelFrame(root, text="SMTP MODE", padding=8)
        box.pack(fill="x", padx=10, pady=(10, 4))

        self.smtp_mode = tk.StringVar(value="multiple")
        ttk.Radiobutton(box, text="Single SMTP", variable=self.smtp_mode,
                        value="single").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(box, text="Multiple SMTP", variable=self.smtp_mode,
                        value="multiple").grid(row=0, column=1, sticky="w")

        ttk.Label(box, text="Host").grid(row=1, column=0, sticky="w")
        self.e_host = ttk.Entry(box, width=24)
        self.e_host.insert(0, "smtp.gmail.com")
        self.e_host.grid(row=1, column=1, sticky="w", padx=4)
        ttk.Label(box, text="Port").grid(row=1, column=2, sticky="w")
        self.e_port = ttk.Entry(box, width=8)
        self.e_port.insert(0, "587")
        self.e_port.grid(row=1, column=3, sticky="w", padx=4)
        ttk.Label(box, text="User").grid(row=1, column=4, sticky="w")
        self.e_user = ttk.Entry(box, width=24)
        self.e_user.grid(row=1, column=5, sticky="w", padx=4)
        ttk.Label(box, text="Pass").grid(row=1, column=6, sticky="w")
        self.e_pass = ttk.Entry(box, width=20, show="*")
        self.e_pass.grid(row=1, column=7, sticky="w", padx=4)

        ttk.Button(box, text="Select SMTP File",
                   command=self.load_smtp).grid(row=2, column=0, pady=6,
                                                sticky="w")
        self.lbl_smtp = ttk.Label(box, text="SMTP servers: 0  (host port user pass)")
        self.lbl_smtp.grid(row=2, column=1, columnspan=4, sticky="w")
        ttk.Label(box, text="Rotation").grid(row=2, column=5, sticky="e")
        self.rotation = tk.StringVar(value="sequential")
        ttk.Combobox(box, textvariable=self.rotation, width=12,
                     values=["sequential", "random"],
                     state="readonly").grid(row=2, column=6, columnspan=2,
                                            sticky="w", padx=4)

        ttk.Label(box, text="Concurrent threads").grid(row=3, column=0,
                                                       sticky="w")
        self.spin_threads = tk.Spinbox(box, from_=1, to=20, width=6)
        self.spin_threads.delete(0, "end")
        self.spin_threads.insert(0, "3")
        self.spin_threads.grid(row=3, column=1, sticky="w")
        ttk.Label(box, text="Delay between sends (ms)").grid(row=3, column=2,
                                                             columnspan=2,
                                                             sticky="w")
        self.spin_delay = tk.Spinbox(box, from_=0, to=60000, increment=100,
                                     width=8)
        self.spin_delay.delete(0, "end")
        self.spin_delay.insert(0, "300")
        self.spin_delay.grid(row=3, column=4, sticky="w")
        ttk.Label(box, text="Retries on failure").grid(row=3, column=5,
                                                       sticky="e")
        self.spin_retry = tk.Spinbox(box, from_=0, to=5, width=6)
        self.spin_retry.delete(0, "end")
        self.spin_retry.insert(0, "1")
        self.spin_retry.grid(row=3, column=6, sticky="w", padx=4)

    def _build_recipients_section(self, root):
        box = ttk.LabelFrame(root, text="RECIPIENTS", padding=8)
        box.pack(fill="x", padx=10, pady=4)
        ttk.Button(box, text="Select Email List File",
                   command=self.load_emails).grid(row=0, column=0, sticky="w")
        self.lbl_emails = ttk.Label(box, text="Recipients: 0")
        self.lbl_emails.grid(row=0, column=1, sticky="w", padx=8)

    def _build_message_section(self, root):
        box = ttk.LabelFrame(root, text="MESSAGE + SEND OPTIONS", padding=8)
        box.pack(fill="both", expand=True, padx=10, pady=4)

        ttk.Label(box, text="Subject").grid(row=0, column=0, sticky="w")
        self.e_subject = ttk.Entry(box, width=80)
        self.e_subject.grid(row=0, column=1, columnspan=3, sticky="we", padx=4)

        ttk.Label(box, text="Spoof Mode:").grid(row=1, column=0, sticky="w",
                                                pady=4)
        self.spoof_mode = tk.StringVar(value="none")
        ttk.Combobox(box, textvariable=self.spoof_mode, width=22,
                     values=["none", "direct", "reply"],
                     state="readonly").grid(row=1, column=1, sticky="w",
                                            padx=4)
        ttk.Label(box, text="Spoofed email (optional)").grid(row=1, column=2,
                                                             sticky="e")
        self.e_spoof = ttk.Entry(box, width=30)
        self.e_spoof.grid(row=1, column=3, sticky="w", padx=4)

        ttk.Label(box, text="Sender display name (optional)").grid(
            row=2, column=0, sticky="w")
        self.e_display = ttk.Entry(box, width=30)
        self.e_display.grid(row=2, column=1, sticky="w", padx=4, pady=4)
        self.is_html = tk.BooleanVar(value=False)
        ttk.Checkbutton(box, text="Send as HTML", variable=self.is_html).grid(
            row=2, column=2, sticky="w")
        ttk.Label(box, text="none=From SMTP user | direct=From spoofed | "
                            "reply=Reply-To spoofed").grid(
            row=2, column=3, sticky="w")

        self.txt_body = scrolledtext.ScrolledText(box, height=8, width=100)
        self.txt_body.grid(row=3, column=0, columnspan=4, sticky="nsew",
                           pady=4)
        self.txt_body.insert("1.0", "Message body...")
        box.grid_rowconfigure(3, weight=1)
        box.grid_columnconfigure(1, weight=1)

        ttk.Button(box, text="Select Attachments",
                   command=self.load_attachments).grid(row=4, column=0,
                                                       sticky="w")
        self.lbl_attach = ttk.Label(box, text="Attachments: 0")
        self.lbl_attach.grid(row=4, column=1, sticky="w", padx=8)
        ttk.Button(box, text="Clear", command=self.clear_attachments).grid(
            row=4, column=2, sticky="w")

    def _build_action_bar(self, root):
        bar = ttk.Frame(root, padding=4)
        bar.pack(fill="x", padx=10)
        ttk.Button(bar, text="Test SMTP Connection",
                   command=self.on_test).pack(side="left", padx=4)
        ttk.Button(bar, text="Preview Email",
                   command=self.on_preview).pack(side="left", padx=4)
        self.btn_start = ttk.Button(bar, text="START SENDING",
                                    command=self.on_start)
        self.btn_start.pack(side="left", padx=4)
        self.btn_stop = ttk.Button(bar, text="Stop", command=self.on_stop,
                                   state="disabled")
        self.btn_stop.pack(side="left", padx=4)
        ttk.Button(bar, text="Save Report",
                   command=self.on_save_report).pack(side="left", padx=4)

    def _build_status_section(self, root):
        box = ttk.LabelFrame(root, text="STATUS + ACTIVITY LOG", padding=8)
        box.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        self.lbl_stats = ttk.Label(box, text="Sent: 0    Failed: 0    Total: 0")
        self.lbl_stats.pack(anchor="w")
        self.lbl_rate = ttk.Label(box, text="Success rate: 0%    Speed: 0/s")
        self.lbl_rate.pack(anchor="w")
        self.log = scrolledtext.ScrolledText(box, height=8, width=100,
                                             state="disabled")
        self.log.pack(fill="both", expand=True, pady=4)

    # -- file loaders ---------------------------------------------------
    def load_smtp(self):
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            servers, bad = load_smtp_file(path)
        except OSError as e:
            messagebox.showerror("Error", "Failed to read SMTP file: %s" % e)
            return
        self.smtp_servers = servers
        self.lbl_smtp.config(text="SMTP servers: %d%s" % (
            len(servers), ("  (%d bad lines skipped)" % bad) if bad else ""))
        self._log("Loaded %d SMTP servers from %s" % (len(servers), path))

    def load_emails(self):
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            emails, bad = load_email_file(path)
        except OSError as e:
            messagebox.showerror("Error", "Failed to read email file: %s" % e)
            return
        self.email_list = emails
        self.lbl_emails.config(text="Recipients: %d%s" % (
            len(emails), ("  (%d bad lines skipped)" % bad) if bad else ""))
        self._log("Loaded %d recipient emails from %s" % (len(emails), path))

    def load_attachments(self):
        paths = filedialog.askopenfilenames(
            filetypes=[("All files", "*.*")])
        for p in paths:
            if p not in self.attachments:
                self.attachments.append(p)
        self.lbl_attach.config(text="Attachments: %d" % len(self.attachments))

    def clear_attachments(self):
        self.attachments = []
        self.lbl_attach.config(text="Attachments: 0")

    # -- logging / queue ------------------------------------------------
    def _log(self, text):
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log.config(state="normal")
        self.log.insert("end", "[%s] %s\n" % (stamp, text))
        self.log.see("end")
        self.log.config(state="disabled")

    def _pump_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "done":
                    self._on_send_done(payload)
        except queue.Empty:
            pass
        self.root.after(200, self._pump_queue)

    # -- smtp source ----------------------------------------------------
    def _active_servers(self):
        if self.smtp_mode.get() == "single":
            host = self.e_host.get().strip()
            user = self.e_user.get().strip()
            pw = self.e_pass.get()
            try:
                port = int(self.e_port.get().strip())
            except ValueError:
                return None, "Invalid single SMTP port."
            rec = parse_smtp_line("%s %d %s %s" % (host, port, user, pw))
            if not rec:
                return None, ("Invalid single SMTP format. "
                               "Expected: host port user pass")
            return [rec], ""
        if not self.smtp_servers:
            return None, "No SMTP servers loaded."
        return list(self.smtp_servers), ""

    # -- actions --------------------------------------------------------
    def on_test(self):
        servers, err = self._active_servers()
        if err:
            messagebox.showerror("Error", err)
            return
        threading.Thread(target=self._test_worker, args=(servers,),
                         daemon=True).start()
        self._log("Testing SMTP: %d server(s)..." % len(servers))

    def _test_worker(self, servers):
        for s in servers:
            label = "%s:%d:%s" % (s["host"], s["port"], s["user"])
            ok, info = smtp_test(s)
            self.ui_queue.put(("log", "SMTP test %s: %s (%s)" % (
                "passed" if ok else "failed", label, info)))

    def on_preview(self):
        servers, err = self._active_servers()
        if err:
            messagebox.showerror("Error", err)
            return
        if not self.email_list:
            messagebox.showerror("Error", "No recipient emails loaded.")
            return
        body = self.txt_body.get("1.0", "end").strip()
        if not body:
            messagebox.showerror("Error", "Message body is empty.")
            return
        msg = build_message(
            servers[0]["user"], self.email_list[0],
            self.e_subject.get().strip(), body, self.is_html.get(),
            self.e_display.get().strip(), self.spoof_mode.get(),
            self.e_spoof.get().strip(), self.attachments)
        win = tk.Toplevel(self.root)
        win.title("Preview Email")
        win.geometry("760x560")
        txt = scrolledtext.ScrolledText(win, width=90, height=32)
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("1.0", "SMTP Line: %s:%d:%s:****\n" % (
            servers[0]["host"], servers[0]["port"], servers[0]["user"]))
        txt.insert("end", "Envelope-From: %s\n\n" % servers[0]["user"])
        txt.insert("end", msg.as_string())
        txt.config(state="disabled")
        if self.is_html.get():
            bar = ttk.Frame(win)
            bar.pack(fill="x", padx=8, pady=(0, 8))
            ttk.Button(bar, text="Buka render HTML di browser",
                       command=lambda: self.open_rendered_html(
                           self.txt_body.get("1.0", "end").strip())
                       ).pack(side="left")

    @staticmethod
    def open_rendered_html(html_body):
        """Write HTML to a temp file and open it in the OS browser."""
        try:
            with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".html", delete=False,
                    encoding="utf-8") as f:
                f.write(html_body)
                path = f.name
            webbrowser.open("file://%s" % path.replace("\\", "/"))
        except OSError as e:
            messagebox.showerror("Error", "Failed to open preview: %s" % e)

    def on_start(self):
        servers, err = self._active_servers()
        if err:
            messagebox.showerror("Error", err)
            return
        if not self.email_list:
            messagebox.showerror("Error", "No recipient emails loaded.")
            return
        body = self.txt_body.get("1.0", "end").strip()
        if not body:
            messagebox.showerror("Error", "Message body is empty.")
            return
        try:
            threads = max(1, min(20, int(self.spin_threads.get())))
            delay_ms = max(0, int(self.spin_delay.get()))
            retries = max(0, min(5, int(self.spin_retry.get())))
        except ValueError:
            messagebox.showerror("Error", "Threads / delay / retries must be numbers.")
            return
        self.sending = True
        self.stop_event.clear()
        self.results = []
        self.start_ts = time.time()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        cfg = {
            "servers": servers,
            "rotation": self.rotation.get(),
            "subject": self.e_subject.get().strip(),
            "body": body,
            "is_html": self.is_html.get(),
            "display": self.e_display.get().strip(),
            "spoof_mode": self.spoof_mode.get(),
            "spoof": self.e_spoof.get().strip(),
            "attachments": list(self.attachments),
            "delay": delay_ms / 1000.0,
            "retries": retries,
        }
        self._log("Started sending %d emails with %d thread(s)." % (
            len(self.email_list), threads))
        threading.Thread(target=self._send_master,
                         args=(cfg, threads), daemon=True).start()

    def on_stop(self):
        self.stop_event.set()
        self._log("Stop requested...")

    def _send_master(self, cfg, threads):
        total = len(self.email_list)
        idx = [0]
        sent_n = [0]
        lock = threading.Lock()

        def worker():
            while not self.stop_event.is_set():
                with lock:
                    if idx[0] >= total:
                        return
                    my = idx[0]
                    idx[0] += 1
                rcpt = self.email_list[my]
                ok, info, used = self._send_one(rcpt, my, cfg)
                with lock:
                    if ok:
                        sent_n[0] += 1
                    self.results.append({"email": rcpt, "ok": ok,
                                         "info": info, "smtp": used})
                    done = len(self.results)
                self._refresh_stats(done, total, sent_n[0])
                if cfg["delay"] > 0:
                    time.sleep(cfg["delay"])

        workers = [threading.Thread(target=worker, daemon=True)
                   for _ in range(min(threads, total))]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        elapsed = time.time() - self.start_ts
        stopped = self.stop_event.is_set() and len(self.results) < total
        self.ui_queue.put(("done", (elapsed, stopped)))

    def _send_one(self, rcpt, counter, cfg):
        last_info, used_host = "no attempt", "?"
        attempt = 0
        while attempt <= cfg["retries"] and not self.stop_event.is_set():
            server = pick_smtp(cfg["servers"], cfg["rotation"],
                               counter + attempt)
            used_host = "%s:%d" % (server["host"], server["port"])
            msg = build_message(
                server["user"], rcpt, cfg["subject"], cfg["body"],
                cfg["is_html"], cfg["display"], cfg["spoof_mode"],
                cfg["spoof"], cfg["attachments"])
            ok, info = smtp_send(server, msg)
            if ok:
                return True, info, used_host
            last_info, attempt = info, attempt + 1
        return False, last_info, used_host

    def _refresh_stats(self, done, total, sent):
        failed = done - sent
        pct = (100.0 * done / total) if total else 0.0
        elapsed = max(0.1, time.time() - self.start_ts)
        speed = done / elapsed
        eta = (total - done) / speed if speed > 0 else 0
        rate = (100.0 * sent / done) if done else 0.0
        self.root.after(0, self.lbl_stats.config,
                        {"text": "Sending... (%.0f%%)  Sent: %d    Failed: %d"
                                 "    Total: %d" % (pct, sent, failed, total)})
        self.root.after(0, self.lbl_rate.config,
                        {"text": "Success rate: %.1f%%    Speed: %.1f/s    "
                                 "ETA %s" % (rate, speed, _fmt_eta(eta))})

    def _on_send_done(self, payload):
        elapsed, stopped = payload
        self.sending = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        sent = sum(1 for r in self.results if r["ok"])
        failed = len(self.results) - sent
        rate = (100.0 * sent / len(self.results)) if self.results else 0.0
        self.lbl_stats.config(text="Sent: %d    Failed: %d    Total: %d" % (
            sent, failed, len(self.results)))
        self.lbl_rate.config(text="Success rate: %.1f%%" % rate)
        if stopped:
            self._log("Stopped")
        self._log("Done. Sent: %d, Failed: %d, Total: %d (%.1fs)" % (
            sent, failed, len(self.results), elapsed))

    def on_save_report(self):
        if not self.results:
            messagebox.showinfo("Report", "No results yet.")
            return
        elapsed = time.time() - self.start_ts if self.start_ts else 0.0
        text = build_report(self.results, elapsed)
        fname = "report_%s.txt" % datetime.datetime.now().strftime(
            "%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            initialfile=fname, defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as e:
            messagebox.showerror("Error", "Failed to save report: %s" % e)
            return
        self._log("Report saved: %s" % path)


def _fmt_eta(sec):
    sec = int(sec)
    if sec < 60:
        return "%ds" % sec
    m, s = divmod(sec, 60)
    if m < 60:
        return "%dm %ds" % (m, s)
    h, m = divmod(m, 60)
    return "%dh %dm" % (h, m)


def main():
    if "--cli" in sys.argv:
        sys.argv.remove("--cli")
        sys.exit(cli_main(sys.argv[1:]))
    root = tk.Tk()
    SenderApp(root)
    root.mainloop()


# --------------------------------------------------------------------------
# CLI mode (headless / batch, no GUI)
# --------------------------------------------------------------------------

def cli_main(argv):
    ap = argparse.ArgumentParser(
        description="Personal bulk-mail sender (offline CLI).")
    ap.add_argument("--smtp", help="SMTP file (host port user pass per line)")
    ap.add_argument("--smtp-single",
                    help="one SMTP as 'host port user pass' (quoted)")
    ap.add_argument("--list", help="recipient email file (one per line)")
    ap.add_argument("--from-checker",
                    help="email_checker.py JSONL output: auto-take emails "
                         "with wanted statuses (mergeable with --list)")
    ap.add_argument("--checker-status", default="valid,likely",
                    help="comma list of checker statuses to take "
                         "(default: valid,likely)")
    ap.add_argument("--subject", default="", help="message subject")
    ap.add_argument("--body", default="", help="message body text")
    ap.add_argument("--body-file", help="read body from file")
    ap.add_argument("--html", action="store_true", help="send as HTML")
    ap.add_argument("--display", default="",
                    help="sender display name (optional)")
    ap.add_argument("--spoof-mode", default="none",
                    choices=["none", "direct", "reply"])
    ap.add_argument("--spoof", default="",
                    help="spoofed email (optional)")
    ap.add_argument("--attach", action="append", default=[],
                    help="attachment path (repeatable)")
    ap.add_argument("--rotation", default="sequential",
                    choices=["sequential", "random"])
    ap.add_argument("--threads", type=int, default=3)
    ap.add_argument("--delay-ms", type=int, default=300)
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--report",
                    help="report output path (default report_YYYYMMDD_HHMMSS.txt)")
    ap.add_argument("--test-only", action="store_true",
                    help="only test SMTP login(s), send nothing")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse inputs + print first message, send nothing")
    ap.add_argument("--preview-html",
                    help="write rendered HTML of first message to PATH "
                         "(works with --dry-run too)")
    args = ap.parse_args(argv)

    # -- collect SMTP servers -------------------------------------------
    servers = []
    if args.smtp_single:
        rec = parse_smtp_line(args.smtp_single)
        if not rec:
            print("ERROR: invalid --smtp-single, expected 'host port user pass'")
            return 2
        servers.append(rec)
    if args.smtp:
        try:
            loaded, bad = load_smtp_file(args.smtp)
        except OSError as e:
            print("ERROR: cannot read SMTP file: %s" % e)
            return 2
        servers.extend(loaded)
        if bad:
            print("[*] %d bad SMTP line(s) skipped" % bad)
    if not servers:
        print("ERROR: no SMTP servers (use --smtp FILE or --smtp-single)")
        return 2
    print("[*] SMTP servers: %d" % len(servers))

    if args.test_only:
        failed = 0
        for s in servers:
            label = "%s:%d:%s" % (s["host"], s["port"], s["user"])
            ok, info = smtp_test(s, timeout=args.timeout)
            print("%s %s -> %s" % ("OK " if ok else "FAIL", label, info))
            if not ok:
                failed += 1
        print("[*] %d/%d passed" % (len(servers) - failed, len(servers)))
        return 1 if failed else 0

    # -- collect recipients ---------------------------------------------
    emails, seen_rcpt = [], set()

    def _add_rcpt(addr):
        key = addr.strip().lower()
        if key and key not in seen_rcpt:
            seen_rcpt.add(key)
            emails.append(addr.strip())

    if args.from_checker:
        statuses = [s for s in args.checker_status.split(",")]
        try:
            cemails, kept, skipped = load_checker_emails(args.from_checker,
                                                         statuses)
        except OSError as e:
            print("ERROR: cannot read checker file: %s" % e)
            return 2
        for a in cemails:
            _add_rcpt(a)
        kstr = ", ".join("%s=%d" % kv for kv in sorted(kept.items())) or "none"
        sstr = ", ".join("%s=%d" % kv for kv in sorted(skipped.items())) or "none"
        print("[*] from checker: took [%s], skipped [%s]" % (kstr, sstr))
    if args.list:
        try:
            lemails, ebad = load_email_file(args.list)
        except OSError as e:
            print("ERROR: cannot read list file: %s" % e)
            return 2
        for a in lemails:
            _add_rcpt(a)
        if ebad:
            print("[*] %d bad email line(s) skipped" % ebad)
    if not emails:
        print("ERROR: no valid recipients "
              "(use --list FILE and/or --from-checker results.jsonl)")
        return 2
    print("[*] Recipients: %d" % len(emails))

    # -- body ------------------------------------------------------------
    body = args.body
    if args.body_file:
        try:
            with open(args.body_file, "r", encoding="utf-8",
                      errors="replace") as f:
                body = f.read()
        except OSError as e:
            print("ERROR: cannot read body file: %s" % e)
            return 2
    if not body.strip():
        print("ERROR: message body is empty")
        return 2

    cfg = {
        "servers": servers,
        "rotation": args.rotation,
        "subject": args.subject,
        "body": body,
        "is_html": args.html,
        "display": args.display,
        "spoof_mode": args.spoof_mode,
        "spoof": args.spoof,
        "attachments": args.attach,
        "delay": max(0, args.delay_ms) / 1000.0,
        "retries": max(0, args.retries),
        "timeout": args.timeout,
    }

    if args.preview_html:
        html_doc = body if args.html else (
            "<html><body><pre>%s</pre></body></html>" % body.replace(
                "&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        try:
            with open(args.preview_html, "w", encoding="utf-8") as f:
                f.write(html_doc)
            print("[*] preview HTML -> %s" % args.preview_html)
        except OSError as e:
            print("ERROR: cannot write preview: %s" % e)
            return 2

    if args.dry_run:
        msg = build_message(servers[0]["user"], emails[0], cfg["subject"],
                            body, args.html, args.display, args.spoof_mode,
                            args.spoof, args.attach)
        print("--- first message (envelope-from: %s) ---" % servers[0]["user"])
        print(msg.as_string()[:4000])
        return 0

    # -- send ------------------------------------------------------------
    threads = max(1, min(20, args.threads))
    stop = threading.Event()
    lock = threading.Lock()
    idx = [0]
    results = []
    start_ts = time.time()
    total = len(emails)
    print("[*] Sending %d emails with %d thread(s)..." % (total, threads))

    def send_one(rcpt, counter):
        attempt, last_info, used = 0, "no attempt", "?"
        while attempt <= cfg["retries"] and not stop.is_set():
            server = pick_smtp(cfg["servers"], cfg["rotation"],
                               counter + attempt)
            used = "%s:%d" % (server["host"], server["port"])
            msg = build_message(server["user"], rcpt, cfg["subject"],
                                cfg["body"], cfg["is_html"], cfg["display"],
                                cfg["spoof_mode"], cfg["spoof"],
                                cfg["attachments"])
            ok, info = smtp_send(server, msg, timeout=cfg["timeout"])
            if ok:
                return True, info, used
            last_info, attempt = info, attempt + 1
        return False, last_info, used

    def worker():
        while not stop.is_set():
            with lock:
                if idx[0] >= total:
                    return
                my = idx[0]
                idx[0] += 1
            rcpt = emails[my]
            ok, info, used = send_one(rcpt, my)
            with lock:
                results.append({"email": rcpt, "ok": ok,
                                "info": info, "smtp": used})
                done = len(results)
            print("[%d/%d] %s %s -> %s" % (
                done, total, "OK " if ok else "FAIL", rcpt, info))
            if cfg["delay"] > 0:
                time.sleep(cfg["delay"])

    try:
        workers = [threading.Thread(target=worker, daemon=True)
                   for _ in range(min(threads, total))]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
    except KeyboardInterrupt:
        stop.set()
        print("\n[*] interrupted, stopping...")

    elapsed = time.time() - start_ts
    text = build_report(results, elapsed)
    out = args.report or ("report_%s.txt" % datetime.datetime.now().strftime(
        "%Y%m%d_%H%M%S"))
    try:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print("[*] report -> %s" % out)
    except OSError as e:
        print("ERROR: cannot write report: %s" % e)
        return 2
    sent = sum(1 for r in results if r["ok"])
    print("[*] Done. Sent: %d, Failed: %d, Total: %d (%.1fs)" % (
        sent, len(results) - sent, len(results), elapsed))
    return 0 if sent == len(results) else 1


if __name__ == "__main__":
    main()
