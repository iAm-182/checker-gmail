import argparse
import asyncio
import json
import re
import smtplib
import socket
import sys
import threading
import urllib.error
import urllib.request

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

DISPOSABLE_API = "https://open.kickbox.com/v1/disposable/"

_api_cache = {}
_api_lock = threading.Lock()

_egress = {"checked": False, "reachable": None, "detail": ""}


def check_syntax(email: str) -> tuple[bool, str]:
    if not email or not EMAIL_RE.match(email):
        return False, "invalid_syntax"
    local, _, domain = email.rpartition("@")
    if len(local) > 64 or len(email) > 254:
        return False, "too_long"
    if ".." in email:
        return False, "consecutive_dots"
    return True, "ok"


def is_disposable(email: str) -> bool:
    domain = email.rpartition("@")[2].lower()
    return domain in DISPOSABLE_DOMAINS


def is_role_based(email: str) -> bool:
    local = email.rpartition("@")[0].lower()
    return local in ROLE_PREFIXES


def check_mx(domain: str) -> tuple[bool, str, list]:
    if not HAS_DNS:
        return False, "dnspython_missing", []
    try:
        answers = dns.resolver.resolve(domain, "MX")
        records = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers]
        )
        if not records:
            return False, "no_mx_records", []
        return True, "ok", records
    except dns.resolver.NXDOMAIN:
        return False, "domain_not_found", []
    except dns.resolver.NoAnswer:
        return False, "no_mx_records", []
    except dns.resolver.NoNameservers:
        return False, "ns_failure", []
    except Exception as e:
        return False, f"dns_error:{e.__class__.__name__}", []


def api_is_disposable(domain: str, timeout: int = 6) -> bool | None:
    """Free no-auth disposable lookup. None when the service is unusable."""
    domain = domain.lower()
    with _api_lock:
        if domain in _api_cache:
            return _api_cache[domain]
    verdict = None
    try:
        req = urllib.request.Request(
            DISPOSABLE_API + domain, headers={"User-Agent": "mail-hygiene/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status == 200:
                payload = json.loads(r.read().decode("utf-8", "replace"))
                if isinstance(payload.get("disposable"), bool):
                    verdict = payload["disposable"]
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        verdict = None
    with _api_lock:
        _api_cache[domain] = verdict
    return verdict


def preflight_smtp(timeout: int = 6, hosts=None) -> bool:
    """One-shot TCP/25 reachability probe so batch runs do not stall on it."""
    if _egress["checked"]:
        return _egress["reachable"]
    hosts = hosts or ("aspmx.l.google.com", "mail.yahoo.com")
    reachable = False
    detail = ""
    for host in hosts:
        try:
            s = socket.create_connection((host, 25), timeout=timeout)
            s.close()
            reachable = True
            detail = f"tcp25_open:{host}"
            break
        except (socket.timeout, TimeoutError):
            detail = f"tcp25_timeout:{host}"
        except ConnectionRefusedError:
            detail = f"tcp25_refused:{host}"
        except OSError as e:
            detail = f"tcp25_error:{host}:{e.errno}"
    _egress.update({"checked": True, "reachable": reachable, "detail": detail})
    return reachable


def _enhanced_code(text: str) -> str | None:
    """Extract RFC 3463 enhanced status code (e.g. 5.1.1, 5.2.1) from an
    SMTP response. This is the exact signal bulk checkers use to split
    Not-Exist from Disabled instead of lumping every 55x together."""
    m = re.search(r"\b([245]\.\d{1,3}\.\d{1,3})\b", text)
    return m.group(1) if m else None


def _classify_reject(code: int | None, text: str) -> tuple[str, str]:
    """Map a 55x RCPT rejection to (verdict, reason).

    Gmail's documented mapping (support.google.com/mail/answer/3726730):
      5.1.0 / 5.1.1  NoSuchUser    -> mailbox does not exist
      5.2.1          DisabledUser  -> mailbox exists but is disabled/inactive
    Caveat: bare 5.2.1 is ALSO used for ReceivingRatePerm (rate-limited
    recipient). Only DisabledUser in the text proves disabled; otherwise
    the verdict stays undecided instead of guessing.
    """
    low = text.lower()
    enh = _enhanced_code(text)
    detail = f"{code}/{enh}" if enh else f"{code}"
    if enh in ("5.1.0", "5.1.1") or "nosuchuser" in low:
        return "rejected_notfound", f"mailbox_not_found_{detail}"
    if "disableduser" in low or "account has been disabled" in low:
        return "rejected_disabled", f"mailbox_disabled_{detail}"
    if enh == "5.2.1":
        if "receivingrateperm" in low or "rate" in low and "prevent" in low:
            return "temp", f"recipient_rate_limited_{detail}"
        return "soft", f"ambiguous_5_2_1_{detail}"
    if code in (550, 551, 552, 553) or any(
        k in low for k in ("not found", "does not exist", "user unknown",
                           "no such user", "unknown user", "recipient rejected",
                           "inactive", "disabled", "suspended")
    ):
        if any(k in low for k in ("inactive", "disabled", "suspended")):
            return "soft", f"possible_disabled_{detail}"
        return "rejected_notfound", f"rcpt_rejected_{detail}"
    return "soft", f"rcpt_rejected_{detail}"


def _smtp_probe(email: str, mx_host: str, timeout: int) -> tuple[str, int | None, str]:
    """One SMTP session. Returns (verdict, code, message)."""
    try:
        # Host passed to the constructor (not bare SMTP() + connect()) so
        # STARTTLS has a proper server_hostname for SNI on py3.12+.
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as s:
            s.ehlo("checker.local")
            try:
                s.starttls()
                s.ehlo("checker.local")
            except smtplib.SMTPNotSupportedError:
                pass
            code, _ = s.mail("probe@checker.local")
            if code != 250:
                return "network", code, "sender_rejected"
            code, msg = s.rcpt(email)
            text = (msg or b"").decode(errors="replace").strip()
            if code == 250:
                return "accepted", code, text
            if code in (450, 451, 452):
                return "temp", code, text
            verdict, reason = _classify_reject(code, text)
            return verdict, code, reason
    except (socket.timeout, TimeoutError):
        return "network", None, "tcp25_timeout"
    except ConnectionRefusedError:
        return "network", None, "tcp25_refused"
    except smtplib.SMTPConnectError as e:
        return "network", getattr(e, "smtp_code", None), f"connect_error:{e.smtp_code}"
    except smtplib.SMTPResponseException as e:
        code = e.smtp_code
        text = str(e.smtp_error or b"").strip()
        verdict, reason = _classify_reject(code, text)
        return verdict, code, reason
    except (smtplib.SMTPException, OSError) as e:
        return "network", None, f"io_error:{e.__class__.__name__}"


def check_smtp(email: str, mx_records: list, timeout: int = 10) -> tuple[str, str]:
    """Aggregate verdicts across MX hosts.

    'accepted' is never promoted to a mailbox-exists claim on its own; the caller
    decides that only after catch-all has been ruled out.
    """
    saw_protocol = False
    saw_network_only = False
    last_detail = ""

    for _, mx_host in mx_records:
        verdict, code, detail = _smtp_probe(email, mx_host, timeout)
        last_detail = detail

        if verdict == "accepted":
            return "accepted", f"rcpt_accepted_{code}"
        if verdict == "rejected_notfound":
            return "invalid", detail
        if verdict == "rejected_disabled":
            return "disabled", detail
        if verdict == "temp":
            saw_protocol = True
        if verdict == "soft":
            saw_protocol = True
        if verdict == "network":
            saw_network_only = True

    if saw_protocol:
        return "unknown", "smtp_undecided"
    if saw_network_only:
        return "unreachable", last_detail or "smtp_unreachable"
    return "unreachable", "no_mx_reachable"


def detect_catch_all(domain: str, mx_records: list, timeout: int = 10) -> bool | None:
    """None when the probe could not reach a verdict (network blocked)."""
    probe = "nonexistent-probe-xyz123@%s" % domain
    status, _ = check_smtp(probe, mx_records, timeout)
    if status == "unreachable":
        return None
    return status == "accepted"


def gmail_oracle(email: str, proxy: str | None = None) -> str:
    """Lazy wrapper so playwright is only imported when the oracle runs."""
    try:
        from gmail_oracle import is_gmail, oracle_check
    except ImportError:
        try:
            from checker_gmail.gmail_oracle import (  # type: ignore
                is_gmail, oracle_check)
        except ImportError:
            return "error:module_missing"
    if not is_gmail(email):
        return "skipped_non_gmail"
    try:
        return oracle_check(email, proxy=proxy)
    except Exception as e:
        return f"error:{e.__class__.__name__}"


def check_email(email: str, probe_catch_all: bool = False, timeout: int = 10,
                use_api: bool = True, allow_smtp: bool = True,
                use_oracle: bool = False) -> dict:
    """Statuses:
        invalid    - not deliverable (syntax, disposable, no MX, MX said no)
        valid      - MX accepted RCPT and catch-all was ruled out
        disabled   - mailbox exists but is disabled/inactive (SMTP 5.2.1)
        likely     - MX present and catch-all ruled out, but RCPT gave no proof
        unknown    - could not determine from here
    """
    email = email.strip()
    result = {"email": email, "valid": False, "status": "invalid", "reason": "", "notes": []}

    ok, reason = check_syntax(email)
    if not ok:
        result["reason"] = reason
        return result

    domain = email.rpartition("@")[2].lower()

    if is_disposable(email):
        result["reason"] = "disposable_domain"
        result["notes"].append("disposable")
        return result

    if use_api:
        remote = api_is_disposable(domain)
        if remote is True:
            result["reason"] = "disposable_domain"
            result["notes"].append("disposable")
            result["notes"].append("disposable_api")
            return result
        if remote is False:
            result["notes"].append("disposable_api_ok")

    if is_role_based(email):
        result["notes"].append("role_based")

    ok, reason, mx_records = check_mx(domain)
    if not ok:
        result["reason"] = reason
        return result

    if not allow_smtp:
        result["status"] = "likely"
        result["reason"] = "mx_present_smtp_skipped"
        result["notes"].append("dns_only")
        if use_oracle:
            oc = gmail_oracle(email)
            result["notes"].append("gmail_oracle")
            if oc == "exists":
                result["status"] = "valid"
                result["valid"] = True
                result["reason"] = "gmail_oracle_exists"
            elif oc == "absent":
                result["status"] = "invalid"
                result["reason"] = "gmail_oracle_absent"
            else:
                result["notes"].append(f"gmail_oracle_{oc.splitlines()[0][:90]}")
        return result

    if not preflight_smtp(timeout=min(timeout, 6)):
        result["status"] = "likely"
        result["reason"] = "mx_present_smtp_unreachable"
        result["notes"].append("dns_only")
        result["notes"].append(_egress["detail"] or "tcp25_blocked")
        return result

    catch_all = None
    if probe_catch_all:
        catch_all = detect_catch_all(domain, mx_records, timeout)
        if catch_all:
            result["reason"] = "catch_all_domain"
            result["status"] = "likely"
            result["notes"].append("catch_all")
            return result
        if catch_all is None:
            result["notes"].append("catch_all_unknown")

    status, reason = check_smtp(email, mx_records, timeout)

    if status == "accepted":
        if catch_all is False:
            result["status"] = "valid"
            result["valid"] = True
            result["reason"] = reason
        elif catch_all is None:
            result["status"] = "likely"
            result["reason"] = reason
            result["notes"].append("catch_all_unchecked")
        else:
            result["status"] = "likely"
            result["reason"] = "catch_all_domain"
            result["notes"].append("catch_all")
        return result

    if status == "invalid":
        result["status"] = "invalid"
        result["reason"] = reason
        return result

    if status == "disabled":
        # Mailbox exists but is disabled/inactive (SMTP 5.2.1 + DisabledUser).
        # Neither valid (can't receive) nor invalid (it exists).
        result["status"] = "disabled"
        result["reason"] = reason
        result["notes"].append("mailbox_exists_but_disabled")
        return result

    if status == "unreachable":
        result["status"] = "likely"
        result["reason"] = reason
        result["notes"].append("smtp_unreachable")
        return result

    result["status"] = "likely"
    result["reason"] = reason
    result["notes"].append("unverified")
    return result


async def check_email_async(email: str, sem: asyncio.Semaphore, **kw) -> dict:
    async with sem:
        return await asyncio.to_thread(check_email, email, **kw)


async def check_batch(emails: list, concurrency: int = 10, delay: float = 0.5,
                      probe_catch_all: bool = False, timeout: int = 10,
                      use_api: bool = True, allow_smtp: bool = True,
                      use_oracle: bool = False) -> list:
    sem = asyncio.Semaphore(concurrency)
    results = []
    tasks = []
    for i, email in enumerate(emails):
        tasks.append(check_email_async(
            email, sem,
            probe_catch_all=probe_catch_all, timeout=timeout,
            use_api=use_api, allow_smtp=allow_smtp, use_oracle=use_oracle,
        ))
        if delay > 0 and (i + 1) % concurrency == 0:
            batch = await asyncio.gather(*tasks)
            results.extend(batch)
            tasks = []
            await asyncio.sleep(delay)
    if tasks:
        results.extend(await asyncio.gather(*tasks))
    return results


def load_emails(path: str) -> list:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        return [line.strip() for line in f if line.strip() and not line.lstrip("\ufeff").startswith("#")]


def save_results(results: list, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _print(r: dict) -> None:
    marks = {"valid": "OK ", "likely": "~  ", "unknown": "?? ",
             "invalid": "X  ", "disabled": "D  "}
    mark = marks.get(r["status"], "?? ")
    notes = (" [" + ",".join(r["notes"]) + "]") if r["notes"] else ""
    print(f"{mark}{r['email']} -> {r['status']} ({r['reason']}){notes}")


TEST_EMAILS = [
    "user@gmail.com",
    "nonexistent@randomdomain123.xyz",
    "bad-email",
    "admin@mailinator.com",
    "noreply@example.com",
]


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description="Email hygiene checker (DNS + optional SMTP).")
    ap.add_argument("listfile", nargs="?", help="file with one email per line")
    ap.add_argument("out", nargs="?", default="results.jsonl", help="JSONL output path")
    ap.add_argument("--test", action="store_true", help="run built-in samples")
    ap.add_argument("--smtp", action="store_true",
                    help="enable SMTP verification (needs reachable tcp/25; "
                         "disabled by default because port 25 egress is usually blocked)")
    ap.add_argument("--dns-only", action="store_true",
                    help="no-op, kept for compatibility (DNS-only is now the default)")
    ap.add_argument("--no-api", action="store_true", help="skip free disposable API")
    ap.add_argument("--no-catch-all", action="store_true", help="skip catch-all probe")
    ap.add_argument("--gmail-oracle", action="store_true",
                    help="second pass: self-built Google identifier oracle over "
                         "'likely' gmail candidates (slow, ~15s each, uses local Chromium)")
    ap.add_argument("--oracle-delay", type=float, default=8.0,
                    help="seconds between oracle checks (default 8)")
    ap.add_argument("--oracle-proxies", default=None,
                    help="SOCKS5 proxy list for oracle rotation "
                         "(default: existing pool if present)")
    ap.add_argument("--gmail-deep", action="store_true",
                    help="deep classification in the oracle pass: identifier + "
                         "ONE dummy-password submit -> live/disabled/verify "
                          "(~25s/check, never brute-forces)")
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args(argv)

    emails = TEST_EMAILS if (args.test or not args.listfile) else load_emails(args.listfile)
    allow_smtp = args.smtp

    if allow_smtp:
        reachable = preflight_smtp(timeout=min(args.timeout, 6))
        if reachable:
            print("[*] tcp/25 reachable - full verification enabled")
        else:
            print(f"[*] tcp/25 BLOCKED ({_egress['detail']})")
            print("[*] continuing DNS-only: results are 'likely', not confirmed mailboxes")
    else:
        print("[*] mode: DNS-only (pass --smtp to attempt mailbox verification)")

    results = asyncio.run(check_batch(
        emails,
        concurrency=args.concurrency,
        delay=args.delay,
        probe_catch_all=not args.no_catch_all,
        timeout=args.timeout,
        use_api=not args.no_api,
        allow_smtp=allow_smtp,
    ))

    if args.gmail_oracle:
        from gmail_oracle import is_gmail, load_proxies, oracle_batch, oracle_batch_mt
        candidates = [r["email"] for r in results
                      if r["status"] == "likely" and is_gmail(r["email"])]
        if candidates:
            pool = args.oracle_proxies
            if pool is None:
                import os as _os
                default_pool = (r"E:\ilham_yarsi\qoder-trial-claimer\proxies_ok.txt")
                if _os.path.exists(default_pool):
                    pool = default_pool
            proxies = load_proxies(pool) if pool else []
            print(f"[*] oracle pass: {len(candidates)} gmail candidates, "
                  f"{len(proxies)} proxies, {args.oracle_delay}s delay"
                  + (" + DEEP" if args.gmail_deep else ""))
            show = lambda e, v: print(
                f"{'OK ' if v.split(' [')[0] in ('exists', 'live') else ('X  ' if v.split(' [')[0] in ('absent', 'not_exist') else '?? ')}"
                f"{e} -> {v} [gmail_oracle]", flush=True)
            if args.gmail_deep:
                oresults = oracle_batch_mt(
                    candidates, proxies=proxies or None, concurrency=1,
                    delay=args.oracle_delay, headless=False, deep=True,
                    progress=show,
                )
            else:
                oresults = oracle_batch(
                    candidates, proxies=proxies or None,
                    delay=args.oracle_delay, headless=False,
                    progress=show,
                )
            overdict = {o["email"]: o for o in oresults
                        if not o["email"].startswith("__")}
            for r in results:
                if r["email"] in overdict:
                    o = overdict[r["email"]]
                    oc = o["oracle"]
                    r["notes"].append("gmail_oracle")
                    for n in o.get("notes", []):
                        r["notes"].append(str(n)[:90])
                    if oc in ("exists", "live"):
                        r["status"] = "valid"
                        r["valid"] = True
                        r["reason"] = f"gmail_oracle_{oc}"
                    elif oc in ("absent", "not_exist"):
                        r["status"] = "invalid"
                        r["reason"] = f"gmail_oracle_{oc}"
                    elif oc in ("disabled", "verify", "verify_2fa"):
                        r["status"] = "likely"
                        r["reason"] = f"gmail_oracle_{oc}"
                        r["notes"].append("account_exists_unusual_state")
                    else:
                        r["notes"].append(f"gmail_oracle_{oc.splitlines()[0][:90]}")
            stopped = [o for o in oresults if o["email"].startswith("__")]
            if stopped:
                print(f"[*] oracle stopped early: {stopped[0]['oracle']}")
        else:
            print("[*] oracle pass: no 'likely' gmail candidates")

    for r in results:
        _print(r)

    if args.listfile and not args.test:
        save_results(results, args.out)
        counts = {}
        for r in results:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"\n{len(results)} checked ({summary}) -> {args.out}")
    else:
        print(f"\n{len(results)} checked (no file written)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
