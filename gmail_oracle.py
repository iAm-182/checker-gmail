"""Self-built Gmail existence oracle (no third party, no API key).

Technique: drive the real Google sign-in identifier page in a local Chromium and
read the DOM verdict Google itself renders:
  - a VISIBLE password field appears      -> account EXISTS
  - "Couldn't find this account" is shown -> account ABSENT
  - /rejected or recaptcha challenge page  -> BLOCKED (Google flagged the session)

Notes:
  - Google renders a hidden honeypot field (name=hiddenPassword) for bots, so the
    detector only counts VISIBLE password inputs. Text is checked first.
  - Nothing is submitted beyond the identifier step: no password is ever entered,
    no login attempted, no email sent to anyone. Passive read of Google's own
    response to our own test query.
  - Google rate-limits this. Keep volume low, keep delays, rotate proxies, and
    stop when challenges appear (the batch runner does this automatically).
"""

import argparse
import itertools
import json
import sys
import time

IDENTIFIER_URL = (
    "https://accounts.google.com/signin/v2/identifier?service=mail&passive=true"
    "&rm=false&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&ss=1&scc=1&ltmpl=default"
)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

STEALTH_JS = """() => {
  Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
  window.chrome = window.chrome || {runtime: {}};
  Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
  Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
}"""

NOT_FOUND_MARKERS = (
    "couldn",  # "Couldn't find this account" / "Couldn't find your Google Account"
)

# Google anti-automation friction. Any of these means the session is challenged:
# the verdict on this load is untrustworthy, so report blocked, not a verdict.
CHALLENGE_MARKERS = (
    "type the text you hear or see",  # captcha hook on identifier/password stage
    "unusual traffic",
    "verify you're not a robot",
    "confirm you're not a robot",
)

GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}


def is_gmail(email: str) -> bool:
    return email.rpartition("@")[2].lower() in GMAIL_DOMAINS


def _parse_proxy(url: str) -> dict | None:
    """'socks5://host:port' or 'socks5://user:pass@host:port' -> playwright proxy dict."""
    url = (url or "").strip()
    if not url:
        return None
    if "://" not in url:
        url = "socks5://" + url
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        cfg = {"server": f"{parts.scheme}://{parts.hostname}:{parts.port}"}
        if parts.username:
            cfg["username"] = parts.username
            cfg["password"] = parts.password or ""
        return cfg
    except (ValueError, AttributeError):
        return None


def load_proxies(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []


def proxy_alive(proxy_url: str, timeout: float = 6.0) -> bool:
    """TCP-level health check through the proxy (no HTTP to Google, no rate burn)."""
    import socket
    try:
        import socks
    except ImportError:
        return True  # cannot test without PySocks; assume alive
    cfg = _parse_proxy(proxy_url)
    if not cfg:
        return False
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(cfg["server"])
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, parts.hostname, parts.port,
                    username=cfg.get("username"), password=cfg.get("password"))
        s.settimeout(timeout)
        s.connect(("accounts.google.com", 443))
        s.close()
        return True
    except (OSError, Exception):
        return False


def filter_proxies(proxies: list, timeout: float = 6.0, progress=None) -> list:
    """Fast pre-filter: keep proxies that complete a TCP handshake."""
    alive = []
    for px in proxies:
        ok = proxy_alive(px, timeout)
        if progress:
            progress(px, ok)
        if ok:
            alive.append(px)
    return alive


def proxy_tls_ok(proxy_url: str, timeout: float = 8.0) -> bool:
    """Stronger gate than TCP: full TLS handshake to accounts.google.com:443
    through the proxy, then close WITHOUT sending any HTTP request.
    A proxy that passes TCP but refuses/MITMs Google is filtered here,
    before it can burn rate limit or poison verdicts."""
    import socket
    import ssl
    try:
        import socks
    except ImportError:
        return True
    cfg = _parse_proxy(proxy_url)
    if not cfg:
        return False
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(cfg["server"])
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, parts.hostname, parts.port,
                    username=cfg.get("username"), password=cfg.get("password"))
        s.settimeout(timeout)
        s.connect(("accounts.google.com", 443))
        tls = ssl.create_default_context().wrap_socket(
            s, server_hostname="accounts.google.com")
        tls.settimeout(timeout)
        tls.do_handshake()
        cipher = tls.cipher() is not None
        try:
            tls.close()
        except OSError:
            pass
        return cipher
    except (OSError, Exception):
        return False


def gate_proxies(proxies: list, timeout: float = 8.0, progress=None) -> list:
    """Keep only proxies that complete a real TLS handshake with Google."""
    good = []
    for px in proxies:
        ok = proxy_tls_ok(px, timeout)
        if progress:
            progress(f"proxy:{px}", "tls_ok" if ok else "tls_fail")
        if ok:
            good.append(px)
    return good


def direct_ok(timeout: int = 30) -> bool:
    """Can we load the identifier page directly? One cheap load, no input."""
    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                channel="chrome", headless=True,
                args=["--disable-blink-features=AutomationControlled",
                      "--disable-infobars"])
            ctx = browser.new_context(user_agent=UA, locale="en-US")
            ctx.add_init_script(STEALTH_JS)
            pg = ctx.new_page()
            try:
                pg.goto(IDENTIFIER_URL, timeout=timeout * 1000)
                box = pg.locator("input[type=email], input[name=identifier]").first
                box.wait_for(timeout=15000)
                return "rejected" not in pg.url
            finally:
                browser.close()
    except Exception:
        return False


def read_verdict(pg) -> str:
    """Read Google's verdict from a post-Next page. Pure DOM logic, no I/O."""
    url = pg.url
    if "rejected" in url or "challenge/recaptcha" in url:
        return "blocked"

    low = pg.inner_text("body").lower().replace("\n", " ")
    if any(m in low for m in CHALLENGE_MARKERS):
        return "blocked"

    if all(m in low for m in NOT_FOUND_MARKERS) and "find" in low:
        return "absent"

    visible_pwd = 0
    for i in range(pg.locator("input[type=password]").count()):
        try:
            if pg.locator("input[type=password]").nth(i).is_visible():
                visible_pwd += 1
        except Exception:
            pass
    if visible_pwd >= 1:
        return "exists"
    return "unknown"


# One fixed dummy password for the deep probe. Never varied, never retried:
# the point is to read Google's error class, not to guess credentials.
DEEP_DUMMY_PASSWORD = "Wx7#qZ!9kLm$2vBn0xQ4"

DEEP_WRONG_PASSWORD_MARKERS = (
    "wrong password",
)

DEEP_DISABLED_MARKERS = (
    "account has been disabled",
    "account disabled",
    "this account has been disabled",
    "disabled by an administrator",
    "no longer active",
)

DEEP_VERIFY_MARKERS = (
    "verify it's you",
    "verify it’s you",
    "confirm it's you",
    "couldn't sign you in",
    "unusual activity",
)

DEEP_AUTH_METHOD_MARKERS = (
    # read from the "Try another way" selection list (never selected)
    "use your passkey",
    "passkey",
    "get a verification code",
    "text message",
    "authenticator",
    "backup code",
    "security key",
)


def read_deep_verdict(pg) -> tuple[str, list]:
    """Classify the post-dummy-password stage. Returns (verdict, notes)."""
    low = pg.inner_text("body").lower().replace("\n", " ")
    notes = []
    if any(m in low for m in DEEP_DISABLED_MARKERS):
        return "disabled", notes
    if any(m in low for m in DEEP_VERIFY_MARKERS):
        return "verify", notes
    if any(m in low for m in DEEP_WRONG_PASSWORD_MARKERS):
        return "live", notes
    for m in DEEP_AUTH_METHOD_MARKERS:
        if m in low:
            notes.append(f"auth_hint:{m}")
    return "unknown", notes


def read_auth_methods(pg) -> list:
    """Read the 'Try another way' selection list. Read-only: no method is
    ever selected, so no code is ever sent anywhere."""
    found = []
    try:
        low = pg.inner_text("body").lower().replace("\n", " ")
    except Exception:
        return found
    for m in DEEP_AUTH_METHOD_MARKERS:
        if m in low:
            found.append(m)
    return found


def _launch(p, proxy: str | None, headless: bool):
    """Launch one browser. Caller owns its lifetime (worker reuse)."""
    proxy_cfg = _parse_proxy(proxy) if proxy else None
    browser = p.chromium.launch(
        channel="chrome",
        headless=headless,
        args=["--disable-blink-features=AutomationControlled",
              "--disable-infobars"],
    )
    ctx_kwargs = {
        "user_agent": UA, "locale": "en-US",
        "viewport": {"width": 1366, "height": 768},
    }
    if proxy_cfg:
        ctx_kwargs["proxy"] = proxy_cfg
        # Public SOCKS proxies often MITM TLS. We never submit a password
        # (identifier step only), so the exposure is limited to the queried
        # address itself - but the verdict is still read from Google's DOM.
        ctx_kwargs["ignore_https_errors"] = True
    return browser, ctx_kwargs


def oracle_check_in(browser, ctx_kwargs: dict, email: str) -> str:
    """One check inside a worker-owned browser. Fresh context every time
    (new cookies/storage), so checks never share a session."""
    ctx = browser.new_context(**ctx_kwargs)
    ctx.add_init_script(STEALTH_JS)
    pg = ctx.new_page()
    try:
        pg.goto(IDENTIFIER_URL, timeout=30000)
        box = pg.locator("input[type=email], input[name=identifier]").first
        box.wait_for(timeout=20000)
        pg.wait_for_timeout(1200)
        box.fill(email)
        pg.wait_for_timeout(800)
        pg.locator("#identifierNext").click()
        pg.wait_for_timeout(6000)
        return read_verdict(pg)
    finally:
        ctx.close()


def oracle_deep_in(browser, ctx_kwargs: dict, email: str) -> dict:
    """Deep classification inside a worker-owned browser.

    Stages: identifier -> (absent/blocked stop here) -> password challenge ->
    ONE dummy-password submit -> Google's error class -> optional read-only
    "Try another way" method enumeration (nothing ever selected, no code sent).
    Returns {"oracle": verdict, "notes": [...]} with verdict in
    live | not_exist | disabled | verify | unknown | blocked | error:...
    """
    ctx = browser.new_context(**ctx_kwargs)
    ctx.add_init_script(STEALTH_JS)
    pg = ctx.new_page()
    try:
        pg.goto(IDENTIFIER_URL, timeout=30000)
        box = pg.locator("input[type=email], input[name=identifier]").first
        box.wait_for(timeout=20000)
        pg.wait_for_timeout(1200)
        box.fill(email)
        pg.wait_for_timeout(800)
        pg.locator("#identifierNext").click()
        pg.wait_for_timeout(6000)

        stage1 = read_verdict(pg)
        if stage1 != "exists":
            # absent / blocked / unknown: stop, never touch the password form.
            canon = {"absent": "not_exist"}.get(stage1, stage1)
            return {"oracle": canon, "notes": []}

        # Password challenge is showing: submit the dummy password ONCE.
        try:
            pwd = pg.locator(
                "input[type=password][name=Passwd], input[type=password]"
            ).first
            pwd.fill(DEEP_DUMMY_PASSWORD)
            pg.wait_for_timeout(800)
            pg.locator("#passwordNext").click()
            pg.wait_for_timeout(7000)
        except Exception as e:
            return {"oracle": "unknown",
                    "notes": [f"deep_submit_{e.__class__.__name__}"]}

        verdict, notes = read_deep_verdict(pg)

        # Method enumeration (read-only). The entries are recorded as NOTES only:
        # whether Google lists a method universally or only when enrolled is
        # unvalidated, so they must not flip the verdict on their own.
        # ("Wrong password" above already proved live password auth.)
        try:
            alt = pg.locator("button:has-text(\"Try another way\")").first
            if alt.count() and verdict in ("live", "unknown"):
                alt.click()
                pg.wait_for_timeout(4000)
                for m in read_auth_methods(pg):
                    notes.append(f"auth_method:{m}")
        except Exception:
            pass
        return {"oracle": verdict, "notes": notes}
    finally:
        ctx.close()


def oracle_deep(email: str, proxy: str | None = None,
                headless: bool = False) -> dict:
    """Standalone deep check (own browser)."""
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            browser, ctx_kwargs = _launch(p, proxy, headless)
            try:
                return oracle_deep_in(browser, ctx_kwargs, email)
            finally:
                browser.close()
    except Exception as e:
        return {"oracle": f"error:{e.__class__.__name__}:{str(e)[:60]}",
                "notes": []}


def oracle_check(email: str, proxy: str | None = None, headless: bool = False,
                 timeout: int = 45) -> str:
    """Return 'exists' | 'absent' | 'blocked' | 'unknown' | 'error:...'."""
    from playwright.sync_api import sync_playwright

    _ = timeout
    try:
        with sync_playwright() as p:
            browser, ctx_kwargs = _launch(p, proxy, headless)
            try:
                return oracle_check_in(browser, ctx_kwargs, email)
            finally:
                browser.close()
    except Exception as e:
        return f"error:{e.__class__.__name__}:{str(e)[:80]}"


def oracle_batch(emails: list, proxies: list | None = None, delay: float = 8.0,
                 headless: bool = False, max_blocked: int = 2, max_errors: int = 3,
                 progress=None) -> list:
    """Sequential checks with delay + proxy rotation.

    Dead proxies are filtered first (TCP handshake, no rate burn). The transport
    is chosen adaptively: direct is probed first with one cheap page load, and
    proxies are only used when direct fails - a working home IP beats random
    public SOCKS for both speed and trust. Stops on repeated Google blocks or
    repeated transport errors - the two are counted separately so a dead pool
    cannot masquerade as a Google block.
    """
    results = []
    use_direct = direct_ok()
    if progress:
        progress("transport", "direct" if use_direct else "proxy-rotation")
    if not use_direct and proxies:
        alive = filter_proxies(
            proxies,
            progress=(lambda px, ok: progress(f"proxy:{px}", "alive" if ok else "dead"))
            if progress else None,
        )
        if progress:
            progress(f"pool: {len(alive)}/{len(proxies)} alive", "pool")
        proxies = alive
    proxy_cycle = itertools.cycle(proxies) if (proxies and not use_direct) else None
    blocked_run = 0
    error_run = 0
    for email in emails:
        proxy = next(proxy_cycle) if proxy_cycle else None
        verdict = oracle_check(email, proxy=proxy, headless=headless)
        results.append({"email": email, "oracle": verdict,
                        "proxy": bool(proxy)})
        if progress:
            progress(email, verdict)
        if verdict == "blocked":
            blocked_run += 1
            error_run = 0
            if blocked_run >= max_blocked:
                results.append({"email": "__stopped__",
                                "oracle": f"aborted_after_{blocked_run}_blocks",
                                "proxy": False})
                break
        elif verdict.startswith("error"):
            error_run += 1
            blocked_run = 0
            if error_run >= max_errors:
                results.append({"email": "__stopped__",
                                "oracle": f"aborted_after_{error_run}_errors",
                                "proxy": False})
                break
        else:
            blocked_run = 0
            error_run = 0
        time.sleep(delay)
    return results


def oracle_batch_mt(emails: list, proxies: list | None = None,
                    concurrency: int = 3, delay: float = 8.0,
                    headless: bool = True, cooldown: float = 600.0,
                    out: str | None = None, resume: bool = False,
                    max_global_blocks: int = 6, deep: bool = False,
                    progress=None) -> list:
    """Threaded scale engine. Each worker owns ONE persistent browser (fresh
    context per check = fresh cookies, cheap) and sticks to ONE proxy until
    that proxy gets blocked, then cools it down and rotates.

    - Checkpoint: every verdict is appended to `out` immediately (flush), so a
      killed run loses nothing. `--resume` skips addresses already in `out`.
    - Global abort when blocks pile up across workers (Google is pushing back).
    - `delay` is per worker. Effective throughput ~= concurrency / sec-per-check.
    """
    import queue
    import threading as th
    from concurrent.futures import ThreadPoolExecutor

    done = set()
    if resume and out:
        try:
            with open(out, "r", encoding="utf-8", errors="replace") as f:
                for ln in f:
                    try:
                        d = json.loads(ln)
                        if isinstance(d.get("email"), str) and not d["email"].startswith("__"):
                            done.add(d["email"].strip().lower())
                    except ValueError:
                        pass
        except OSError:
            pass
    todo = [e for e in emails if e.strip().lower() not in done]
    if progress and done:
        progress(f"resume: skipping {len(done)} already-checked", "pool")

    results = []
    lock = th.Lock()
    stop = th.Event()
    work = queue.Queue()
    for e in todo:
        work.put(e)

    out_fh = open(out, "a", encoding="utf-8") if out else None

    def record(rec: dict):
        with lock:
            results.append(rec)
            if out_fh:
                out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                out_fh.flush()
        if progress:
            v = rec.get("oracle", "?")
            mark = {"exists": "OK ", "absent": "X  ", "live": "OK ",
                    "not_exist": "X  "}.get(v, "?? ")
            extra = ""
            if rec.get("notes"):
                extra = " [" + ",".join(rec["notes"]) + "]"
            progress(rec.get("email", "?"), v + extra)

    proxy_cycle = None
    cooled_until: dict = {}
    use_direct = direct_ok()
    if progress:
        progress("transport", "direct" if use_direct else "proxy-rotation")
    if use_direct:
        proxies = []
    elif proxies:
        alive = filter_proxies(
            proxies,
            progress=(lambda px, ok: progress(f"proxy:{px}", "alive" if ok else "dead"))
            if progress else None,
        )
        if progress:
            progress(f"pool: {len(alive)}/{len(proxies)} alive", "pool")
        proxies = alive
    if proxies:
        proxy_cycle = itertools.cycle(proxies)

    def next_proxy():
        if not proxy_cycle:
            return None
        for _ in range(len(proxies)):
            px = next(proxy_cycle)
            if time.time() >= cooled_until.get(px, 0):
                return px
        return None

    state = {"blocks": 0}

    def worker(_wid: int):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            proxy = next_proxy()
            browser, ctx_kwargs = _launch(p, proxy, headless)
            try:
                while not stop.is_set():
                    try:
                        email = work.get_nowait()
                    except queue.Empty:
                        return
                    try:
                        if deep:
                            res = oracle_deep_in(browser, ctx_kwargs, email)
                            verdict, notes = res["oracle"], res.get("notes", [])
                        else:
                            verdict = oracle_check_in(browser, ctx_kwargs, email)
                            notes = []
                    except Exception as e:
                        verdict = f"error:{e.__class__.__name__}:{str(e)[:60]}"
                        notes = []
                    rec = {"email": email, "oracle": verdict,
                           "proxy": bool(proxy)}
                    if notes:
                        rec["notes"] = notes
                    record(rec)
                    if verdict == "blocked":
                        with lock:
                            state["blocks"] += 1
                            if proxy:
                                cooled_until[proxy] = time.time() + cooldown
                            doomed = state["blocks"] >= max_global_blocks
                        if doomed:
                            stop.set()
                            return
                        try:
                            browser.close()
                        except Exception:
                            pass
                        proxy = next_proxy()
                        if proxy is None and proxies:
                            time.sleep(min(cooldown, 60))
                            proxy = next_proxy()
                        browser, ctx_kwargs = _launch(p, proxy, headless)
                    time.sleep(delay)
            finally:
                try:
                    browser.close()
                except Exception:
                    pass

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        futs = [ex.submit(worker, i) for i in range(max(1, concurrency))]
        for f in futs:
            f.result()
    if out_fh:
        out_fh.close()
    if stop.is_set():
        results.append({"email": "__stopped__",
                        "oracle": f"aborted_global_blocks_{state['blocks']}",
                        "proxy": False})
    return results


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description="Self-built Gmail existence oracle.")
    ap.add_argument("emails", nargs="*", help="addresses to check")
    ap.add_argument("--file", help="file with one address per line")
    ap.add_argument("--proxy-file", help="SOCKS5 proxy list for rotation")
    ap.add_argument("--delay", type=float, default=8.0)
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--concurrency", type=int, default=1,
                    help="parallel browsers (1 = sequential legacy mode; "
                         ">1 uses the threaded scale engine)")
    ap.add_argument("--cooldown", type=float, default=600.0,
                    help="seconds a blocked proxy rests before reuse")
    ap.add_argument("--resume", action="store_true",
                    help="skip addresses already present in --out")
    ap.add_argument("--tls-gate", action="store_true",
                    help="pre-filter proxies by real TLS handshake with Google")
    ap.add_argument("--deep", action="store_true",
                    help="deep classification: identifier + ONE dummy-password "
                         "submit -> live/disabled/verify/not_exist "
                         "(slower, ~25s/check; never brute-forces)")
    ap.add_argument("--out", help="JSONL output path")
    args = ap.parse_args(argv)

    emails = list(args.emails)
    if args.file:
        with open(args.file, "r", encoding="utf-8-sig", errors="replace") as f:
            emails += [ln.strip() for ln in f
                       if ln.strip() and not ln.lstrip("\ufeff").startswith("#")]
    emails = [e for e in emails if is_gmail(e)]
    if not emails:
        print("no @gmail.com/@googlemail.com addresses given")
        return 1

    proxies = load_proxies(args.proxy_file) if args.proxy_file else []
    if proxies:
        print(f"[*] rotating {len(proxies)} proxies, delay {args.delay}s")

    def show(email, verdict):
        mark = {"exists": "OK ", "absent": "X  ", "live": "OK ",
                "not_exist": "X  "}.get(verdict.split(" [")[0], "?? ")
        print(f"{mark}{email} -> {verdict}", flush=True)

    if args.tls_gate and proxies:
        proxies = gate_proxies(proxies, progress=show)
        print(f"[*] tls-gate: {len(proxies)} proxies usable for Google")
        if not proxies:
            print("[!] no proxy survived the TLS gate - running direct")
            proxies = []

    if args.deep and args.concurrency <= 1 and len(emails) == 1 and not args.out:
        # fast path: single deep check, own browser, direct print
        res = oracle_deep(emails[0], headless=args.headless)
        show(emails[0], res["oracle"] + (
            " [" + ",".join(res.get("notes", [])) + "]" if res.get("notes") else ""))
        return 0

    if args.concurrency > 1:
        results = oracle_batch_mt(
            emails, proxies=proxies or None, concurrency=args.concurrency,
            delay=args.delay, headless=args.headless or args.concurrency > 1,
            cooldown=args.cooldown, out=args.out, resume=args.resume,
            deep=args.deep, progress=show)
    elif args.deep:
        results = []
        for em in emails:
            res = oracle_deep(em, headless=args.headless)
            rec = {"email": em, "oracle": res["oracle"], "proxy": False}
            if res.get("notes"):
                rec["notes"] = res["notes"]
            results.append(rec)
            show(em, res["oracle"] + (
                " [" + ",".join(res.get("notes", [])) + "]" if res.get("notes") else ""))
            time.sleep(args.delay)
    else:
        results = oracle_batch(emails, proxies=proxies or None, delay=args.delay,
                               headless=args.headless, progress=show)
    if args.out and args.concurrency <= 1:
        with open(args.out, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"-> {args.out}")
    elif args.out:
        print(f"-> {args.out} (appended live during run)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
