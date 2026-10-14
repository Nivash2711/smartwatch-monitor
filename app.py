import asyncio
import hashlib
import ipaddress
import json
import os
import re
import smtplib
import socket
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, HttpUrl
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

DB_PATH = Path(os.getenv("DATABASE_PATH", "./data/monitor.db"))
SNAPSHOT_DIR = Path(os.getenv("SNAPSHOT_DIR", "./data/snapshots"))
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

scheduler = AsyncIOScheduler()
check_locks: dict[int, asyncio.Lock] = {}
domain_last_fetch: dict[str, float] = {}
MIN_DOMAIN_GAP_SECONDS = 5
MAX_PAGE_BYTES = 5_000_000
BROWSER_TIMEOUT_MS = 30_000


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS monitors (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          url TEXT NOT NULL,
          interval_minutes INTEGER NOT NULL,
          sensitivity REAL NOT NULL DEFAULT 0.03,
          watch_selector TEXT NOT NULL DEFAULT '',
          ignore_selectors TEXT NOT NULL DEFAULT '',
          keywords TEXT NOT NULL DEFAULT '',
          track_numbers INTEGER NOT NULL DEFAULT 0,
          email TEXT NOT NULL DEFAULT '',
          telegram_chat_id TEXT NOT NULL DEFAULT '',
          digest_enabled INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1,
          status TEXT NOT NULL DEFAULT 'pending',
          last_checked TEXT,
          last_changed TEXT,
          last_error TEXT,
          last_hash TEXT,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS snapshots (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
          content_hash TEXT NOT NULL,
          text_content TEXT NOT NULL,
          screenshot_path TEXT NOT NULL,
          created_at TEXT NOT NULL,
          change_summary TEXT NOT NULL DEFAULT '',
          numbers_json TEXT NOT NULL DEFAULT '{}',
          UNIQUE(monitor_id, content_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_monitor_created
          ON snapshots(monitor_id, created_at DESC);
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
          event_key TEXT NOT NULL,
          kind TEXT NOT NULL,
          message TEXT NOT NULL,
          created_at TEXT NOT NULL,
          UNIQUE(monitor_id, event_key)
        );
        CREATE TABLE IF NOT EXISTS notification_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
          snapshot_id INTEGER,
          channel TEXT NOT NULL,
          dedupe_key TEXT NOT NULL,
          sent_at TEXT NOT NULL,
          UNIQUE(monitor_id, channel, dedupe_key)
        );
        """)


class MonitorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=8, max_length=2048)
    interval_minutes: int = Field(default=60, ge=15, le=1440)
    sensitivity: float = Field(default=0.03, ge=0.0, le=1.0)
    watch_selector: str = Field(default="", max_length=500)
    ignore_selectors: str = Field(default="", max_length=2000)
    keywords: str = Field(default="", max_length=1000)
    track_numbers: bool = False
    email: str = Field(default="", max_length=320)
    telegram_chat_id: str = Field(default="", max_length=100)
    digest_enabled: bool = False


def resolve_public_url(url: str) -> tuple[str, str]:
    """Basic SSRF guard: only public HTTP(S) URLs; repeated for browser subrequests too."""
    try:
        p = urlparse(url.strip())
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Only public http:// and https:// URLs are supported.")
        if p.username or p.password:
            raise ValueError("URLs containing usernames or passwords are not allowed.")
        host = p.hostname.rstrip(".").lower()
        if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local"):
            raise ValueError("Local/private hosts are not allowed.")
        try:
            infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise ValueError("The hostname could not be resolved.")
        ips = {ipaddress.ip_address(x[4][0].split("%")[0]) for x in infos}
        if not ips:
            raise ValueError("The hostname did not resolve.")
        for ip in ips:
            if not ip.is_global:
                raise ValueError("Private, loopback, link-local, and reserved IP addresses are not allowed.")
        clean = urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))
        return clean, host
    except ValueError:
        raise
    except Exception:
        raise ValueError("Invalid URL.")


def normalize_text(text: str) -> str:
    # Remove common high-noise values while preserving meaningful text.
    text = text.replace("\u00a0", " ")
    text = re.sub(r"\b\d{1,2}:\d{2}(?::\d{2})?\b", " ", text)  # clock times
    text = re.sub(r"\b\d{4}-\d{2}-\d{2}(?:[T ][0-9:.Z+-]+)?\b", " ", text)  # timestamps
    text = re.sub(r"\b(?:session|request|trace)[-_ ]?(?:id)?[:= ]+[A-Za-z0-9_-]{8,}\b", " ", text, flags=re.I)
    text = re.sub(r"\b[0-9a-f]{16,}\b", " ", text, flags=re.I)  # random hashes/tokens
    text = re.sub(r"\s+", " ", text).strip()
    return text


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def get_monitor(monitor_id: int):
    with db() as c:
        row = c.execute("SELECT * FROM monitors WHERE id=?", (monitor_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Monitor not found")
    return dict(row)


def safe_snapshot_path(monitor_id: int, digest: str) -> Path:
    return SNAPSHOT_DIR / f"monitor_{monitor_id}_{digest[:20]}.png"


def extract_numbers(text: str):
    values = re.findall(r"(?<!\w)(?:[$€£₹]\s*)?-?\d[\d,]*(?:\.\d+)?%?(?!\w)", text)
    counts = {}
    for v in values:
        counts[v.strip()] = counts.get(v.strip(), 0) + 1
    return counts


async def wait_for_domain(host: str):
    # Process-local throttle. For multi-worker deployments, replace with Redis distributed limiter.
    gap = MIN_DOMAIN_GAP_SECONDS - (time.monotonic() - domain_last_fetch.get(host, 0))
    if gap > 0:
        await asyncio.sleep(gap)
    domain_last_fetch[host] = time.monotonic()


async def capture_page(monitor: dict):
    url, host = resolve_public_url(monitor["url"])
    await wait_for_domain(host)
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        context = await browser.new_context(
            viewport={"width": 1365, "height": 900},
            device_scale_factor=1,
            ignore_https_errors=False,
        )
        page = await context.new_page()
        page.set_default_timeout(BROWSER_TIMEOUT_MS)

        async def guard_route(route):
            request_url = route.request.url
            try:
                parsed = urlparse(request_url)
                if parsed.scheme not in ("http", "https"):
                    await route.abort()
                    return
                resolve_public_url(request_url)
                await route.continue_()
            except Exception:
                await route.abort()

        await page.route("**/*", guard_route)
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=BROWSER_TIMEOUT_MS)
            status_code = response.status if response else 0
            # HTTP failures are operational states, never content snapshots.
            if status_code in (401, 403, 404, 407, 429):
                return {"error": f"blocked_or_unavailable_http_{status_code}", "status": "blocked"}
            if status_code >= 500:
                return {"error": f"origin_server_error_http_{status_code}", "status": "error"}
            if status_code >= 400:
                return {"error": f"http_error_{status_code}", "status": "error"}
            # Let common client-side content settle without waiting forever for analytics.
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightTimeoutError:
                pass

            # Remove common volatile/irrelevant areas, but only in the page DOM used for extraction.
            await page.evaluate("""() => {
              const selectors = [
                'script','style','noscript','svg','canvas',
                '[aria-live="polite"]','[aria-live="assertive"]',
                'iframe[src*="ads"]','[class*="advert"]','[id*="advert"]',
                '[class*="cookie-banner"]','[id*="cookie-banner"]'
              ];
              for (const s of selectors) {
                try { document.querySelectorAll(s).forEach(e => e.remove()); } catch {}
              }
            }""")

            ignore = [x.strip() for x in (monitor.get("ignore_selectors") or "").splitlines() if x.strip()]
            if ignore:
                await page.evaluate("""(selectors) => {
                  for (const s of selectors) {
                    try { document.querySelectorAll(s).forEach(e => e.remove()); } catch {}
                  }
                }""", ignore)

            selector = (monitor.get("watch_selector") or "").strip()
            if selector:
                try:
                    target = page.locator(selector).first
                    if await target.count() == 0:
                        return {"error": f"watch_selector_not_found: {selector}", "status": "error"}
                    text = await target.inner_text(timeout=5000)
                except Exception as e:
                    return {"error": f"invalid_or_unreadable_selector: {str(e)[:180]}", "status": "error"}
            else:
                text = await page.locator("body").inner_text(timeout=5000)

            text = normalize_text(text[:MAX_PAGE_BYTES])
            if not text:
                return {"error": "empty_page_text", "status": "error"}

            # CAPTCHA / bot-check pages often return HTTP 200. Detect common markers
            # and classify them as blocked rather than saving them as a content change.
            captcha_markers = (
                "verify you are human", "verify you're human", "are you human",
                "captcha", "cf-challenge", "checking your browser", "unusual traffic",
                "complete the security check", "robot check"
            )
            if any(marker in text.lower() for marker in captcha_markers):
                return {"error": "captcha_or_bot_challenge_detected", "status": "blocked"}

            digest = text_hash(text)
            shot_path = safe_snapshot_path(monitor["id"], digest)
            # Screenshot only needs to be written for a new content hash.
            with db() as c:
                existing = c.execute(
                    "SELECT id FROM snapshots WHERE monitor_id=? AND content_hash=?",
                    (monitor["id"], digest)
                ).fetchone()
            if not existing and not shot_path.exists():
                await page.screenshot(path=str(shot_path), full_page=True, animations="disabled", timeout=10000)

            title = await page.title()
            return {
                "status": "ok", "http_status": status_code, "text": text, "hash": digest,
                "screenshot_path": str(shot_path), "title": title[:300],
                "numbers": extract_numbers(text)
            }
        except PlaywrightTimeoutError:
            return {"error": "page_timeout", "status": "error"}
        except Exception as e:
            return {"error": f"fetch_failed: {str(e)[:240]}", "status": "error"}
        finally:
            await context.close()
            await browser.close()


def summarize_change(old_text: str, new_text: str, max_items=8) -> str:
    import difflib
    old_lines = old_text.splitlines() or [old_text]
    new_lines = new_text.splitlines() or [new_text]
    diff = list(difflib.unified_diff(old_lines, new_lines, lineterm=""))
    meaningful = [x for x in diff if x.startswith(("+", "-")) and not x.startswith(("+++", "---"))]
    if not meaningful:
        return "Page content changed."
    return " ".join(x[:180] for x in meaningful[:max_items])[:1200]


def should_notify(monitor: dict, old_text: str, new_text: str, summary: str) -> tuple[bool, str]:
    keywords = [x.strip().lower() for x in (monitor.get("keywords") or "").split(",") if x.strip()]
    if keywords:
        old_lower, new_lower = old_text.lower(), new_text.lower()
        matched = [k for k in keywords if k in new_lower and k not in old_lower]
        if not matched:
            return False, "No configured keyword appeared for the first time."
        return True, "Keyword match: " + ", ".join(matched)
    # Sensitivity is a minimum fraction of changed words. Default 3%; zero means any change.
    old_words = old_text.split()
    new_words = new_text.split()
    import difflib
    ratio = difflib.SequenceMatcher(a=old_words, b=new_words, autojunk=False).ratio()
    changed_fraction = 1 - ratio
    threshold = float(monitor.get("sensitivity") or 0)
    if changed_fraction < threshold:
        return False, f"Change below sensitivity threshold ({changed_fraction:.1%} < {threshold:.1%})."
    return True, summary


def send_email(to_addr: str, subject: str, body: str):
    host = os.getenv("SMTP_HOST", "").strip()
    if not host or not to_addr:
        return False
    msg = EmailMessage()
    msg["From"] = os.getenv("SMTP_FROM") or os.getenv("SMTP_USER") or "monitor@localhost"
    msg["To"] = to_addr
    msg["Subject"] = subject[:180]
    msg.set_content(body)
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as server:
        server.starttls()
        user, password = os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASSWORD", "")
        if user:
            server.login(user, password)
        server.send_message(msg)
    return True


async def send_webhook(url: str, payload: dict):
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(url, json=payload)
        r.raise_for_status()


async def send_notifications(monitor: dict, snapshot_id: int, digest: str, summary: str):
    dedupe_key = digest
    diff_url = f"{APP_BASE_URL}/monitors/{monitor['id']}/diff?from_previous=1"
    body = f"{monitor['name']} changed.\n\n{summary}\n\nCompare versions: {diff_url}"
    channels = []
    if monitor.get("email"):
        channels.append(("email", monitor["email"]))
    if monitor.get("telegram_chat_id") and os.getenv("TELEGRAM_BOT_TOKEN"):
        channels.append(("telegram", monitor["telegram_chat_id"]))
    if os.getenv("DISCORD_WEBHOOK_URL"):
        channels.append(("discord", os.getenv("DISCORD_WEBHOOK_URL")))

    for channel, target in channels:
        with db() as c:
            already = c.execute(
                "SELECT 1 FROM notification_log WHERE monitor_id=? AND channel=? AND dedupe_key=?",
                (monitor["id"], channel, dedupe_key)
            ).fetchone()
        if already:
            continue
        try:
            if channel == "email":
                await asyncio.to_thread(send_email, target, f"Website changed: {monitor['name']}", body)
            elif channel == "telegram":
                token = os.getenv("TELEGRAM_BOT_TOKEN")
                async with httpx.AsyncClient(timeout=10) as client:
                    r = await client.post(
                        f"https://api.telegram.org/bot{token}/sendMessage",
                        json={"chat_id": target, "text": body[:4000], "disable_web_page_preview": True}
                    )
                    r.raise_for_status()
            else:
                await send_webhook(target, {"content": body[:1900]})
            with db() as c:
                c.execute(
                    "INSERT OR IGNORE INTO notification_log(monitor_id,snapshot_id,channel,dedupe_key,sent_at) VALUES(?,?,?,?,?)",
                    (monitor["id"], snapshot_id, channel, dedupe_key, now_iso())
                )
        except Exception as e:
            print(f"Notification failed ({channel}) for monitor {monitor['id']}: {e}")


async def run_check(monitor_id: int):
    lock = check_locks.setdefault(monitor_id, asyncio.Lock())
    if lock.locked():
        return
    async with lock:
        try:
            monitor = get_monitor(monitor_id)
        except HTTPException:
            return
        if not monitor["enabled"]:
            return
        result = await capture_page(monitor)
        checked_at = now_iso()

        if result["status"] != "ok":
            with db() as c:
                c.execute(
                    "UPDATE monitors SET status=?,last_checked=?,last_error=? WHERE id=?",
                    (result["status"], checked_at, result.get("error", "unknown error"), monitor_id)
                )
                c.execute(
                    "INSERT INTO events(monitor_id,event_key,kind,message,created_at) VALUES(?,?,?,?,?)",
                    (monitor_id, f"{result['status']}:{checked_at[:16]}", result["status"],
                     result.get("error", "Check failed"), checked_at)
                )
            return

        digest = result["hash"]
        with db() as c:
            previous = c.execute(
                "SELECT * FROM snapshots WHERE monitor_id=? ORDER BY id DESC LIMIT 1",
                (monitor_id,)
            ).fetchone()
            c.execute(
                "UPDATE monitors SET status='ok',last_checked=?,last_error=NULL WHERE id=?",
                (checked_at, monitor_id)
            )
            if previous and previous["content_hash"] == digest:
                return
            # Avoid duplicate snapshots even if concurrent requests occur.
            existing = c.execute(
                "SELECT * FROM snapshots WHERE monitor_id=? AND content_hash=?",
                (monitor_id, digest)
            ).fetchone()
            if existing:
                c.execute("UPDATE monitors SET last_hash=? WHERE id=?", (digest, monitor_id))
                return

            old_text = previous["text_content"] if previous else ""
            summary = summarize_change(old_text, result["text"]) if previous else "Initial snapshot saved."
            cur = c.execute(
                """INSERT INTO snapshots(monitor_id,content_hash,text_content,screenshot_path,created_at,change_summary,numbers_json)
                   VALUES(?,?,?,?,?,?,?)""",
                (monitor_id, digest, result["text"], result["screenshot_path"], checked_at,
                 summary, json.dumps(result["numbers"]))
            )
            snapshot_id = cur.lastrowid
            c.execute(
                "UPDATE monitors SET last_hash=?,last_changed=? WHERE id=?",
                (digest, checked_at, monitor_id)
            )
            if previous:
                event_key = f"change:{digest}"
                c.execute(
                    "INSERT OR IGNORE INTO events(monitor_id,event_key,kind,message,created_at) VALUES(?,?,?,?,?)",
                    (monitor_id, event_key, "change", summary, checked_at)
                )
        if previous:
            should_send, notification_summary = should_notify(monitor, old_text, result["text"], summary)
            if should_send:
                await send_notifications(monitor, snapshot_id, digest, notification_summary)


async def scheduled_checks():
    with db() as c:
        rows = c.execute("SELECT id FROM monitors WHERE enabled=1").fetchall()
    now = datetime.now(timezone.utc)
    for row in rows:
        m = get_monitor(row["id"])
        last = m.get("last_checked")
        due = True
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                due = (now - last_dt).total_seconds() >= int(m["interval_minutes"]) * 60
            except Exception:
                due = True
        if due:
            asyncio.create_task(run_check(m["id"]))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    scheduler.add_job(scheduled_checks, "interval", seconds=30, id="monitor_scheduler", max_instances=1)
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="SmartWatch Website Monitor", version="1.0.0", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(INDEX_HTML)


@app.get("/api/monitors")
async def list_monitors():
    with db() as c:
        rows = c.execute("""
          SELECT m.*,
            (SELECT COUNT(*) FROM snapshots s WHERE s.monitor_id=m.id) AS version_count
          FROM monitors m ORDER BY m.created_at DESC
        """).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/monitors")
async def create_monitor(payload: MonitorCreate):
    try:
        clean_url, _ = resolve_public_url(payload.url)
    except ValueError as e:
        raise HTTPException(400, str(e))
    with db() as c:
        cur = c.execute("""
          INSERT INTO monitors(name,url,interval_minutes,sensitivity,watch_selector,ignore_selectors,
            keywords,track_numbers,email,telegram_chat_id,digest_enabled,created_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """, (payload.name.strip(), clean_url, payload.interval_minutes, payload.sensitivity,
              payload.watch_selector.strip(), payload.ignore_selectors.strip(), payload.keywords.strip(),
              int(payload.track_numbers), payload.email.strip(), payload.telegram_chat_id.strip(),
              int(payload.digest_enabled), now_iso()))
        monitor_id = cur.lastrowid
    asyncio.create_task(run_check(monitor_id))
    return {"id": monitor_id, "message": "Monitor created; first check started."}


@app.get("/api/monitors/{monitor_id}")
async def monitor_detail(monitor_id: int):
    monitor = get_monitor(monitor_id)
    with db() as c:
        snaps = c.execute(
            "SELECT id,content_hash,created_at,change_summary,numbers_json FROM snapshots WHERE monitor_id=? ORDER BY id DESC",
            (monitor_id,)
        ).fetchall()
        events = c.execute(
            "SELECT kind,message,created_at FROM events WHERE monitor_id=? ORDER BY id DESC LIMIT 50",
            (monitor_id,)
        ).fetchall()
    monitor["snapshots"] = [dict(x) for x in snaps]
    monitor["events"] = [dict(x) for x in events]
    return monitor


@app.post("/api/monitors/{monitor_id}/check")
async def check_now(monitor_id: int):
    get_monitor(monitor_id)
    asyncio.create_task(run_check(monitor_id))
    return {"message": "Check queued."}


@app.patch("/api/monitors/{monitor_id}")
async def update_monitor(monitor_id: int, request: Request):
    get_monitor(monitor_id)
    data = await request.json()
    allowed = {"name", "interval_minutes", "sensitivity", "watch_selector", "ignore_selectors",
               "keywords", "track_numbers", "email", "telegram_chat_id", "digest_enabled", "enabled"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        raise HTTPException(400, "No editable fields supplied.")
    if "interval_minutes" in updates and not 15 <= int(updates["interval_minutes"]) <= 1440:
        raise HTTPException(400, "interval_minutes must be between 15 and 1440.")
    if "sensitivity" in updates and not 0 <= float(updates["sensitivity"]) <= 1:
        raise HTTPException(400, "sensitivity must be between 0 and 1.")
    cols = list(updates)
    vals = [int(updates[k]) if k in ("track_numbers", "digest_enabled", "enabled") else updates[k] for k in cols]
    with db() as c:
        c.execute(f"UPDATE monitors SET {','.join(k+'=?' for k in cols)} WHERE id=?", (*vals, monitor_id))
    return {"message": "Monitor updated."}


@app.delete("/api/monitors/{monitor_id}")
async def delete_monitor(monitor_id: int):
    get_monitor(monitor_id)
    with db() as c:
        c.execute("DELETE FROM monitors WHERE id=?", (monitor_id,))
    for path in SNAPSHOT_DIR.glob(f"monitor_{monitor_id}_*.png"):
        try:
            path.unlink()
        except OSError:
            pass
    return {"message": "Monitor deleted."}


@app.get("/api/monitors/{monitor_id}/snapshots/{snapshot_id}/screenshot")
async def screenshot(monitor_id: int, snapshot_id: int):
    with db() as c:
        row = c.execute("SELECT screenshot_path FROM snapshots WHERE id=? AND monitor_id=?",
                        (snapshot_id, monitor_id)).fetchone()
    if not row:
        raise HTTPException(404, "Snapshot not found")
    path = Path(row["screenshot_path"]).resolve()
    if SNAPSHOT_DIR.resolve() not in path.parents or not path.exists():
        raise HTTPException(404, "Screenshot not found")
    from fastapi.responses import FileResponse
    return FileResponse(path, media_type="image/png", filename=path.name)


@app.get("/monitors/{monitor_id}/diff", response_class=HTMLResponse)
async def diff_page(monitor_id: int, from_previous: int = 1, a: int | None = None, b: int | None = None):
    get_monitor(monitor_id)
    with db() as c:
        rows = c.execute("SELECT * FROM snapshots WHERE monitor_id=? ORDER BY id DESC",
                         (monitor_id,)).fetchall()
    if len(rows) < 2:
        return HTMLResponse("<h2>Not enough versions to compare yet.</h2>")
    if a is not None and b is not None:
        left = next((r for r in rows if r["id"] == a), None)
        right = next((r for r in rows if r["id"] == b), None)
    else:
        left, right = rows[1], rows[0]
    if not left or not right:
        raise HTTPException(404, "Version not found")
    import difflib
    html_diff = difflib.HtmlDiff(wrapcolumn=100).make_table(
        left["text_content"].splitlines(), right["text_content"].splitlines(),
        f"Version {left['id']}", f"Version {right['id']}", context=True, numlines=3
    )
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8">
    <title>Version comparison</title><style>
    body{{font-family:system-ui;margin:24px;color:#182230}} table{{border-collapse:collapse;width:100%;font-size:13px}}
    td,th{{padding:5px;border:1px solid #ddd;vertical-align:top;white-space:pre-wrap}}
    .diff_add{{background:#d9fbe3}} .diff_sub{{background:#ffe0e0}} .diff_chg{{background:#fff0b8}}
    </style></head><body><h1>Version comparison</h1>
    <p>Monitor: {html_escape(get_monitor(monitor_id)['name'])} · {html_escape(left['created_at'])} → {html_escape(right['created_at'])}</p>
    <p><a href="/api/monitors/{monitor_id}/snapshots/{left['id']}/screenshot">Older screenshot</a> ·
    <a href="/api/monitors/{monitor_id}/snapshots/{right['id']}/screenshot">Newer screenshot</a></p>
    {html_diff}</body></html>""")


@app.get("/api/monitors/{monitor_id}/rss")
async def rss_feed(monitor_id: int):
    monitor = get_monitor(monitor_id)
    with db() as c:
        rows = c.execute("SELECT * FROM snapshots WHERE monitor_id=? ORDER BY id DESC LIMIT 30",
                         (monitor_id,)).fetchall()
    items = []
    for r in rows:
        items.append(f"<item><title>{xml_escape(r['change_summary'] or 'Snapshot')}</title>"
                     f"<link>{APP_BASE_URL}/monitors/{monitor_id}/diff</link>"
                     f"<guid>{monitor_id}-{r['id']}</guid><pubDate>{r['created_at']}</pubDate>"
                     f"<description>{xml_escape(r['change_summary'] or '')}</description></item>")
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           f'<rss version="2.0"><channel><title>{xml_escape(monitor["name"])}</title>'
           f'<link>{xml_escape(monitor["url"])}</link><description>Website change history</description>'
           + "".join(items) + '</channel></rss>')
    return PlainTextResponse(xml, media_type="application/rss+xml")


def html_escape(s):
    import html
    return html.escape(str(s), quote=True)


def xml_escape(s):
    import html
    return html.escape(str(s), quote=True)


INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SmartWatch — Website Change Monitor</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:#172033;background:#f4f7fb}
*{box-sizing:border-box}body{margin:0}.wrap{max-width:1180px;margin:auto;padding:24px}
header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:22px}
h1{font-size:28px;margin:0} .muted{color:#667085;font-size:13px}
.grid{display:grid;grid-template-columns:340px 1fr;gap:18px}
.panel,.monitor{background:white;border:1px solid #e2e8f0;border-radius:16px;padding:18px;box-shadow:0 3px 14px #102a4308}
h2{font-size:17px;margin:0 0 14px}label{display:block;font-size:13px;font-weight:650;margin:12px 0 5px}
input,textarea,select{width:100%;border:1px solid #cfd8e3;border-radius:9px;padding:10px;font:inherit;font-size:13px;background:white}
textarea{min-height:60px;resize:vertical}button,.linkbtn{border:0;border-radius:9px;background:#2458d3;color:white;padding:10px 13px;font-weight:650;cursor:pointer;text-decoration:none;display:inline-block;font-size:13px}
button.secondary{background:#edf2ff;color:#2448a8}button.danger{background:#fee2e2;color:#991b1b}
form button{width:100%;margin-top:16px}.monitor{margin-bottom:12px}.mhead{display:flex;justify-content:space-between;gap:10px;align-items:start}
.mname{font-weight:750;font-size:16px;overflow-wrap:anywhere}.url{font-size:12px;color:#667085;overflow-wrap:anywhere;margin:6px 0 12px}
.pill{display:inline-block;border-radius:99px;padding:4px 8px;font-size:11px;font-weight:750;background:#e5e7eb;color:#374151}
.pill.ok{background:#dcfce7;color:#166534}.pill.error{background:#fee2e2;color:#991b1b}.pill.blocked{background:#ffedd5;color:#9a3412}
.stats{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:#667085;margin:10px 0}
.actions{display:flex;gap:7px;flex-wrap:wrap}.empty{padding:50px 15px;text-align:center;color:#667085}
#notice{display:none;padding:10px;border-radius:9px;margin-bottom:12px;background:#e0f2fe;color:#075985;font-size:13px}
@media(max-width:800px){.grid{grid-template-columns:1fr}.wrap{padding:14px}header{align-items:start;flex-direction:column}}
</style></head><body><div class="wrap">
<header><div><h1>◉ SmartWatch</h1><div class="muted">Meaningful website changes, without the noise.</div></div>
<button class="secondary" onclick="loadMonitors()">↻ Refresh</button></header>
<div id="notice"></div>
<div class="grid"><section class="panel"><h2>＋ Watch a page</h2>
<form id="createForm">
<label>Monitor name *</label><input name="name" required placeholder="University admissions page">
<label>Public URL *</label><input name="url" type="url" required placeholder="https://example.com/admissions">
<label>Check interval</label><select name="interval_minutes"><option value="15">Every 15 minutes</option><option value="30">Every 30 minutes</option><option value="60" selected>Every hour</option><option value="180">Every 3 hours</option><option value="360">Every 6 hours</option><option value="720">Every 12 hours</option><option value="1440">Every 24 hours</option></select>
<label>Sensitivity (minimum changed-word fraction)</label><select name="sensitivity"><option value="0">Any change</option><option value="0.01">1% — high</option><option value="0.03" selected>3% — balanced</option><option value="0.1">10% — low noise</option><option value="0.25">25% — major changes only</option></select>
<label>Watch CSS selector (optional)</label><input name="watch_selector" placeholder="main, #results, .price">
<label>Ignore CSS selectors (one per line)</label><textarea name="ignore_selectors" placeholder=".timestamp&#10;.ad-banner&#10;#visitor-counter"></textarea>
<label>Keyword-only alerts (comma-separated, optional)</label><input name="keywords" placeholder="deadline, application open, price">
<label>Alert email (optional; configure SMTP)</label><input name="email" type="email" placeholder="you@example.com">
<label>Telegram chat ID (optional; configure bot token)</label><input name="telegram_chat_id" placeholder="123456789">
<label><input name="track_numbers" type="checkbox" style="width:auto"> Track numbers (stored with each version)</label>
<button type="submit">Create monitor</button>
</form>
<p class="muted">Only monitor public pages you are permitted to access. No logins or stored credentials.</p>
</section>
<section><div id="monitors"><div class="empty">Loading monitors…</div></div></section></div></div>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function notice(msg){const n=document.getElementById('notice');n.textContent=msg;n.style.display='block';setTimeout(()=>n.style.display='none',6000)}
document.getElementById('createForm').addEventListener('submit',async e=>{
 e.preventDefault();const f=e.currentTarget;const d=Object.fromEntries(new FormData(f).entries());
 d.interval_minutes=Number(d.interval_minutes);d.sensitivity=Number(d.sensitivity);d.track_numbers=f.track_numbers.checked;
 try{const r=await fetch('/api/monitors',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
 const j=await r.json();if(!r.ok)throw Error(j.detail||'Could not create monitor');f.reset();notice('Monitor created. Its first check has started.');loadMonitors();}
 catch(err){notice('Error: '+err.message)}
});
async function loadMonitors(){
 try{const r=await fetch('/api/monitors');const ms=await r.json();const root=document.getElementById('monitors');
 if(!ms.length){root.innerHTML='<div class="panel empty">No monitors yet. Add your first public webpage on the left.</div>';return}
 root.innerHTML=ms.map(m=>`<article class="monitor"><div class="mhead"><div><div class="mname">${esc(m.name)}</div><div class="url">${esc(m.url)}</div></div><span class="pill ${esc(m.status)}">${esc((m.status||'pending').toUpperCase())}</span></div>
 <div class="stats"><span>⏱ Every ${m.interval_minutes} min</span><span>▤ ${m.version_count} version(s)</span><span>Checked: ${esc(m.last_checked||'not yet')}</span><span>Changed: ${esc(m.last_changed||'not yet')}</span></div>
 ${m.last_error?`<div class="muted" style="color:#b42318;margin-bottom:10px">${esc(m.last_error)}</div>`:''}
 <div class="actions"><button onclick="checkNow(${m.id})">Check now</button><a class="linkbtn" href="/monitors/${m.id}/diff" target="_blank" style="background:#edf2ff;color:#2448a8">Compare latest</a><a class="linkbtn" href="/api/monitors/${m.id}/rss" target="_blank" style="background:#edf2ff;color:#2448a8">RSS feed</a><button class="secondary" onclick="history(${m.id})">History</button><button class="danger" onclick="removeMonitor(${m.id})">Delete</button></div><div id="history-${m.id}"></div></article>`).join('');
 }catch(e){notice('Could not load monitors: '+e.message)}
}
async function checkNow(id){const r=await fetch(`/api/monitors/${id}/check`,{method:'POST'});const j=await r.json();notice(j.message||'Check queued');setTimeout(loadMonitors,1800)}
async function removeMonitor(id){if(!confirm('Delete this monitor and its saved history?'))return;const r=await fetch(`/api/monitors/${id}`,{method:'DELETE'});if(r.ok){notice('Monitor deleted');loadMonitors()}}
async function history(id){const box=document.getElementById('history-'+id);if(box.dataset.loaded){box.dataset.loaded='';box.innerHTML='';return}
 const r=await fetch(`/api/monitors/${id}`);const m=await r.json();box.dataset.loaded='1';
 box.innerHTML='<h3 style="font-size:14px;margin-top:18px">Version timeline</h3>'+((m.snapshots||[]).map(s=>`<div style="padding:9px 0;border-top:1px solid #edf0f4;font-size:12px"><b>Version ${s.id}</b> · ${esc(s.created_at)}<p>${esc(s.change_summary)}</p><a href="/api/monitors/${id}/snapshots/${s.id}/screenshot" target="_blank">Screenshot</a> · <a href="/monitors/${id}/diff?a=${m.snapshots[m.snapshots.length-1]?.id||s.id}&b=${s.id}" target="_blank">Compare</a></div>`).join(''))||'<p class="muted">No snapshots yet.</p>');
}
loadMonitors();setInterval(loadMonitors,30000);
</script></body></html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
