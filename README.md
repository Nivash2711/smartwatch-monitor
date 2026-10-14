# SmartWatch — Website Change Monitor (MVP)

A runnable hackathon MVP using FastAPI, Playwright, SQLite, and APScheduler.

## Features included
- Add public URL, monitor name, interval (15 minutes–24 hours), sensitivity.
- Headless Chromium page rendering, text extraction, and screenshots.
- Store a new version only when normalized text hash changes.
- Basic noise normalization, configurable watch selector, ignore selectors.
- Text diff comparison page, screenshot links, version timeline.
- Email, Telegram, and Discord notifications (optional environment configuration).
- Keyword-only alerts, per-monitor RSS feed, number extraction saved per snapshot.
- Status reporting: `ok`, `error`, `blocked`.
- Per-monitor in-process locking and basic per-domain fetch spacing.

## Run with Docker (recommended)

Requirements: Docker Desktop or Docker Engine + Compose.

```bash
docker compose up --build
```

Open http://localhost:8000

Data persists in the `monitor_data` Docker volume. To stop:

```bash
docker compose down
```

## Run locally

Python 3.11+ recommended.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
playwright install --with-deps chromium
mkdir -p data
uvicorn app:app --reload
```

Open http://localhost:8000.

## Optional notifications

Set environment variables before starting the server, or configure them in your deployment:

- Email: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`
- Telegram: `TELEGRAM_BOT_TOKEN`, then enter the destination chat ID on the form
- Discord: `DISCORD_WEBHOOK_URL`

Never commit tokens or passwords to source control. For a local `.env` file, use a dotenv loader or export variables in your shell; this project intentionally does not load `.env` automatically.

## How to test quickly

1. Create a monitor for a stable public page you are allowed to monitor.
2. Wait for the first snapshot, or click **Check now**.
3. Create a tiny change on a test page you control, then click **Check now** again.
4. Use **History** and **Compare latest** to inspect versions and screenshots.
5. Check the RSS URL at `/api/monitors/{id}/rss`.

## Important design decisions

- HTTP 401/403/429/503 responses are treated as blocked/unavailable states, not content changes.
- A timeout or failed browser navigation is an error, not a page-content change.
- Duplicate content hashes do not create duplicate snapshots.
- Notification dedupe is per monitor, channel, and content hash.
- Sensitivity compares old and new word sequences. Keyword-only mode alerts only when a configured keyword is newly present.
- Common timestamp formats, long hex strings, and several likely ad/cookie selectors are filtered. Site-specific noise should be excluded using the ignore CSS selectors.

## MVP limitations / before public production

This is a prototype, not a hardened multi-tenant service:
- The scheduler and domain limiter are in-process. Multiple server replicas need a shared queue and distributed per-domain rate limiter (e.g. Redis/Celery).
- Browser URL checks reduce SSRF risk but DNS rebinding and browser/network-level edge cases require production egress controls. Run workers in a restricted network.
- No user authentication or authorization is included; do not expose it publicly without adding both.
- `digest_enabled` is stored but daily digest delivery is not implemented yet.
- `track_numbers` stores extracted numeric values per snapshot; chart UI is not included.
- Screenshot storage is only for new normalized text hashes. A screenshot can still differ visually when text is unchanged.
- The CSS visual picker, highlighted pixel-level screenshot diff, browser extension, and AI-generated summaries are not included in this MVP.
- The page's own robots.txt/terms and applicable rate limits should be respected. Avoid monitoring sensitive or access-controlled content.
- Notification delivery is best-effort. A production system should add an outbox/retry table and delivery status.

## API overview
- `GET /api/monitors` — list monitors
- `POST /api/monitors` — create monitor
- `GET /api/monitors/{id}` — details and version history
- `POST /api/monitors/{id}/check` — trigger check
- `PATCH /api/monitors/{id}` — update settings
- `DELETE /api/monitors/{id}` — delete monitor
- `GET /api/monitors/{id}/rss` — RSS feed
- `GET /monitors/{id}/diff` — compare latest two versions
