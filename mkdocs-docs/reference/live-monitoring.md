# Live Monitoring & Push Ingest

These features bring evidence into a case in real time, as events happen.

---

## Velociraptor Live Monitoring

Stream CLIENT_EVENT artifacts (like Windows Event Log real-time forwarding or EDR telemetry) into a case automatically.

**Set up:** Settings → Velociraptor → Live Monitoring.

- Add a monitor for a specific client+artifact, or use **⚡ Auto-monitor configured events** to pick up every artifact already enabled in Velociraptor's Client Monitoring table.
- The server polls for new rows every 30 seconds (configurable via `DFIR_VELO_MONITOR_POLL_S`).
- New rows are ingested automatically → same import pipeline → re-synthesis in background.
- A **🔴 LIVE** badge appears in the toolbar when at least one monitor is active.
- The poll cursor is persisted — a restart resumes without re-ingesting old data.

---

## Push Ingest (Webhook)

Any external tool can POST evidence to a case via a webhook.

```http
POST /cases/<caseId>/push
X-DFIR-Key: <your token>
Content-Type: application/json

{ "source": "MyTool", "events": [...] }
```

Or POST any file the Import button would accept (multipart/form-data).

**Configure:** Settings → General → Push ingest token (or `DFIR_PUSH_TOKEN` in `.env`). The endpoint is disabled until a token is set (returns `403 Disabled`). Per-case tokens are also supported.

!!! warning
    The push endpoint is disabled by default. It requires a token to prevent unauthorised writes to your cases.
