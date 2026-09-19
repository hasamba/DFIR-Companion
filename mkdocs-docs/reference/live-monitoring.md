# Live Monitoring & Push Ingest

These features bring evidence into a case in real time, as events happen.

---

## Velociraptor Live Monitoring

Stream CLIENT_EVENT artifacts (like Windows Event Log real-time forwarding or EDR telemetry) into a case automatically.

**Set up:** the dashboard's **Fleet Collection** panel → Live Monitoring. Monitors are per case, which is why they are not in Settings.

- Add a monitor for a specific client+artifact, or use **⚡ Auto-monitor configured events** to pick up every artifact already enabled in Velociraptor's Client Monitoring table.
- Starting a monitor **enables the artifact in Velociraptor → Client Monitoring** when it is not there yet, so it appears in Velociraptor's client-events list and clients start collecting it. Velociraptor scopes monitoring by label, not by client, so the entry is fleet-wide even for a single-client monitor. If Velociraptor does not accept it (the API user lacks the permission, or the artifact does not exist on the server), the monitor is not created and the reason is shown.
- The monitor row says **enabled in Velociraptor by the companion** when the companion added the entry. Deleting the last monitor for that artifact (across all cases) removes the entry again; an artifact that was already configured is never touched.
- **Poll now** also re-checks the table: if someone removed the artifact in the Velociraptor GUI, the monitor turns to an error instead of showing a healthy, empty stream. Resume it to re-enable the artifact.
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
