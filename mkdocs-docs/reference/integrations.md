# Integrations

All integrations are configured in **Settings → Integrations** (or via the Setup Wizard). Each is optional — removing credentials from `.env` disables the integration.

---

## Velociraptor

Run fleet hunts, collect artifacts, and stream live monitoring events into cases.

**Configure:** Settings → Velociraptor → set the API config file path. Click **Reconnect** to apply without restarting.

### Capabilities

- Browse available server artifacts
- Run hunt bundles (preset collections of artifacts)
- Custom VQL hunts from the dashboard
- Per-hunt auto-collect (results import automatically after `DFIR_VELO_HUNT_WAIT_MIN`)
- Live CLIENT_EVENT monitoring (see [Live Monitoring](live-monitoring.md))
- Triage bundles (Fast Triage / Full Triage / custom)

### Triage Bundles

Settings → Velociraptor → Bundles. Built-in bundles include **Fast Triage** (quick artifact set) and **Full Triage** (comprehensive). You can create and save custom bundles. Run a bundle from the Settings tab — it launches a fleet hunt and auto-imports results.

---

## DFIR-IRIS

**Push:** Export findings, timeline, and IOCs from a Companion case into an IRIS case. The push dialog
shows the case name it will target — defaulting to `<case id> — <friendly name>` — and lets you type a
different one; your choice is remembered so later pushes keep hitting the same IRIS case instead of
reverting to the default.

**Pull/Import:** Import an existing IRIS case (assets, IOCs, timeline) into a Companion case. Toolbar → Import case → From DFIR-IRIS.

**Configure:** Settings → Integrations → DFIR-IRIS (URL + API key). Reconnect button applies without restart.

---

## Timesketch

Push or download two separate timelines to/from a Timesketch instance, both landing in the same
sketch (so neither clobbers the other):

- **Forensic Timeline export** — the curated, detections-focused timeline
- **Super Timeline export** — the full super-timeline (forensic timeline + raw host-triage artifacts),
  for collaborative analysis over everything that was imported, not just what synthesis flagged

**Configure:** Settings → Integrations → Timesketch. Reconnect without restart after saving credentials.

Command-line: `npm run timesketch:push -- <caseId>`

---

## Notion

Export a case to a Notion page.

- **New page:** created in your Notion database or as a child of a parent page
- **Re-export:** updates the managed content block on the same page without touching anything you wrote outside it

Toolbar → Export → Export to Notion.

---

## ClickUp

Push the Response Playbook as tasks to a ClickUp list.

- Task status maps to the list's real custom statuses
- Priority maps to ClickUp priority levels
- **Re-push:** updates existing tasks (by saved task ID) instead of duplicating

Toolbar → Export → Push playbook to ClickUp.
