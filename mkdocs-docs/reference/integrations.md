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

#### Time scope

The bundle run form has a **Time scope** control: **All time** (the default), last 24 hours / 7 days / 30 days / 90 days, or a custom UTC start/end range. The window is applied during collection, not after: it's mapped onto each artifact's own date parameters (names vary by artifact — `DateAfter`/`DateBefore`, `StartDate`, …), so fewer rows leave the endpoint and the hunt finishes faster, rather than importing everything and filtering it out afterward.

Relative presets (24h/7d/30d/90d) set a lower bound only, with no upper bound. This is deliberate — a hunt keeps scheduling on clients that check in after launch, and pinning an upper bound at launch time would silently drop activity that happens in between.

Not every artifact exposes a date parameter (Shellbags, SAM, and other state-based artifacts have none); those still collect in full, and the run form's preview says how many and lists them. If the detected mapping for a scoped artifact is wrong, correct it inline in that preview and **Save mapping** — the correction persists on the bundle for future runs. If the server reports no parameter metadata at all, the preview and the resulting hunt job instead say coverage **could not be verified**, which is distinct from "nothing to scope."

The resolved window is recorded on the hunt job and shown on its card. Read it as part of the evidence record: the absence of results outside that window is a **collection boundary**, not an absence of activity.

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
