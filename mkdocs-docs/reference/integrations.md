# Integrations

Most integrations are configured in **Settings → Integrations** (or via the Setup Wizard). Each is
optional—removing credentials from `.env` disables it. MCP analysis is the exception: configure the
connection in Claude Code, then allow it in **Settings → All → Tools**.

---

## MCP Analysis

Connect Claude Code to an external forensic analysis environment, then use plain-English requests
from a case to investigate an evidence file. Companion supports separate evidence delivery by
shared path or SCP and records the transfer in the chain of custody.

See [MCP Analysis](mcp-analysis.md) for the complete setup and recommended
[REMnux](https://github.com/REMnux/remnux-mcp-server) and
[SIFT MCP](https://github.com/AppliedIR/sift-mcp) servers.

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
- Triage bundles (Best Practice / Best Practice - Big Hogs / Super-Timeline Triage / Linux Triage / custom)

### Triage Bundles

Settings → Velociraptor. Four bundles ship built-in — **Best Practice** (the quick-wins detection sweep), **Best Practice - Big Hogs** (the DetectRaptor YARA file and webshell scans, the DetectRaptor MFT keyword scan, and THOR, split out because they all walk the whole disk and run far longer than the rest of Best Practice; 7200s default timeout, longer than the other bundles' 6000s), **Super-Timeline Triage** (raw host artifacts; results go to the super-timeline only), and **Linux Triage**. Every bundle is editable in place, and **Reset to default** restores a built-in. You can also create and save custom bundles. Run a bundle from the Settings tab — it launches a fleet hunt and auto-imports results. See [Step 3a of the walkthrough](../walkthrough.md) for the run procedure.

#### Third-party tools

Some artifacts need a third-party tool (THOR, the DetectRaptor YARA packs, an extension feed). Velociraptor fetches **every** tool a bundle needs while it compiles the hunt — before any client is contacted — so one tool it cannot obtain aborts the whole run and returns no hunt id at all.

The pre-flight checks each tool against the server's own tool inventory and reports two different problems:

- **A tool with no usable download URL** — the `todo.…` placeholder that licensed tools ship with. Its artifact is dropped from the run and named, so the rest of the bundle still collects.
- **A tool the server holds no file for yet**, even though its URL looks fine. Nothing is dropped for this — on a server with internet access those download on first use — but the tools are listed on the bundle card, and if the hunt then refuses to start, the error names them as the likeliest cause. This is the usual failure on an air-gapped or proxied server: upload the file under **Server Artifacts → Tools** in the Velociraptor GUI, or remove the artifact that needs it from the bundle.

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

---

## Jira

File a **finding** as a Jira issue. Works with Jira Cloud (email + API token) and Server / Data Center (username + password).

- Severity maps to the issue priority (critical → Highest, high → High, medium → Medium, low → Low)
- Every issue is labelled `dfir-companion` and the case ID, and links to the **browse page**, not the REST API
- **Re-push:** updates the issue it created (by saved issue key) instead of filing a duplicate

Findings panel → the **Jira** chip on a finding row. Select several findings and use **🎫 Push to Jira** in the bulk bar to file them in one call; a finding Jira refuses is reported and the rest still go.

**Configure:** `DFIR_JIRA_URL`, `DFIR_JIRA_USER`, `DFIR_JIRA_TOKEN` (all three required), plus optional `DFIR_JIRA_PROJECT_KEY` and `DFIR_JIRA_ISSUE_TYPE` defaults. The buttons stay hidden until it is configured.

---

## ServiceNow

Open a **finding** as a ServiceNow incident.

- Severity maps to urgency and impact (critical/high → 1, medium → 2, low → 3)
- Caller, category and subcategory fall back to the configured defaults
- **Re-push:** updates the incident it opened (by saved sys_id) instead of opening a duplicate

Findings panel → the **SNow** chip on a finding row, or **🎫 Push to ServiceNow** in the bulk bar for the whole selection.

**Configure:** `DFIR_SERVICENOW_URL`, `DFIR_SERVICENOW_USER`, `DFIR_SERVICENOW_PASSWORD` (all three required), plus optional `DFIR_SERVICENOW_CALLER`, `DFIR_SERVICENOW_CATEGORY` and `DFIR_SERVICENOW_SUBCATEGORY` defaults. The buttons stay hidden until it is configured.

---

## War-Room Slash-Command Bot

Two-way Slack / Teams / Telegram: run `/dfir findings`, `/dfir iocs malicious` or `/dfir ask <question>` from the incident channel. Needs an inbound URL (a tunnel) rather than just outbound access — see [War-Room Slash-Command Bot](war-room-bot.md).
