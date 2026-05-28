# Forensic Screenshot & AI Analysis Tool — Design

**Date:** 2026-05-28
**Status:** Approved (design)

## Problem

During forensic (DFIR) investigations, the investigator reviews many artifacts in
parallel and jumps from lead to lead — finding something, chasing it, discovering a new
lead, chasing that, and losing track of what was already checked. At the end, a precise
summary of everything examined is required, with no finding forgotten. Screenshots and
CSV exports of results are often not captured in the moment. The investigator works
primarily through Velociraptor's web UI (in the Comet browser, Chromium-based), alongside
other web tools (VirusTotal, MITRE ATT&CK, etc.).

The tool must:
1. Continuously capture what the investigator sees in the browser (time-based + on events).
2. Let the investigator later replay where they were.
3. Analyze the screenshots with AI in parallel to understand what was seen and found.
4. Maintain a coherent, deduplicated incident report — viewable live (dynamic) or
   generated at the end (batch), the investigator's choice.

## Goals

- Never lose an artifact or finding; provide an accurate audit trail of the investigation.
- Solve "I don't remember what I already checked" via a persistent, accumulating
  investigation state that *is* the memory.
- Keep raw evidence capture independent of (and more reliable than) AI analysis.
- Support multiple AI providers (Ollama Cloud, OpenRouter, OpenAI, Gemini), configurable.
- Produce a DFIR-grade report: Executive summary, Timeline, Findings, MITRE ATT&CK mapping.

## Non-Goals

- Background-tab capture (only the active visible tab is captured).
- Desktop/OS-wide capture outside the browser.
- Built-in PDF or CASE/UCO export (Markdown/JSON/CSV only for now).

## Architecture

Three components, each with a single clear responsibility.

```
┌─────────────────────┐      HTTP/WebSocket      ┌──────────────────────────┐
│  Chrome Extension   │ ───── localhost ───────► │   Companion (Node/TS)    │
│  (Comet/Chromium)   │   screenshots + metadata │                          │
│ • Service worker    │ ◄──── live updates ───── │  Capture Ingest          │
│   (timer + events)  │     (findings/state)     │  Analysis Pipeline (B)   │
│ • Capture logic     │                          │  AI Provider Layer ──────┼──► Ollama/OpenRouter/
│ • Popup UI          │                          │  Report Generator        │   OpenAI/Gemini
└─────────────────────┘                          │         │                │
┌─────────────────────┐                          │         ▼                │
│  Dashboard (web UI)  │ ◄──── WebSocket ──────── │  Case Folder (disk)      │
└─────────────────────┘                          └──────────────────────────┘
```

### Components

1. **Chrome Extension (Manifest V3)** — captures the active visible tab on a configurable
   timer plus significant events, attaches metadata, sends to the companion over localhost.
   Popup UI controls: start/stop investigation, select case, choose live/batch mode,
   tune capture interval and dedup threshold, show connection + active-AI-provider status.

2. **Companion (Node.js / TypeScript, localhost server)** — the core. Ingests captures,
   runs the accumulating-state analysis pipeline, manages AI providers, generates reports,
   and persists everything to the case folder. Serves the dashboard.

3. **Dashboard (web UI served by the companion)** — displays a live timeline, findings,
   and an updating report over WebSocket. This is where the investigator "goes back to see
   where they were."

### Data flow

Screenshot → ingest (raw evidence written to disk immediately) → analysis queue →
AI updates the investigation state → state pushed to dashboard and persisted.

**Key separation:** raw evidence persistence does NOT depend on AI. If analysis fails, the
screenshot and metadata are already safe on disk. The evidence path is deterministic and
must not fail; the analysis path is best-effort and may retry.

## Capture Pipeline (Extension)

- **Capture mechanism:** `chrome.tabs.captureVisibleTab` captures the active tab — exactly
  what the investigator sees (Velociraptor, VirusTotal, etc.).
- **Triggers:** configurable timer (default 10s) + events: `tabs.onActivated` (tab switch),
  `webNavigation.onCommitted` (navigation), and clicks / text entry via a content script
  that notifies the service worker.
- **Deduplication:** a perceptual hash (not byte hash — robust to cursor/animation jitter)
  is computed per screenshot. If the screen is near-identical to the previous one (hash
  distance below a tunable threshold), the screenshot is still **saved as evidence** but
  marked `duplicate` and **not sent for analysis**. Prevents N AI calls while quietly
  reading one screen. Threshold ships with a default and is tunable in the popup.
- **Metadata per capture:**
  ```
  { caseId, timestamp, url, tabTitle,
    triggerType: "timer" | "navigation" | "tab_switch" | "click",
    perceptualHash, isDuplicate, sequenceNumber }
  ```
  URL and title give the AI context ("this is a Velociraptor hunt screen") and feed the timeline.
- **Resilience:** if the companion is unavailable, the extension queues captures in
  IndexedDB and syncs when the connection returns — no lost evidence.
- **Privacy:** screenshots are sent only to localhost. The chosen AI provider (including a
  local Ollama) determines whether anything leaves the machine; the dashboard shows a clear
  indicator when a cloud provider is active.

## Analysis Pipeline (Approach B — windowed + accumulating state)

### Investigation State (one persistent object per case, saved after every update)

```
InvestigationState {
  findings: Finding[]          // accumulating findings, each with a stable id
  iocs: IOC[]                  // IPs, hashes, domains, file/process names
  openThreads: Thread[]        // open leads — what is being chased and not yet closed
  timeline: TimelineEntry[]    // one entry per analysis window
  mitreTechniques: Technique[] // accumulating ATT&CK mapping
  lastSummary: string          // rolling executive summary
}

Finding {
  id, severity,                // severity: Critical | High | Medium | Low | Info
  title, description,
  relatedIocs[], sourceScreenshots[], mitreTechniques[],
  firstSeen, lastUpdated, status
}
```

### Analysis cycle (per window / event)

1. Screenshots accumulate into a **window** (by count or time, or immediately on a
   significant event). `duplicate` screenshots are excluded.
2. A batch is sent to the AI: `[new screenshots] + [summary of current state: existing
   findings, IOCs, openThreads]`.
3. The AI returns **structured JSON** (strict schema, validated): new findings, updates/
   links to existing findings (by id — so jumping back to a topic updates rather than
   duplicates), new IOCs, MITRE mapping, and what closed/opened in openThreads.
4. The companion **merges** the response into the state (merge, not replace), saves to
   disk, and pushes to the dashboard.

### Why this solves "I don't remember what I checked"

- `openThreads` is a live list of what was opened and not yet closed → at the end the
  investigator sees what remains pending.
- Returning to an old topic gives the AI the existing finding in context, so it *updates*
  it instead of creating a duplicate.
- The timeline records every jump in true chronological order.

### Cost & resilience

- AI call failure → retry with exponential backoff; on persistent failure the screenshot
  is marked `pending_analysis` and stays queued (not lost), analyzable later.
- State context is sent as a **summary**, not raw, to avoid blowing the context window on
  long investigations.
- Strict schema means malformed responses are rejected and never pollute the state.

## Report Generation & Case Folder

### Report sections (all derived from the same InvestigationState)

- **Executive summary** — `lastSummary`, free-text.
- **Timeline** — chronological, each entry links to its source screenshot(s).
- **Findings** — sorted by severity, with IOCs and evidence links.
- **MITRE ATT&CK** — accumulating technique table mapped to findings.

### Live vs Batch — same engine, only timing differs

- **Live:** dashboard subscribes over WebSocket; every state merge pushes an update.
- **Batch:** screenshots accumulate; "Generate Report" runs full analysis (optionally one
  holistic final pass to polish the executive summary). Same state, same renderer.
- Selectable in popup/dashboard; can start live and switch to batch mid-investigation.

### Exports

Markdown (readable report), JSON (full state), and separate CSVs for findings, IOCs, and
timeline (Node CSV library, no pandas).

### Case folder layout

```
cases/<caseId>/
├── case.json                 # metadata: name, date, investigator, AI provider
├── screenshots/
│   ├── 000123_<ts>.webp       # raw evidence (sequential number + timestamp)
│   └── ...
├── metadata/
│   └── captures.jsonl         # one line per capture (append-only, audit trail)
├── state/
│   └── investigation.json     # InvestigationState (saved after every merge)
└── reports/
    ├── report.md
    ├── findings.csv / iocs.csv / timeline.csv
    └── state-export.json
```

- `captures.jsonl` is **append-only** — an immutable audit trail of every capture
  (including duplicates), important for chain of custody.
- Screenshot filenames include sequential number + timestamp → gaps in the sequence are
  easy to detect/verify.

## AI Provider Layer

- Provider abstraction normalizing requests/responses across Ollama Cloud, OpenRouter,
  OpenAI, and Gemini.
- Each provider normalizes its errors (rate limit, auth, timeout) to a uniform format.
- The active provider is configurable and can be switched mid-case without losing state.
- Vision input (screenshots) + structured-output enforcement against the response schema.

## Error Handling

- **Extension → companion:** companion down → IndexedDB queue + auto-sync on reconnect;
  connection indicator in popup.
- **Evidence write:** disk write precedes any analysis. Write failure → blocking error in
  popup (must not continue an investigation without saving evidence).
- **AI call:** retry with exponential backoff; persistent failure → `pending_analysis` in
  queue, investigation continues, analyzable later. No evidence lost to an AI failure.
- **Schema validation:** invalid AI response → rejected, logged, does not pollute state;
  retry with a format-correction instruction.
- **AI provider:** provider layer normalizes errors to a uniform format; switch provider
  mid-case without losing state.

## Testing Strategy (TDD, target 80%+)

- **Unit:** dedup (perceptual hash + threshold), state merge logic (most critical — that
  jumping back to an old topic updates rather than duplicates), schema validation, provider
  normalizers, CSV/MD export.
- **Integration:** ingest→state→disk path with a mock AI; queue/replay after disconnect;
  provider switch mid-case.
- **E2E:** load the extension in Chromium, simulate an investigation (several pages +
  jumps), verify the case folder is created correctly and the dashboard shows findings.
  AI providers are always mocked in tests (deterministic, zero cost).
- **Contract tests** per AI provider against the response schema, to catch API changes.

**Guiding principle:** a hard separation between the evidence path (deterministic, must not
fail) and the analysis path (best-effort, may retry). This is what makes the tool reliable
enough for real DFIR work.
