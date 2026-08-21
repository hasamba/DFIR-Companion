# DFIR Companion — Full Codebase Review

*Date: 2026-08-20 · Base commit: 2d26b187 (`master` tip) · Method: six parallel review passes
(architecture, error handling, duplication/dead code, test coverage, VQL/parsing performance,
Docker/dependencies), every finding independently re-verified against the code before inclusion.
Only confirmed findings appear below; each will receive a corresponding fix commit on
`chore/codebase-review`, after which its Status line is updated with the commit.
A SECOND full review pass ran on 2026-08-21 over the post-fix tree (same method); its findings
appear in per-section "Second pass" subsections and the Finding Index.*

There is no Python source in this repository (the only `.py` files are vendored inside
`node_modules`), so the "VQL/Python parsing" scope resolves to the hunt-query language parser
(`companion/src/analysis/huntQueryParser.ts`), the Velociraptor integration
(`companion/src/integrations/velociraptor/`), and the ~40 evidence-import parsers under
`companion/src/analysis/`.

## 1. Architecture Overview

*Refreshed in the second review pass (2026-08-21) to reflect this branch's container-hardening and module extractions.*

### What the system is

DFIR Companion is a localhost-first, AI-assisted **post-detection triage layer** for incident response. It does not detect; it ingests verdicts and artifacts from tools that do (Velociraptor, Chainsaw, Hayabusa, EDR/SIEM exports, screenshots of investigation consoles) and correlates them into a per-case forensic timeline, findings, IOCs, an asset graph, and exportable reports. The OPSEC posture is explicit in code: the server binds `127.0.0.1` by default (`companion/src/server.ts`), evidence stays on disk, and the AI provider is pluggable (`companion/src/providers/` covers OpenAI, Anthropic, Gemini, Ollama, LiteLLM, OpenRouter, plus Claude Code/Codex CLI runners) — with deterministic detectors (`analysis/beaconDetect.ts` etc.) guaranteed to work when no provider is configured.

### Runtime topology

Four pieces. (1) A Node 22 **TypeScript ESM Express server** (~135k lines, entry `companion/src/server.ts`, now a 642-line composition root after the #384/#416 decomposition). (2) A **no-bundler browser dashboard**: `public/dashboard.html` plus ~150 files in `public/js/` (~35k lines) served statically through a whitelist (`companion/src/http/staticAssets.ts`), updated live over WebSocket (`companion/src/live/hub.ts`, `wsGate.ts`); `public/sw.js` is a deliberately minimal PWA shell scoped to `/mobile` only. (3) An **MV3 browser extension** (`extension/manifest.json`) that captures screenshots and pushes detections into the local server. (4) **Upstream/downstream integrations**: Velociraptor inbound (`companion/src/integrations/velociraptor/velociraptorApi.ts` shells out to the `velociraptor` binary with `--api_config` rather than reimplementing gRPC+mTLS; the VQL runner is injectable for tests, and the pure enrolled-client primitives — client-id shape, record normalization, host→record matching — now live in a dependency-free sibling, `integrations/velociraptor/clientInventory.ts`), outbound push clients (IRIS, MISP, Timesketch, Jira, ServiceNow, Notion, ClickUp), and an agentic MCP mode that spawns `claude -p` (`integrations/mcp/mcpAgentRunner.ts`).

The container stack was hardened materially on this branch. The 3-stage `Dockerfile` (server build, extension zip, slim runtime) now builds every stage from the **same digest-pinned** `node:22-slim` base, bakes an image-level `HEALTHCHECK` (probing `/health` on `PORT`/`DFIR_PORT` so plain `docker run`/Portainer users get liveness, not just compose), and no longer runs the server as root. Because Docker auto-creates missing bind mounts root-owned, a bare `USER` directive would break a clean-checkout `docker compose up`; instead `docker-entrypoint.sh` starts as root solely to hand writable mounts over, then `setpriv`-drops before `exec node dist/server.js` — running **as the owner of the cases-root mount** (falling back to the image's `node` uid only when the mount is root-owned), so a host operator's own files are never disowned. The chown handoffs are deliberately confined: `deny_chown` refuses `/`, the `/app` code tree, `/opt` (the bundled extension), and every OS directory; `chown_tree` uses a no-follow `find … -exec chown -h` so a compromised server cannot plant a symlink that a later root chown dereferences into protected targets; and the cases root's *parent* is never chowned — each known global store plus the `.dfir-auth-<hash>` dir is pre-created and handed off individually, with the hash derived from a lexical (non-dereferencing) normalization to match `authFactory`'s `path.resolve`. Dashboard-writable path overrides persisted to the settings dotenv are re-read by the entrypoint with a dotenv-mirroring parser, so they too pass confinement before any chown. `/app` stays root-owned on purpose (the server must not be able to rewrite its own code); all mutable state is steered onto the `/data` tree via `DFIR_OCR_CACHE=/data/ocr-cache` (tesseract.js model cache, honored by `analysis/ocrRedact.ts`) and `DFIR_ENV_FILE=/data/companion.env` (the Settings `.env` written atomically by `POST /settings/env`, `settings/envManager.ts`). `docker-compose.yml` still maps the port to host loopback only (`127.0.0.1:4773:4773`) and marks that exact posture with `DFIR_ALLOW_UNAUTHENTICATED_REMOTE: "container-loopback-proxy"`; an operator-supplied `user:` override skips the root handoff path entirely.

### Layering and data flow

`ARCHITECTURE.md` describes a five-layer model (Composition → Delivery → Domain → Platform → Shared) and — unusually — it is *enforced*: `npm run check:boundaries` checks every file against `companion/scripts/module-map.json`, with a shrink-only ledger of 39 grandfathered violations (`companion/scripts/boundary-violations.json`), alongside `check:size` and `check:imports` ratchets. A test asserts the document matches the JSON, and the branch kept the asserted compliance figure current (now 1,830 of 1,869 cross-domain dependencies complying). The doc is accurate to the code, with minor staleness (it still says `src/analysis/` is 296 flat files; it is now ~327 flat files plus the `analysis/ai/` and `analysis/ingest/` directories — the only domains physically carved out so far).

Data flows: capture/ingest (extension `POST /captures`, a drop-folder watcher, Velociraptor hunt/monitor pulls, ~40 `*Import.ts` parsers dispatched via `importDetect`) → serialized per-case by `analysis/importLock.ts` → canonical `ForensicEvent`s (`analysis/stateTypes.ts`, imported by ~190 files) → `analysis/forensicGate.ts` partitions severity ≥ Low into the **forensic timeline** and Info telemetry into the **super-timeline** → deterministic detectors and optional AI synthesis (`analysis/pipeline.ts` is now a 758-line facade delegating to `analysis/ai/`) → per-case storage → ~60 route modules registered in a load-bearing order by `composition/routeRegistry.ts` → dashboard via REST + WS broadcast. The parsers themselves now share single-source utilities extracted on this branch: `analysis/bsdTime.ts` (the `MONTHS` table and RFC 3164 timestamp parser once copied byte-identically into the syslog and Cisco ASA importers), `analysis/internalIp.ts` (one `isInternalIpv4` range table replacing six drifted copies, re-exported through `siemImport.ts`), and `analysis/veloMessageFields.ts` (precompiled rendered-message field extraction for `velociraptorImport.ts`). The governing forensic rule — *the model reads the forensic timeline; nothing automatic reads the raw record* — is documented, tested (`tests/analysis/forensicBoundary.test.ts`), and honest about its one capped exception (`viewSummary`).

### Key decisions in evidence

Per-case storage is a directory per case under `casesRoot` (`storage/caseStore.ts`): `case.json`, hash-chained evidence with custody listeners, `state/*.json` files enumerated in `analysis/investigationStateFiles.ts`, and `investigation.sqlite` as the primary indexed backend. SQLite uses Node's built-in `node:sqlite` (Node ≥ 22.5 floor, `analysis/sqliteRuntime.ts`) run inside a **worker thread** (`analysis/caseSqliteWorker.ts`) that opens the DB per transaction, keeping synchronous SQLite off the event loop. The global stores (logs, templates, team-auth, etc.) sit beside the cases root as siblings (`runtimeStores.ts`) — a layout the container entrypoint now mirrors exactly, pre-creating each named store rather than chowning the shared parent. The frontend's classic-scripts-on-`window` pattern is a deliberate resilience choice — a feature module that 404s becomes a no-op, not a blank page (`public/js/dashboard-facade.js` documents and implements the stub layer) — with load order enforced by `tests/dashboard/dashboardLoadOrder.test.ts` instead of an import graph. Wiring is explicit dependency injection: `createApp` composes ~28 named factories from `companion/src/composition/` into a `RouteContext`, and `startServer` builds the ~120-member `AppOptions` bag (`composition/appWiring.ts`).

### Architectural tensions

- **Everything meets at one seam.** `AppOptions` (~120 members) and `RouteContext` are very wide injection bags; construction order inside `createApp` is explicitly load-bearing, with thunks papering over genuine cycles. Tests pin it, but the whole system is coupled through two literals.
- **The frontend's module graph is invisible to tooling.** 150-ish classic scripts resolve every cross-module name through `window` at call time; `check:imports` sees 138 nodes and 0 edges, and 32 runtime cycles exist by design. Correctness rests on bespoke tests (load order, feature manifest, stub coverage) rather than anything a bundler or type-checker can verify.
- **The map is enforced; the geography lags it.** Eleven `analysis/` domains exist in `module-map.json` but ~327 files still sit flat, with a 39-entry violation ledger and `integrations/` straddling two layers (`velociraptorApi.ts` is Platform-shaped code filed under Delivery, as the doc itself concedes — though the branch's `clientInventory.ts` extraction shows the remedy pattern: peel the pure primitives out of the subprocess-owning module).
- **A core capability rides an external binary.** Velociraptor hunting depends on spawning the `velociraptor` executable and parsing its stdout/stderr under output caps (`vqlDiagnostics.ts`) — pragmatic, injectable, and off by default, but a process-management and parsing surface where a native client would be a typed one.
- **The privilege drop moved policy into shell.** `docker-entrypoint.sh` is now 249 lines of POSIX sh that must faithfully mirror server-side path semantics — `authFactory`'s lexical `path.resolve` hashing, `runtimeStores.ts`'s sibling layout, dotenv's parsing grammar, `expandHome()` — and each is annotated with why. The confinement logic is sound and was iteratively hardened, but it is a second implementation of the server's path model, in a language with no test harness of its own, that silently diverges if a new store type or env var lands on the TypeScript side alone (the entrypoint's `KNOWN_STORES` list is the canary).

## 2. Error Handling Gaps

Error handling in `companion/src` is unusually disciplined: every async route flows through `express-async-errors` into the terminal JSON error handler in `composition/httpStack.ts`, process-level nets (`logging/unhandledRejectionNet.ts`, `logging/uncaughtExceptionNet.ts`) are installed with clearly documented log-then-contain vs. log-then-exit semantics, and virtually every swallowed catch in the importers and Velociraptor paths (`composition/veloHunts.ts`, `analysis/custody.ts`, `analysis/hostScopeStore.ts`) carries a comment justifying the degradation and a per-line-skip pattern that keeps one bad record from sinking a whole read. The defects that remain sit at the edges: one server-side catch in `composition/captureAnalysis.ts` that misdiagnoses a corrupt capture log as "no log", and the newest browser-side modules (`public/js/dashboard-host-scope.js`, `public/js/dashboard-asset-graph.js`, `extension/src/serviceWorker.ts`) which drop failures silently where their older siblings surface them.

### EH-1 — AI-on backfill misreads a corrupt captures.jsonl as "no capture log" and silently skips the whole screenshot backlog  `MEDIUM`

**Location:** `companion/src/composition/captureAnalysis.ts:359`

backfill() (run on every AI off-to-on transition) reads captures.jsonl and JSON.parses every line inside one try block. captures.jsonl is written by appendFile (companion/src/storage/caseStore.ts:353), so a crash or ENOSPC mid-append can leave one truncated line. That single bad line makes the whole map() throw, and the catch treats every failure as "no capture log (import-only case)": it calls catchUpSynthesis() and returns, so ALL pending screenshots captured while AI was off are silently never analyzed - no log line, no status, and the condition never heals because the corrupt line stays and lastAnalyzedSeq never advances. The catch also conflates non-ENOENT read failures (EACCES etc.) the same way. The codebase's own convention elsewhere (routes/caseLifecycle.ts:425 import-log loop, routes/system.ts:287) is a per-line try/catch that skips only the malformed line.

**Evidence:**
```
    let captures: CaptureMetadata[];
    try {
      const log = await readFile(store.capturesLogPath(caseId), "utf8");
      captures = log
        .split("\n")
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l) as CaptureMetadata);
    } catch {
      await catchUpSynthesis(); // no capture log (import-only case) → still synthesize imported evidence
      return;
    }
```

**Fix:** Restrict the readFile catch to ENOENT (log a warnLine and still fall back to catchUpSynthesis for other read errors), and parse lines individually with a per-line try/catch that skips a malformed line - mirroring the importLog loop in routes/caseLifecycle.ts:419-429 - so a single truncated tail line cannot suppress the whole backfill. Log how many lines were skipped.

**Status:** Fixed in e83eaf69.

### EH-2 — Host-clearance decision failures are silently swallowed - the void'ed decideHostScope has no rejection or !ok handling  `MEDIUM`

**Location:** `public/js/dashboard-host-scope.js:291`

onPanelClick fires the clearance/out-of-scope decision with `void decideHostScope(...)`. decideHostScope has no internal try/catch, returns false on !r.ok, and nobody consumes either: a rejected fetch (companion restarting, network blip) escapes as an unhandled promise rejection, and a server rejection (400 "a reason is required", 500 from the deliberately fail-loud HostScopeStore, auth failure) is dropped by `if (!r.ok) return false`. Either way the analyst - who just typed a justification into the prompt() that the UI says "is recorded against your name and quoted in the report" - gets no message, no repaint, and no record; the decision silently never lands in the append-only ledger. This defeats HostScopeStore's own design (companion/src/analysis/hostScopeStore.ts deliberately throws on a corrupt file so decisions are never silently erased) and breaks the module's sibling convention: hunt-workbench.js uses `void deleteHunt().catch(reportActionError)` and dashboard-velo-triage.js writes every failure into a message element.

**Evidence:**
```
  async function decideHostScope(caseId, host, to, reason) {
    const r = await fetch(
      `/cases/${encodeURIComponent(caseId)}/host-scope/${encodeURIComponent(host)}`,
      ...
    );
    if (!r.ok) return false;
    ...
  }
  ...
    void decideHostScope(caseId.trim(), host, to, reason);
```

**Fix:** Consume the outcome and surface failures: read the error body in decideHostScope (`const e = await r.json().catch(() => ({})); throw new Error(e.error || "HTTP " + r.status)` instead of `return false`), and in onPanelClick replace the bare void with `decideHostScope(...).catch((err) => alert("Could not record decision for " + host + ": " + err.message))` (or write into a panel message element, matching dashboard-velo-triage.js).

**Status:** Fixed in e83eaf69.

### EH-3 — loadAssetGraph misses the r.ok check its sibling has, caching an error body as graph data and wedging the panel silently  `LOW`

**Location:** `public/js/dashboard-asset-graph.js:32`

loadAssetGraph does `.then((r) => r.json())` with no r.ok guard - unlike loadAssetOverrides ten lines below, which does `.then((r) => (r.ok ? r.json() : null))`. On any non-2xx from GET /cases/:id/asset-graph (404 after a case deletion, 500 from a state-store failure) the JSON error body `{error: "..."}` is assigned to assetGraphData; renderAssetGraph() then throws `TypeError` at `assetGraphData.assets.length` (line 290), which the chain's swallow-all `.catch(() => {})` hides. Net effect: the previously rendered graph (possibly from another case) stays on screen, hasAssetGraph() (line 343, `return !!assetGraphData`) wrongly reports a graph exists, and nothing in the console or UI explains why the panel stopped updating.

**Evidence:**
```
    fetch(`/cases/${caseId}/asset-graph${DfirTimelineView.timeQuery()}`)
      .then((r) => r.json())
      .then((g) => {
        assetGraphData = g;
        renderAssetGraph();
      })
      .catch(() => {});
```

**Fix:** Mirror loadAssetOverrides: `.then((r) => (r.ok ? r.json() : null)).then((g) => { if (!g || !Array.isArray(g.assets)) return; assetGraphData = g; renderAssetGraph(); })` - so a failed read leaves the last good data in place instead of poisoning the module state.

**Status:** Fixed in e83eaf69.

### EH-4 — Service-worker message handlers pass sendResponse to .then() with no rejection arm, leaving the popup with no answer on failure  `LOW`

**Location:** `extension/src/serviceWorker.ts:395`

The capture_once handler (and its activate_site/push_artifact siblings at lines 387 and 400) does `void captureActiveTab("manual", true).then(sendResponse); return true;`. captureActiveTab can reject - e.g. `await this.queue.enqueue(payload)` in captureController.ts rejects with QuotaExceededError once the IndexedDB offline queue of base64 PNGs hits quota while the companion is down, and browserApi.storage.local.set can reject too. On rejection sendResponse is never called, so the kept-open message channel dies unanswered: popup.ts:350 (`const result = await browserApi.runtime.sendMessage(message)`, itself uncaught in the captureOnce onclick, unlike line 131 which has `.catch(() => false)`) rejects with "message port closed", the status element is never updated, and the analyst's one-off capture is lost with zero feedback plus an unhandled rejection in both contexts.

**Evidence:**
```
    void captureActiveTab("manual", true).then(sendResponse);
    return true;
```

**Fix:** Give each of the three handlers a rejection arm that still answers the channel, e.g. `void captureActiveTab("manual", true).then(sendResponse, (e) => sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) }));` (activate_site can respond `false`, push_artifact `{ ok: false, error }`). Optionally also wrap popup.ts's captureOnce sendMessage in try/catch to write the failure into statusEl.

**Status:** Fixed in e83eaf69.


### Second pass (2026-08-21)

The four first-pass defects (EH-1..EH-4) are genuinely fixed and pinned by new tests: `companion/src/composition/captureAnalysis.ts` now separates ENOENT from other read failures and skips malformed capture lines individually, `public/js/dashboard-host-scope.js` throws and alerts when a clearance decision fails to land, `public/js/dashboard-asset-graph.js` gained an `r.ok` guard plus a generation token, and `extension/src/serviceWorker.ts` answers every kept-open message channel on rejection. The branch's server-side rework (the `syslogImport.ts` streaming accumulator, `ocrRedact.ts` tesseractDataOptions, `velociraptorApi.ts` getFlowInfo, and the new bsdTime/internalIp/clientInventory/veloMessageFields modules) is clean from an error-handling standpoint — abort signals, per-line skips, and degrade-with-log conventions are all carried through. What remains sits exactly where the first pass said the weakness lives, the browser-side edges: the host-scope panel's *load* path still swallows failures its *decide* path now surfaces, and the asset-graph fix's own clearing logic does not run on the rejection arm it left as `.catch(() => {})`.

#### EH2-1 — loadHostScope silently ignores a failed ledger read and keeps the previous case's clearance ledger on screen  `MEDIUM`

**Location:** `public/js/dashboard-host-scope.js:228`

loadHostScope (the sibling of the EH-2-fixed decideHostScope) still swallows every failure: `if (!r.ok) return;` drops server rejections without reading the error body, and the catch below contains network failures without repainting. Neither path clears `hostScopeLedger` or touches the DOM, and the per-case resets in dashboard-case-connect.js (lines ~291-330) do not reset this module's state. Consequence: (1) on a case switch where the new case's GET /cases/:id/host-scope fails, the panel keeps rendering the PREVIOUS case's clearance board — "Cleared"/"Confirmed" statuses for the wrong case on a surface analysts use for scoping calls, with no indication anything failed; (2) the 500 produced when HostScopeStore deliberately throws on a corrupt ledger file (routes/hostScope.ts:66-68 returns the error message) never reaches the analyst — the fail-loud corruption design is silenced at the last hop, and the analyst only discovers it if they happen to POST a new decision (whose EH-2 fix alerts).

**Evidence:**
```
  async function loadHostScope(caseId) {
    if (!caseId) return;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/host-scope`);
      if (!r.ok) return;
      hostScopeLedger = await r.json();
      paintHostScope();
    } catch {
      // A panel that cannot load must not take the dashboard down with it.
    }
  }
```

**Fix:** Add `let hostScopeLoadSeq = 0;` and in loadHostScope take `const seq = ++hostScopeLoadSeq;` before the fetch; in both the !r.ok path and the catch, bail if `seq !== hostScopeLoadSeq`. On !r.ok: `const e = await r.json().catch(() => ({})); hostScopeLedger = null;` then, for 501 (store not configured), just `paintHostScope()` (renders the default 'No scope data.' empty state); otherwise write the failure into the panel via `const el = document.getElementById("hostScopeBody"); if (el) el.innerHTML = `<p class="hs-empty">Host scope unavailable: ${esc(e.error || "HTTP " + r.status)}</p>`;` (null-guard required — paintHostScope guards the same lookup, and the unit-test harness stubs getElementById to return null). In the catch (after the seq check): `hostScopeLedger = null;` and the same guarded write with a generic 'Host scope could not be loaded.' message. Also guard the success assignment with the seq check so a late stale success cannot overwrite the newer case's ledger.

**Status:** Open

#### EH2-2 — loadAssetGraph's rejection arm bypasses the new generation-token clearing, leaving the stale cross-case graph the fix claims to prevent  `LOW`

**Location:** `public/js/dashboard-asset-graph.js:53`

The EH-3 fix added a generation token and an explicit invariant, stated in its own comment: for the LATEST load "a failure clears the graph and repaints empty, so a case switch whose graph fails cannot leave the previous case's assets on screen." But that logic lives only in the fulfilled arm; the chain still ends in a bare `.catch(() => {})`. A network-level failure (companion restarting mid-case-switch — the exact scenario EH-2's fix cites) or a 2xx response with a malformed body makes `fetch`/`r.json()` REJECT, skipping both `.then`s entirely: the seq token is never consulted, `assetGraphData` is never cleared, and no repaint happens. The previous case's graph stays rendered under the new case, and `hasAssetGraph()`/`assetGraphAssets()` keep serving the stale cross-case data to the refresh fan-out and to dashboard-asset-overrides' rename-candidate matching — precisely the outcome the fix's comment says cannot happen, restored through the one arm the fix did not cover.

**Evidence:**
```
        if (!g || !Array.isArray(g.assets)) {
          assetGraphData = null;
          renderAssetGraph();
          renderAssetList();
          return;
        }
        assetGraphData = g;
        renderAssetGraph();
      })
      .catch(() => {});
```

**Fix:** Give the catch the same latest-load semantics as the null branch: `.catch(() => { if (seq !== assetGraphLoadSeq) return; assetGraphData = null; renderAssetGraph(); renderAssetList(); });` — or extract the four-line failure block into a local `failed(seq)` helper called from both the `!g` branch and the catch, so a rejected fetch and an HTTP error degrade identically and a superseded load's late rejection still cannot touch state.

**Status:** Open


## 3. Code Duplication and Dead Code

Code sharing in `companion/src` is genuinely good at the infrastructure level — the SIEM-style importers all reuse `aggregateEvents`/`addIoc`/`cleanIp` from `companion/src/analysis/siemImport.ts`, no source file in the tree is orphaned, and the dashboard's deliberately duplicated `esc()` XSS primitive is pinned by a byte-identity drift test (`public/js/dashboard-escape.js` + `tests/reports/dashboardEscape.test.ts`). The gaps are small-helper duplication that has already started to drift: the private-IPv4 classifier is hand-rolled in six modules with a divergent copy in `companion/src/analysis/emailImport.ts`, the `{ Critical: 0 … Info: 4 }` severity-rank table is re-declared 21+ times despite a canonical export in `companion/src/analysis/severityFloor.ts`, and the RFC-3164 month-table/timestamp parser is copied verbatim between the syslog and Cisco ASA importers. A repo-wide reference scan also surfaced ~160 exported symbols never referenced outside their defining file — most are merely vestigial `export` keywords, but a handful (e.g. `resolveIocAlias`, `SECTION_LABELS`, four `_reset*Cache` test hooks) are fully dead with zero references anywhere, including tests, `public/js`, and the extension.

### DUP-1 — isPrivateIp re-implemented in 6 modules, with a drifted copy in emailImport that treats CGNAT and 0/8 as public  `MEDIUM`

**Location:** `companion/src/analysis/emailImport.ts:490`

The private/internal IPv4 classifier is hand-rolled separately in snortImport.ts:56, ciscoAsaImport.ts:66, ecarImport.ts:82, syslogImport.ts:87, emailImport.ts:490, and (inverted, as isPublicIpv4) siemImport.ts:~823 — alongside the canonical isPrivateIpv4 in iocValue.ts:60. Five of the copies include CGNAT 100.64/10 and 0/8 as internal, but the emailImport copy omits both. Consequence: walking Received headers bottom-up for the "first public IPv4", emailImport will return a CGNAT hop (100.64.x.x) or a 0.x.x.x artifact as the message's origin IP and promote it to an IOC, while every other importer would correctly discard it — inconsistent IOC quality depending on which importer saw the address, and any future range fix must be repeated in six places.

**Evidence:**
```
function isPrivateIp(ip: string): boolean {
  const o = ip.split(".").map(Number);
  if (o.length !== 4) return false;
  return (
    o[0] === 10 ||
    (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
    (o[0] === 192 && o[1] === 168) ||
    o[0] === 127 ||
    (o[0] === 169 && o[1] === 254)
  );
}
```

**Fix:** Share one classifier as proposed (siemImport.ts export, full range set), delete the five importer-local copies — but do NOT replace siemImport's private isPublicIpv4 with a plain negation. Its comment and callers require non-IPv4 / blank input ('-', '::1', '', IPv6) to count as internal, whereas !isInternalIpv4(x) returns true (public) for non-IPv4 strings; a naive negation would make logonRisk grade e.g. a blank-source type-3 logon as internet-facing (T1078 Medium). Keep isPublicIpv4 as a thin wrapper: IPv4-shaped AND !isInternalIpv4(ip). The five importer call sites (`ip && !isPrivateIp(ip)`) can use the negated shared function directly since their inputs are regex-extracted IPv4 strings.

**Status:** Fixed in b6af24c7.

### DUP-2 — Severity-rank table { Critical: 0 … Info: 4 } duplicated 21+ times despite canonical SEVERITY_RANK export  `MEDIUM`

**Location:** `companion/src/analysis/correlate.ts:38`

companion/src/analysis/severityFloor.ts:24 exports the canonical `SEVERITY_RANK` (its own comment says "Matches the ranking used across the codebase (correlate, assetGraph…)"), yet `grep -rn 'Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4' companion/src --include='*.ts'` finds 21 identical single-line re-declarations (correlate.ts:38, assetGraph.ts:78, exfilCorrelate.ts:18, graphContext.ts:23, sessionSegmentation.ts:70, memoryNextStep.ts:91, evidenceGraph.ts:72, geoMap.ts:76, gapDetect.ts:90, timelineAnomalies.ts:203, socratesImport.ts:53, initialAccess.ts:14, assetOverrides.ts:55, thorImport.ts:166, siemImport.ts:104, auditdImport.ts:296, reports/interactiveHtml.ts:43, …) plus multiline copies in huntSuggest.ts:139, playbookHunt.ts:274 and reports/markdown.ts:73, while severityFloor is imported only 5 times. Three of the copies (HUNT_SEVERITY_RANK, PLAYBOOK_HUNT_SEVERITY_RANK, MEMORY_NEXTSTEP_SEVERITY_RANK) are additionally exported "for the dashboard" but have zero references anywhere in companion/src, companion/tests, public/, or extension/ — dead exports. Adding a severity tier or changing ordering requires touching ~24 files, and slashCommand.ts:166 already uses an incompatible inverted encoding.

**Evidence:**
```
const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
```

**Fix:** As proposed (hoist to stateTypes.ts or keep in severityFloor.ts — either is cycle-free since stateTypes has only type imports), but explicitly exclude forensicGate.ts, notifications.ts, and slashCommand.ts from the replacement (they use inverted encodings with their own tests), and handle synthSelect.ts's Record<string, number> indexing when swapping its copy.

**Status:** Fixed in b6af24c7 — SEVERITY_RANK hoisted to `stateTypes.ts` (the Fix's sanctioned alternative: severityFloor.ts sits in a layer its consumers may not import), all listed sites plus two the list missed (burstDetect.ts, findingGrounding.ts) now import it; the three dead rank exports are deleted.

### DUP-3 — MONTHS lookup table copied in 4 importers and byte-identical year-less timestamp parser in syslog and Cisco ASA importers  `LOW`

**Location:** `companion/src/analysis/ciscoAsaImport.ts:93`

The Jan→"01" … Dec→"12" month table is declared four times (ciscoAsaImport.ts:78, syslogImport.ts:56, combinedLogImport.ts:~98, siemImport.ts:538 as KIBANA_MONTHS), and the RFC-3164 "MMM DD HH:MM:SS"-at-assumed-year parser is byte-identical between parseAsaTime (ciscoAsaImport.ts:93-102) and parse3164Time (syslogImport.ts:118-126), with a near-clone parseSnortTime in snortImport.ts:65. Any fix to the year-stamping/fraction handling (e.g. the same year-clamp interaction documented in snortImport's header) must be repeated in each file, and the copies can silently diverge.

**Evidence:**
```
function parseAsaTime(ts: string, year: number): string {
  const m = ts.trim().match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (!m) return "";
  const [, mon, dd, hh, mi, ss] = m;
  const month = MONTHS[mon];
  if (!month) return "";
  const t = Date.parse(`${year}-${month}-${dd.padStart(2, "0")}T${hh}:${mi}:${ss}Z`);
  return Number.isNaN(t) ? "" : new Date(t).toISOString();
}
```

**Fix:** Export `MONTHS` and a shared `parseBsdTime(ts: string, year: number): string` from siemImport.ts (the module these importers already import aggregateEvents/addIoc/cleanIp from). Replace parseAsaTime and parse3164Time with calls to it and delete the three duplicate MONTHS tables (KIBANA_MONTHS in siemImport becomes the exported one).

**Status:** Fixed in b6af24c7.

### DUP-4 — Dead exports in reportTemplate.ts: SECTION_LABELS and emptyReportTemplate have zero references repo-wide  `LOW`

**Location:** `companion/src/reports/reportTemplate.ts:46`

`grep -rn -w SECTION_LABELS companion/src companion/tests public extension companion/scripts` returns only the definition at reportTemplate.ts:46, and the same grep for `emptyReportTemplate` returns only its definition at reportTemplate.ts:177; no namespace (`import * as`) imports of reportTemplate.ts exist, and no string-based lookup references either name in public/js or dashboard.html. Both are unused API surface that readers must assume is load-bearing, and SECTION_LABELS executes Object.fromEntries at module load for nothing.

**Evidence:**
```
export const SECTION_LABELS: Record<ReportSectionKey, string> = Object.fromEntries(
  REPORT_SECTION_DEFS.map((s) => [s.key, s.label]),
) as Record<ReportSectionKey, string>;
```

**Fix:** Delete SECTION_LABELS (lines 46-48) and emptyReportTemplate (lines 177-179). REPORT_SECTION_DEFS, ALL_SECTION_KEYS, and normalizeReportTemplate — which the two dead symbols wrap — remain exported and used.

**Status:** Fixed in b6af24c7.

### DUP-5 — Four exported _reset*Cache test hooks are referenced by no test or source file  `LOW`

**Location:** `companion/src/analysis/d3fendData.ts:124`

_resetD3fendCache (d3fendData.ts:124), _resetAdversaryGroupsCache (adversaryGroupsData.ts:139), _resetMitigationsCache (attackMitigationsData.ts:107), and _resetIncidentTypesCache (incidentTypesData.ts:102) each have exactly one occurrence in the repo — their definition (verified with `grep -rn -w` across companion/src, companion/tests, public, extension, companion/scripts). The sibling data loaders' hooks ARE used (`_resetCentroidCache` in tests/analysis/countryCentroids.test.ts, `_resetKnownPlaybooksCache` in tests/analysis/knownPlaybooksData.test.ts, `_resetDedupCache` in eight test files), so these four are pattern-parity code whose consuming tests were never written — dead weight that also hides the fact that the four cached loaders are never tested against a fresh cache.

**Evidence:**
```
// Test-only: drop the cache so a test can point the loader at a fresh state.
export function _resetD3fendCache(): void {
  cached = null;
  warned = false;
}
```

**Fix:** Either delete the four unused hooks, or (preferred, matching the countryCentroids pattern) add a `beforeEach(() => _reset…Cache())` to the corresponding loader tests so the hooks earn their keep; pick one option and apply it to all four files consistently.

**Status:** Fixed in b6af24c7.

### DUP-6 — resolveIocAlias is dead — stateMerge re-implements the alias lookup inline, dropping the trim normalization  `LOW`

**Location:** `companion/src/analysis/iocAlias.ts:27`

`grep -rn -w resolveIocAlias` across companion/src, companion/tests, public, and extension finds only the definition (IocAliasStore and emptyIocAliasMap in the same file ARE used). The one place that resolves aliases — stateMerge.ts:101 — does `ctx.iocAliases?.[incomingLower]` with `incoming.value.toLowerCase()` (no `.trim()`), while resolveIocAlias and IocAliasStore.add both normalize with `.trim().toLowerCase()`. A merged-away IOC value that re-arrives with leading/trailing whitespace would miss the alias map and recreate the duplicate — exactly the drift this canonical resolver was written to prevent, and it sits unused three files away.

**Evidence:**
```
// Canonical IOC id for a value the analyst previously merged away, or undefined if none.
export function resolveIocAlias(value: string, map: IocAliasMap): string | undefined {
  return map.aliases[value.trim().toLowerCase()];
}
```

**Fix:** Delete resolveIocAlias, or swap stateMerge.ts:101 to call it purely as single-source-of-truth hygiene — but frame it as consistency, not a bug fix: the read side is already effectively trim().toLowerCase() because repairIocValue trims two lines above, and the only test touching the alias path (tests/analysis/stateMerge.test.ts:353, `iocAliases: { "evil.com": "i002" }`) passes either way.

**Status:** Fixed in b6af24c7 — dead `resolveIocAlias` deleted (the Fix's first option; the swap variant was implemented and rejected by `check:boundaries` as a new analysis/timeline → analysis/findings violation, and the read side is already trim-normalized via repairIocValue).


### Second pass (2026-08-21)

The first pass's consolidations landed cleanly: `SEVERITY_RANK` lives once in `stateTypes.ts`, all six importer IP-classifier copies now route through `internalIp.ts` via `siemImport.ts`'s re-export, `bsdTime.ts` owns the shared `MONTHS`/`parseBsdTime` pair, and every dead symbol named in DUP-4..6 is gone with the four `_reset*Cache` hooks wired into their loader tests. The branch's own extractions (`veloMessageFields.ts`, `clientInventory.ts`) are fully referenced, nothing was orphaned by the streaming-syslog or Docker-entrypoint rework, and the deliberate exclusions (inverted ranks in forensicGate/notifications/slashCommand, the dashboard `esc()` byte-identity pair) hold. What remains is residue at the edges of those sweeps: the internal-IPv4 canon stops short of `iocValue.ts`'s enrichment gate, two reports-layer files (`attackLayer.ts`, `iocBlocklist.ts`) still keep private inverted severity tables outside the sanctioned trio, and three tiny helpers — `escapeRegExp`, the worst-severity comparator, and the routes' streaming-import kind predicate — are still declared per-file.

#### DUP2-1 — The internal-IPv4 consolidation stopped short of iocValue.ts — the enrichment SSRF gate still treats CGNAT 100.64/10 as public  `MEDIUM`

**Location:** `companion/src/analysis/iocValue.ts:60`

DUP-1's fix made internalIp.ts the one range table (RFC1918 + loopback + 0/8 + link-local + CGNAT) precisely because per-module copies had drifted on CGNAT, but iocValue.ts's isPrivateIpv4 — which backs the exported isInternalTarget() SSRF guard that enrichService.ts uses to decide what may be enriched — still lacks the 100.64/10 branch. So isInternalTarget("100.64.0.5", "ip") returns false and a CGNAT address (or a URL/IPv6-mapped host embedding one) is treated as a routable public target, while every importer now refuses to mint CGNAT IOCs, anonymize.ts classifies CGNAT as internal/victim, and providers/urlValidation.ts blocks CGNAT with a pinned test. anonymize.ts:199 even carries a comment explicitly working around this gap ("Classification still uses isInternalIp() (not iocValue.ts's isPrivateIpv4) so the CGNAT range stays covered here") — documentation of known drift, not intent. No test pins CGNAT as enrichable (iocValue.test.ts's public cases are 8.8.8.8/1.1.1.1 only).

**Evidence:**
```
function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  return false;
}
```

**Fix:** Do NOT import ./internalIp.js (analysis/findings tier 2 importing analysis/ingest tier 3 fails check:boundaries, and the ledger only shrinks). Instead add the missing branch to isPrivateIpv4 — `if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10` — extend the range comment at iocValue.ts:58-59, and pin it: isInternalTarget("100.64.0.5", "ip") === true plus a mapped/URL variant (e.g. "http://100.64.0.5/" and "::ffff:100.64.0.5"). This mirrors how urlValidation.ts and anonymize.ts, also below the ingest tier, each keep the range locally with a CGNAT-pinned test. Optionally soften the now-outdated parenthetical in anonymize.ts:199. Full consolidation would require first re-homing internalIp.ts to the shared domain in module-map.json's flatAnalysisFiles (it imports nothing, so it qualifies) — a separate architectural edit.

**Status:** Open

#### DUP2-2 — DUP-2's sweep missed two more local severity-rank tables: inverted encodings in reports/attackLayer.ts and reports/iocBlocklist.ts  `LOW`

**Location:** `companion/src/reports/attackLayer.ts:60`

The new canonical-table comment in stateTypes.ts:6-8 states that only forensicGate.ts, notifications.ts and slashCommand.ts "deliberately keep their own INVERTED encodings", but two more files re-declare a private SEVERITY_RANK with inverted (higher = worse) semantics: reports/attackLayer.ts:60 (Critical: 5 … Info: 1, used by its worse() at :80 and the sort at :157) and reports/iocBlocklist.ts:24 (Critical: 4 … Info: 0, used once at :93). Both escaped DUP-2's grep because they are multi-line and not the { Critical: 0 … } literal; neither is exported, tested against its numeric values, or named in the sanctioned exclusion set — unlike forensicGate's, which is a cross-module contract consumed by findingGrounding. Consequence: a future severity-tier change to the canonical table silently misses these two report generators, and the stateTypes comment's inventory of exceptions is already wrong.

**Evidence:**
```
// Worst-wins ordering (higher = worse) when several findings/events touch the same technique.
const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1,
};
```

**Fix:** In attackLayer.ts delete the local table, import SEVERITY_RANK from ../analysis/stateTypes.js (the file already imports Severity from there) and flip the two comparisons (worse(): `SEVERITY_RANK[a] <= SEVERITY_RANK[b] ? a : b`; the sort at :157: `SEVERITY_RANK[a[1].worst] - SEVERITY_RANK[b[1].worst]`). In iocBlocklist.ts delete its local table and flip the single comparison at :93 to `SEVERITY_RANK[iocSeverity(ioc)] > SEVERITY_RANK[minSev]`. Both swaps are behavior-preserving (SEVERITY_SCORE/SEVERITY_COLOR are untouched); existing report tests pin the output either way.

**Status:** Open

#### DUP2-3 — escapeRegExp is hand-rolled nine times across companion/src, including a fresh copy the branch carried into veloMessageFields.ts  `LOW`

**Location:** `companion/src/analysis/veloMessageFields.ts:30`

The byte-identical MDN regex-escape idiom `.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")` exists as five named function copies (analysis/anonymize.ts:96, analysis/assetGraph.ts:91, analysis/geoMap.ts:82, analysis/redactPaths.ts:65, reports/glossary.ts:58) and four inline uses (analysis/veloMessageFields.ts:30 — placed in this new module by the branch's extraction, analysis/fpCascade.ts:26, analysis/initialAccess.ts:38, analysis/lookalikeDomains.ts:336). This is exactly the small-helper duplication class DUP-1/DUP-3 consolidated for IP ranges and month tables, and it guards security-relevant surfaces (anonymize's tokenizer, redactPaths): a future correction — e.g. escaping `/` for a literal-embedded pattern, or the `u`-flag identity-escape caveat anonymize.ts:127 documents only locally — must be found and repeated in nine files, and any copy silently drifting weakens the guarantee where it drifts.

**Evidence:**
```
function labelPattern(label: string): RegExp {
  return new RegExp(`${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:[ \\t]*([^\\r\\n]+)`, "i");
}
```

**Fix:** Create companion/src/analysis/regexEscape.ts exporting escapeRegExp with anonymize.ts's Unicode-mode safety comment, AND add "regexEscape.ts": "shared" to module-map.json's flatAnalysisFiles (the shared layer, rank 0, is importable from all nine sites including reports/glossary.ts — same classification stateTypes.ts already has; without the entry check:boundaries hard-errors on the unclassified file). Then swap the nine sites and run check:boundaries plus tests/architecture/moduleMap.test.ts.

**Status:** Open

#### DUP2-4 — The streaming-import kind predicate (evtxxml || syslog) is copied five times across the import routes and the resume handler  `LOW`

**Location:** `companion/src/routes/import.ts:335`

The branch's cancellable-syslog fix widened `kind === "evtxxml"` into the two-kind list `kind === "evtxxml" || kind === "syslog"` in five places: routes/import.ts:335 and :645 (cancellable in the twin /import and /import-file job registrations), :362 and :672 (the onParseProgress spread in the same twin blocks), and routes/importRecovery.ts:185 (cancellable for RESUMED jobs). These five literals must stay in lockstep — the next streaming importer (the same fix pattern is queued for other large formats per REVIEW.md's PERF notes) requires editing all five, and missing only importRecovery.ts:185 would produce a job that is cancellable on first run but silently uncancellable after a server restart resumes it, with no test tying the two files together.

**Evidence:**
```
        cancellable: aiDependent || kind === "evtxxml" || kind === "syslog",
...
        ...(kind === "evtxxml" || kind === "syslog" ? { onParseProgress: tracking.onParseProgress } : {}),
...
// importRecovery.ts:185
      cancellable: (job) => job.parameters?.kind === "evtxxml" || job.parameters?.kind === "syslog",
```

**Fix:** Hoist `export const PARSE_PROGRESS_KINDS = new Set(["evtxxml", "syslog"])` with a hasParseProgress(kind) helper into a new routes/importKinds.ts (auto-classified by the routes/** glob; avoid the name "streaming", which import.ts:587 already uses for plaso file-streaming), replace the five literals, and add a test asserting importRecovery's kind-driven cancellable component matches the registration's per kind (the registrations additionally OR in aiDependent, which the resume predicate intentionally lacks — assert only the kind part).

**Status:** Open

#### DUP2-5 — The worst-severity comparator is still declared in nine files although siemImport.ts already exports it as worst()  `LOW`

**Location:** `companion/src/analysis/siemImport.ts:1201`

DUP-2's fix consolidated the SEVERITY_RANK table but left its 2-line worst-wins comparator duplicated: siemImport.ts:1201 exports the canonical `worst` (imported by the syslog/combined-log importers), yet eight more files declare a byte-equivalent private copy over the now-shared table — assetGraph.ts:84, assetOverrides.ts:55, burstDetect.ts:34, correlate.ts:99 (the `<=` variant, same semantics), evidenceGraph.ts:72, exfilCorrelate.ts:18, geoMap.ts:85, initialAccess.ts:14 — plus attackLayer.ts:79's inverted-table variant (finding DUP2-2). This is the identical shape DUP-2 removed one level down: a canonical export exists while consumers re-declare it, because the graph/correlation modules may not import the importer-layer siemImport. Direction is easy to get backwards when copying (an inverted `<` silently returns the LESS severe value), and the drift can only be caught by eye since each copy compiles fine.

**Evidence:**
```
// assetGraph.ts:84 (same two lines in 7 more files)
function worse(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[b] < SEVERITY_RANK[a] ? b : a;
}
// siemImport.ts:1201 — the already-exported canonical
export function worst(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[b] < SEVERITY_RANK[a] ? b : a;
}
```

**Fix:** Apply the branch's own pattern one more time: add `export function worstSeverity(a: Severity, b: Severity): Severity` to stateTypes.ts beside SEVERITY_RANK (cycle-free — stateTypes has only type imports), delete the eight local copies in favor of it, and keep siemImport's `worst` as a one-line re-export (exactly how isInternalIpv4 is surfaced there) so the many existing importer call sites are untouched. attackLayer.ts picks it up as part of DUP2-2's swap.

**Status:** Open


## 4. Test Coverage Gaps

Test coverage in this repository is unusually strong for its riskiest surfaces: `companion/tests/analysis/zipExtract.test.ts` and `zipArchive.test.ts` exercise zip-slip, zip-bomb caps, and even AES-tamper-vs-wrong-password discrimination with real fixtures; `caseEncryption.test.ts` pins a frozen v1 container as a regression vector; and `http/originGuard.test.ts` covers DNS-rebinding from every angle. The remaining gaps cluster at the team-authentication trust boundary: the OIDC ID-token verifier (`companion/src/auth/oidcClient.ts`) has only a happy-path test and no forged/alg-none/wrong-nonce rejections, the `/auth/bootstrap` first-admin route (`companion/src/auth/authRoutes.ts`) has no refusal-branch tests, and the single-writer guard's corruption/release-safety branches are unexercised. One demonstrated crash branch in `zipExtract.ts`'s central-directory scan also lacks a corrupt-archive test.

### TC-1 — OIDC ID-token verification has zero negative-path tests — a forged token regression would pass the suite  `HIGH`

**Location:** `companion/src/auth/oidcClient.ts:299`

verifyIdToken/validateClaims implement the checks that make team-mode OIDC login trustworthy: rejecting alg 'none' and symmetric algorithms, unadvertised algorithms, unknown kids, invalid signatures, wrong issuer/audience/azp, expired exp, and mismatched nonce. The only ID-token test in companion/tests/http/oidcClient.test.ts validates one correctly signed RS256 token (the happy path); the second test only covers browser-state binding and state reuse before any token is fetched. Not one test presents a token that must be REFUSED. If any of these checks regresses — e.g. the algorithm allowlist regex is loosened, the `validSignature` result stops being checked, or the nonce comparison is dropped — every test stays green while OIDC login becomes forgeable, which is account takeover for any team deployment.

**Evidence:**
```
if (algorithm === "none" || !/^(?:RS|PS|ES)(?:256|384|512)$|^EdDSA$/.test(algorithm)) {
      throw new Error(`OIDC ID token algorithm ${algorithm} is unsupported`);
    }
```

**Fix:** Extend companion/tests/http/oidcClient.test.ts, reusing its existing mock-IdP fetchFn and generateKeyPairSync helper: (1) token endpoint returns an id_token signed with a DIFFERENT RSA key — expect client.complete() to reject with /signature/; (2) header {alg:'none', kid:'key-1'} with empty signature — expect /unsupported/; (3) alg HS256 — expect /unsupported/; (4) correctly signed token whose nonce claim is 'wrong-nonce' — expect /nonce/; (5) aud 'other-client' — expect /audience/; (6) exp = now - 3600 — expect /expired/. Each case is ~10 lines using the existing encode() helper.

**Status:** Fixed in d566a138.

### TC-2 — POST /auth/bootstrap refusal branches (wrong token 403, already-bootstrapped 409, loopback fallback) are untested  `HIGH`

**Location:** `companion/src/auth/authRoutes.ts:189`

The bootstrap route hands out the FIRST global administrator account on an empty identity store. Both call sites in tests (companion/tests/http/teamAuth.test.ts:67, companion/tests/http/loginRateLimit.test.ts:39) send the CORRECT bootstrap token and assert 201. No test asserts the 403 on a wrong or missing token, the 409 once an identity exists, or the loopback-only fallback (`auth.isLoopbackRequest`) that gates bootstrap when no token is configured — the exact branch that decides whether a remote unauthenticated caller can seize an empty store and become admin. A regression that inverts or weakens `bootstrapAllowed` (or makes `bootstrapTokenMatches('')` succeed) would pass the entire suite.

**Evidence:**
```
const bootstrapAllowed = auth.bootstrapToken
      ? auth.bootstrapTokenMatches(suppliedToken)
      : auth.isLoopbackRequest(req);
    if (!bootstrapAllowed) return res.status(403).json({ error: "valid bootstrap token required" });
```

**Fix:** Add to companion/tests/http/teamAuth.test.ts (the app fixture already exists): (1) POST /auth/bootstrap with bootstrapToken:'wrong-token' → expect 403 and authStore.countIdentities() === 0; (2) same with no bootstrapToken field → 403; (3) after a successful bootstrap, a second POST with the CORRECT token → 409 and still exactly one identity. For the loopback fallback, unit-test TeamAuth.isLoopbackRequest directly (it only reads req.socket.remoteAddress): fake requests with remoteAddress '10.0.0.5' → false, '127.0.0.1'/'::1'/'::ffff:127.0.0.1' → true, undefined → false.

**Status:** Fixed in d566a138.

### TC-3 — writerGuard's corrupt-guard branches and release-must-not-delete-another-writer's-guard property are untested  `MEDIUM`

**Location:** `companion/src/auth/writerGuard.ts:90`

acquireWriterGuard enforces one team-mode writer per cases root — the safeguard against two processes interleaving writes into the same case store. companion/tests/http/teamAuthRuntime.test.ts covers the second-writer refusal and stale-guard recovery for a VALID record with a dead pid, but three branches are unexercised: (a) an unparseable guard file with fresh mtime (< 30s) must throw the 'incomplete; retry' error rather than being deleted mid-write by a racing starter; (b) an unparseable guard with old mtime must be recovered; (c) release() uses removeIfUnchanged, so releasing must NOT delete a guard file whose contents were replaced by another writer — the classic unlock-safety property. If someone 'simplifies' release() to unlinkSync, all current tests pass while a released stale handle can delete an active writer's guard, letting a third process acquire and yielding two concurrent writers.

**Evidence:**
```
if (!existing && Date.now() - statSync(path).mtimeMs < 30_000) {
        throw new Error("the team-mode writer guard is incomplete; retry startup in a few seconds");
      }
      removeIfUnchanged(path, existingText);
```

**Fix:** Extend companion/tests/http/teamAuthRuntime.test.ts: (1) writeFile(path, 'not-json'); expect acquireWriterGuard(path) to throw /incomplete/; (2) utimes(path, ...) to set mtime 60s in the past; expect acquireWriterGuard to succeed and overwrite; (3) guard = acquireWriterGuard(path); writeFile(path, JSON.stringify({pid: process.pid, token: 'other-writer', startedAt: '...'})); guard.release(); expect readFile(path) to still return the replacement contents (file not deleted).

**Status:** Fixed in d566a138.

### TC-4 — checkRegexSafety's case-fold range branch is untested — its own suite never passes flags at all  `MEDIUM`

**Location:** `companion/src/analysis/regexSafety.ts:101`

checkRegexSafety guards every user-authored regex that later runs against event text (importer match rules, tagger rules, IOC whitelist/exclude — the latter two hard-code the 'i' flag at iocWhitelist.ts:139 and iocExclude.ts:100). The module's foldCase exists solely for the 'i' flag, and its docblock records a measured 4831ms blow-up for a pattern that is only ambiguous under folding. Yet companion/tests/analysis/regexSafety.test.ts never passes a flags argument to any call; the single indirect test (huntQueryParser.test.ts:114, '^(a|A)+b$') exercises only the literal-chars branch of foldCase. The RANGE-folding arithmetic (mapping [a-z]<->[A-Z] with the ±32 offsets) has no coverage anywhere: if it regresses, a pattern like '([a-z]|[A-Z])+' is accepted under 'i' and a saved IOC-whitelist rule then hangs the event loop on every subsequent match pass.

**Evidence:**
```
const ranges: [number, number][] = [...s.ranges];
  for (const [lo, hi] of s.ranges) {
    const lower: [number, number] = [Math.max(lo, 0x61), Math.min(hi, 0x7a)]; // a-z
    if (lower[0] <= lower[1]) ranges.push([lower[0] - 32, lower[1] - 32]);
```

**Fix:** Add a 'checkRegexSafety — i-flag folding' describe block to companion/tests/analysis/regexSafety.test.ts: expect(checkRegexSafety('^(a|A)+b$', 'i').ok).toBe(false) and .toBe(true) without the flag; expect(checkRegexSafety('^([a-z]|[A-Z])+!$', 'i').ok).toBe(false) (range branch) and true without the flag; expect(checkRegexSafety('^[a-z]*[A-Z]*$', 'i').ok).toBe(false) (adjacent-loop overlap under folding) and true without.

**Status:** Fixed in d566a138.

### TC-5 — archiveIsEncrypted crashes with a raw RangeError on a crafted central-directory offset — no corrupt-EOCD test exists  `LOW`

**Location:** `companion/src/analysis/zipExtract.ts:72`

extractZipEntries calls archiveIsEncrypted before readZip's guarded parser ever runs, and the central-directory pointer read at line 71 (`ptr = archive.readUInt32LE(eocd + 16)`) is attacker-controlled. A zip whose EOCD declares total=1 with an out-of-bounds offset makes `archive.readUInt32LE(ptr)` throw ERR_OUT_OF_RANGE — verified by running the function against a 34-byte crafted buffer: it threw `RangeError: The value of "offset" is out of range... Received 4294967040`. The tools run-upload route catches it (routes/tools.ts:152-154), so the analyst receives a 400 whose body is Node's internal offset message and an import-failure record naming it — not the actionable 'corrupt ZIP' wording every other malformed-archive path produces. zipExtract.test.ts covers passwords, zip-slip, nesting, and truncation, but never a structurally corrupt central directory, so this branch is invisible to the suite.

**Evidence:**
```
let ptr = archive.readUInt32LE(eocd + 16);
  for (let i = 0; i < total; i++) {
    if (archive.readUInt32LE(ptr) !== 0x02014b50) return false;
```

**Fix:** Keep the proposed test in companion/tests/analysis/zipExtract.test.ts, but guard BOTH functions: in archiveIsEncrypted (zipExtract.ts:71), add `if (ptr + 46 > archive.length) return false;` at the top of the loop body; and in readZip (zipArchive.ts:178-179), add `if (ptr + 46 > archive.length) throw new Error("corrupt ZIP: central directory out of bounds");` before the SIG_CENTRAL read (and ideally the same bound on localOffset + 30 before the local-header reads at lines 193-194). Only with the readZip guard does the analyst get the actionable 'corrupt ZIP' wording instead of Node's internal RangeError message.

**Status:** Fixed in d566a138.


### Second pass (2026-08-21)

The first pass's five gaps (TC-1..TC-5) are genuinely closed, and most of this branch's fix commits arrived with their behavior pinned: `parseSyslogProgress`'s abort/progress contract (`companion/tests/analysis/syslogImport.test.ts`), all three `tesseractDataOptions` resolution branches (`ocrRedact.test.ts`), the `client_info() FROM scope()` projection in `getFlowInfo` (`tests/integrations/velociraptor.test.ts`), the backfill per-line skip (`tests/composition/backfillCaptureLog.test.ts`), the host-scope decision throw (`tests/dashboard/hostScopePanel.test.ts`), and the extracted `clientInventory.ts`/`veloMessageFields.ts`/`bsdTime.ts` modules all keep their pre-move coverage through re-exports. What remains untested clusters where a fix introduced a NEW invariant without a test to guard it — the consolidated IP classifier's IPv4-shape requirement in `siemImport.ts`, the asset-graph generation token in `public/js/dashboard-asset-graph.js`, and `huntQueryParser.ts`'s rewritten position arithmetic — plus one residual crash branch (`zipArchive.ts`'s local-header offset) that the TC-5 guard demonstrably does not reach. `docker-entrypoint.sh`'s run-as-mount-owner and confined-chown logic is POSIX shell and outside vitest's reach; its ~25 external-review fixes remain manually verified only.

#### TC2-1 — isPublicIpv4's IPv4-shape requirement (blank/IPv6 logon sources count as internal) is pinned by zero tests — the naive-negation regression the code's own comment forbids passes the whole suite  `MEDIUM`

**Location:** `companion/src/analysis/siemImport.ts:815`

The DUP-1 consolidation rewrote isPublicIpv4 as a thin wrapper over the new shared isInternalIpv4, and both its comment (siemImport.ts:812-813) and internalIp.ts:6-8 warn that it must stay "IPv4-shaped AND not internal", never a plain !isInternalIpv4 — because isInternalIpv4 returns false (not-internal) for non-IPv4 strings. But no test anywhere exercises that property: the logonRisk suite (companion/tests/analysis/siemImport.test.ts:84-112) feeds only IPv4-shaped sources for types 3/10 (the empty-string calls are types 8/9, which are Medium unconditionally), the mapWindows end-to-end tests use "203.0.113.9" and "::ffff:10.10.200.11" (which cleanIp normalizes to IPv4 before logonRisk sees it), loginGraph.test.ts uses only IPv4s, and no test references isInternalIpv4 at all. If someone "simplifies" line 815 to `!isInternalIpv4(ip)` — the exact cleanup the comment forbids, natural now that the shared classifier sits one import away — every one of the 9,962 tests stays green while logonRisk grades every blank-source 4624 type-3 logon (IpAddress "-" is routine for local/service logons; cleanIp maps it to "") and every routable-IPv6 source (which cleanIp deliberately keeps, siemImport.ts:629) as an internet-facing logon: Medium + T1078, silently flooding the forensic timeline that AI synthesis reads with false external-access findings. The shared classifier's own range boundaries (172.15 vs 172.16, 100.63 vs 100.64, 0/8, 169.254) also have no direct unit spec — only CGNAT/0-8 are pinned indirectly via one emailImport Received-walk test.

**Evidence:**
```
// so this must stay "IPv4-shaped AND not internal", never a plain !isInternalIpv4 (which would call
// a blank/IPv6 source public and make logonRisk grade e.g. a blank-source type-3 logon external).
function isPublicIpv4(ip: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip.trim()) && !isInternalIpv4(ip);
}
```

**Fix:** Two small additions. (1) In companion/tests/analysis/siemImport.test.ts's "logonRisk — logon-type grading" describe, pin the shape requirement through the public surface: `expect(logonRisk(3, "").severity).toBeUndefined()` and `expect(logonRisk(3, "").mitre).toEqual([])`; same for logonRisk(3, "2001:db8::5") and logonRisk(10, "2001:db8::5") (typeName decoded, severity undefined); plus one mapWindows end-to-end case `parseSiemExport(elastic(logon4624("3", "-")))` asserting severity "Low" and mitreTechniques []. (2) Add companion/tests/analysis/internalIp.test.ts unit-speccing isInternalIpv4's full table: true for 10.0.0.1, 127.0.0.1, 0.1.2.3, 192.168.1.1, 172.16.0.1, 172.31.255.255, 169.254.10.10, 100.64.0.1, 100.127.255.255; false for the boundary neighbours 172.15.255.255, 172.32.0.1, 100.63.255.255, 100.128.0.1, 192.169.0.1, and for non-IPv4 inputs "", "-", "::1", "2001:db8::5", "10.0.0" (documenting that false means "not internal IPv4", not "public").

**Status:** Open

#### TC2-2 — The asset-graph generation-token race guard (commit 8f10ebd3) has no test — the harness can pin the out-of-order-response behavior but no test loads dashboard-asset-graph.js at all  `MEDIUM`

**Location:** `public/js/dashboard-asset-graph.js:39`

Commit 8f10ebd3 added assetGraphLoadSeq to loadAssetGraph so that when an analyst switches cases fast, a stale request's late response (success OR failure) cannot overwrite the newer case's graph, and so that the LATEST load's failure clears the cached graph instead of leaving the previous case's assets on screen with hasAssetGraph() wrongly true. None of this is tested: no file in companion/tests loads dashboard-asset-graph.js (hostFacetMerge.test.ts stubs assetOverrideMerges directly, and the only other mentions are comments), so both new branches — `seq !== assetGraphLoadSeq → ignore` and `!g || !Array.isArray(g.assets) → clear + repaint` — plus hasAssetGraph()'s trust in that state are invisible to the suite. The sibling fix from the same commit series (dashboard-host-scope.js's decideHostScope throw) DID get harness tests in hostScopePanel.test.ts, proving the vm-based loadDashboardModule pattern handles exactly this module shape (stubbed fetch + document). If the token logic regresses — e.g. a refactor to async/await drops the seq capture, or moves the ++ after the fetch — fast case switches silently paint case A's assets and IOC edges over case B again (cross-case evidence displayed under the wrong case id), and every test stays green. The module is load-clean (no module-scope DOM access; assetTypesEnabled is a local Set), so the test needs only fetch, document.getElementById, and DfirTimelineView stubs.

**Evidence:**
```
    const seq = ++assetGraphLoadSeq;
    fetch(`/cases/${caseId}/asset-graph${DfirTimelineView.timeQuery()}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((g) => {
        if (seq !== assetGraphLoadSeq) return; // superseded by a newer load — ignore entirely
        if (!g || !Array.isArray(g.assets)) {
          assetGraphData = null;
          renderAssetGraph();
          renderAssetList();
          return;
        }
        assetGraphData = g;
```

**Fix:** Add companion/tests/dashboard/assetGraphPanel.test.ts following hostScopePanel.test.ts's pattern: `loadDashboardModule<{loadAssetGraph(id: string): void; hasAssetGraph(): boolean; assetGraphAssets(): Array<{name: string}>}>("dashboard-asset-graph.js", ["dashboard-escape.js"], { fetch: fetchStub, document: { getElementById: () => ({ innerHTML: "", textContent: "", style: {} }), querySelectorAll: () => [] }, DfirTimelineView: { timeQuery: () => "" } })` where fetchStub records a manually-resolvable deferred per call. Three tests: (1) out-of-order success — call loadAssetGraph("case-a") then loadAssetGraph("case-b"); resolve B's deferred with `{ok: true, json: async () => ({assets: [{name: "b-host", type: "host", compromised: false}], iocs: [], edges: []})}`, flush microtasks, then resolve A with an a-host graph; assert assetGraphAssets() still returns b-host and hasAssetGraph() is true. (2) stale failure ignored — resolve the OLD load with `{ok: false}` after the new one succeeded; assert the graph survives. (3) latest failure clears — a single loadAssetGraph whose response is `{ok: false, json: async () => ({error: "boom"})}`; assert hasAssetGraph() returns false and assetGraphAssets() is empty (the error body must never be cached as graph data).

**Status:** Open

#### TC2-3 — readZip's local-header offset is unguarded and untested — a crafted zip passes the new TC-5 EOCD guard and still surfaces Node's raw ERR_OUT_OF_RANGE (demonstrated)  `LOW`

**Location:** `companion/src/analysis/zipArchive.ts:193`

The TC-5 fix bounded the central-directory pointer in archiveIsEncrypted (zipExtract.ts:73) with two tests, but its own fix text also called for the same bound "on localOffset + 30 before the local-header reads at lines 193-194" — and the fix commit never touched zipArchive.ts. The gap is real today, not speculative: I built a zip via the repo's own createZip, overwrote the central record's relative-offset-of-local-header field (ptr+42) with 0xffffff00, and called extractZipEntries — archiveIsEncrypted's guard passes (the central record itself is in bounds, signature and flags valid), then readZip line 193 throws `RangeError ERR_OUT_OF_RANGE: The value of "offset" is out of range. It must be >= 0 and <= 125. Received 4294967066`. Through the tools run-upload route (composition/externalTools.ts:256 → routes/tools.ts catch) the analyst again receives Node's internal offset message instead of the actionable "corrupt ZIP" wording — exactly the failure mode TC-5 existed to eliminate. readZip's own ptr walk (line 179) is also unguarded for its second caller, caseExportArchive.ts:496, which never runs archiveIsEncrypted first. No test in zipExtract.test.ts or zipArchive.test.ts crafts a bad localOffset, so the branch is invisible to the suite.

**Evidence:**
```
    // Jump to the local header to find the actual data start (its name/extra lengths may differ).
    const localNameLen = archive.readUInt16LE(localOffset + 26);
    const localExtraLen = archive.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
```

**Fix:** In readZip, add two bounds inside the walk loop: `if (ptr + 46 > archive.length) throw new Error("corrupt ZIP: central directory out of bounds");` before the SIG_CENTRAL check at line 179 (covers the caseExportArchive.ts caller that skips archiveIsEncrypted), and `if (localOffset + 30 > archive.length) throw new Error("corrupt ZIP: local header out of bounds");` before line 193. Then add the test that demonstrated the defect to companion/tests/analysis/zipExtract.test.ts, mirroring the two existing crafted-EOCD tests: build createZip([{path: "sample.bin", data: Buffer.from("payload")}]), locate the EOCD (0x06054b50 scan), read the central-directory start from eocd+16, overwrite the localOffset field with `archive.writeUInt32LE(0xffffff00, ptr + 42)`, and expect extractZipEntries to throw /corrupt ZIP: local header/i — currently it throws the raw RangeError, so the test fails until the guard lands.

**Status:** Open

#### TC2-4 — location()'s binary-search rewrite (PF-2 fix) is only pinned at line 1, column 1 — no test asserts a multi-line or mid-line error position that could catch an off-by-one  `LOW`

**Location:** `companion/src/analysis/huntQueryParser.ts:108`

The PF-2 fix replaced location()'s trivially-correct slice/split with a precomputed newline-offset array, a one-slot module-level memo (newlineMemoText/newlineMemoOffsets), and hand-rolled binary-search arithmetic (`line: low + 1`, `lineStart = newlines[low-1] + 1`, `column: offset - lineStart + 1`). The fix's stated contract was "keeps error-path syntaxError() positions identical", but the only position assertion in companion/tests/analysis/huntQueryParser.test.ts is `line: 1, column: 1` for an error at offset 0 — the degenerate case that almost any wrong formula still satisfies (both `<` and `<=` in the comparison, and ±1 slips in lineStart, all produce 1/1 there). These positions are analyst-facing: hunt-workbench.js:325 renders `"— line ${typed.line}, column ${typed.column}"` next to the query editor on POST /hunt-query/validate and /execute failures. A regression in the comparison direction, the lineStart derivation, or a memo-staleness bug across consecutive parses of different texts would silently point every multi-line error at the wrong place while the entire suite stays green.

**Evidence:**
```
  let low = 0;
  let high = newlines.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (newlines[mid] < offset) low = mid + 1;
    else high = mid;
  }
  const lineStart = low === 0 ? 0 : newlines[low - 1] + 1;
  return { line: low + 1, column: offset - lineStart + 1 };
```

**Fix:** Extend companion/tests/analysis/huntQueryParser.test.ts with three verified cases (I probed each against the actual parser — two of the originally proposed inputs do not behave as described): (1) multi-line: parseHuntQuery("source.ip=192.0.2.1\n| group by sorce.ip") throws code "unknown_field" at { line: 2, column: 12 } — note the grammar is `| group by <field>`; the originally proposed "| group_by sorce.ip" instead throws unknown_stage at line 2, column 3 (usable as a second pin if wanted, but not for the field column). (2) first-line non-1 column: parseHuntQuery("source.ip=192.0.2.1 and sorce.ip=10.0.0.1") throws "unknown_field" at { line: 1, column: 25 } — the originally proposed "severity=Zigh" parses successfully (severity values are not validated at parse time) and must not be used. (3) memo staleness: in one test, parseHuntQuery("host.name=a\nand sorce.ip=1") throws at { line: 2, column: 5 }, then parseHuntQuery("host.name=a and\nsorce.ip=1") throws at { line: 2, column: 1 } — same error token, different newline layouts, pinning that newlineOffsets' one-slot memo re-keys on the second text. Each follows the existing try/catch + toMatchObject pattern at huntQueryParser.test.ts:62-75.

**Status:** Open


## 5. Performance Concerns in VQL/Parsing Logic

Parsing and VQL-adjacent code is largely in good shape: the Plaso/CSV pipeline streams multi-hundred-MB super-timelines with bounded memory (`companion/src/analysis/plasoImport.ts` + `csvImport.ts`), the hunt-query executor enforces scanned-row/duration/group/regex budgets with paged SQLite reads (`companion/src/analysis/huntQueryExecutor.ts`), and cross-source correlation uses hash-bucketed union-find instead of pairwise scans (`correlate.ts`). The remaining defects cluster in two patterns: per-row `new RegExp` construction inside million-iteration import loops, and one line-based importer (`syslogImport.ts`) that still materializes every mapped line before aggregating — the exact OOM pattern the Plaso path was rebuilt to avoid, on the same `/import-file` route that explicitly advertises 400 MB+ files. Note: there is no Python source in this repository (the only .py files are vendored under node_modules), so this dimension covers the TypeScript server only.

### PF-1 — parseSyslog materializes every line and mapped event in memory — ~3x input size retained, fully synchronous  `HIGH`

**Location:** `companion/src/analysis/syslogImport.ts:246`

parseSyslog splits the whole file into a lines array AND pushes one MappedEvent per parsed line into `mapped[]` before aggregating, in one synchronous loop with no event-loop yields. Measured: 1M realistic syslog lines (105 MB text) retain an additional ~323 MB of heap for lines[]+mapped[] (~3x input). The /cases/:id/import-file route reads non-Plaso files up to V8's ~512 MB string limit (routes/import.ts:591-601 explicitly supports 400 MB+ files), so a near-limit syslog import peaks around 1.5-2 GB heap — an OOM kill in a memory-limited container — and blocks the event loop for the entire multi-million-line parse (tens of seconds during which every other request stalls). The streaming infrastructure to fix this already exists: createEventAggregator in siemImport.ts was built exactly so callers 'can feed events one at a time without ever materializing the full mapped[] array', and parsePlasoCsv/parsePlasoFromLines use it; parseSyslog does not, because its SSH brute-force post-pass mutates specific mapped entries.

**Evidence:**
```
for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const p = parseSyslogLine(line, year);
    if (!p) continue;
    const m = mapParsedSyslog(p, sink);
    total++;
    const idx = mapped.push(m) - 1;
```

**Fix:** Split the fix in two: (1) inside the existing sync parseSyslog, replace text.split() with an indexOf('\n') cursor loop and feed non-sshd-auth events straight into createEventAggregator(), buffering only the events parseSshAuth matches in a side array keyed by buffer index; after the loop run markSshBruteForce over that buffer, agg.add() the buffered events, then agg.finish() — this delivers the full memory win without touching the signature (finish() re-sorts severity/count/timestamp, so ordering only shifts on exact three-way ties where stable-sort insertion order decides). (2) For the event-loop yield, add an async parseSyslogProgress variant (mirroring the parseWinEventXml / parseWinEventXmlProgress pair in evtxXmlImport.ts) that yields via setImmediate every ~5000 lines, and switch the import route/logImports path to it, leaving the sync export intact for tests and other callers.

**Status:** Fixed in 236d1642.

### PF-2 — Hunt-query tokenizer is O(n²): location() re-slices and re-splits the whole prefix for every token  `MEDIUM`

**Location:** `companion/src/analysis/huntQueryParser.ts:152`

tokenize()'s push() calls location(text, start) for EVERY token, and location() does `text.slice(0, offset).split("\n")` — O(prefix length) work plus an array allocation of all prefix lines per call. For single-line queries V8's sliced strings keep this cheap (~8 ms), but the cost explodes with newline count: a measured 20,000-char query (exactly MAX_QUERY_LENGTH) with one token per line takes ~1.0 second of synchronous CPU in location() calls alone — a 1s event-loop stall per request from a fully in-limits query. parseHuntQuery runs on POST /cases/:id/hunt-query/validate (fired by the dashboard editor), /execute, and two more routes (huntWorkbench.ts:130,165,245,261), so one analyst tab — or one scripted client — repeatedly submitting a multi-line query degrades the whole server.

**Evidence:**
```
const push = (kind: TokenKind, value: string, start: number, end: number, flags?: string): void => {
    const at = location(text, start);
```

**Fix:** Prefer the finding's second variant: precompute the newline-offset array once per tokenize()/parse and binary-search it in location(). The incremental line/lineStart variant is also viable but must additionally count newlines inside spans the main loop jumps over (quoted strings admit literal newlines via decodeQuoted, and regex/parameter scans also advance index in bulk), so it is easier to get subtly wrong; the offset-array approach has no such hazard and keeps error-path syntaxError() positions identical.

**Status:** Fixed in f27c41d9.

### PF-3 — evtxXmlImport compiles ~8 dynamic RegExps per event block across millions of events  `MEDIUM`

**Location:** `companion/src/analysis/evtxXmlImport.ts:57`

elText() and attr() build a `new RegExp` from a template literal on every call, and parseEventBlock() calls them ~8 times per event (EventID, Channel, Computer, Level, EventRecordID + Provider/Name, TimeCreated/SystemTime, Security/UserID) — all from a closed, fixed set of tag/attribute names. A Windows Event Log XML export routinely holds hundreds of thousands to millions of events (files up to the ~512 MB import limit), so this is millions of regex-source string builds + RegExp allocations per import. Measured on 200k realistic System blocks: 1.04 s with per-call construction vs 0.51 s with cached patterns — a 2x slowdown of the per-event field extraction plus sustained GC churn on the import path (parseWinEventXmlProgress yields every 250 events, so the cost is throughput and GC pressure, stretching large imports by tens of seconds).

**Evidence:**
```
function elText(block: string, tag: string): string {
  const m = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, "i").exec(block);
```

**Fix:** Memoize the patterns: a module-level `Map<string, RegExp>` keyed by tag (for elText) and `${element}|${attrName}` (for attr), populated on first use — or simply hoist the 8 concrete patterns as named constants since the call sites are a closed set. While in the file, also replace `(text.match(/<Event\b/gi) ?? []).length` at line 149 with a counting exec/matchAll loop so counting events in a multi-hundred-MB export stops allocating a throwaway array with one string per event.

**Status:** Fixed in f27c41d9.

### PF-4 — fieldFromMessage rebuilds an escaped RegExp for each of ~15 fixed labels on every Velociraptor row  `LOW`

**Location:** `companion/src/analysis/velociraptorImport.ts:184`

fieldFromMessage() escapes the label and constructs a new RegExp on every call, and salientFromMessage() invokes it for all 15 MSG_FIELD_LABELS per row message (plus parsedNewProcess's two more), from per-row mappers (lines 727, 788, 835). Every label is a compile-time constant, so the escape replace() and RegExp construction are pure waste: with the collect row cap of 100,000 rows (DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS default) an ingest performs ~1.7M escape+construct cycles — roughly a second of extra CPU plus allocation churn per hunt import, repeated for every Sigma/detection artifact read.

**Evidence:**
```
function fieldFromMessage(msg: string, label: string): string {
  const re = new RegExp(`${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:[ \\t]*([^\\r\\n]+)`, "i");
```

**Fix:** Precompile once at module level: `const MSG_FIELD_RES = new Map(LABELS.map((l) => [l, new RegExp(escaped(l) + pattern, "i")]))` covering MSG_FIELD_LABELS plus "New Process Name" and "Image"; fieldFromMessage() then does a Map lookup with a lazy-compile fallback for any future dynamic label. No behavior change.

**Status:** Fixed in f27c41d9.

### PF-5 — getFlowInfo enumerates the entire fleet (up to 100k clients via subprocess) to resolve one hostname  `LOW`

**Location:** `companion/src/integrations/velociraptor/velociraptorApi.ts:872`

getFlowInfo() — the external-flow import path — resolves a single already-known clientId's hostname by calling listClients(), which spawns the velociraptor binary, runs `SELECT client_id, os_info, last_seen_at FROM clients() LIMIT 100000`, and parses the full fleet inventory through the 256 MB collect output cap, only to `.find()` one record. On a large estate (thousands to tens of thousands of enrolled clients) that is a multi-second subprocess round-trip and a multi-MB JSONL parse per external-flow import, when a single-row targeted query would do. listClients() results are also uncached (unlike the artifact catalog, which got a 45 s TTL cache for exactly this spawn cost).

**Evidence:**
```
const rec = (await this.listClients()).find((c) => c.clientId === clientId);
```

**Fix:** Fetch just the one client: `SELECT os_info FROM clients(search='id:${clientId}') LIMIT 1` (or `client_info(client_id='${clientId}')`) — clientId is already CLIENT_RE-validated at the top of getFlowInfo, so interpolation stays injection-safe, and the dot-tokenization concern that motivated inventory matching applies to hostname search, not id lookup. Alternatively reuse the persisted client inventory the collect route already prefers before falling back to the live read.

**Status:** Fixed in f27c41d9.


### Second pass (2026-08-21)

The first pass's five performance fixes hold up well under re-review: `huntQueryParser.ts`'s one-slot newline memo is correct under any call pattern (parsing is fully synchronous, every `location()` call in a parse passes the same string, and a text change merely recomputes), `veloMessageFields.ts` precompiles its label patterns with a sound lazy fallback, `evtxXmlImport.ts`'s memoized `elText`/`attr` maps carry no `lastIndex` state, and `getFlowInfo` now does a targeted `client_info()` lookup instead of enumerating the fleet. The second pass found one significant regression-shaped gap in the PF-1 streaming rework: `syslogImport.ts`'s accumulator buffers a full `MappedEvent` for every *failed* sshd auth line even though the brute-force correlation only ever rewrites *accepted* events — so the one input the feature targets (an auth.log flood) measured +526 MB peak and 2x parse time versus +2 MB for an equal-size non-sshd log. Two smaller residues of the same fixed classes remain: the hunt executor still compiles its `matches` RegExp per row (up to 50k throwaway compiles per query), and the evtx count loop the PF-3 fix introduced blocks the event loop ~0.4 s per 300 MB with no yield or abort check — the exact pattern commit b1360438 fixed for syslog's count. The other hunting grounds (`correlate.ts`, `superTimelineStore.ts`'s paged SQLite query, `huntQueryAggregation.ts`, `logAggregate.ts`, `veloRowNormalize.ts`, and the chainsaw/hayabusa/wazuh/k8s importers) came up clean.

#### PF2-1 — Syslog accumulator buffers a full MappedEvent for every failed sshd auth line — a brute-force flood defeats the PF-1 streaming fix (526 MB peak, 2x parse time, measured)  `HIGH`

**Location:** `companion/src/analysis/syslogImport.ts:238`

createSyslogAccumulator.line() holds back BOTH outcomes of parseSshAuth — accepted and failed — as full MappedEvents in sshEvents[] until finish(), but markSshBruteForce() can only ever rewrite ACCEPTED events (sshBruteForce.ts:95-108: the failed branch just records ms into failuresByIp and `continue`s; hits are pushed exclusively from the accepted branch). Failed lines therefore gain nothing from being buffered as events, yet they are the dominant content of exactly the input this correlation targets: an auth.log from an internet-facing host under password guessing is line after line of `Failed password for ... from ...`. Measured on the real route path (parseSyslogProgress): a 2M-line / 212 MB sshd failed-password flood peaks +526 MB RSS and parses in 39.1 s, versus +2 MB and 19.4 s for a same-size non-sshd flood that streams through the aggregator — i.e. for the most plausible large plain-syslog file in IR, the PF-1 materialization (~260 B/line retained plus doubled parse time from allocation/GC churn) is reintroduced, scaling to ~1.3 GB extra at the route's ~512 MB input limit — an OOM kill in a memory-limited container on the same /cases/:id/import-file route PF-1 was rated HIGH for.

**Evidence:**
```
if (/^sshd\b/i.test(p.app)) {
        const auth = parseSshAuth(p.message);
        if (auth) {
          sshAuth.push({
            key: sshEvents.push(m) - 1,
            ms: Date.parse(p.timestamp) || 0,
            ip: auth.ip,
            result: auth.result,
          });
          return;
        }
      }
      agg.add(m);
```

**Fix:** In line(), split by auth.result: for "failed", call agg.add(m) immediately (nothing ever rewrites a failed event) and push only the compact tuple { key: -1, ms, ip, result: "failed" } into sshAuth (markSshBruteForce never reads a failed event's key); keep buffering only "accepted" MappedEvents in sshEvents — bounded by real logins, which are rare. finish() is unchanged: markSshBruteForce hits still reference only accepted keys, so the rewrite/add of the accepted buffer works as today, and ordering stays within the already-documented three-way-tie tolerance of agg.finish()'s re-sort. Optionally go further and fold failures straight into a Map<ip, number[]> of timestamps as lines stream (markSshBruteForce builds exactly that internally), shrinking the flood's residual to raw numbers per IP; but eliminating the per-failure MappedEvent (description + aggKey strings dominate the 526 MB) is the essential, small diff.

**Status:** Open

#### PF2-2 — Hunt executor compiles the matches-predicate RegExp per row per evaluation — the one per-row compile the PF-3/PF-4 sweep missed  `LOW`

**Location:** `companion/src/analysis/huntQueryExecutor.ts:249`

compareScalar() constructs `new RegExp(String(expected ?? ""), predicate.regexFlags)` on every evaluation of a `matches` predicate, although the pattern and flags are per-query constants (a literal from the parsed AST or a resolved $parameter, already validated once by validateHuntRegex at parse time). With maxRegexEvaluations = 50,000 and maxScannedRows = 100,000, a single interactive /hunt-query/execute request performs up to 50k throwaway escape-free compiles of the same pattern: measured 61.4 ms vs 17.2 ms with a cached instance at the full budget — ~45 ms of pure compile waste plus 50k RegExp allocations of GC churn per query, repeated on every keystroke-driven /validate + /execute round-trip from the workbench. duringRange() in the same function similarly re-parses the constant time-window string and re-runs Date.parse(range.from/to) for every row of a `during` predicate. Same defect class as the fixed PF-3/PF-4, on the interactive VQL path instead of the import path.

**Evidence:**
```
return new RegExp(String(expected ?? ""), predicate.regexFlags).test(String(actual ?? ""));
```

**Fix:** Cache per execution in the existing EvaluationContext: add `regexCache: Map<string, RegExp>` (key `${pattern} ${flags}`) created once in executeHuntQuery's state, and in compareScalar look up/compile-once before .test(). Give `during` the same treatment by caching the resolved {fromMs, toMs} per expected-string in the context (the anchorTime is fixed for the whole execution), replacing the per-row duringRange + double Date.parse. No behavior change; both caches die with the request.

**Status:** Open

#### PF2-3 — parseWinEventXmlProgress's event-count loop blocks the event loop ~0.4-0.7 s with no yield or abort check — the exact gap the branch fixed for syslog's count loop  `LOW`

**Location:** `companion/src/analysis/evtxXmlImport.ts:171`

The PF-3 fix replaced the allocating `text.match(/<Event\b/gi)` count with a counting exec loop, but the loop runs fully synchronously before the parse loop's first await: no setImmediate yield and no throwIfImportAborted between the top-of-function check and the end of the count. Measured: 417 ms of uninterrupted event-loop block counting 1M events in a 309 MB export (~0.7 s at the route's ~512 MB limit), during which every other request and any pending job cancellation stalls. The branch itself established that this class must yield — commit b1360438 added SYSLOG_COUNT_CHUNK to parseSyslogProgress with the comment "it MUST yield, or a multi-million-line input would block the event loop (and any pending cancellation) for the whole count before the parse loop's first await" — and the identical reasoning applies verbatim to this sibling counting loop on the same import route.

**Evidence:**
```
let total = 0;
  const countRe = /<Event\b/gi;
  while (countRe.exec(text) !== null) total++;
```

**Fix:** Mirror the syslog count fix: every N matches (e.g. a COUNT_CHUNK of 100_000 — each iteration scans a whole event block, so a coarser budget than syslog's per-line 1M is appropriate) do `await new Promise<void>((resolve) => setImmediate(resolve)); throwIfImportAborted(signal);` inside the counting loop. ~5 lines, identical in shape to syslogImport.ts's SYSLOG_COUNT_CHUNK block.

**Status:** Open


## 6. Docker and Dependency Risks

The container story is mostly well-engineered: the 3-stage `Dockerfile` builds with `npm ci` against the lockfile and prunes dev deps, `.dockerignore` keeps evidence (`cases/`), `.env`, `node_modules`, and `.git` out of the build context, `docker-entrypoint.sh` uses `set -e`, quoted expansions, and `exec node` so the server runs as PID 1 with correct signal handling, and `docker-compose.yml` publishes the port to `127.0.0.1` only. The extension's production dependency surface audits clean, and no secrets are baked into the image or compose file. The gaps that remain are operational rather than architectural: the runtime stage never drops root (no `USER` directive) even though the process parses hostile forensic evidence and holds bind mounts back to the host, and `companion/package-lock.json` pins undici 8.3.0, which carries four HIGH advisories (including a TLS certificate-validation bypass) that a simple lockfile refresh within the existing `^8.3.0` range would clear. Image-level `HEALTHCHECK` and digest-pinned base tags round out the fix list.

### DD-1 — Runtime container runs as root: no USER directive in the final stage  `HIGH`

**Location:** `Dockerfile:71`

The runtime stage (line 40 onward) never issues a USER directive, so the Node server runs as root inside the container. This process parses untrusted forensic evidence (zip archives, images via sharp, OCR via tesseract.js — historically RCE-prone code paths), and the compose file bind-mounts /data/cases and /out back to the host. A compromise of the parser therefore executes as root, can overwrite dist/server.js for persistence, and can write root-owned files through the mounts — including tampering with the pre-built browser extension in /out that the operator is instructed to load unpacked into Chrome, turning a container compromise into a browser-extension compromise on the analyst's machine.

**Evidence:**
```
EXPOSE 4773
ENTRYPOINT ["dfir-entrypoint"]
(no USER directive appears anywhere in the file; the base node:22-slim image ships an unprivileged `node` user that is never used)
```

**Fix:** In the runtime stage, change the existing RUN to `RUN chmod +x /usr/local/bin/dfir-entrypoint && mkdir -p /data/cases /out && chown -R node:node /data /out` (leave /app root-owned and read-only so a compromised server cannot rewrite its own code), then add `USER node` before ENTRYPOINT. In docker-compose.yml, document pre-creating ./cases and ./addon on Linux so the bind mounts are writable by uid 1000 (or add user: "1000:1000"); the entrypoint's `cp ... || true` already tolerates a non-writable /out.

**Status:** Fixed in f1a45b61.

### DD-2 — Lockfile pins undici 8.3.0 and nanoid 5.1.11, each carrying HIGH npm advisories with in-range fixes  `HIGH`

**Location:** `companion/package.json:83`

`npm audit --omit=dev` in companion/ reports 2 HIGH production vulnerabilities. undici (a direct dependency, imported in companion/src/enrichment/tlsFetch.ts) is locked at 8.3.0, hit by 12 advisories including four HIGH: GHSA-vmh5-mc38-953g (TLS certificate validation bypass via dropped requestTls, CVSS 7.4 — directly relevant to a module named tlsFetch), GHSA-38rv-x7px-6hhq and GHSA-vxpw-j846-p89q (WebSocket DoS, CVSS 7.5), and GHSA-4cwx-7wf7-3272 (cross-user information disclosure / parse-time crash, CVSS 7.4). nanoid 5.1.11 (transitive via docx@9.7.1) is hit by GHSA-28wg-ghj8-5hjv (HIGH, infinite loop). All fixes land inside the existing semver ranges (`^8.3.0` admits undici 8.10.0; docx declares nanoid `^5.1.3`, and 5.1.16+ satisfies), so only the lockfile is stale — no breaking upgrade is required.

**Evidence:**
```
"undici": "^8.3.0",
(package-lock.json line 5691-5692: "node_modules/undici": { "version": "8.3.0" }; line 2907-2908: "node_modules/docx/node_modules/nanoid": { "version": "5.1.11" })
```

**Fix:** Run `npm update undici nanoid` (or `npm audit fix`) in companion/ and commit the refreshed package-lock.json — this brings undici to 8.10.0 and nanoid to >=5.1.16 with no package.json change needed. Optionally raise the floor in package.json to "undici": "^8.10.0" so future installs cannot resolve below the patched version.

**Status:** Fixed in f1a45b61.

### DD-3 — No HEALTHCHECK baked into the image; only compose users get liveness checks  `LOW`

**Location:** `Dockerfile:70`

The Dockerfile defines no HEALTHCHECK, so the image published to GHCR (referenced as ghcr.io/hasamba/dfir-companion:latest in docker-compose.yml) reports no health status when run with plain `docker run`, Portainer, Watchtower, or any non-compose orchestrator — a hung or crash-looping server looks 'Up'. The healthcheck exists only in docker-compose.yml (which probes /dashboard) and railway.toml (healthcheckPath = /health); standalone image consumers get neither. The server already exposes /health and the image already contains node with global fetch, so the check costs nothing.

**Evidence:**
```
EXPOSE 4773
ENTRYPOINT ["dfir-entrypoint"]
(no HEALTHCHECK instruction anywhere in the Dockerfile; docker-compose.yml lines 53-58 carry the only container-level healthcheck)
```

**Fix:** Add before ENTRYPOINT: HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||process.env.DFIR_PORT||4773)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" — checking PORT before DFIR_PORT because the entrypoint's remap is not visible to the healthcheck's environment.

**Status:** Fixed in f1a45b61.

### DD-4 — Base images use floating tags without digest pinning; compose pulls :latest  `LOW`

**Location:** `Dockerfile:11`

All three stages build FROM `node:22-slim` with no digest, so the same commit can produce different images on different days (new Node patch, new Debian snapshot), and a compromised or re-tagged upstream image would be pulled silently. This undercuts the .dockerignore header's stated goal of keeping the image 'lean & reproducible' and matters for a forensic tool whose builds may need to be attested. docker-compose.yml compounds it by naming `ghcr.io/hasamba/dfir-companion:latest`, so `docker compose pull` users get whatever was published most recently rather than a version matched to their checkout.

**Evidence:**
```
FROM node:22-slim AS companion-build
(likewise line 28 `FROM node:22-slim AS extension-build` and line 40 `FROM node:22-slim AS runtime`; docker-compose.yml line 21: image: ghcr.io/hasamba/dfir-companion:latest)
```

**Fix:** Pin one digest once (e.g. `FROM node:22-slim@sha256:<current digest> AS ...`, obtained via `docker buildx imagetools inspect node:22-slim`) and reuse it in all three stages with a comment noting the Node version it corresponds to; refresh it deliberately (Dependabot/Renovate handles this automatically). In docker-compose.yml, tag the GHCR image with the release version (e.g. `ghcr.io/hasamba/dfir-companion:0.34.0`) instead of `latest`.

**Status:** Fixed in f1a45b61.


### Second pass (2026-08-21)

After the first pass's DD-1..4 fixes plus the ~14 external-review iterations, this dimension is in strong shape. Production dependencies are now clean: `npm audit --omit=dev` reports **0 vulnerabilities** in `companion/` and **0 HIGH/CRITICAL** in `extension/` (undici/nanoid of DD-2 are refreshed within-range; the extension's vite/vitest/postcss advisories are dev-only and never ship). All three `Dockerfile` stages are digest-pinned (`node:22-slim@sha256:d649c27…`), and `docker-entrypoint.sh` was re-read end-to-end: its lexical/realpath split, `deny_chown` confinement (incl. the new `/opt` denial), dotenv override parsing, and the `KNOWN_STORES` list were all cross-checked against the server's own resolution (`authFactory.ts:22-23`, `server.ts:606`, `runtimeStores.ts`) and found consistent — the auth-hash, cases-root, and store-sibling derivations match on both symlinked and relative roots. One residual inconsistency remains in the healthcheck story: the baked `Dockerfile` probe was deliberately pointed at the auth-exempt `/health` (DD-3), but `docker-compose.yml:61` still probes the auth-gated `/dashboard`.

#### DD2-1 — Compose healthcheck probes auth-gated /dashboard, not /health — reports unhealthy under the recommended team mode  `LOW`

**Location:** `docker-compose.yml:61`

The DD-3 fix deliberately baked a Dockerfile HEALTHCHECK against /health because /health is the one endpoint exempt from both the host-check and the auth gate (PUBLIC_GET in companion/src/auth/policy.ts:14, HOST_CHECK_EXEMPT_PATHS in originGuard.ts:228). The compose healthcheck was left probing GET /dashboard, which is an AUTHENTICATED_SHELL (policy.ts:23). A compose healthcheck overrides the baked one, so compose users' liveness probe is the /dashboard one. In single-user mode (the shipped compose default) /dashboard returns 200 and the probe passes, but when the operator enables the multi-user config that railway.toml explicitly recommends for real cases (DFIR_AUTH_MODE=team), teamAuth.middleware() gates /dashboard: an unauthenticated request whose Accept header lacks text/html — exactly the case for the healthcheck's Node fetch(), which sends Accept: */* — takes the res.status(401).json(...) branch in teamAuth.ts:239 (not the HTML redirect). r.ok is then false, the probe exits 1, and Docker marks the fully-functional container permanently 'unhealthy' (which orchestrators like Portainer/Swarm may act on). The failure consequence is a healthy container reported unhealthy under the documented team-mode deployment.

**Evidence:**
```
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:4773/dashboard').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
```

**Fix:** In docker-compose.yml:61 change the probe URL from /dashboard to /health: test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:4773/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]. If also de-hardcoding the port, read it from the environment inside the Node one-liner exactly as the Dockerfile HEALTHCHECK does ('http://127.0.0.1:'+(process.env.PORT||process.env.DFIR_PORT||4773)+'/health') — compose's CMD exec form performs no shell expansion, so $DFIR_PORT in the URL string would not work.

**Status:** Open


## Finding Index

| ID | Severity | Location | Title |
|----|----------|----------|-------|
| EH-1 | MEDIUM | `companion/src/composition/captureAnalysis.ts:359` | AI-on backfill misreads a corrupt captures.jsonl as "no capture log" and silently skips the whole screenshot backlog |
| EH-2 | MEDIUM | `public/js/dashboard-host-scope.js:291` | Host-clearance decision failures are silently swallowed - the void'ed decideHostScope has no rejection or !ok handling |
| EH-3 | LOW | `public/js/dashboard-asset-graph.js:32` | loadAssetGraph misses the r.ok check its sibling has, caching an error body as graph data and wedging the panel silently |
| EH-4 | LOW | `extension/src/serviceWorker.ts:395` | Service-worker message handlers pass sendResponse to .then() with no rejection arm, leaving the popup with no answer on failure |
| DUP-1 | MEDIUM | `companion/src/analysis/emailImport.ts:490` | isPrivateIp re-implemented in 6 modules, with a drifted copy in emailImport that treats CGNAT and 0/8 as public |
| DUP-2 | MEDIUM | `companion/src/analysis/correlate.ts:38` | Severity-rank table { Critical: 0 … Info: 4 } duplicated 21+ times despite canonical SEVERITY_RANK export |
| DUP-3 | LOW | `companion/src/analysis/ciscoAsaImport.ts:93` | MONTHS lookup table copied in 4 importers and byte-identical year-less timestamp parser in syslog and Cisco ASA importers |
| DUP-4 | LOW | `companion/src/reports/reportTemplate.ts:46` | Dead exports in reportTemplate.ts: SECTION_LABELS and emptyReportTemplate have zero references repo-wide |
| DUP-5 | LOW | `companion/src/analysis/d3fendData.ts:124` | Four exported _reset*Cache test hooks are referenced by no test or source file |
| DUP-6 | LOW | `companion/src/analysis/iocAlias.ts:27` | resolveIocAlias is dead — stateMerge re-implements the alias lookup inline, dropping the trim normalization |
| TC-1 | HIGH | `companion/src/auth/oidcClient.ts:299` | OIDC ID-token verification has zero negative-path tests — a forged token regression would pass the suite |
| TC-2 | HIGH | `companion/src/auth/authRoutes.ts:189` | POST /auth/bootstrap refusal branches (wrong token 403, already-bootstrapped 409, loopback fallback) are untested |
| TC-3 | MEDIUM | `companion/src/auth/writerGuard.ts:90` | writerGuard's corrupt-guard branches and release-must-not-delete-another-writer's-guard property are untested |
| TC-4 | MEDIUM | `companion/src/analysis/regexSafety.ts:101` | checkRegexSafety's case-fold range branch is untested — its own suite never passes flags at all |
| TC-5 | LOW | `companion/src/analysis/zipExtract.ts:72` | archiveIsEncrypted crashes with a raw RangeError on a crafted central-directory offset — no corrupt-EOCD test exists |
| PF-1 | HIGH | `companion/src/analysis/syslogImport.ts:246` | parseSyslog materializes every line and mapped event in memory — ~3x input size retained, fully synchronous |
| PF-2 | MEDIUM | `companion/src/analysis/huntQueryParser.ts:152` | Hunt-query tokenizer is O(n²): location() re-slices and re-splits the whole prefix for every token |
| PF-3 | MEDIUM | `companion/src/analysis/evtxXmlImport.ts:57` | evtxXmlImport compiles ~8 dynamic RegExps per event block across millions of events |
| PF-4 | LOW | `companion/src/analysis/velociraptorImport.ts:184` | fieldFromMessage rebuilds an escaped RegExp for each of ~15 fixed labels on every Velociraptor row |
| PF-5 | LOW | `companion/src/integrations/velociraptor/velociraptorApi.ts:872` | getFlowInfo enumerates the entire fleet (up to 100k clients via subprocess) to resolve one hostname |
| DD-1 | HIGH | `Dockerfile:71` | Runtime container runs as root: no USER directive in the final stage |
| DD-2 | HIGH | `companion/package.json:83` | Lockfile pins undici 8.3.0 and nanoid 5.1.11, each carrying HIGH npm advisories with in-range fixes |
| DD-3 | LOW | `Dockerfile:70` | No HEALTHCHECK baked into the image; only compose users get liveness checks |
| DD-4 | LOW | `Dockerfile:11` | Base images use floating tags without digest pinning; compose pulls :latest |
| EH2-1 | MEDIUM | `public/js/dashboard-host-scope.js:228` | loadHostScope silently ignores a failed ledger read and keeps the previous case's clearance ledger on screen |
| EH2-2 | LOW | `public/js/dashboard-asset-graph.js:53` | loadAssetGraph's rejection arm bypasses the new generation-token clearing, leaving the stale cross-case graph the fix claims to prevent |
| DUP2-1 | MEDIUM | `companion/src/analysis/iocValue.ts:60` | The internal-IPv4 consolidation stopped short of iocValue.ts — the enrichment SSRF gate still treats CGNAT 100.64/10 as public |
| DUP2-2 | LOW | `companion/src/reports/attackLayer.ts:60` | DUP-2's sweep missed two more local severity-rank tables: inverted encodings in reports/attackLayer.ts and reports/iocBlocklist.ts |
| DUP2-3 | LOW | `companion/src/analysis/veloMessageFields.ts:30` | escapeRegExp is hand-rolled nine times across companion/src, including a fresh copy the branch carried into veloMessageFields.ts |
| DUP2-4 | LOW | `companion/src/routes/import.ts:335` | The streaming-import kind predicate (evtxxml || syslog) is copied five times across the import routes and the resume handler |
| DUP2-5 | LOW | `companion/src/analysis/siemImport.ts:1201` | The worst-severity comparator is still declared in nine files although siemImport.ts already exports it as worst() |
| TC2-1 | MEDIUM | `companion/src/analysis/siemImport.ts:815` | isPublicIpv4's IPv4-shape requirement (blank/IPv6 logon sources count as internal) is pinned by zero tests — the naive-negation regression the code's own comment forbids passes the whole suite |
| TC2-2 | MEDIUM | `public/js/dashboard-asset-graph.js:39` | The asset-graph generation-token race guard (commit 8f10ebd3) has no test — the harness can pin the out-of-order-response behavior but no test loads dashboard-asset-graph.js at all |
| TC2-3 | LOW | `companion/src/analysis/zipArchive.ts:193` | readZip's local-header offset is unguarded and untested — a crafted zip passes the new TC-5 EOCD guard and still surfaces Node's raw ERR_OUT_OF_RANGE (demonstrated) |
| TC2-4 | LOW | `companion/src/analysis/huntQueryParser.ts:108` | location()'s binary-search rewrite (PF-2 fix) is only pinned at line 1, column 1 — no test asserts a multi-line or mid-line error position that could catch an off-by-one |
| PF2-1 | HIGH | `companion/src/analysis/syslogImport.ts:238` | Syslog accumulator buffers a full MappedEvent for every failed sshd auth line — a brute-force flood defeats the PF-1 streaming fix (526 MB peak, 2x parse time, measured) |
| PF2-2 | LOW | `companion/src/analysis/huntQueryExecutor.ts:249` | Hunt executor compiles the matches-predicate RegExp per row per evaluation — the one per-row compile the PF-3/PF-4 sweep missed |
| PF2-3 | LOW | `companion/src/analysis/evtxXmlImport.ts:171` | parseWinEventXmlProgress's event-count loop blocks the event loop ~0.4-0.7 s with no yield or abort check — the exact gap the branch fixed for syslog's count loop |
| DD2-1 | LOW | `docker-compose.yml:61` | Compose healthcheck probes auth-gated /dashboard, not /health — reports unhealthy under the recommended team mode |
