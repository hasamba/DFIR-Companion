# DFIR Companion Reports + Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the accumulating investigation state into reports (Executive summary, Timeline, Findings, MITRE ATT&CK) exportable as Markdown, JSON, and CSV, and serve a live dashboard over WebSocket that updates as findings change (live mode) or renders on demand (batch mode).

**Architecture:** Pure render functions transform `InvestigationState` → Markdown / CSV strings (no I/O). A `ReportWriter` writes those into `reports/`. A WebSocket hub broadcasts state updates to connected dashboard clients; the pipeline calls the hub after each merge. A static dashboard page (served by the companion) renders timeline + findings + report and subscribes to updates. Live vs batch is purely a rendering/timing choice over the same state, controlled per case.

**Tech Stack:** Node.js 20+, TypeScript, `ws` (WebSocket), Vitest. Depends on Plans 1–2 (`InvestigationState`, `StateStore`, server).

This is Plan 3 of 4. Prerequisite: Plans 1–2 merged.

---

## File Structure

```
companion/src/
├── reports/
│   ├── markdown.ts      # renderMarkdownReport(state) -> string
│   ├── csv.ts           # findingsCsv/iocsCsv/timelineCsv(state) -> string
│   └── reportWriter.ts  # ReportWriter: writeAll(caseId) -> file paths
├── live/
│   └── hub.ts           # LiveHub: subscribe(caseId, ws), broadcast(state)
└── server.ts            # + GET /cases/:id/state, POST /cases/:id/report, WS upgrade
public/
└── dashboard.html       # static dashboard (timeline + findings + report, WS client)
```

**Responsibilities:** render functions are pure and unit-tested without disk. `ReportWriter` is the only piece that writes report files. `LiveHub` owns socket fan-out only.

---

## Task 1: Markdown report renderer

**Files:**
- Create: `companion/src/reports/markdown.ts`
- Test: `companion/tests/reports/markdown.test.ts`

Renders four sections from state. Findings sorted by severity (Critical→Info).

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("renderMarkdownReport", () => {
  it("renders all four sections", () => {
    const state = emptyState("c1");
    state.lastSummary = "Host WIN-01 compromised via phishing.";
    state.findings.push({ id: "f1", severity: "Critical", title: "Ransomware", description: "encryptor dropped",
      relatedIocs: ["i1"], mitreTechniques: ["T1486"], sourceScreenshots: ["000005_t.webp"],
      firstSeen: "2026-05-28T10:00:00.000Z", lastUpdated: "2026-05-28T10:05:00.000Z", status: "confirmed" });
    state.iocs.push({ id: "i1", type: "hash", value: "abc123", firstSeen: "2026-05-28T10:00:00.000Z" });
    state.timeline.push({ timestamp: "2026-05-28T10:00:00.000Z", windowSequence: 1,
      description: "Reviewed file system", sourceScreenshots: ["000005_t.webp"] });
    state.mitreTechniques.push({ id: "T1486", name: "Data Encrypted for Impact", findingIds: ["f1"] });

    const md = renderMarkdownReport(state);
    expect(md).toContain("## Executive Summary");
    expect(md).toContain("Host WIN-01 compromised");
    expect(md).toContain("## Timeline");
    expect(md).toContain("Reviewed file system");
    expect(md).toContain("## Findings");
    expect(md).toContain("Ransomware");
    expect(md).toContain("## MITRE ATT&CK");
    expect(md).toContain("T1486");
  });

  it("sorts findings by severity (Critical first)", () => {
    const state = emptyState("c1");
    const mk = (id: string, sev: "Critical" | "Low") => ({ id, severity: sev, title: id, description: "",
      relatedIocs: [], mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" as const });
    state.findings.push(mk("low1", "Low"), mk("crit1", "Critical"));
    const md = renderMarkdownReport(state);
    expect(md.indexOf("crit1")).toBeLessThan(md.indexOf("low1"));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/reports/markdown.test.ts`
Expected: FAIL — cannot resolve `markdown.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import type { InvestigationState, Severity } from "../analysis/stateTypes.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4,
};

export function renderMarkdownReport(state: InvestigationState): string {
  const lines: string[] = [];
  lines.push(`# Incident Report — ${state.caseId}`, "");

  lines.push("## Executive Summary", "");
  lines.push(state.lastSummary.trim().length > 0 ? state.lastSummary : "_No summary yet._", "");

  lines.push("## Timeline", "");
  if (state.timeline.length === 0) {
    lines.push("_No timeline entries yet._", "");
  } else {
    for (const t of state.timeline) {
      const shots = t.sourceScreenshots.length ? ` (evidence: ${t.sourceScreenshots.join(", ")})` : "";
      lines.push(`- **${t.timestamp}** — ${t.description}${shots}`);
    }
    lines.push("");
  }

  lines.push("## Findings", "");
  if (state.findings.length === 0) {
    lines.push("_No findings yet._", "");
  } else {
    const sorted = [...state.findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    for (const f of sorted) {
      lines.push(`### [${f.severity}] ${f.title} (${f.id})`);
      lines.push(f.description || "_no description_");
      if (f.relatedIocs.length) lines.push(`- IOCs: ${f.relatedIocs.join(", ")}`);
      if (f.mitreTechniques.length) lines.push(`- MITRE: ${f.mitreTechniques.join(", ")}`);
      if (f.sourceScreenshots.length) lines.push(`- Evidence: ${f.sourceScreenshots.join(", ")}`);
      lines.push(`- Status: ${f.status} | First seen: ${f.firstSeen} | Updated: ${f.lastUpdated}`, "");
    }
  }

  lines.push("## MITRE ATT&CK", "");
  if (state.mitreTechniques.length === 0) {
    lines.push("_No techniques mapped yet._", "");
  } else {
    lines.push("| Technique | Name | Findings |", "| --- | --- | --- |");
    for (const t of state.mitreTechniques) {
      lines.push(`| ${t.id} | ${t.name} | ${t.findingIds.join(", ")} |`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/reports/markdown.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/reports/markdown.ts companion/tests/reports/markdown.test.ts
git commit -m "feat: add markdown report renderer"
```

---

## Task 2: CSV renderers

**Files:**
- Create: `companion/src/reports/csv.ts`
- Test: `companion/tests/reports/csv.test.ts`

Three CSV strings: findings, IOCs, timeline. Fields are quoted and internal quotes doubled (RFC-4180-ish escaping), no external CSV dependency.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from "vitest";
import { findingsCsv, iocsCsv, timelineCsv } from "../../src/reports/csv.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("CSV renderers", () => {
  it("findingsCsv has a header and one row per finding, escaping commas/quotes", () => {
    const state = emptyState("c1");
    state.findings.push({ id: "f1", severity: "High", title: 'PS, "encoded"', description: "d",
      relatedIocs: ["i1"], mitreTechniques: ["T1059"], sourceScreenshots: ["a.webp"],
      firstSeen: "t0", lastUpdated: "t1", status: "open" });
    const csv = findingsCsv(state);
    const rows = csv.trim().split("\n");
    expect(rows[0]).toContain("id,severity,title");
    expect(rows[1]).toContain('"PS, ""encoded"""'); // escaped
  });

  it("iocsCsv and timelineCsv produce headers even when empty", () => {
    const state = emptyState("c1");
    expect(iocsCsv(state).trim()).toBe("id,type,value,firstSeen");
    expect(timelineCsv(state).trim()).toBe("timestamp,windowSequence,description,sourceScreenshots");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/reports/csv.test.ts`
Expected: FAIL — cannot resolve `csv.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import type { InvestigationState } from "../analysis/stateTypes.js";

function cell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}
function row(values: string[]): string {
  return values.map(cell).join(",");
}

export function findingsCsv(state: InvestigationState): string {
  const header = "id,severity,title,description,relatedIocs,mitreTechniques,sourceScreenshots,firstSeen,lastUpdated,status";
  const rows = state.findings.map((f) => row([
    f.id, f.severity, f.title, f.description,
    f.relatedIocs.join("|"), f.mitreTechniques.join("|"), f.sourceScreenshots.join("|"),
    f.firstSeen, f.lastUpdated, f.status,
  ]));
  return [header, ...rows].join("\n") + "\n";
}

export function iocsCsv(state: InvestigationState): string {
  const header = "id,type,value,firstSeen";
  const rows = state.iocs.map((i) => row([i.id, i.type, i.value, i.firstSeen]));
  return [header, ...rows].join("\n") + "\n";
}

export function timelineCsv(state: InvestigationState): string {
  const header = "timestamp,windowSequence,description,sourceScreenshots";
  const rows = state.timeline.map((t) => row([
    t.timestamp, String(t.windowSequence), t.description, t.sourceScreenshots.join("|"),
  ]));
  return [header, ...rows].join("\n") + "\n";
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/reports/csv.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/reports/csv.ts companion/tests/reports/csv.test.ts
git commit -m "feat: add CSV renderers for findings, iocs, timeline"
```

---

## Task 3: ReportWriter

**Files:**
- Create: `companion/src/reports/reportWriter.ts`
- Test: `companion/tests/reports/reportWriter.test.ts`

Loads state, writes `report.md`, `findings.csv`, `iocs.csv`, `timeline.csv`, and `state-export.json` into `reports/`. Returns the written paths.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

let caseStore: CaseStore;
let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-report-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
  const state = emptyState("c1");
  state.lastSummary = "summary text";
  await stateStore.save(state);
});

describe("ReportWriter", () => {
  it("writes all report files and returns their paths", async () => {
    const writer = new ReportWriter(caseStore, stateStore);
    const paths = await writer.writeAll("c1");

    expect(paths.markdown).toMatch(/report\.md$/);
    const md = await readFile(paths.markdown, "utf8");
    expect(md).toContain("summary text");

    const findings = await readFile(paths.findingsCsv, "utf8");
    expect(findings).toContain("id,severity,title");

    const exported = JSON.parse(await readFile(paths.stateJson, "utf8"));
    expect(exported.caseId).toBe("c1");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/reports/reportWriter.test.ts`
Expected: FAIL — cannot resolve `reportWriter.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "../analysis/stateStore.js";
import { renderMarkdownReport } from "./markdown.js";
import { findingsCsv, iocsCsv, timelineCsv } from "./csv.js";

export interface ReportPaths {
  markdown: string;
  findingsCsv: string;
  iocsCsv: string;
  timelineCsv: string;
  stateJson: string;
}

export class ReportWriter {
  constructor(private readonly cases: CaseStore, private readonly state: StateStore) {}

  async writeAll(caseId: string): Promise<ReportPaths> {
    const state = await this.state.load(caseId);
    const dir = this.cases.reportsDir(caseId);
    const paths: ReportPaths = {
      markdown: join(dir, "report.md"),
      findingsCsv: join(dir, "findings.csv"),
      iocsCsv: join(dir, "iocs.csv"),
      timelineCsv: join(dir, "timeline.csv"),
      stateJson: join(dir, "state-export.json"),
    };
    await writeFile(paths.markdown, renderMarkdownReport(state), "utf8");
    await writeFile(paths.findingsCsv, findingsCsv(state), "utf8");
    await writeFile(paths.iocsCsv, iocsCsv(state), "utf8");
    await writeFile(paths.timelineCsv, timelineCsv(state), "utf8");
    await writeFile(paths.stateJson, JSON.stringify(state, null, 2), "utf8");
    return paths;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/reports/reportWriter.test.ts`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add companion/src/reports/reportWriter.ts companion/tests/reports/reportWriter.test.ts
git commit -m "feat: add ReportWriter for md/csv/json exports"
```

---

## Task 4: LiveHub (WebSocket fan-out)

**Files:**
- Create: `companion/src/live/hub.ts`
- Test: `companion/tests/live/hub.test.ts`

Tracks subscribers per caseId and broadcasts a JSON message to them. Uses a minimal `SocketLike` interface (`send`, `readyState`, `OPEN`) so tests don't need a real socket.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from "vitest";
import { LiveHub, type SocketLike } from "../../src/live/hub.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

function fakeSocket(): SocketLike & { sent: string[] } {
  const sent: string[] = [];
  return { sent, readyState: 1, OPEN: 1, send: (d: string) => sent.push(d) };
}

describe("LiveHub", () => {
  it("broadcasts state only to subscribers of that case", () => {
    const hub = new LiveHub();
    const a = fakeSocket();
    const b = fakeSocket();
    hub.subscribe("c1", a);
    hub.subscribe("c2", b);

    hub.broadcast(emptyState("c1"));
    expect(a.sent).toHaveLength(1);
    expect(b.sent).toHaveLength(0);
    expect(JSON.parse(a.sent[0]).type).toBe("state");
  });

  it("drops closed sockets", () => {
    const hub = new LiveHub();
    const s = fakeSocket();
    hub.subscribe("c1", s);
    s.readyState = 3; // CLOSED
    hub.broadcast(emptyState("c1"));
    expect(s.sent).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/live/hub.test.ts`
Expected: FAIL — cannot resolve `hub.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import type { InvestigationState } from "../analysis/stateTypes.js";

export interface SocketLike {
  readyState: number;
  OPEN: number;
  send(data: string): void;
}

export class LiveHub {
  private subs = new Map<string, Set<SocketLike>>();

  subscribe(caseId: string, socket: SocketLike): void {
    const set = this.subs.get(caseId) ?? new Set<SocketLike>();
    set.add(socket);
    this.subs.set(caseId, set);
  }

  unsubscribe(caseId: string, socket: SocketLike): void {
    this.subs.get(caseId)?.delete(socket);
  }

  broadcast(state: InvestigationState): void {
    const set = this.subs.get(state.caseId);
    if (!set) return;
    const message = JSON.stringify({ type: "state", state });
    for (const socket of set) {
      if (socket.readyState === socket.OPEN) socket.send(message);
      else set.delete(socket);
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/live/hub.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/live/hub.ts companion/tests/live/hub.test.ts
git commit -m "feat: add LiveHub websocket fan-out"
```

---

## Task 5: Pipeline broadcasts to the hub after merge

**Files:**
- Modify: `companion/src/analysis/pipeline.ts`
- Modify: `companion/tests/analysis/pipeline.test.ts`

Add an optional `onState` callback to `PipelineOptions`, invoked with the new state after a successful merge/save. The server wires this to `hub.broadcast`.

- [ ] **Step 1: Write the failing test (append to pipeline test file)**

```typescript
it("invokes onState after a successful analysis", async () => {
  let received: string | null = null;
  const pipeline = new AnalysisPipeline({
    provider: new MockProvider("mock", validDelta),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    onState: (s) => { received = s.caseId; },
  });
  await pipeline.analyzeWindow("c1", [capture(1)]);
  expect(received).toBe("c1");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/analysis/pipeline.test.ts`
Expected: FAIL — `onState` not a known option / not called.

- [ ] **Step 3: Modify `pipeline.ts`**

Add to `PipelineOptions`:
```typescript
  onState?: (state: InvestigationState) => void;
```
At the end of `analyzeWindow`, after `await this.opts.stateStore.save(next);` and before `return next;`, add:
```typescript
    this.opts.onState?.(next);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/analysis/pipeline.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/analysis/pipeline.ts companion/tests/analysis/pipeline.test.ts
git commit -m "feat: add onState callback to analysis pipeline"
```

---

## Task 6: Server routes — state, report, WebSocket

**Files:**
- Modify: `companion/src/server.ts`
- Modify: `companion/tests/server.test.ts`

Add `GET /cases/:id/state` (current state JSON) and `POST /cases/:id/report` (write reports, return paths — this is the batch "Generate Report" action). Inject an optional `StateStore` and `ReportWriter` into `createApp` options. WebSocket upgrade is added in `startServer` only (not exercised by supertest).

- [ ] **Step 1: Write the failing test (append to `tests/server.test.ts`)**

```typescript
import { ReportWriter } from "../src/reports/reportWriter.js";

describe("state and report routes", () => {
  it("GET /cases/:id/state returns the current state", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-state-route-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const app = createApp(store, { stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const res = await request(app).get("/cases/c1/state");
    expect(res.status).toBe(200);
    expect(res.body.caseId).toBe("c1");
    expect(res.body.findings).toEqual([]);
  });

  it("POST /cases/:id/report writes reports and returns paths", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-report-route-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore);
    const app = createApp(store, { stateStore, reportWriter });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const res = await request(app).post("/cases/c1/report");
    expect(res.status).toBe(200);
    expect(res.body.markdown).toMatch(/report\.md$/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/server.test.ts`
Expected: FAIL — routes 404 / options not accepted.

- [ ] **Step 3: Modify `server.ts`**

Extend `AppOptions`:
```typescript
import type { StateStore } from "./analysis/stateStore.js";
import type { ReportWriter } from "./reports/reportWriter.js";

export interface AppOptions {
  pipeline?: AnalysisPipeline;
  windowSize?: number;
  stateStore?: StateStore;
  reportWriter?: ReportWriter;
}
```

Inside `createApp`, before `return app;`, add:
```typescript
  app.get("/cases/:id/state", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const state = await options.stateStore.load(req.params.id);
      return res.status(200).json(state);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/report", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const paths = await options.reportWriter.writeAll(req.params.id);
      return res.status(200).json(paths);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/server.test.ts`
Expected: PASS (6 tests total in the file).

- [ ] **Step 5: Commit**

```bash
git add companion/src/server.ts companion/tests/server.test.ts
git commit -m "feat: add state and report HTTP routes"
```

---

## Task 7: Wire WebSocket + hub + report writer into startServer

**Files:**
- Modify: `companion/src/server.ts`
- Modify: `companion/package.json` (add `ws` dependency)

- [ ] **Step 1: Add the `ws` dependency**

Run: `cd companion && npm install ws && npm install -D @types/ws`
Expected: `ws` and `@types/ws` added to package.json.

- [ ] **Step 2: Modify `startServer` in `server.ts`**

Add imports:
```typescript
import { WebSocketServer } from "ws";
import { LiveHub } from "./live/hub.js";
import { ReportWriter } from "./reports/reportWriter.js";
import { readFile } from "node:fs/promises";
```

Replace `startServer` with:
```typescript
export function startServer(casesRoot: string, port = 4773): void {
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const hub = new LiveHub();
  const reportWriter = new ReportWriter(store, stateStore);

  const pipeline = buildPipeline(store);
  if (pipeline) {
    // re-create with onState wired to the hub
  }
  const wiredPipeline = pipeline
    ? new AnalysisPipeline({
        provider: (pipeline as unknown as { opts: { provider: AnalyzeProvider } }).opts.provider,
        stateStore,
        imageLoader: makeImageLoader(store),
        onState: (s) => hub.broadcast(s),
      })
    : undefined;

  const app = createApp(store, { pipeline: wiredPipeline, stateStore, reportWriter });

  // Serve the dashboard.
  app.get("/dashboard", async (_req, res) => {
    const html = await readFile(new URL("../../public/dashboard.html", import.meta.url), "utf8");
    res.type("html").send(html);
  });

  const server = app.listen(port, "127.0.0.1", () => {
    console.log(`DFIR companion on http://127.0.0.1:${port} (dashboard at /dashboard)`);
  });

  const wss = new WebSocketServer({ server, path: "/ws" });
  wss.on("connection", (socket, req) => {
    const caseId = new URL(req.url ?? "", "http://localhost").searchParams.get("caseId") ?? "";
    hub.subscribe(caseId, socket as unknown as import("./live/hub.js").SocketLike);
    socket.on("close", () => hub.unsubscribe(caseId, socket as unknown as import("./live/hub.js").SocketLike));
  });
}
```

To make `buildPipeline`'s provider reusable, change `buildPipeline` to also export the chosen provider. Replace `buildPipeline` with:
```typescript
import type { AIProvider as AnalyzeProvider } from "./providers/provider.js";

export function buildProvider(): AnalyzeProvider | undefined {
  const name = process.env.DFIR_AI_PROVIDER;
  const model = process.env.DFIR_AI_MODEL ?? "";
  const apiKey = process.env.DFIR_AI_KEY ?? "";
  if (!name) return undefined;
  const registry = new ProviderRegistry();
  registry.register(new OpenAIProvider({ apiKey, model }));
  registry.register(new OpenRouterProvider({ apiKey, model }));
  registry.register(new OllamaCloudProvider({ apiKey, model }));
  registry.register(new GeminiProvider({ apiKey, model }));
  return registry.get(name);
}
```

And simplify the `startServer` pipeline construction to use it:
```typescript
  const provider = buildProvider();
  const wiredPipeline = provider
    ? new AnalysisPipeline({ provider, stateStore, imageLoader: makeImageLoader(store), onState: (s) => hub.broadcast(s) })
    : undefined;
```
(Remove the earlier `buildPipeline`/`pipeline` block and the `as unknown as` cast.)

- [ ] **Step 3: Build to verify types compile**

Run: `cd companion && npm run build`
Expected: `tsc` completes with no errors.

- [ ] **Step 4: Run the full suite**

Run: `cd companion && npm test`
Expected: PASS across all suites.

- [ ] **Step 5: Commit**

```bash
git add companion/src/server.ts companion/package.json companion/package-lock.json
git commit -m "feat: wire websocket hub and report writer into startServer"
```

---

## Task 8: Dashboard page

**Files:**
- Create: `public/dashboard.html`
- Test: `companion/tests/reports/dashboardHtml.test.ts`

Single static page: connects to `/ws?caseId=...`, renders summary, timeline, findings (by severity), open threads, and MITRE table; a "Generate Report" button POSTs to `/cases/:id/report`. The test asserts the file contains the required hooks (no browser automation here — E2E is Plan 4).

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";

describe("dashboard.html", () => {
  it("contains websocket wiring and report button", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("/ws?caseId=");
    expect(html).toContain('id="findings"');
    expect(html).toContain('id="timeline"');
    expect(html).toContain('id="openThreads"');
    expect(html).toContain('id="generateReport"');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/reports/dashboardHtml.test.ts`
Expected: FAIL — file not found.

- [ ] **Step 3: Create `public/dashboard.html`**

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>DFIR Companion Dashboard</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; background: #0f1115; color: #e6e6e6; }
    header { padding: 12px 16px; background: #161a22; display: flex; gap: 12px; align-items: center; }
    main { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 16px; }
    section { background: #161a22; border-radius: 8px; padding: 12px; }
    h2 { margin: 0 0 8px; font-size: 14px; text-transform: uppercase; letter-spacing: .05em; color: #9aa4b2; }
    .sev-Critical { color: #ff5c5c; } .sev-High { color: #ff9f43; }
    .sev-Medium { color: #ffd93b; } .sev-Low { color: #6bcB77; } .sev-Info { color: #6aa9ff; }
    .finding { border-left: 3px solid #2a2f3a; padding: 6px 10px; margin-bottom: 8px; }
    button { background: #2d6cdf; color: white; border: 0; padding: 8px 12px; border-radius: 6px; cursor: pointer; }
    input { background: #0f1115; color: #e6e6e6; border: 1px solid #2a2f3a; padding: 6px; border-radius: 6px; }
    #status { font-size: 12px; color: #9aa4b2; }
  </style>
</head>
<body>
  <header>
    <strong>DFIR Companion</strong>
    <input id="caseId" placeholder="caseId" />
    <button id="connect">Connect</button>
    <button id="generateReport">Generate Report</button>
    <span id="status">disconnected</span>
  </header>
  <main>
    <section><h2>Executive Summary</h2><div id="summary">—</div></section>
    <section><h2>Open Threads</h2><div id="openThreads">—</div></section>
    <section><h2>Findings</h2><div id="findings">—</div></section>
    <section><h2>Timeline</h2><div id="timeline">—</div></section>
    <section style="grid-column: 1 / -1"><h2>MITRE ATT&CK</h2><div id="mitre">—</div></section>
  </main>
  <script>
    const SEV = ["Critical", "High", "Medium", "Low", "Info"];
    let ws = null;

    function render(state) {
      document.getElementById("summary").textContent = state.lastSummary || "—";
      document.getElementById("openThreads").innerHTML =
        (state.openThreads.filter(t => t.status === "open").map(t => `<div>• ${t.description}</div>`).join("")) || "—";
      const sorted = [...state.findings].sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity));
      document.getElementById("findings").innerHTML =
        sorted.map(f => `<div class="finding"><span class="sev-${f.severity}">[${f.severity}]</span> <strong>${f.title}</strong><br><small>${f.description}</small></div>`).join("") || "—";
      document.getElementById("timeline").innerHTML =
        state.timeline.map(t => `<div>• <small>${t.timestamp}</small> ${t.description}</div>`).join("") || "—";
      document.getElementById("mitre").innerHTML =
        state.mitreTechniques.map(m => `<div>${m.id} — ${m.name} (${m.findingIds.join(", ")})</div>`).join("") || "—";
    }

    function connect() {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      fetch(`/cases/${caseId}/state`).then(r => r.json()).then(render).catch(() => {});
      ws = new WebSocket(`ws://${location.host}/ws?caseId=${encodeURIComponent(caseId)}`);
      ws.onopen = () => document.getElementById("status").textContent = "connected (live)";
      ws.onclose = () => document.getElementById("status").textContent = "disconnected";
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data);
        if (msg.type === "state") render(msg.state);
      };
    }

    document.getElementById("connect").onclick = connect;
    document.getElementById("generateReport").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      fetch(`/cases/${caseId}/report`, { method: "POST" })
        .then(r => r.json())
        .then(p => document.getElementById("status").textContent = `report written: ${p.markdown}`);
    };
  </script>
</body>
</html>
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/reports/dashboardHtml.test.ts`
Expected: PASS (1 test).

- [ ] **Step 5: Manual smoke test (live + batch)**

Run (PowerShell):
```
cd companion; $env:DFIR_CASES_ROOT="./cases"; npm run dev
```
Open `http://127.0.0.1:4773/dashboard`, enter a caseId that exists, click **Connect** (status shows "connected (live)"), then click **Generate Report** (status shows the written `report.md` path; confirm files appear under `cases/<id>/reports/`).

- [ ] **Step 6: Commit**

```bash
git add public/dashboard.html companion/tests/reports/dashboardHtml.test.ts
git commit -m "feat: add live dashboard page"
```

---

## Self-Review

**Spec coverage (Plan 3 scope = reports + dashboard):**
- Four report sections (Executive, Timeline, Findings, MITRE) → Task 1 (Markdown). ✓
- Findings sorted by severity → Task 1 (dedicated test). ✓
- Exports: Markdown, JSON, separate CSVs (findings/iocs/timeline) → Tasks 2–3. ✓
- Live mode: dashboard subscribes over WebSocket; every merge pushes an update → Tasks 4,5,7,8. ✓
- Batch mode: "Generate Report" on demand, same state/renderer → Task 6 (`POST /report`) + Task 8 (button). ✓
- Live/batch selectable per case (same engine) → dashboard connects for live and/or triggers report for batch; identical underlying state. ✓
- Timeline entries link to source screenshots → Task 1 (evidence list) + state carries `sourceScreenshots`. ✓
- Out of scope (later): the Chrome/Comet extension and full E2E → Plan 4.

**Placeholder scan:** No TBD/TODO; full code in every code step; exact commands + expected results. ✓

**Type consistency:** Render functions consume `InvestigationState`/`Finding`/`Severity` from Plan 2 unchanged. `ReportPaths` (Task 3) returned by `/report` route (Task 6) and shown by the dashboard (Task 8). `SocketLike` (Task 4) used by `LiveHub.broadcast` and adapted from `ws` sockets in Task 7. `onState` option (Task 5) consumed in `startServer` wiring (Task 7). `AppOptions` extended additively in Tasks 6 — earlier `pipeline`/`windowSize` fields preserved. ✓
