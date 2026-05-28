# DFIR Companion Analysis Pipeline + AI Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the accumulating "investigation state" (Approach B): windowed AI analysis of captures that merges structured findings into a persistent per-case state, behind a provider abstraction supporting Ollama Cloud, OpenRouter, OpenAI, and Gemini.

**Architecture:** A `StateStore` persists `investigation.json`. An `AIProvider` interface normalizes vision+structured-output calls; concrete adapters wrap each vendor. The `AnalysisPipeline` accumulates non-duplicate captures into a window, builds a compact summary of the current state, asks the AI for a strict-schema JSON delta, validates it, and merges it into the state (merge, not replace — so returning to an old topic updates an existing finding by id rather than duplicating). Failures mark captures `pending_analysis` and are retried; evidence (Plan 1) is never affected.

**Tech Stack:** Node.js 20+, TypeScript, Zod (response schema), Vitest. Depends on Plan 1 (`CaseStore`, `ingestCapture`, types).

This is Plan 2 of 4. Prerequisite: Plan 1 merged.

---

## File Structure

```
companion/src/
├── analysis/
│   ├── stateTypes.ts        # Finding, IOC, Thread, TimelineEntry, Technique, InvestigationState, Severity
│   ├── stateStore.ts        # load/save investigation.json (per case)
│   ├── responseSchema.ts    # Zod schema for the AI delta response
│   ├── stateMerge.ts        # mergeDelta(state, delta) -> new state  (pure, critical)
│   ├── summary.ts           # buildStateSummary(state) -> compact context string
│   └── pipeline.ts          # AnalysisPipeline: window, analyze, merge, persist
└── providers/
    ├── provider.ts          # AIProvider interface + AnalyzeRequest/AnalyzeResult + registry
    ├── ollama.ts            # OllamaCloudProvider
    ├── openrouter.ts        # OpenRouterProvider
    ├── openai.ts            # OpenAIProvider
    └── gemini.ts            # GeminiProvider
```

**Responsibilities:** `stateMerge.ts` is pure and the most safety-critical (no duplication on revisits). Providers contain ONLY transport + normalization, no domain logic. `pipeline.ts` orchestrates and is provider-agnostic.

---

## Task 1: Investigation state types

**Files:**
- Create: `companion/src/analysis/stateTypes.ts`

- [ ] **Step 1: Create `companion/src/analysis/stateTypes.ts`**

```typescript
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type FindingStatus = "open" | "confirmed" | "dismissed";
export type ThreadStatus = "open" | "closed";

export interface IOC {
  id: string;
  type: "ip" | "domain" | "hash" | "file" | "process" | "url" | "other";
  value: string;
  firstSeen: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  relatedIocs: string[];        // IOC ids
  sourceScreenshots: string[];  // screenshot filenames
  mitreTechniques: string[];    // technique ids, e.g. "T1059"
  firstSeen: string;
  lastUpdated: string;
  status: FindingStatus;
}

export interface Thread {
  id: string;
  description: string;
  status: ThreadStatus;
  openedAt: string;
  closedAt: string | null;
}

export interface TimelineEntry {
  timestamp: string;
  windowSequence: number;
  description: string;
  sourceScreenshots: string[];
}

export interface Technique {
  id: string;            // e.g. "T1059.001"
  name: string;
  findingIds: string[];
}

export interface InvestigationState {
  caseId: string;
  findings: Finding[];
  iocs: IOC[];
  openThreads: Thread[];
  timeline: TimelineEntry[];
  mitreTechniques: Technique[];
  lastSummary: string;
  updatedAt: string;
}

export function emptyState(caseId: string): InvestigationState {
  return {
    caseId,
    findings: [],
    iocs: [],
    openThreads: [],
    timeline: [],
    mitreTechniques: [],
    lastSummary: "",
    updatedAt: new Date(0).toISOString(),
  };
}
```

- [ ] **Step 2: Commit**

```bash
git add companion/src/analysis/stateTypes.ts
git commit -m "feat: add investigation state types"
```

---

## Task 2: StateStore

**Files:**
- Create: `companion/src/analysis/stateStore.ts`
- Test: `companion/tests/analysis/stateStore.test.ts`

Loads `state/investigation.json`; returns `emptyState` if missing. Saves atomically via temp-file rename.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

let caseStore: CaseStore;
let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-state-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
});

describe("StateStore", () => {
  it("returns empty state when none saved", async () => {
    const state = await stateStore.load("c1");
    expect(state.findings).toEqual([]);
    expect(state.caseId).toBe("c1");
  });

  it("round-trips a saved state", async () => {
    const state = emptyState("c1");
    state.lastSummary = "initial recon of host WIN-01";
    await stateStore.save(state);

    const loaded = await stateStore.load("c1");
    expect(loaded.lastSummary).toBe("initial recon of host WIN-01");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/analysis/stateStore.test.ts`
Expected: FAIL — cannot resolve `stateStore.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { type InvestigationState, emptyState } from "./stateTypes.js";

export class StateStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "investigation.json");
  }

  async load(caseId: string): Promise<InvestigationState> {
    try {
      const raw = await readFile(this.path(caseId), "utf8");
      return JSON.parse(raw) as InvestigationState;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyState(caseId);
      throw err;
    }
  }

  async save(state: InvestigationState): Promise<void> {
    const target = this.path(state.caseId);
    const tmp = target + ".tmp";
    await writeFile(tmp, JSON.stringify(state, null, 2), "utf8");
    await rename(tmp, target); // atomic replace
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/analysis/stateStore.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/analysis/stateStore.ts companion/tests/analysis/stateStore.test.ts
git commit -m "feat: add StateStore with atomic save"
```

---

## Task 3: AI response schema

**Files:**
- Create: `companion/src/analysis/responseSchema.ts`
- Test: `companion/tests/analysis/responseSchema.test.ts`

The strict shape the AI must return per window: a delta of new/updated findings, IOCs, MITRE techniques, thread changes, a timeline note, and a summary.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from "vitest";
import { deltaSchema } from "../../src/analysis/responseSchema.js";

describe("deltaSchema", () => {
  it("parses a valid delta", () => {
    const delta = deltaSchema.parse({
      findings: [{
        id: "f1", severity: "High", title: "Suspicious PowerShell",
        description: "Encoded command observed", relatedIocs: [], mitreTechniques: ["T1059.001"],
        status: "open",
      }],
      iocs: [{ id: "i1", type: "process", value: "powershell.exe" }],
      mitreTechniques: [{ id: "T1059.001", name: "PowerShell" }],
      threadsOpened: [{ id: "t1", description: "trace parent process" }],
      threadsClosed: [],
      timelineNote: "Reviewed process list on WIN-01",
      summary: "Found encoded PowerShell on WIN-01",
    });
    expect(delta.findings[0].id).toBe("f1");
  });

  it("rejects invalid severity", () => {
    expect(() => deltaSchema.parse({
      findings: [{ id: "f1", severity: "Catastrophic", title: "x", description: "y",
        relatedIocs: [], mitreTechniques: [], status: "open" }],
      iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
      timelineNote: "n", summary: "s",
    })).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/analysis/responseSchema.test.ts`
Expected: FAIL — cannot resolve `responseSchema.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import { z } from "zod";

export const deltaSchema = z.object({
  findings: z.array(z.object({
    id: z.string().min(1),
    severity: z.enum(["Critical", "High", "Medium", "Low", "Info"]),
    title: z.string().min(1),
    description: z.string(),
    relatedIocs: z.array(z.string()),
    mitreTechniques: z.array(z.string()),
    status: z.enum(["open", "confirmed", "dismissed"]),
  })),
  iocs: z.array(z.object({
    id: z.string().min(1),
    type: z.enum(["ip", "domain", "hash", "file", "process", "url", "other"]),
    value: z.string().min(1),
  })),
  mitreTechniques: z.array(z.object({
    id: z.string().min(1),
    name: z.string(),
  })),
  threadsOpened: z.array(z.object({ id: z.string().min(1), description: z.string() })),
  threadsClosed: z.array(z.string()), // thread ids
  timelineNote: z.string(),
  summary: z.string(),
});

export type AnalysisDelta = z.infer<typeof deltaSchema>;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/analysis/responseSchema.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/analysis/responseSchema.ts companion/tests/analysis/responseSchema.test.ts
git commit -m "feat: add AI analysis delta schema"
```

---

## Task 4: State merge (critical — no duplication on revisit)

**Files:**
- Create: `companion/src/analysis/stateMerge.ts`
- Test: `companion/tests/analysis/stateMerge.test.ts`

Pure function. New finding ids are added; existing ids are updated in place (description/severity/links merged, `lastUpdated` refreshed, `firstSeen` preserved). IOCs and techniques dedupe by id/value. Opened threads append; closed thread ids flip status to `closed` with `closedAt`. The timeline gets one entry per window. Summary replaced with the latest.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from "vitest";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

const baseDelta: AnalysisDelta = {
  findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
  timelineNote: "", summary: "",
};

describe("mergeDelta", () => {
  it("adds a new finding with firstSeen and lastUpdated", () => {
    const state = emptyState("c1");
    const next = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "v1",
        relatedIocs: [], mitreTechniques: ["T1059"], status: "open" }],
      timelineNote: "window 1", summary: "s1",
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["000001_t.webp"] });

    expect(next.findings).toHaveLength(1);
    expect(next.findings[0].firstSeen).toBe("2026-05-28T10:00:00.000Z");
    expect(next.findings[0].lastUpdated).toBe("2026-05-28T10:00:00.000Z");
    expect(state.findings).toHaveLength(0); // original not mutated
  });

  it("updates an existing finding by id instead of duplicating (revisit)", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "Medium", title: "PS abuse", description: "v1",
        relatedIocs: [], mitreTechniques: [], status: "open" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["a.webp"] });

    state = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "v2 escalated",
        relatedIocs: ["i1"], mitreTechniques: ["T1059"], status: "confirmed" }],
    }, { windowSequence: 5, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: ["b.webp"] });

    expect(state.findings).toHaveLength(1);
    const f = state.findings[0];
    expect(f.severity).toBe("High");
    expect(f.description).toBe("v2 escalated");
    expect(f.status).toBe("confirmed");
    expect(f.firstSeen).toBe("2026-05-28T10:00:00.000Z"); // preserved
    expect(f.lastUpdated).toBe("2026-05-28T10:05:00.000Z"); // refreshed
    expect(f.relatedIocs).toContain("i1");
    expect(f.sourceScreenshots).toEqual(["a.webp", "b.webp"]); // accumulated, deduped
  });

  it("dedupes IOCs by value and closes threads", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i1", type: "ip", value: "10.0.0.5" }],
      threadsOpened: [{ id: "t1", description: "trace lateral movement" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });

    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i2", type: "ip", value: "10.0.0.5" }], // same value
      threadsClosed: ["t1"],
    }, { windowSequence: 2, timestamp: "2026-05-28T10:01:00.000Z", sourceScreenshots: [] });

    expect(state.iocs).toHaveLength(1);
    expect(state.openThreads[0].status).toBe("closed");
    expect(state.openThreads[0].closedAt).toBe("2026-05-28T10:01:00.000Z");
  });

  it("appends a timeline entry per window", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, { ...baseDelta, timelineNote: "did X" },
      { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["a.webp"] });
    expect(state.timeline).toHaveLength(1);
    expect(state.timeline[0].description).toBe("did X");
    expect(state.timeline[0].windowSequence).toBe(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/analysis/stateMerge.test.ts`
Expected: FAIL — cannot resolve `stateMerge.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import type { AnalysisDelta } from "./responseSchema.js";
import type { InvestigationState, Finding, IOC, Technique } from "./stateTypes.js";

export interface WindowContext {
  windowSequence: number;
  timestamp: string;
  sourceScreenshots: string[];
}

function uniq(values: string[]): string[] {
  return Array.from(new Set(values));
}

export function mergeDelta(
  state: InvestigationState,
  delta: AnalysisDelta,
  ctx: WindowContext,
): InvestigationState {
  const findings: Finding[] = state.findings.map((f) => ({ ...f }));

  for (const incoming of delta.findings) {
    const existing = findings.find((f) => f.id === incoming.id);
    if (existing) {
      existing.severity = incoming.severity;
      existing.title = incoming.title;
      existing.description = incoming.description;
      existing.status = incoming.status;
      existing.relatedIocs = uniq([...existing.relatedIocs, ...incoming.relatedIocs]);
      existing.mitreTechniques = uniq([...existing.mitreTechniques, ...incoming.mitreTechniques]);
      existing.sourceScreenshots = uniq([...existing.sourceScreenshots, ...ctx.sourceScreenshots]);
      existing.lastUpdated = ctx.timestamp;
    } else {
      findings.push({
        id: incoming.id,
        severity: incoming.severity,
        title: incoming.title,
        description: incoming.description,
        relatedIocs: uniq(incoming.relatedIocs),
        mitreTechniques: uniq(incoming.mitreTechniques),
        sourceScreenshots: uniq(ctx.sourceScreenshots),
        firstSeen: ctx.timestamp,
        lastUpdated: ctx.timestamp,
        status: incoming.status,
      });
    }
  }

  const iocs: IOC[] = state.iocs.map((i) => ({ ...i }));
  for (const incoming of delta.iocs) {
    if (!iocs.some((i) => i.value === incoming.value)) {
      iocs.push({ id: incoming.id, type: incoming.type, value: incoming.value, firstSeen: ctx.timestamp });
    }
  }

  const mitreTechniques: Technique[] = state.mitreTechniques.map((t) => ({ ...t, findingIds: [...t.findingIds] }));
  for (const incoming of delta.mitreTechniques) {
    const existing = mitreTechniques.find((t) => t.id === incoming.id);
    const findingIds = delta.findings.filter((f) => f.mitreTechniques.includes(incoming.id)).map((f) => f.id);
    if (existing) {
      existing.findingIds = uniq([...existing.findingIds, ...findingIds]);
    } else {
      mitreTechniques.push({ id: incoming.id, name: incoming.name, findingIds: uniq(findingIds) });
    }
  }

  const openThreads = state.openThreads.map((t) => ({ ...t }));
  for (const t of delta.threadsOpened) {
    if (!openThreads.some((x) => x.id === t.id)) {
      openThreads.push({ id: t.id, description: t.description, status: "open", openedAt: ctx.timestamp, closedAt: null });
    }
  }
  for (const closedId of delta.threadsClosed) {
    const t = openThreads.find((x) => x.id === closedId);
    if (t && t.status === "open") {
      t.status = "closed";
      t.closedAt = ctx.timestamp;
    }
  }

  const timeline = [...state.timeline];
  if (delta.timelineNote.trim().length > 0) {
    timeline.push({
      timestamp: ctx.timestamp,
      windowSequence: ctx.windowSequence,
      description: delta.timelineNote,
      sourceScreenshots: uniq(ctx.sourceScreenshots),
    });
  }

  return {
    caseId: state.caseId,
    findings,
    iocs,
    openThreads,
    timeline,
    mitreTechniques,
    lastSummary: delta.summary.trim().length > 0 ? delta.summary : state.lastSummary,
    updatedAt: ctx.timestamp,
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/analysis/stateMerge.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/analysis/stateMerge.ts companion/tests/analysis/stateMerge.test.ts
git commit -m "feat: add state merge with revisit-safe finding updates"
```

---

## Task 5: State summary builder

**Files:**
- Create: `companion/src/analysis/summary.ts`
- Test: `companion/tests/analysis/summary.test.ts`

Builds a compact text summary of the current state to send as context (avoids sending the full raw state, keeping the AI context small on long investigations).

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from "vitest";
import { buildStateSummary } from "../../src/analysis/summary.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("buildStateSummary", () => {
  it("notes an empty state", () => {
    expect(buildStateSummary(emptyState("c1"))).toContain("No findings yet");
  });

  it("lists finding ids, open threads, and IOC values", () => {
    const state = emptyState("c1");
    state.findings.push({ id: "f1", severity: "High", title: "PS abuse", description: "d",
      relatedIocs: [], mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });
    state.openThreads.push({ id: "t1", description: "trace parent", status: "open", openedAt: "", closedAt: null });
    state.iocs.push({ id: "i1", type: "ip", value: "10.0.0.5", firstSeen: "" });

    const summary = buildStateSummary(state);
    expect(summary).toContain("f1");
    expect(summary).toContain("PS abuse");
    expect(summary).toContain("t1");
    expect(summary).toContain("10.0.0.5");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/analysis/summary.test.ts`
Expected: FAIL — cannot resolve `summary.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import type { InvestigationState } from "./stateTypes.js";

export function buildStateSummary(state: InvestigationState): string {
  if (state.findings.length === 0 && state.openThreads.length === 0) {
    return "No findings yet. This is early in the investigation.";
  }
  const findings = state.findings
    .map((f) => `- [${f.id}] (${f.severity}) ${f.title}: ${f.description}`)
    .join("\n");
  const threads = state.openThreads
    .filter((t) => t.status === "open")
    .map((t) => `- [${t.id}] ${t.description}`)
    .join("\n");
  const iocs = state.iocs.map((i) => `${i.type}:${i.value}`).join(", ");

  return [
    "EXISTING FINDINGS (update by id; do not duplicate):",
    findings || "(none)",
    "",
    "OPEN THREADS (close by id when resolved):",
    threads || "(none)",
    "",
    `KNOWN IOCS: ${iocs || "(none)"}`,
  ].join("\n");
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/analysis/summary.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/analysis/summary.ts companion/tests/analysis/summary.test.ts
git commit -m "feat: add compact state summary builder"
```

---

## Task 6: AIProvider interface + registry

**Files:**
- Create: `companion/src/providers/provider.ts`
- Test: `companion/tests/providers/provider.test.ts`

Defines the contract all providers implement, plus a registry to pick a provider by name. Includes a `MockProvider` for tests (exported from this file).

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from "vitest";
import { ProviderRegistry, MockProvider, type AnalyzeRequest } from "../../src/providers/provider.js";

describe("ProviderRegistry", () => {
  it("registers and resolves a provider by name", () => {
    const registry = new ProviderRegistry();
    registry.register(new MockProvider("mock", '{"summary":"ok"}'));
    const p = registry.get("mock");
    expect(p.name).toBe("mock");
  });

  it("throws for unknown provider", () => {
    const registry = new ProviderRegistry();
    expect(() => registry.get("nope")).toThrow();
  });

  it("MockProvider returns its canned response", async () => {
    const p = new MockProvider("mock", "RAW-JSON");
    const req: AnalyzeRequest = { systemPrompt: "s", userPrompt: "u", images: [] };
    const result = await p.analyze(req);
    expect(result.rawText).toBe("RAW-JSON");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/providers/provider.test.ts`
Expected: FAIL — cannot resolve `provider.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
export interface AnalyzeImage {
  base64: string;
  mimeType: string; // e.g. "image/webp"
}

export interface AnalyzeRequest {
  systemPrompt: string;
  userPrompt: string;
  images: AnalyzeImage[];
}

export interface AnalyzeResult {
  rawText: string; // expected to be JSON matching deltaSchema
}

export class ProviderError extends Error {
  constructor(message: string, readonly kind: "auth" | "rate_limit" | "timeout" | "transport" | "other") {
    super(message);
    this.name = "ProviderError";
  }
}

export interface AIProvider {
  readonly name: string;
  analyze(req: AnalyzeRequest): Promise<AnalyzeResult>;
}

export class ProviderRegistry {
  private providers = new Map<string, AIProvider>();
  register(p: AIProvider): void {
    this.providers.set(p.name, p);
  }
  get(name: string): AIProvider {
    const p = this.providers.get(name);
    if (!p) throw new ProviderError(`unknown provider: ${name}`, "other");
    return p;
  }
}

export class MockProvider implements AIProvider {
  constructor(readonly name: string, private readonly canned: string) {}
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    return { rawText: this.canned };
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/providers/provider.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/providers/provider.ts companion/tests/providers/provider.test.ts
git commit -m "feat: add AIProvider interface, registry, and mock"
```

---

## Task 7: Concrete providers (OpenAI, Gemini, OpenRouter, Ollama Cloud)

**Files:**
- Create: `companion/src/providers/openai.ts`
- Create: `companion/src/providers/openrouter.ts`
- Create: `companion/src/providers/gemini.ts`
- Create: `companion/src/providers/ollama.ts`
- Test: `companion/tests/providers/openai.test.ts`

Each provider wraps a vision chat-completion call and returns `rawText`. They use the global `fetch` (Node 20+), accept an injected `fetchFn` for testing, and normalize HTTP errors to `ProviderError`. OpenRouter shares OpenAI's wire format. Test covers OpenAI's request shaping + error normalization (others follow the same pattern).

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect, vi } from "vitest";
import { OpenAIProvider } from "../../src/providers/openai.js";
import { ProviderError } from "../../src/providers/provider.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("OpenAIProvider", () => {
  it("sends images and returns assistant content", async () => {
    const fetchFn = vi.fn(async () =>
      jsonResponse({ choices: [{ message: { content: '{"summary":"done"}' } }] }),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    const result = await p.analyze({
      systemPrompt: "s", userPrompt: "u",
      images: [{ base64: "AAAA", mimeType: "image/webp" }],
    });
    expect(result.rawText).toBe('{"summary":"done"}');
    expect(fetchFn).toHaveBeenCalledOnce();
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.model).toBe("gpt-4o");
    expect(JSON.stringify(body)).toContain("data:image/webp;base64,AAAA");
  });

  it("maps 429 to a rate_limit ProviderError", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ error: "slow down" }, 429));
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }))
      .rejects.toMatchObject({ kind: "rate_limit" } as Partial<ProviderError>);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/providers/openai.test.ts`
Expected: FAIL — cannot resolve `openai.js`.

- [ ] **Step 3: Write the OpenAI implementation `companion/src/providers/openai.ts`**

```typescript
import { type AIProvider, type AnalyzeRequest, type AnalyzeResult, ProviderError } from "./provider.js";

type FetchFn = typeof fetch;

export interface OpenAIOptions {
  apiKey: string;
  model: string;
  baseUrl?: string;
  fetchFn?: FetchFn;
}

function mapStatus(status: number): ProviderError["kind"] {
  if (status === 401 || status === 403) return "auth";
  if (status === 429) return "rate_limit";
  if (status === 408 || status >= 500) return "transport";
  return "other";
}

export class OpenAIProvider implements AIProvider {
  readonly name = "openai";
  private readonly fetchFn: FetchFn;
  private readonly baseUrl: string;
  constructor(private readonly opts: OpenAIOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.baseUrl = opts.baseUrl ?? "https://api.openai.com/v1";
  }

  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    const content: unknown[] = [{ type: "text", text: req.userPrompt }];
    for (const img of req.images) {
      content.push({ type: "image_url", image_url: { url: `data:${img.mimeType};base64,${img.base64}` } });
    }
    const res = await this.fetchFn(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${this.opts.apiKey}` },
      body: JSON.stringify({
        model: this.opts.model,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: req.systemPrompt },
          { role: "user", content },
        ],
      }),
    });
    if (!res.ok) throw new ProviderError(`OpenAI HTTP ${res.status}`, mapStatus(res.status));
    const json = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const text = json.choices?.[0]?.message?.content;
    if (!text) throw new ProviderError("OpenAI returned no content", "other");
    return { rawText: text };
  }
}
```

- [ ] **Step 4: Write OpenRouter `companion/src/providers/openrouter.ts` (OpenAI-compatible wire format)**

```typescript
import { OpenAIProvider, type OpenAIOptions } from "./openai.js";

export class OpenRouterProvider extends OpenAIProvider {
  override readonly name = "openrouter";
  constructor(opts: OpenAIOptions) {
    super({ ...opts, baseUrl: opts.baseUrl ?? "https://openrouter.ai/api/v1" });
  }
}
```

- [ ] **Step 5: Write Ollama Cloud `companion/src/providers/ollama.ts` (OpenAI-compatible endpoint)**

```typescript
import { OpenAIProvider, type OpenAIOptions } from "./openai.js";

export class OllamaCloudProvider extends OpenAIProvider {
  override readonly name = "ollama";
  constructor(opts: OpenAIOptions) {
    super({ ...opts, baseUrl: opts.baseUrl ?? "https://ollama.com/v1" });
  }
}
```

- [ ] **Step 6: Write Gemini `companion/src/providers/gemini.ts`**

```typescript
import { type AIProvider, type AnalyzeRequest, type AnalyzeResult, ProviderError } from "./provider.js";

type FetchFn = typeof fetch;

export interface GeminiOptions {
  apiKey: string;
  model: string;       // e.g. "gemini-1.5-pro"
  baseUrl?: string;
  fetchFn?: FetchFn;
}

function mapStatus(status: number): ProviderError["kind"] {
  if (status === 401 || status === 403) return "auth";
  if (status === 429) return "rate_limit";
  if (status === 408 || status >= 500) return "transport";
  return "other";
}

export class GeminiProvider implements AIProvider {
  readonly name = "gemini";
  private readonly fetchFn: FetchFn;
  private readonly baseUrl: string;
  constructor(private readonly opts: GeminiOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.baseUrl = opts.baseUrl ?? "https://generativelanguage.googleapis.com/v1beta";
  }

  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    const parts: unknown[] = [{ text: `${req.systemPrompt}\n\n${req.userPrompt}` }];
    for (const img of req.images) {
      parts.push({ inline_data: { mime_type: img.mimeType, data: img.base64 } });
    }
    const url = `${this.baseUrl}/models/${this.opts.model}:generateContent?key=${this.opts.apiKey}`;
    const res = await this.fetchFn(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contents: [{ role: "user", parts }],
        generationConfig: { responseMimeType: "application/json" },
      }),
    });
    if (!res.ok) throw new ProviderError(`Gemini HTTP ${res.status}`, mapStatus(res.status));
    const json = (await res.json()) as { candidates?: { content?: { parts?: { text?: string }[] } }[] };
    const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) throw new ProviderError("Gemini returned no content", "other");
    return { rawText: text };
  }
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/providers/openai.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 8: Commit**

```bash
git add companion/src/providers/openai.ts companion/src/providers/openrouter.ts companion/src/providers/ollama.ts companion/src/providers/gemini.ts companion/tests/providers/openai.test.ts
git commit -m "feat: add OpenAI, OpenRouter, Ollama Cloud, and Gemini providers"
```

---

## Task 8: Analysis pipeline (window → analyze → merge → persist)

**Files:**
- Create: `companion/src/analysis/pipeline.ts`
- Test: `companion/tests/analysis/pipeline.test.ts`

`AnalysisPipeline` buffers non-duplicate captures per case. `analyzeWindow(caseId, captures, imageLoader)` builds the prompt (system + state summary + user), calls the provider, validates with `deltaSchema`, merges via `mergeDelta`, and saves the state. On provider/parse failure it throws (caller marks captures `pending_analysis`). Retries with backoff are handled here via a small retry helper.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { CaptureMetadata } from "../../src/types.js";

let caseStore: CaseStore;
let stateStore: StateStore;

function capture(seq: number): CaptureMetadata {
  return {
    caseId: "c1", sequenceNumber: seq, timestamp: `2026-05-28T10:0${seq}:00.000Z`,
    url: "https://velociraptor.local", tabTitle: "VR", triggerType: "timer",
    perceptualHash: "0000000000000000", isDuplicate: false, screenshotFile: `00000${seq}_t.webp`,
  };
}

const validDelta = JSON.stringify({
  findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "encoded cmd",
    relatedIocs: [], mitreTechniques: ["T1059"], status: "open" }],
  iocs: [], mitreTechniques: [{ id: "T1059", name: "Command Interpreter" }],
  threadsOpened: [], threadsClosed: [], timelineNote: "reviewed processes", summary: "found PS abuse",
});

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-pipeline-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
});

describe("AnalysisPipeline", () => {
  it("analyzes a window and persists merged state", async () => {
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", validDelta),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const state = await pipeline.analyzeWindow("c1", [capture(1)]);
    expect(state.findings).toHaveLength(1);
    expect(state.findings[0].title).toBe("PS abuse");

    const reloaded = await stateStore.load("c1");
    expect(reloaded.findings).toHaveLength(1);
  });

  it("throws on malformed AI response and leaves state unchanged", async () => {
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "not json at all"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      retries: 0,
    });

    await expect(pipeline.analyzeWindow("c1", [capture(1)])).rejects.toThrow();
    const state = await stateStore.load("c1");
    expect(state.findings).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/analysis/pipeline.test.ts`
Expected: FAIL — cannot resolve `pipeline.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import type { AIProvider, AnalyzeImage } from "../providers/provider.js";
import type { CaptureMetadata } from "../types.js";
import type { StateStore } from "./stateStore.js";
import type { InvestigationState } from "./stateTypes.js";
import { deltaSchema } from "./responseSchema.js";
import { buildStateSummary } from "./summary.js";
import { mergeDelta } from "./stateMerge.js";

const SYSTEM_PROMPT = [
  "You are a DFIR analyst assistant. You are shown screenshots from a forensic investigation",
  "(Velociraptor, VirusTotal, etc.) plus a summary of findings already recorded.",
  "Return ONLY JSON matching the required schema. Update existing findings by their id;",
  "never create a duplicate finding for a topic already listed. Open a thread for any lead",
  "you start chasing and close it by id when resolved.",
].join(" ");

export interface PipelineOptions {
  provider: AIProvider;
  stateStore: StateStore;
  imageLoader: (caseId: string, screenshotFile: string) => Promise<AnalyzeImage>;
  retries?: number;
  backoffMs?: number;
}

async function withRetry<T>(fn: () => Promise<T>, retries: number, backoffMs: number): Promise<T> {
  let attempt = 0;
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      if (attempt >= retries) throw err;
      await new Promise((r) => setTimeout(r, backoffMs * 2 ** attempt));
      attempt++;
    }
  }
}

export class AnalysisPipeline {
  constructor(private readonly opts: PipelineOptions) {}

  async analyzeWindow(caseId: string, captures: CaptureMetadata[]): Promise<InvestigationState> {
    const analyzable = captures.filter((c) => !c.isDuplicate);
    if (analyzable.length === 0) return this.opts.stateStore.load(caseId);

    const state = await this.opts.stateStore.load(caseId);
    const images = await Promise.all(
      analyzable.map((c) => this.opts.imageLoader(caseId, c.screenshotFile)),
    );
    const contextLines = analyzable
      .map((c) => `Screenshot ${c.screenshotFile} — ${c.tabTitle} (${c.url}) at ${c.timestamp}`)
      .join("\n");
    const userPrompt = `${buildStateSummary(state)}\n\nNEW SCREENSHOTS:\n${contextLines}\n\nReturn the JSON delta.`;

    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;

    const delta = await withRetry(async () => {
      const result = await this.opts.provider.analyze({ systemPrompt: SYSTEM_PROMPT, userPrompt, images });
      return deltaSchema.parse(JSON.parse(result.rawText));
    }, retries, backoffMs);

    const windowSequence = analyzable[analyzable.length - 1].sequenceNumber;
    const next = mergeDelta(state, delta, {
      windowSequence,
      timestamp: analyzable[analyzable.length - 1].timestamp,
      sourceScreenshots: analyzable.map((c) => c.screenshotFile),
    });
    await this.opts.stateStore.save(next);
    return next;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/analysis/pipeline.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/analysis/pipeline.ts companion/tests/analysis/pipeline.test.ts
git commit -m "feat: add analysis pipeline with retry and state merge"
```

---

## Task 9: Wire analysis into the server (windowing + pending_analysis)

**Files:**
- Modify: `companion/src/server.ts`
- Create: `companion/src/analysis/imageLoader.ts`
- Modify: `companion/tests/server.test.ts`

Add a window buffer keyed by caseId. On each non-duplicate capture, push to the buffer; when the buffer reaches `windowSize` (default 4) OR the trigger is a significant event (`navigation`/`tab_switch`), flush the window through the pipeline. On pipeline failure, log and keep captures queued (they remain in `captures.jsonl`; a `pending_analysis` marker file records sequence numbers to retry). The pipeline + provider are injected into `createApp` so tests use `MockProvider`.

- [ ] **Step 1: Create `companion/src/analysis/imageLoader.ts`**

```typescript
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { AnalyzeImage } from "../providers/provider.js";

export function makeImageLoader(store: CaseStore) {
  return async (caseId: string, screenshotFile: string): Promise<AnalyzeImage> => {
    const bytes = await readFile(join(store.screenshotsDir(caseId), screenshotFile));
    return { base64: bytes.toString("base64"), mimeType: "image/webp" };
  };
}
```

- [ ] **Step 2: Write the failing test (append to `tests/server.test.ts`)**

```typescript
import { AnalysisPipeline } from "../src/analysis/pipeline.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { MockProvider } from "../src/providers/provider.js";

describe("server analysis wiring", () => {
  it("flushes a window on a navigation trigger and updates state", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-an-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", JSON.stringify({
        findings: [{ id: "f1", severity: "High", title: "Hit", description: "d",
          relatedIocs: [], mitreTechniques: [], status: "open" }],
        iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        timelineNote: "n", summary: "s",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, windowSize: 10 });

    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await request(app).post("/captures").send({
      caseId: "c1", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
      triggerType: "navigation", imageBase64: await pngBase64(),
    });

    // analysis runs async after the response; poll the state briefly.
    let state = await stateStore.load("c1");
    for (let i = 0; i < 20 && state.findings.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    expect(state.findings).toHaveLength(1);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/server.test.ts`
Expected: FAIL — `createApp` does not accept a second options argument / pipeline undefined.

- [ ] **Step 4: Modify `companion/src/server.ts`**

Replace the `createApp` signature and the `/captures` handler body with the version below (keep `/cases` unchanged). Add the imports at the top.

```typescript
// add to imports at top:
import { writeFile } from "node:fs/promises";
import type { AnalysisPipeline } from "./analysis/pipeline.js";
import type { CaptureMetadata } from "./types.js";

export interface AppOptions {
  pipeline?: AnalysisPipeline;
  windowSize?: number;
}

export function createApp(store: CaseStore, options: AppOptions = {}): Express {
  const app = express();
  app.use(express.json({ limit: "25mb" }));

  const windowSize = options.windowSize ?? 4;
  const buffers = new Map<string, CaptureMetadata[]>();
  const SIGNIFICANT = new Set(["navigation", "tab_switch"]);

  async function flush(caseId: string): Promise<void> {
    const buf = buffers.get(caseId) ?? [];
    if (buf.length === 0 || !options.pipeline) return;
    buffers.set(caseId, []);
    try {
      await options.pipeline.analyzeWindow(caseId, buf);
    } catch (err) {
      const seqs = buf.map((c) => c.sequenceNumber);
      await writeFile(
        join(store.stateDir(caseId), "pending_analysis.json"),
        JSON.stringify({ pending: seqs, error: (err as Error).message }, null, 2),
        "utf8",
      );
    }
  }

  // /cases handler stays exactly as in Plan 1.
  app.post("/cases", async (req: Request, res: Response) => {
    try {
      const { caseId, name, investigator, aiProvider } = req.body ?? {};
      if (!caseId || !name) return res.status(400).json({ error: "caseId and name are required" });
      const meta = await store.createCase({
        caseId, name, investigator: investigator ?? "unknown", aiProvider: aiProvider ?? null,
      });
      return res.status(201).json(meta);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/captures", async (req: Request, res: Response) => {
    try {
      const metadata = await ingestCapture(store, req.body);
      res.status(201).json(metadata);
      if (!metadata.isDuplicate && options.pipeline) {
        const buf = buffers.get(metadata.caseId) ?? [];
        buf.push(metadata);
        buffers.set(metadata.caseId, buf);
        if (buf.length >= windowSize || SIGNIFICANT.has(metadata.triggerType)) {
          void flush(metadata.caseId);
        }
      }
      return;
    } catch (err) {
      if (err instanceof ZodError) return res.status(400).json({ error: "invalid payload", details: err.issues });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  return app;
}
```

Also update `startServer` to build a pipeline from env (provider/model/key). Append after `createApp`:

```typescript
import { StateStore } from "./analysis/stateStore.js";
import { AnalysisPipeline } from "./analysis/pipeline.js";
import { makeImageLoader } from "./analysis/imageLoader.js";
import { ProviderRegistry } from "./providers/provider.js";
import { OpenAIProvider } from "./providers/openai.js";
import { OpenRouterProvider } from "./providers/openrouter.js";
import { OllamaCloudProvider } from "./providers/ollama.js";
import { GeminiProvider } from "./providers/gemini.js";

export function buildPipeline(store: CaseStore): AnalysisPipeline | undefined {
  const name = process.env.DFIR_AI_PROVIDER;
  const model = process.env.DFIR_AI_MODEL ?? "";
  const apiKey = process.env.DFIR_AI_KEY ?? "";
  if (!name) return undefined;
  const registry = new ProviderRegistry();
  registry.register(new OpenAIProvider({ apiKey, model }));
  registry.register(new OpenRouterProvider({ apiKey, model }));
  registry.register(new OllamaCloudProvider({ apiKey, model }));
  registry.register(new GeminiProvider({ apiKey, model }));
  return new AnalysisPipeline({
    provider: registry.get(name),
    stateStore: new StateStore(store),
    imageLoader: makeImageLoader(store),
  });
}
```

And change `startServer` to:

```typescript
export function startServer(casesRoot: string, port = 4773): void {
  const store = new CaseStore(casesRoot);
  const app = createApp(store, { pipeline: buildPipeline(store) });
  app.listen(port, "127.0.0.1", () => {
    console.log(`DFIR companion listening on http://127.0.0.1:${port}`);
  });
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/server.test.ts`
Expected: PASS (4 tests — the 3 from Plan 1 plus the new wiring test).

- [ ] **Step 6: Run the full suite**

Run: `cd companion && npm test`
Expected: PASS across dedup, storage, ingest, analysis, providers, server.

- [ ] **Step 7: Commit**

```bash
git add companion/src/server.ts companion/src/analysis/imageLoader.ts companion/tests/server.test.ts
git commit -m "feat: wire analysis pipeline into server with windowing and pending_analysis"
```

---

## Self-Review

**Spec coverage (Plan 2 scope = analysis pipeline + providers):**
- Investigation state (findings, iocs, openThreads, timeline, mitreTechniques, lastSummary) → Task 1. ✓
- State persisted after every merge → Task 2 (StateStore) + Task 8 (save in pipeline). ✓
- Windowed analysis + significant-event flush → Task 9. ✓
- Strict schema enforcement; invalid responses rejected, state unpolluted → Task 3 + Task 8 (`deltaSchema.parse`, test asserts unchanged state). ✓
- Merge not replace; revisit updates by id, no duplication → Task 4 (dedicated test). ✓
- `openThreads` as the "what is still open" mechanism → Task 1 + Task 4 (open/close). ✓
- Compact summary context (not raw state) for long investigations → Task 5. ✓
- Provider abstraction for Ollama Cloud / OpenRouter / OpenAI / Gemini, switchable, normalized errors → Tasks 6–7. ✓
- AI failure → retry/backoff, then `pending_analysis`, evidence untouched → Task 8 (retry) + Task 9 (pending marker). ✓
- Out of scope (later): report generation, CSV/MD/JSON export, dashboard/WebSocket, live-vs-batch UI control → Plan 3. Extension → Plan 4.

**Placeholder scan:** No TBD/TODO; full code in every code step; exact commands + expected results. ✓

**Type consistency:** `InvestigationState`/`Finding`/`IOC`/`Thread`/`Technique`/`Severity` (Task 1) used consistently in Tasks 2,4,5,8. `AnalysisDelta`/`deltaSchema` (Task 3) consumed by Tasks 4,8. `mergeDelta(state, delta, ctx)` signature (Task 4) matches the call in Task 8. `AIProvider.analyze(AnalyzeRequest): AnalyzeResult` (Task 6) implemented identically by all providers (Task 7) and called in Task 8. `AnalysisPipeline.analyzeWindow(caseId, captures)` (Task 8) matches calls in Task 9. `CaseStore.stateDir/screenshotsDir` from Plan 1 used in Tasks 2,9. ✓
