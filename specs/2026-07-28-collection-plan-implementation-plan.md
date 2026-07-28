# Collection Plan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each incident type a *Collection plan* panel — its ordered evidence steps, ticked off automatically from the evidence already in the case, with analyst overrides — and delete the two fictional fields (`huntBundles`, `reportFraming`) that #236 shipped unused.

**Architecture:** A pure module owns the evidence vocabulary and derives each step's state from the case timeline's `sources` labels; a small per-case store holds analyst overrides; three routes expose the built plan and the overrides; a data-gated dashboard panel renders it. No AI, no new import hooks — the plan is recomputed on read from data already in memory.

**Tech Stack:** TypeScript (ESM, `.js` import specifiers), Express 4, Zod, Vitest + Supertest, vanilla JS in `public/dashboard.html`.

**Design spec:** `specs/2026-07-28-collection-plan-design.md`

## Global Constraints

- **Worktree:** `/home/hasamba/Projects/DFIR-347`, branch `feat/issue-347`. Never commit to `master`.
- **Never touch `cases/`.**
- Immutability — return new objects, never mutate inputs.
- Files 200–400 lines typical, 800 max; functions under 50 lines.
- Validate at boundaries; handle errors explicitly, never silently swallowed.
- Imports use the `.js` extension even for `.ts` sources (ESM/NodeNext).
- No attribution trailers in commits. Conventional commit types only.
- Verify with the commands CI runs, in order: `npm run build`, `npm run typecheck`, `npm test`. **`tsc --noEmit` is not sufficient — it skips the tests.**
- A step id is `[a-z-]+`. Analyst-facing labels are sentence case.

---

### Task 1: Evidence vocabulary and the pure plan builder

**Files:**
- Create: `companion/src/analysis/collectionPlan.ts`
- Test: `companion/tests/analysis/collectionPlan.test.ts`

**Interfaces:**
- Consumes: `ForensicEvent` from `./stateTypes.js` (field used: `sources: string[]`).
- Produces:
  - `COLLECTION_STEPS: readonly CollectionStepDef[]` where
    `CollectionStepDef = { id: string; label: string; satisfiedBy: readonly string[] }`
  - `type CollectionStepState = "collected" | "outstanding" | "external" | "override-collected" | "override-na"`
  - `type CollectionStep = { id: string; label: string; satisfiedBy: readonly string[]; state: CollectionStepState; reason: string }`
  - `type CollectionPlan = { steps: CollectionStep[]; nextStepId: string; collected: number; total: number }`
  - `getCollectionStep(id: string): CollectionStepDef | undefined`
  - `buildCollectionPlan(stepIds: readonly string[], events: readonly ForensicEvent[], overrides: Readonly<Record<string, CollectionOverride>>): CollectionPlan`
  - `type CollectionOverride = { state: "collected" | "na"; reason: string }`

- [ ] **Step 1: Write the failing test**

Create `companion/tests/analysis/collectionPlan.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import {
  COLLECTION_STEPS,
  getCollectionStep,
  buildCollectionPlan,
} from "../../src/analysis/collectionPlan.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(sources: string[]): ForensicEvent {
  return {
    id: `e${sources.join("-")}`, timestamp: "2026-01-01T00:00:00Z", description: "",
    severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], sources,
  };
}

describe("collection step vocabulary", () => {
  it("defines every step with a label and a satisfiedBy list", () => {
    expect(COLLECTION_STEPS.length).toBeGreaterThan(0);
    for (const s of COLLECTION_STEPS) {
      expect(s.id).toMatch(/^[a-z0-9-]+$/);
      expect(s.label.length).toBeGreaterThan(0);
      expect(Array.isArray(s.satisfiedBy)).toBe(true);
    }
    expect(new Set(COLLECTION_STEPS.map((s) => s.id)).size).toBe(COLLECTION_STEPS.length);
  });

  it("resolves a step by id", () => {
    expect(getCollectionStep("edr")?.label).toBe("EDR telemetry");
    expect(getCollectionStep("nope")).toBeUndefined();
  });

  // "CSV import" / "Log import" mean "we could not tell what this was" — they must satisfy nothing.
  it("never lets an unidentified import satisfy a step", () => {
    const all = COLLECTION_STEPS.flatMap((s) => s.satisfiedBy);
    expect(all).not.toContain("CSV import");
    expect(all).not.toContain("Log import");
  });
});

describe("buildCollectionPlan", () => {
  it("marks a step collected when the timeline holds a matching source", () => {
    const plan = buildCollectionPlan(["edr", "network"], [ev(["EDR (ECAR)"])], {});
    expect(plan.steps.find((s) => s.id === "edr")!.state).toBe("collected");
    expect(plan.steps.find((s) => s.id === "network")!.state).toBe("outstanding");
    expect(plan.collected).toBe(1);
    expect(plan.total).toBe(2);
  });

  it("ticks a step from ANY of its satisfying sources, not just the first", () => {
    for (const label of ["Chainsaw", "Hayabusa", "EVTX", "Sysmon", "Windows Event Log"]) {
      const plan = buildCollectionPlan(["windows-event-logs"], [ev([label])], {});
      expect(plan.steps[0].state, `${label} should satisfy windows-event-logs`).toBe("collected");
    }
  });

  it("preserves the declared order and names the next outstanding step", () => {
    const plan = buildCollectionPlan(["edr", "network", "siem"], [ev(["EDR (ECAR)"])], {});
    expect(plan.steps.map((s) => s.id)).toEqual(["edr", "network", "siem"]);
    expect(plan.nextStepId).toBe("network");
  });

  it("reports no next step once everything is collected", () => {
    const plan = buildCollectionPlan(["edr"], [ev(["EDR (ECAR)"])], {});
    expect(plan.nextStepId).toBe("");
  });

  // A step nothing can import is real work, but the tool must not nag about it.
  it("marks a step with no satisfying sources as external and never as next", () => {
    const plan = buildCollectionPlan(["physical-access", "network"], [], {});
    expect(plan.steps.find((s) => s.id === "physical-access")!.state).toBe("external");
    expect(plan.nextStepId).toBe("network");
  });

  it("excludes external steps from the collected/total counts", () => {
    const plan = buildCollectionPlan(["physical-access", "edr"], [ev(["EDR (ECAR)"])], {});
    expect(plan.total).toBe(1);
    expect(plan.collected).toBe(1);
  });

  it("lets an override beat the derived state in both directions", () => {
    const collected = buildCollectionPlan(["network"], [], { network: { state: "collected", reason: "pcap on the SAN" } });
    expect(collected.steps[0].state).toBe("override-collected");
    expect(collected.steps[0].reason).toBe("pcap on the SAN");
    expect(collected.collected).toBe(1);

    const na = buildCollectionPlan(["edr"], [ev(["EDR (ECAR)"])], { edr: { state: "na", reason: "no EDR here" } });
    expect(na.steps[0].state).toBe("override-na");
    expect(na.collected).toBe(0);
    expect(na.total).toBe(0);          // n/a leaves the denominator, like an external step
  });

  it("never proposes an overridden step as next", () => {
    const plan = buildCollectionPlan(["network", "siem"], [], { network: { state: "na", reason: "" } });
    expect(plan.nextStepId).toBe("siem");
  });

  it("ignores an unknown step id rather than rendering a blank row", () => {
    const plan = buildCollectionPlan(["edr", "not-a-step"], [], {});
    expect(plan.steps.map((s) => s.id)).toEqual(["edr"]);
  });

  it("is pure — does not mutate its inputs", () => {
    const events = [ev(["EDR (ECAR)"])];
    const overrides = { edr: { state: "na" as const, reason: "x" } };
    const snapshot = JSON.stringify({ events, overrides });
    buildCollectionPlan(["edr"], events, overrides);
    expect(JSON.stringify({ events, overrides })).toBe(snapshot);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/analysis/collectionPlan.test.ts`
Expected: FAIL — `Failed to resolve import ".../collectionPlan.js"`.

- [ ] **Step 3: Write the implementation**

Create `companion/src/analysis/collectionPlan.ts`:

```typescript
import type { ForensicEvent } from "./stateTypes.js";

// Guided evidence collection per incident type (#347). Steps name EVIDENCE, not tools: an analyst
// knows they need Windows event logs before they know which importer produces them, and a
// tool-named step would sit unticked because they used the other tool that yields the same evidence.
//
// `satisfiedBy` lists the event source labels that count. Labels come from two places and BOTH must
// be covered or a step under-ticks:
//   1. importer literals  — a fixed label the importer stamps ("MemProcFS", "Entra ID", ...)
//   2. detectTool()       — CSV/log/SIEM imports derive the label from the filename, yielding
//                           vendor names ("SentinelOne", "Splunk", ...)
// Missing (2) would leave the EDR step blind to Defender, SentinelOne, Carbon Black and Cortex XDR
// — the ones an analyst is most likely to actually have. collectionPlanVocabulary.test.ts pins
// every label against the real importers so an invented one fails the build.
//
// Pure and deterministic — no I/O, no AI.

export interface CollectionStepDef {
  id: string;
  label: string;
  // Empty = this evidence cannot be imported by this tool; the step is still worth doing, and
  // renders as "collect outside DFIR Companion" rather than nagging forever.
  satisfiedBy: readonly string[];
}

export const COLLECTION_STEPS: readonly CollectionStepDef[] = [
  { id: "edr", label: "EDR telemetry", satisfiedBy: ["EDR (ECAR)", "CrowdStrike Falcon", "SentinelOne", "Carbon Black", "Cortex XDR", "Microsoft Defender", "Wazuh", "Falco"] },
  { id: "windows-event-logs", label: "Windows event logs", satisfiedBy: ["Chainsaw", "Hayabusa", "EVTX", "Sysmon", "Windows Event Log"] },
  { id: "endpoint-triage", label: "Endpoint triage artifacts", satisfiedBy: ["Velociraptor", "KAPE", "Autopsy", "Cyber Triage", "MFT", "UsnJrnl", "Prefetch", "Amcache", "ShimCache", "LNK", "JumpLists", "Shellbags", "RecycleBin", "SRUM"] },
  { id: "memory", label: "Memory image", satisfiedBy: ["MemProcFS", "Volatility", "Rekall", "VolWeb"] },
  { id: "network", label: "Network traffic / IDS", satisfiedBy: ["Zeek", "Suricata", "Snort", "Security Onion", "Cisco ASA", "Arkime", "Wireshark"] },
  { id: "web-logs", label: "Web server access logs", satisfiedBy: ["Web Access Log"] },
  { id: "m365", label: "Microsoft 365 / mailbox audit", satisfiedBy: ["Microsoft 365", "Email"] },
  { id: "identity", label: "Identity sign-in logs", satisfiedBy: ["Entra ID"] },
  { id: "cloud-audit", label: "Cloud control-plane audit", satisfiedBy: ["AWS CloudTrail", "Azure Activity", "GCP Audit", "Kubernetes Audit"] },
  { id: "siem", label: "SIEM / aggregated logs", satisfiedBy: ["SIEM", "SIEM import", "Splunk", "Elastic", "Microsoft Sentinel", "QRadar", "Graylog", "Syslog", "journald", "auditd", "osquery", "sysdig"] },
  { id: "sandbox", label: "Malware sandbox report", satisfiedBy: ["CAPEv2", "Falcon Sandbox"] },
  { id: "super-timeline", label: "Super-timeline", satisfiedBy: ["Plaso", "Timesketch"] },
  { id: "threat-scan", label: "Threat / YARA scan", satisfiedBy: ["THOR", "YARA", "VirusTotal", "Nessus"] },
  { id: "physical-access", label: "Physical access records", satisfiedBy: [] },
];

const BY_ID = new Map<string, CollectionStepDef>(COLLECTION_STEPS.map((s) => [s.id, s]));

export function getCollectionStep(id: string): CollectionStepDef | undefined {
  return BY_ID.get(id);
}

export interface CollectionOverride {
  state: "collected" | "na";
  reason: string;
}

export type CollectionStepState =
  | "collected"           // derived: matching evidence is in the case
  | "outstanding"         // derived: not yet collected
  | "external"            // nothing can import this; collect it outside the tool
  | "override-collected"  // analyst asserted they have it
  | "override-na";        // analyst asserted it does not apply here

export interface CollectionStep {
  id: string;
  label: string;
  satisfiedBy: readonly string[];
  state: CollectionStepState;
  reason: string;         // the analyst's override reason ("" when derived)
}

export interface CollectionPlan {
  steps: CollectionStep[];
  nextStepId: string;     // the first step still worth collecting ("" when none)
  collected: number;
  total: number;          // excludes external and n/a steps — they are not collectable here
}

// Build the plan for one case. `stepIds` is the incident type's declared order; unknown ids are
// dropped rather than rendered as blank rows (a typo in a custom type's JSON must not reach the UI).
export function buildCollectionPlan(
  stepIds: readonly string[],
  events: readonly ForensicEvent[],
  overrides: Readonly<Record<string, CollectionOverride>>,
): CollectionPlan {
  // One pass over the timeline; every other panel already holds it in memory.
  const present = new Set<string>();
  for (const e of events) for (const s of e.sources ?? []) present.add(s);

  const steps: CollectionStep[] = [];
  for (const id of stepIds) {
    const def = BY_ID.get(id);
    if (!def) continue;
    const override = overrides[id];
    const state: CollectionStepState = override
      ? (override.state === "collected" ? "override-collected" : "override-na")
      : def.satisfiedBy.length === 0
        ? "external"
        : def.satisfiedBy.some((s) => present.has(s))
          ? "collected"
          : "outstanding";
    steps.push({ id: def.id, label: def.label, satisfiedBy: def.satisfiedBy, state, reason: override?.reason ?? "" });
  }

  const countable = steps.filter((s) => s.state !== "external" && s.state !== "override-na");
  return {
    steps,
    nextStepId: steps.find((s) => s.state === "outstanding")?.id ?? "",
    collected: countable.filter((s) => s.state === "collected" || s.state === "override-collected").length,
    total: countable.length,
  };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/analysis/collectionPlan.test.ts`
Expected: PASS, 12 tests.

- [ ] **Step 5: Commit**

```bash
cd /home/hasamba/Projects/DFIR-347
git add companion/src/analysis/collectionPlan.ts companion/tests/analysis/collectionPlan.test.ts
git commit -m "feat(collection-plan): evidence vocabulary and pure plan builder (#347)"
```

---

### Task 2: The vocabulary guard test

This is the task that stops #347 repeating #236's mistake. It has no implementation — it asserts the vocabulary from Task 1 refers to labels the importers really stamp.

**Files:**
- Test: `companion/tests/analysis/collectionPlanVocabulary.test.ts`

**Interfaces:**
- Consumes: `COLLECTION_STEPS` from Task 1; `detectTool` from `../../src/analysis/toolDetect.js`.
- Produces: nothing.

- [ ] **Step 1: Write the test**

Create `companion/tests/analysis/collectionPlanVocabulary.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { COLLECTION_STEPS } from "../../src/analysis/collectionPlan.js";
import { detectTool } from "../../src/analysis/toolDetect.js";

// #236 shipped 27 hunt-bundle ids and 8 report-template ids that referred to nothing. This test is
// the guard against doing it again: every source label a collection step claims to be satisfied by
// must be a label some importer actually stamps on an event, or a name detectTool() resolves.
// A renamed or invented label fails the build instead of silently leaving a step that never ticks.

const SRC = fileURLToPath(new URL("../../src/", import.meta.url));

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) return walk(full);
    return full.endsWith(".ts") ? [full] : [];
  });
}

// Labels written as literals in the importers: `sources: ["X"]` or `const X_SOURCE = "Y"`.
function importerLiterals(): Set<string> {
  const found = new Set<string>();
  for (const file of walk(SRC)) {
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(/sources:\s*\["([^"]+)"\]/g)) found.add(m[1]);
    for (const m of text.matchAll(/_SOURCE\s*=\s*"([^"]+)"/g)) found.add(m[1]);
    for (const m of text.matchAll(/\?\?\s*"([A-Z][^"]+)"/g)) found.add(m[1]);
  }
  return found;
}

describe("collection-plan vocabulary is grounded in real importers", () => {
  const literals = importerLiterals();

  it("finds the importer source literals to check against", () => {
    // Guards the guard: if the scrape breaks, every label would "pass" vacuously.
    expect(literals.size).toBeGreaterThan(20);
    expect(literals).toContain("MemProcFS");
    expect(literals).toContain("Entra ID");
  });

  it("every satisfying label is a real importer literal or a detectTool name", () => {
    const unknown: string[] = [];
    for (const step of COLLECTION_STEPS) {
      for (const label of step.satisfiedBy) {
        // detectTool round-trips its own vendor names: its patterns match the name itself.
        if (literals.has(label) || detectTool(label) === label) continue;
        unknown.push(`${step.id} → "${label}"`);
      }
    }
    expect(unknown, `labels no importer produces:\n${unknown.join("\n")}`).toEqual([]);
  });

  it("every step is either satisfiable or explicitly external", () => {
    for (const step of COLLECTION_STEPS) {
      const satisfiable = step.satisfiedBy.length > 0;
      const external = step.id === "physical-access";
      expect(satisfiable || external, `step "${step.id}" can never be satisfied`).toBe(true);
    }
  });
});
```

- [ ] **Step 2: Run it and verify it passes against Task 1's vocabulary**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/analysis/collectionPlanVocabulary.test.ts`
Expected: PASS, 3 tests.

- [ ] **Step 3: Prove the guard actually catches an invented label**

Temporarily add `"Definitely Not A Real Tool"` to the `edr` step's `satisfiedBy` in
`companion/src/analysis/collectionPlan.ts`, then run the test again.
Expected: FAIL, listing `edr → "Definitely Not A Real Tool"`.
**Then remove the fake label** and re-run to confirm PASS. A guard that has never failed is not
known to work.

- [ ] **Step 4: Commit**

```bash
cd /home/hasamba/Projects/DFIR-347
git add companion/tests/analysis/collectionPlanVocabulary.test.ts
git commit -m "test(collection-plan): pin the evidence vocabulary to real importer labels (#347)"
```

---

### Task 3: Per-case overrides store

**Files:**
- Create: `companion/src/analysis/collectionPlanStore.ts`
- Test: `companion/tests/analysis/collectionPlanStore.test.ts`

**Interfaces:**
- Consumes: `CollectionOverride` from Task 1; `CaseStore` from `../storage/caseStore.js`; `atomicWrite` from `../storage/atomicWrite.js`.
- Produces:
  - `class CollectionPlanStore` with `constructor(cases: CaseStore)`
  - `load(caseId: string): Promise<Record<string, CollectionOverride>>`
  - `set(caseId: string, stepId: string, override: CollectionOverride): Promise<Record<string, CollectionOverride>>`
  - `clear(caseId: string, stepId: string): Promise<Record<string, CollectionOverride>>`

- [ ] **Step 1: Write the failing test**

Create `companion/tests/analysis/collectionPlanStore.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CollectionPlanStore } from "../../src/analysis/collectionPlanStore.js";

async function makeStore() {
  const root = await mkdtemp(join(tmpdir(), "dfir-cplan-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { cases, store: new CollectionPlanStore(cases) };
}

describe("CollectionPlanStore", () => {
  it("returns no overrides for a case that has never set one", async () => {
    const { store } = await makeStore();
    expect(await store.load("c1")).toEqual({});
  });

  it("round-trips an override", async () => {
    const { store } = await makeStore();
    await store.set("c1", "edr", { state: "na", reason: "no EDR in this estate" });
    expect(await store.load("c1")).toEqual({ edr: { state: "na", reason: "no EDR in this estate" } });
  });

  it("keeps overrides for other steps when setting one", async () => {
    const { store } = await makeStore();
    await store.set("c1", "edr", { state: "na", reason: "a" });
    const after = await store.set("c1", "network", { state: "collected", reason: "b" });
    expect(Object.keys(after).sort()).toEqual(["edr", "network"]);
  });

  it("clears one override without touching the others", async () => {
    const { store } = await makeStore();
    await store.set("c1", "edr", { state: "na", reason: "a" });
    await store.set("c1", "network", { state: "collected", reason: "b" });
    expect(await store.clear("c1", "edr")).toEqual({ network: { state: "collected", reason: "b" } });
  });

  it("clearing an override that was never set is a no-op, not an error", async () => {
    const { store } = await makeStore();
    expect(await store.clear("c1", "edr")).toEqual({});
  });

  // A corrupt file must not block the panel — the analyst can re-assert an override, but they
  // cannot recover a case whose every read throws.
  it("returns no overrides when the file is corrupt", async () => {
    const { cases, store } = await makeStore();
    const dir = cases.stateDir("c1");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "collection-plan.json"), "{ not json", "utf8");
    expect(await store.load("c1")).toEqual({});
  });

  it("drops a malformed override rather than trusting it", async () => {
    const { cases, store } = await makeStore();
    const dir = cases.stateDir("c1");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "collection-plan.json"),
      JSON.stringify({ overrides: { edr: { state: "banana", reason: "x" }, network: { state: "na", reason: "ok" } } }), "utf8");
    expect(await store.load("c1")).toEqual({ network: { state: "na", reason: "ok" } });
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/analysis/collectionPlanStore.test.ts`
Expected: FAIL — cannot resolve `collectionPlanStore.js`.

- [ ] **Step 3: Write the implementation**

Create `companion/src/analysis/collectionPlanStore.ts`:

```typescript
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { CollectionOverride } from "./collectionPlan.js";

// Per-case collection-plan overrides (#347), in state/collection-plan.json. A stateless wrapper
// over CaseStore (mirrors IncidentTypeStore / ClockSkewStore). Only the analyst's assertions live
// here — every derived state is recomputed from the timeline on read, so there is nothing to stale.

const overrideSchema = z.object({
  state: z.enum(["collected", "na"]),
  reason: z.string().catch(""),
});

// A malformed entry is dropped, not defaulted: an override is an analyst assertion, and inventing
// one would silently mark evidence collected that nobody vouched for.
const recordSchema = z.object({
  overrides: z.record(z.string(), overrideSchema.nullable().catch(null)).catch({}),
});

export type CollectionOverrides = Record<string, CollectionOverride>;

export class CollectionPlanStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "collection-plan.json");
  }

  async load(caseId: string): Promise<CollectionOverrides> {
    let raw: string;
    try {
      raw = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
    try {
      const parsed = recordSchema.parse(JSON.parse(raw));
      const out: CollectionOverrides = {};
      for (const [stepId, override] of Object.entries(parsed.overrides)) {
        if (override) out[stepId] = override;
      }
      return out;
    } catch {
      // Corrupt file — the panel still renders from derived state.
      return {};
    }
  }

  private async save(caseId: string, overrides: CollectionOverrides): Promise<CollectionOverrides> {
    await atomicWrite(this.path(caseId), JSON.stringify({ overrides }, null, 2));
    return overrides;
  }

  async set(caseId: string, stepId: string, override: CollectionOverride): Promise<CollectionOverrides> {
    const current = await this.load(caseId);
    return this.save(caseId, { ...current, [stepId]: override });
  }

  async clear(caseId: string, stepId: string): Promise<CollectionOverrides> {
    const current = await this.load(caseId);
    if (!(stepId in current)) return current;
    const { [stepId]: _removed, ...rest } = current;
    return this.save(caseId, rest);
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/analysis/collectionPlanStore.test.ts`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
cd /home/hasamba/Projects/DFIR-347
git add companion/src/analysis/collectionPlanStore.ts companion/tests/analysis/collectionPlanStore.test.ts
git commit -m "feat(collection-plan): per-case analyst override store (#347)"
```

---

### Task 4: Rewrite the incident types and drop the fictional fields

**Files:**
- Modify: `companion/data/incident-types/*.json` (all 8)
- Modify: `companion/src/analysis/incidentTypes.ts`
- Modify: `companion/tests/analysis/incidentTypes.test.ts`
- Test: `companion/tests/analysis/incidentTypePlans.test.ts` (create)

**Interfaces:**
- Consumes: `COLLECTION_STEPS` / `getCollectionStep` from Task 1.
- Produces: `IncidentType` no longer carries `huntBundles`, `reportFraming`, or the
  `IncidentTypeReportFraming` type. `recommendedImportOrder` now holds collection step ids.

- [ ] **Step 1: Write the failing test**

Create `companion/tests/analysis/incidentTypePlans.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { loadBuiltInIncidentTypes } from "../../src/analysis/incidentTypesData.js";
import { getCollectionStep } from "../../src/analysis/collectionPlan.js";

describe("incident-type collection plans", () => {
  const types = loadBuiltInIncidentTypes();

  it("every type declares a non-empty plan of DEFINED step ids", () => {
    for (const t of types) {
      expect(t.recommendedImportOrder.length, `${t.id} has no collection plan`).toBeGreaterThan(0);
      for (const id of t.recommendedImportOrder) {
        expect(getCollectionStep(id), `${t.id} references unknown step "${id}"`).toBeDefined();
      }
    }
  });

  it("no type repeats a step", () => {
    for (const t of types) {
      expect(new Set(t.recommendedImportOrder).size, `${t.id} repeats a step`).toBe(t.recommendedImportOrder.length);
    }
  });

  it("matches the orders agreed in the design", () => {
    const byId = new Map(types.map((t) => [t.id, t.recommendedImportOrder]));
    expect(byId.get("ransomware")).toEqual(["edr", "memory", "windows-event-logs", "endpoint-triage", "network", "siem"]);
    expect(byId.get("bec")).toEqual(["m365", "identity", "siem", "network"]);
    expect(byId.get("data-exfiltration")).toEqual(["network", "siem", "edr", "cloud-audit", "m365", "endpoint-triage"]);
    expect(byId.get("intrusion")).toEqual(["network", "edr", "windows-event-logs", "endpoint-triage", "siem"]);
    expect(byId.get("insider-threat")).toEqual(["siem", "endpoint-triage", "super-timeline", "m365", "cloud-audit", "physical-access"]);
    expect(byId.get("cloud-compromise")).toEqual(["cloud-audit", "identity", "m365", "siem", "edr"]);
    expect(byId.get("web-app-intrusion")).toEqual(["web-logs", "network", "edr", "windows-event-logs", "siem"]);
    expect(byId.get("malware-outbreak")).toEqual(["edr", "memory", "sandbox", "windows-event-logs", "network", "threat-scan"]);
  });

  it("no longer carries the fictional hunt-bundle and report-framing fields", () => {
    for (const t of types) {
      expect(t).not.toHaveProperty("huntBundles");
      expect(t).not.toHaveProperty("reportFraming");
    }
  });

  // An analyst's custom type written against the old shape must keep working.
  it("ignores the removed fields rather than rejecting an older custom definition", async () => {
    const { parseIncidentType } = await import("../../src/analysis/incidentTypes.js");
    const parsed = parseIncidentType({
      id: "legacy", name: "Legacy",
      recommendedImportOrder: ["edr"],
      huntBundles: ["vss-delete"],
      reportFraming: { template: "ransomware-executive", audience: "board", summaryPrompt: "x" },
    });
    expect(parsed).not.toBeNull();
    expect(parsed).not.toHaveProperty("huntBundles");
    expect(parsed).not.toHaveProperty("reportFraming");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/analysis/incidentTypePlans.test.ts`
Expected: FAIL — the JSON still holds the old `recommendedImportOrder` values and both removed fields.

- [ ] **Step 3: Strip the two fields from the type**

In `companion/src/analysis/incidentTypes.ts`:

1. Delete the `IncidentTypeReportFraming` interface.
2. From `interface IncidentType`, delete the `huntBundles`, `findingsSeeds`-adjacent
   `reportFraming` lines — keep `recommendedImportOrder` and `findingsSeeds`. The block becomes:

```typescript
export interface IncidentType extends CaseTemplate {
  recommendedImportOrder: string[];   // ordered collection-plan step ids (#347)
  findingsSeeds: string[];            // expected finding categories, pre-seeded as open questions
  synthesisHint: string;              // one-line context for the synthesis prompt
}
```

3. From `incidentTypeSchema`, delete the `huntBundles` and `reportFraming` entries. Zod strips
   unknown keys by default, so an older custom file carrying them still parses and the extra keys
   are dropped — which is what the last test above asserts.
4. Update the module header comment: remove the "defined and served over the API, not yet
   consumed (#347)" note and describe `recommendedImportOrder` as the collection plan.

- [ ] **Step 4: Rewrite the eight JSON files**

For each file in `companion/data/incident-types/`, delete the `huntBundles` and `reportFraming`
keys and replace `recommendedImportOrder` with the agreed order:

| File | `recommendedImportOrder` |
|---|---|
| `ransomware.json` | `["edr","memory","windows-event-logs","endpoint-triage","network","siem"]` |
| `bec.json` | `["m365","identity","siem","network"]` |
| `data-exfiltration.json` | `["network","siem","edr","cloud-audit","m365","endpoint-triage"]` |
| `intrusion.json` | `["network","edr","windows-event-logs","endpoint-triage","siem"]` |
| `insider-threat.json` | `["siem","endpoint-triage","super-timeline","m365","cloud-audit","physical-access"]` |
| `cloud-compromise.json` | `["cloud-audit","identity","m365","siem","edr"]` |
| `web-app-intrusion.json` | `["web-logs","network","edr","windows-event-logs","siem"]` |
| `malware-outbreak.json` | `["edr","memory","sandbox","windows-event-logs","network","threat-scan"]` |

Leave every other key (`initialKeyQuestions`, `initialNextSteps`, `findingsSeeds`,
`synthesisHint`, …) untouched.

- [ ] **Step 5: Update the existing incident-type test**

In `companion/tests/analysis/incidentTypes.test.ts`:

- In "every built-in carries the fields the pickers and the apply path read", delete the
  `expect(t.huntBundles.length)...` and `expect(t.reportFraming.template.length)...` assertions.
- In "ransomware seeds VSS deletion … BEC seeds inbox rules and OAuth", delete
  `expect(ransomware.huntBundles).toContain("vss-delete")` and
  `expect(bec.huntBundles).toContain("mailbox-rules")`. The findings-seed assertions stay.
- In "keeps a definition whose optional fields are malformed", delete the `huntBundles` and
  `reportFraming` inputs and their two assertions.
- In the `customType()` helper, delete the `huntBundles` and `reportFraming` properties.

- [ ] **Step 6: Run both test files to verify they pass**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/analysis/incidentTypePlans.test.ts tests/analysis/incidentTypes.test.ts`
Expected: PASS — 5 tests in the new file, the existing file's tests all still green.

- [ ] **Step 7: Commit**

```bash
cd /home/hasamba/Projects/DFIR-347
git add companion/data/incident-types companion/src/analysis/incidentTypes.ts \
        companion/tests/analysis/incidentTypes.test.ts companion/tests/analysis/incidentTypePlans.test.ts
git commit -m "feat(collection-plan): rewrite type plans in evidence terms, drop unused fields (#347)"
```

---

### Task 5: Routes and server wiring

**Files:**
- Create: `companion/src/routes/collectionPlan.ts`
- Modify: `companion/src/server.ts`
- Test: `companion/tests/server/collectionPlanRoutes.test.ts`

**Interfaces:**
- Consumes: `buildCollectionPlan` (Task 1), `CollectionPlanStore` (Task 3), `IncidentTypeStore` (existing).
- Produces:
  - `registerCollectionPlanRoutes(app: Express, ctx: RouteContext): void`
  - `AppOptions.collectionPlanStore?: CollectionPlanStore`
  - `GET /cases/:id/collection-plan` → `{ typeId, plan }` (`plan` is `null` with no incident type)
  - `PUT /cases/:id/collection-plan/:stepId` body `{ state: "collected"|"na", reason?: string }` → `{ typeId, plan }`
  - `DELETE /cases/:id/collection-plan/:stepId` → `{ typeId, plan }`

- [ ] **Step 1: Write the failing test**

Create `companion/tests/server/collectionPlanRoutes.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { CollectionPlanStore } from "../../src/analysis/collectionPlanStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

function ev(sources: string[]): ForensicEvent {
  return {
    id: `e-${sources[0]}`, timestamp: "2026-01-01T00:00:00Z", description: "", severity: "Info",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], sources,
  };
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-cplanroute-"));
  const casesRoot = join(root, "cases");
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const app = createApp(store, {
    stateStore, aiConfigured: false,
    activityLogStore: new ActivityLogStore(store),
    incidentTypeStore: new IncidentTypeStore(store, join(root, "incident-types")),
    collectionPlanStore: new CollectionPlanStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const withEvents = async (events: ForensicEvent[]) => {
    const s = await stateStore.load("c1");
    await stateStore.save({ ...s, forensicTimeline: events } as InvestigationState);
  };
  return { app, stateStore, withEvents };
}

describe("GET /cases/:id/collection-plan", () => {
  it("returns no plan for a case with no incident type", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/collection-plan");
    expect(res.status).toBe(200);
    expect(res.body.typeId).toBe("");
    expect(res.body.plan).toBeNull();
  });

  it("returns the type's ordered plan, ticking what the case already holds", async () => {
    const { app, withEvents } = await makeApp();
    await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });
    await withEvents([ev(["EDR (ECAR)"])]);

    const res = await request(app).get("/cases/c1/collection-plan");
    expect(res.status).toBe(200);
    expect(res.body.typeId).toBe("ransomware");
    expect(res.body.plan.steps.map((s: { id: string }) => s.id))
      .toEqual(["edr", "memory", "windows-event-logs", "endpoint-triage", "network", "siem"]);
    expect(res.body.plan.steps[0].state).toBe("collected");
    expect(res.body.plan.nextStepId).toBe("memory");
  });
});

describe("PUT/DELETE /cases/:id/collection-plan/:stepId", () => {
  it("sets an override that beats the derived state", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });

    const res = await request(app).put("/cases/c1/collection-plan/edr").send({ state: "na", reason: "no EDR here" });
    expect(res.status).toBe(200);
    const step = res.body.plan.steps.find((s: { id: string }) => s.id === "edr");
    expect(step.state).toBe("override-na");
    expect(step.reason).toBe("no EDR here");
    expect(res.body.plan.nextStepId).toBe("memory");
  });

  it("clears an override, returning the step to automatic", async () => {
    const { app, withEvents } = await makeApp();
    await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });
    await withEvents([ev(["EDR (ECAR)"])]);
    await request(app).put("/cases/c1/collection-plan/edr").send({ state: "na", reason: "x" });

    const res = await request(app).delete("/cases/c1/collection-plan/edr");
    expect(res.status).toBe(200);
    expect(res.body.plan.steps.find((s: { id: string }) => s.id === "edr").state).toBe("collected");
  });

  it("rejects an unknown step id and an invalid state", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });
    expect((await request(app).put("/cases/c1/collection-plan/nope").send({ state: "na" })).status).toBe(404);
    expect((await request(app).put("/cases/c1/collection-plan/edr").send({ state: "banana" })).status).toBe(400);
    expect((await request(app).put("/cases/c1/collection-plan/edr").send({})).status).toBe(400);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/server/collectionPlanRoutes.test.ts`
Expected: FAIL — cannot resolve `collectionPlanStore.js` in `server.ts` / routes not registered (404s).

- [ ] **Step 3: Write the routes**

Create `companion/src/routes/collectionPlan.ts`:

```typescript
import type { Express, Request, Response } from "express";
import { buildCollectionPlan, getCollectionStep, type CollectionPlan } from "../analysis/collectionPlan.js";
import type { RouteContext } from "./context.js";

/**
 * Collection-plan domain (#347): the case's incident type expressed as an ordered evidence
 * checklist, each step derived from the evidence already in the case, with analyst overrides.
 *   - GET    /cases/:id/collection-plan           — the built plan (null with no incident type).
 *   - PUT    /cases/:id/collection-plan/:stepId   — assert collected / not-applicable.
 *   - DELETE /cases/:id/collection-plan/:stepId   — return the step to automatic.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 */
export function registerCollectionPlanRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  // Build the response shared by all three routes: the chosen type id plus its plan. Recomputed
  // every time from the timeline — no derived state is ever persisted, so nothing can go stale.
  async function plan(caseId: string): Promise<{ typeId: string; plan: CollectionPlan | null }> {
    const type = options.incidentTypeStore ? await options.incidentTypeStore.loadType(caseId) : null;
    if (!type) return { typeId: "", plan: null };
    const state = await options.stateStore!.load(caseId);
    const overrides = options.collectionPlanStore ? await options.collectionPlanStore.load(caseId) : {};
    return { typeId: type.id, plan: buildCollectionPlan(type.recommendedImportOrder, state.forensicTimeline, overrides) };
  }

  function configured(res: Response): boolean {
    if (!options.collectionPlanStore || !options.stateStore) {
      res.status(501).json({ error: "collection-plan store not configured" });
      return false;
    }
    return true;
  }

  app.get("/cases/:id/collection-plan", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      return res.status(200).json(await plan(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/collection-plan/:stepId", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const { stepId } = req.params;
    if (!getCollectionStep(stepId)) return res.status(404).json({ error: `unknown collection step "${stepId}"` });
    const state = req.body?.state;
    if (state !== "collected" && state !== "na") {
      return res.status(400).json({ error: 'state must be "collected" or "na"' });
    }
    const reason = typeof req.body?.reason === "string" ? req.body.reason.slice(0, 500) : "";
    try {
      await options.collectionPlanStore!.set(req.params.id, stepId, { state, reason });
      return res.status(200).json(await plan(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/collection-plan/:stepId", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const { stepId } = req.params;
    if (!getCollectionStep(stepId)) return res.status(404).json({ error: `unknown collection step "${stepId}"` });
    try {
      await options.collectionPlanStore!.clear(req.params.id, stepId);
      return res.status(200).json(await plan(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
```

- [ ] **Step 4: Wire it into the server**

In `companion/src/server.ts`, four edits mirroring how `incidentTypeStore` is wired:

1. Beside `import { registerIncidentTypeRoutes } from "./routes/incidentTypes.js";` add:

```typescript
import { registerCollectionPlanRoutes } from "./routes/collectionPlan.js";
```

2. Beside `import { IncidentTypeStore } from "./analysis/incidentTypeStore.js";` add:

```typescript
import { CollectionPlanStore } from "./analysis/collectionPlanStore.js";
```

3. In `AppOptions`, after the `incidentTypeStore?: IncidentTypeStore;` block, add:

```typescript
  // Collection plan (#347): per-case analyst overrides for the incident type's evidence checklist.
  // The plan itself is derived on read from the timeline — only the overrides are stored.
  collectionPlanStore?: CollectionPlanStore;
```

4. After `registerIncidentTypeRoutes(app, ctx);` add:

```typescript
  registerCollectionPlanRoutes(app, ctx);
```

5. In `startServer`, after the `const incidentTypeStore = ...` line add:

```typescript
  const collectionPlanStore = new CollectionPlanStore(store);
```

and add `collectionPlanStore,` to the options object passed to `createApp`, immediately after
`incidentTypeStore,`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/server/collectionPlanRoutes.test.ts`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
cd /home/hasamba/Projects/DFIR-347
git add companion/src/routes/collectionPlan.ts companion/src/server.ts companion/tests/server/collectionPlanRoutes.test.ts
git commit -m "feat(collection-plan): routes for the plan and analyst overrides (#347)"
```

---

### Task 6: Dashboard panel and section wiring

**Files:**
- Modify: `public/dashboard.html`
- Modify: `companion/src/analysis/dashboardViews.ts`
- Test: `companion/tests/analysis/dashboardViews.test.ts` — **this file already exists. Append a
  new `describe` block to it; do not overwrite it.** It already asserts every profile references
  only registered section ids, so adding the section to a profile without registering it fails there
  too.

**Interfaces:**
- Consumes: `GET/PUT/DELETE /cases/:id/collection-plan` from Task 5.
- Produces: section id `sec-collection-plan`, registered everywhere §8 of CLAUDE.md requires.

- [ ] **Step 1: Write the failing test**

Append this `describe` block to the end of the existing
`companion/tests/analysis/dashboardViews.test.ts`. `BUILT_IN_DASHBOARD_VIEWS` and
`DASHBOARD_SECTION_IDS` are already imported at the top of that file — do not re-import them.

```typescript
describe("sec-collection-plan registration (#347)", () => {
  it("is a registered dashboard section", () => {
    expect(DASHBOARD_SECTION_IDS).toContain("sec-collection-plan");
  });

  it("appears in the Triage and Hunt Prep profiles", () => {
    for (const id of ["triage", "hunt-prep"]) {
      const view = BUILT_IN_DASHBOARD_VIEWS.find((v) => v.id === id)!;
      expect(view.sections, `${id} is missing sec-collection-plan`).toContain("sec-collection-plan");
    }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/analysis/dashboardViews.test.ts`
Expected: FAIL — `sec-collection-plan` is in neither list.

- [ ] **Step 3: Register the section**

In `companion/src/analysis/dashboardViews.ts`:

1. Add `"sec-collection-plan",` to `DASHBOARD_SECTION_IDS`, immediately after `"sec-next-steps",`.
2. In the `triage` view's `sections`, add `"sec-collection-plan",` immediately after `"sec-next-steps",`.
3. In the `hunt-prep` view's `sections`, add `"sec-collection-plan",` immediately after `"sec-next-steps",`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/hasamba/Projects/DFIR-347/companion && npx vitest run tests/analysis/dashboardViews.test.ts`
Expected: PASS.

- [ ] **Step 5: Add the panel markup**

In `public/dashboard.html`, immediately after the `sec-next-steps` section element, insert. Note
`data-gate-open=""` — the section stays hidden until its render sets the attribute to `"1"`, which
is how a case with no incident type shows nothing (the same mechanism `sec-mem-nextsteps` uses):

```html
    <!-- Collection plan (#347): the incident type's evidence checklist; hidden until a type is set. -->
    <section id="sec-collection-plan" data-gate-open="" style="grid-column: 1 / -1; display:none"><h2>Collection Plan<span class="ev-sub">the evidence this incident type calls for, in order — ticked off from what the case already holds (derived, no AI)</span></h2><div id="collectionPlan">—</div></section>
    <style>
      #sec-collection-plan .cp-row{display:flex;align-items:baseline;gap:10px;padding:6px 8px;border-bottom:1px solid var(--c-232a33)}
      #sec-collection-plan .cp-row:last-child{border-bottom:none}
      #sec-collection-plan .cp-mark{width:16px;flex:0 0 16px;text-align:center}
      #sec-collection-plan .cp-label{font-weight:600}
      #sec-collection-plan .cp-next{color:var(--c-ffb454)}
      #sec-collection-plan .cp-hint{color:var(--c-9aa4b2);font-size:11px}
      #sec-collection-plan .cp-act{margin-left:auto;display:flex;gap:6px}
      #sec-collection-plan .cp-act button{padding:1px 8px;font-size:11px;text-transform:none;letter-spacing:0;font-weight:400}
      #sec-collection-plan .cp-done{color:var(--c-9aa4b2);font-size:12px;margin-bottom:8px}
    </style>
```

- [ ] **Step 6: Add the render + interaction script**

In `public/dashboard.html`, add these functions next to the other per-section renderers, and call
`renderCollectionPlan()` from the same place other sections refresh after a state load:

```javascript
    // Collection plan (#347). Derived server-side from the case timeline; this only renders it and
    // posts the analyst's overrides. The section is data-gated: no incident type → no plan → stays
    // hidden, because a generic collection plan would be guesswork.
    const CP_MARK = {
      collected: "✔", "override-collected": "✔", "override-na": "—", external: "↗", outstanding: "○",
    };
    async function renderCollectionPlan() {
      const caseId = document.getElementById("caseId").value.trim();
      const sec = document.getElementById("sec-collection-plan");
      const el = document.getElementById("collectionPlan");
      if (!caseId) { sec.dataset.gateOpen = ""; applySectionsVis(); return; }
      let data;
      try {
        const r = await fetch(`/cases/${encodeURIComponent(caseId)}/collection-plan`);
        data = r.ok ? await r.json() : null;
      } catch { data = null; }
      if (!data || !data.plan) { sec.dataset.gateOpen = ""; applySectionsVis(); return; }

      const p = data.plan;
      const rows = p.steps.map(s => {
        const isNext = s.id === p.nextStepId;
        const hint = s.state === "external"
          ? "collect outside DFIR Companion"
          : s.reason ? esc(s.reason)
          : s.state === "outstanding" ? "satisfied by: " + esc(s.satisfiedBy.join(", "))
          : "";
        const acts = s.state === "collected"
          ? ""
          : (s.state === "override-collected" || s.state === "override-na")
            ? `<button data-cp-clear="${esc(s.id)}">Undo</button>`
            : `<button data-cp-set="${esc(s.id)}" data-cp-state="collected">Have it</button>`
              + `<button data-cp-set="${esc(s.id)}" data-cp-state="na">N/A</button>`;
        return `<div class="cp-row"><span class="cp-mark">${CP_MARK[s.state] || "○"}</span>`
          + `<span class="cp-label${isNext ? " cp-next" : ""}">${esc(s.label)}${isNext ? " — collect next" : ""}</span>`
          + `<span class="cp-hint">${hint}</span><span class="cp-act">${acts}</span></div>`;
      }).join("");
      el.innerHTML = `<div class="cp-done">${p.collected} of ${p.total} collected</div>${rows}`;
      sec.dataset.gateOpen = "1";
      applySectionsVis();
    }

    document.getElementById("collectionPlan").addEventListener("click", async (e) => {
      const setBtn = e.target.closest("[data-cp-set]");
      const clearBtn = e.target.closest("[data-cp-clear]");
      if (!setBtn && !clearBtn) return;
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) return;
      const stepId = setBtn ? setBtn.dataset.cpSet : clearBtn.dataset.cpClear;
      const url = `/cases/${encodeURIComponent(caseId)}/collection-plan/${encodeURIComponent(stepId)}`;
      try {
        if (setBtn) {
          const state = setBtn.dataset.cpState;
          const reason = prompt(state === "na" ? "Why does this not apply?" : "Where is this evidence?") ?? "";
          await fetch(url, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ state, reason }) });
        } else {
          await fetch(url, { method: "DELETE" });
        }
      } catch { /* transient — the next render re-reads the truth from the server */ }
      renderCollectionPlan();
    });
```

**Before writing this, confirm two names against the file:** `applySectionVisibility` and `esc`.
Grep for them (`grep -n "function applySectionVisibility\|function esc(" public/dashboard.html`)
and use the real names if they differ — the section-visibility function in particular is the one
`isSectionDataOpen` feeds.

- [ ] **Step 7: Register the section in the visibility editor**

In `public/dashboard.html`, add to the `SECTION_DEFS` array (around line 19065), immediately after
the `sec-next-steps` entry:

```javascript
      { id: "sec-collection-plan", label: "Collection Plan" },
```

- [ ] **Step 8: Verify live**

```bash
cp "/home/hasamba/Projects/DFIR-Companion/companion/.env" "/home/hasamba/Projects/DFIR-347/companion/.env"
```

```bash
cd "/home/hasamba/Projects/DFIR-347/companion" && DFIR_PORT=4774 DFIR_CASES_ROOT=/tmp/dfir-347-test npm run dev
```

At http://127.0.0.1:4774/dashboard: create a case with incident type Ransomware; confirm the
Collection Plan panel appears with six steps, all outstanding, "EDR telemetry — collect next", and
"0 of 6 collected". Create a second case with no incident type and confirm the panel does **not**
appear. Back on the first case, click **N/A** on EDR telemetry, give a reason, and confirm the row
shows `—` with the reason and the next-step marker moves to Memory image. Click **Undo** and
confirm it reverts.

Then stop the server and clean up — the `.env` is a copy of the real config:

```bash
rm -f "/home/hasamba/Projects/DFIR-347/companion/.env" && rm -rf /tmp/dfir-347-test
```

- [ ] **Step 9: Commit**

```bash
cd /home/hasamba/Projects/DFIR-347
git add public/dashboard.html companion/src/analysis/dashboardViews.ts companion/tests/analysis/dashboardViews.test.ts
git commit -m "feat(collection-plan): Collection Plan dashboard panel (#347)"
```

---

### Task 7: Documentation and full verification

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `mkdocs-docs/reference/cases.md`
- Modify: `mkdocs-docs/reference/dashboard.md`

- [ ] **Step 1: Add the CHANGELOG entry**

Under `## [Unreleased]`, in the existing `### Added` section, add one line:

```markdown
- **Collection plan** (#347) — the incident type's evidence checklist as a dashboard panel: what to collect for this kind of incident, in order, each item ticking itself off once matching evidence is in the case, with "we have it" / "not applicable" overrides for steps the tool can't see. Replaces the unused hunt-bundle and report-framing fields shipped with #236, which referenced bundles and report templates that do not exist.
```

- [ ] **Step 2: Update the incident-type manual page**

In `mkdocs-docs/reference/cases.md`, in the "Picking one seeds the case with:" list, add a bullet
after **Expected findings**:

```markdown
- **A collection plan** — the evidence this incident type calls for, in order, shown in its own
  dashboard panel. Each item ticks itself off once matching evidence is imported, whichever tool
  produced it, so "Windows event logs" is satisfied by Chainsaw, Hayabusa, or raw event logs alike.
  Mark an item *N/A* when your environment can't provide it (no EDR, no badge system) and it stops
  being proposed.
```

- [ ] **Step 3: Document the panel**

In `mkdocs-docs/reference/dashboard.md`, add a section alongside the other panel descriptions:

```markdown
### Collection Plan

Shown only for a case with an incident type. Lists the evidence that type calls for, in collection
order, and marks each one:

| Mark | Meaning |
|---|---|
| ✔ | Collected — the case holds evidence from a matching source |
| ○ | Outstanding; the next one is flagged **collect next** |
| ↗ | Collect outside DFIR Companion — the tool cannot import this (e.g. building access records) |
| — | Marked not applicable by an analyst |

Derived from the evidence already imported, with no AI. **Have it** records evidence held outside
the tool; **N/A** retires a step this environment can't satisfy; **Undo** returns a step to
automatic.
```

- [ ] **Step 4: Run the full CI sequence**

```bash
cd "/home/hasamba/Projects/DFIR-347/companion" && npm run build && npm run typecheck && npm test
```

Expected: build clean, typecheck clean, all tests pass. **All three are required** — `npm run build`
alone type-checks only `src/`, so a test-only type error slips through.

- [ ] **Step 5: Commit and push**

```bash
cd /home/hasamba/Projects/DFIR-347
git add CHANGELOG.md mkdocs-docs/reference/cases.md mkdocs-docs/reference/dashboard.md
git commit -m "docs(collection-plan): manual and changelog for the collection plan (#347)"
git push -u origin feat/issue-347
```

- [ ] **Step 6: Open the PR**

Before pushing, scan the diff for secrets, real hostnames, org domains, real names, or client
codenames (CLAUDE.md §2 rule 5). Then:

```bash
cd /home/hasamba/Projects/DFIR-347 && gh pr create --base master --title "feat(collection-plan): incident-type guided evidence collection (#347)" --body "$(cat specs/2026-07-28-collection-plan-design.md | head -40)

Closes #347"
```

Confirm all four CI checks pass before merging. `gh pr checks` exits non-zero when a check fails —
read its output, do not rely on its exit code.

---

## Self-Review

**Spec coverage**

| Spec section | Task |
|---|---|
| §1 remove `huntBundles` / `reportFraming` | 4 |
| §2 scope (no per-case step editing, no new importers) | respected throughout; no task adds either |
| §3 evidence vocabulary + both label sources | 1, guarded by 2 |
| §4 per-type plans | 4 (asserted verbatim) |
| §5.1 panel, next-step callout, hidden with no type | 6 (`data-gate-open`) |
| §5.2 derivation from `sources`, no new store | 1, 5 |
| §5.3 external steps | 1 (`external` state), 6 (`↗` render) |
| §5.4 overrides + persistence | 3, 5, 6 |
| §6 file structure | 1, 3, 5 |
| §6.1 panel wiring (4 points) | 6 — section ids, visibility editor, Triage + Hunt Prep; no report section, as specified |
| §7 testing (7 groups) | 1, 2, 3, 4, 5, 6 |
| §8 failure modes | 2 (invented/renamed label), 4 (typo'd step id), 1 (single pass), 4 (legacy custom type) |

**Gap found and closed:** §6 says the New Case picker's preview line should show the new evidence
labels. No task covered it. It is now Task 6 Step 6a below.

- [ ] **Task 6, Step 6a: Update the New Case picker preview**

In `public/dashboard.html`, `onTemplateSelectChange()` renders
`t.recommendedImportOrder.join(" → ")`, which would now print step ids (`edr → memory`). Map them
to labels first. Add near `renderCollectionPlan`:

```javascript
    // Step id → analyst-facing label, mirroring COLLECTION_STEPS server-side (#347). Kept here so
    // the New Case preview reads "EDR telemetry → Memory image" rather than raw ids.
    const CP_LABELS = {
      "edr": "EDR telemetry", "windows-event-logs": "Windows event logs",
      "endpoint-triage": "Endpoint triage artifacts", "memory": "Memory image",
      "network": "Network traffic / IDS", "web-logs": "Web server access logs",
      "m365": "Microsoft 365 / mailbox audit", "identity": "Identity sign-in logs",
      "cloud-audit": "Cloud control-plane audit", "siem": "SIEM / aggregated logs",
      "sandbox": "Malware sandbox report", "super-timeline": "Super-timeline",
      "threat-scan": "Threat / YARA scan", "physical-access": "Physical access records",
    };
```

and change the import-order branch of `onTemplateSelectChange()` to:

```javascript
        const imports = kind === "type" && t.recommendedImportOrder?.length
          ? { label: "Collect in order", value: t.recommendedImportOrder.map(id => CP_LABELS[id] || id).join(" → ") }
```

**Placeholder scan:** no TBD/TODO; every code step carries real code; no "similar to Task N".

**Type consistency:** `CollectionOverride`, `CollectionStepState`, `CollectionPlan`,
`buildCollectionPlan`, `getCollectionStep`, `COLLECTION_STEPS`, `CollectionPlanStore.load/set/clear`
are used identically in Tasks 1, 3, 5 and 6. The route response shape `{ typeId, plan }` matches
between Task 5's implementation, its tests, and Task 6's renderer.
