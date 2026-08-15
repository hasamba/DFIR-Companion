# Host Near-Duplicate Merge Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop AI synthesis when one machine appears under two spellings (`WIN11` vs `WIN11.windomain.local`) until the analyst merges or dismisses the pair, and make that merge actually reach the model.

**Architecture:** A pure derivation (`findNearDuplicates` minus persisted dismissals) is checked at one chokepoint inside `synthesize()`, throwing a typed error before any prompt is built or token spent. The same `HostAliasIndex` that answers "is this pair resolved?" is then threaded into every site where synthesis renders or ranks a host name, so a merge changes what the model sees.

**Tech Stack:** TypeScript (ESM, `.js` import specifiers), Express, Zod, Vitest + Supertest, classic-script dashboard modules.

## Global Constraints

- **Design doc:** `specs/2026-08-15-host-near-duplicate-merge-gate-design.md`. Read it first.
- **Working dir:** all paths below are relative to `companion/` unless prefixed `public/`. `public/` is a **sibling** of `companion/`, not inside it.
- **Imports:** ESM with explicit `.js` extensions (`import { x } from "./y.js"`). `src/analysis/` may **not** import from `src/integrations/`.
- **File size:** any NEW file must stay under **800 lines** (`npm run check:size`). Ledgered files may not grow by even one line.
- **Module map (bites every new `src/analysis/` file):** register it in `companion/scripts/module-map.json` under `flatAnalysisFiles`, or `npm run check:boundaries` fails. Domains are tiered and **an import may only go DOWN a tier or sideways, never up**: `timeline`=0, `case`/`privacy`/`intel`=1, `findings`/`detect`/`hunt`/`notify`=2, `ingest`=3, `workflow`=4, `ai`=5. File the two new modules from Tasks 1–2 as **`analysis/timeline`** (tier 0) — they are consumed from `ai` (5), `workflow` (4) and the routes, so any higher tier re-breaks the gate. `hostAlias.ts` was moved to tier 0 for exactly this reason in the commit preceding this plan.
- **Two documented counters move when the map changes:** `ARCHITECTURE.md`'s "N of the M cross-domain file dependencies already comply" sentence is asserted by `tests/architecture/moduleMap.test.ts`. Read the live pair from `node scripts/check-boundaries.mjs --json` and update the sentence.
- **Timeout-shaped failures in `tests/architecture/` are contention, not breakage.** Re-run the file on its own before debugging.
- **Never rewrite stored evidence.** Host resolution happens at render time only; `event.asset` on disk is never modified.
- **Gate is opt-in.** When `hostDuplicateDismissalStore` is absent from `PipelineOptions`, the gate does not run. This matches the documented convention in `ai/pipelineOptions.ts` ("absent means the feature is simply off") and keeps CLI scripts and existing tests unaffected.
- **Verification per task:** `npx vitest run <the test file>`. Before the final commit of each task also run `npm run typecheck` and `npm run lint`. Run `npm run check:size` on any task that adds or grows a file.
- **Commits:** conventional prefix (`feat(hosts):`, `fix(hosts):`, `test(hosts):`). **No `Co-Authored-By` trailer** — this repo forbids it.

---

### Task 1: Dismissals store

The only new persisted state. Everything else is derived.

**Files:**
- Create: `src/analysis/hostDuplicateDismissals.ts`
- Test: `tests/analysis/hostDuplicateDismissals.test.ts`

**Interfaces:**
- Consumes: `CaseStore` from `../storage/caseStore.js`, `atomicWrite` from `../storage/atomicWrite.js`
- Produces:
  - `interface HostDuplicateDismissal { canonical: string; other: string; dismissedAt: string; dismissedBy: string }`
  - `class HostDuplicateDismissalStore { constructor(cases: CaseStore); load(caseId: string): Promise<HostDuplicateDismissal[]>; append(caseId: string, d: HostDuplicateDismissal): Promise<HostDuplicateDismissal[]> }`
  - `function dismissalKey(canonical: string, other: string): string`

- [ ] **Step 1: Write the failing test**

Create `tests/analysis/hostDuplicateDismissals.test.ts`:

```ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  HostDuplicateDismissalStore,
  dismissalKey,
} from "../../src/analysis/hostDuplicateDismissals.js";

let cases: CaseStore;
let store: HostDuplicateDismissalStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostdupdismiss-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new HostDuplicateDismissalStore(cases);
});

describe("HostDuplicateDismissalStore", () => {
  it("returns an empty list for a case with no file", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("round-trips a dismissal", async () => {
    const d = {
      canonical: "win11.windomain.local",
      other: "win11",
      dismissedAt: "2026-08-15T10:00:00Z",
      dismissedBy: "alice",
    };
    await store.append("c1", d);
    expect(await store.load("c1")).toEqual([d]);
  });

  it("appends without dropping earlier dismissals", async () => {
    await store.append("c1", { canonical: "a.corp", other: "a", dismissedAt: "t1", dismissedBy: "x" });
    await store.append("c1", { canonical: "b.corp", other: "b", dismissedAt: "t2", dismissedBy: "y" });
    expect(await store.load("c1")).toHaveLength(2);
  });

  it("normalizes host names so a dismissal survives a casing change", async () => {
    await store.append("c1", {
      canonical: "WIN11.Windomain.Local",
      other: "WIN11",
      dismissedAt: "t",
      dismissedBy: "x",
    });
    const [row] = await store.load("c1");
    expect(row.canonical).toBe("win11.windomain.local");
    expect(row.other).toBe("win11");
  });

  it("is idempotent — appending the same pair twice stores one row", async () => {
    const d = { canonical: "a.corp", other: "a", dismissedAt: "t1", dismissedBy: "x" };
    await store.append("c1", d);
    await store.append("c1", { ...d, dismissedAt: "t2", dismissedBy: "y" });
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("returns an empty list rather than throwing on a corrupt file", async () => {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(join(cases.stateDir("c1"), "host-duplicate-dismissals.json"), "{ not json");
    expect(await store.load("c1")).toEqual([]);
  });

  it("dismissalKey is order-sensitive and case-insensitive", () => {
    expect(dismissalKey("A.corp", "A")).toBe(dismissalKey("a.corp", "a"));
    expect(dismissalKey("a.corp", "a")).not.toBe(dismissalKey("a", "a.corp"));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analysis/hostDuplicateDismissals.test.ts`
Expected: FAIL — `Cannot find module '../../src/analysis/hostDuplicateDismissals.js'`

- [ ] **Step 3: Write the implementation**

Create `src/analysis/hostDuplicateDismissals.ts`:

```ts
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { canonicalHostName } from "./hostAlias.js";

// Pairs the analyst has judged to be genuinely DIFFERENT machines, so the merge gate stops asking
// about them. This is the only piece of the gate that is persisted: the pending list itself is
// derived on read (findNearDuplicates minus these), and a MERGE needs no record here because a
// merged pair resolves to one canonical name and stops being a near-duplicate on its own.
//
// Corruption degrades to "no dismissals" rather than throwing. That direction is deliberate: the
// failure mode is re-asking about a pair the analyst already dismissed, which is a nuisance. The
// opposite default would silently un-gate a case, which is the thing this feature exists to prevent.

const dismissalSchema = z.object({
  canonical: z.string(),
  other: z.string(),
  dismissedAt: z.string(),
  dismissedBy: z.string(),
});

const dismissalsSchema = z.array(dismissalSchema).catch([]);

export type HostDuplicateDismissal = z.infer<typeof dismissalSchema>;

// Order matters: "a" folded into "a.corp" is a different statement than the reverse, and the pair
// findNearDuplicates emits always puts the FQDN in `canonical`.
export function dismissalKey(canonical: string, other: string): string {
  return `${canonicalHostName(canonical)}|${canonicalHostName(other)}`;
}

export class HostDuplicateDismissalStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "host-duplicate-dismissals.json");
  }

  async load(caseId: string): Promise<HostDuplicateDismissal[]> {
    try {
      return dismissalsSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      return []; // malformed → treat as no dismissals (see the note above)
    }
  }

  // Idempotent: re-dismissing a pair keeps the FIRST decision, so the recorded timestamp and
  // analyst stay the ones who actually made the call.
  async append(caseId: string, d: HostDuplicateDismissal): Promise<HostDuplicateDismissal[]> {
    const existing = await this.load(caseId);
    const normalized: HostDuplicateDismissal = {
      ...d,
      canonical: canonicalHostName(d.canonical),
      other: canonicalHostName(d.other),
    };
    const key = dismissalKey(normalized.canonical, normalized.other);
    if (existing.some((e) => dismissalKey(e.canonical, e.other) === key)) return existing;
    const next = [...existing, normalized];
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/analysis/hostDuplicateDismissals.test.ts`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/analysis/hostDuplicateDismissals.ts tests/analysis/hostDuplicateDismissals.test.ts && git commit -m "feat(hosts): persist near-duplicate dismissals per case"
```

---

### Task 2: Pending-pair derivation and the gate error

The pure core. No I/O, no stores — everything is passed in.

**Files:**
- Create: `src/analysis/hostDuplicateGate.ts`
- Test: `tests/analysis/hostDuplicateGate.test.ts`

**Interfaces:**
- Consumes: `HostDuplicateDismissal`, `dismissalKey` (Task 1); `findNearDuplicates`, `type NearDuplicate`, `type HostAliasIndex` from `./hostAlias.js`; `type InvestigationState` from `./stateTypes.js`
- Produces:
  - `class HostMergeDecisionRequired extends Error { readonly pairs: NearDuplicate[] }`
  - `function hostNamesFromState(state: InvestigationState): string[]`
  - `function pendingNearDuplicates(hostNames: readonly string[], aliasIndex: HostAliasIndex, dismissals: readonly HostDuplicateDismissal[]): NearDuplicate[]`

- [ ] **Step 1: Write the failing test**

Create `tests/analysis/hostDuplicateGate.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  HostMergeDecisionRequired,
  hostNamesFromState,
  pendingNearDuplicates,
} from "../../src/analysis/hostDuplicateGate.js";

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "d",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

const EMPTY_INDEX = buildHostAliasIndex([], {});

describe("hostNamesFromState", () => {
  it("collects distinct assets and ignores blanks", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11"), ev("c", "  "), ev("d", "DC01"));
    expect(hostNamesFromState(s).sort()).toEqual(["DC01", "WIN11"]);
  });
});

describe("pendingNearDuplicates", () => {
  it("flags a short-name/FQDN pair nothing has linked", () => {
    const pending = pendingNearDuplicates(["WIN11", "WIN11.windomain.local"], EMPTY_INDEX, []);
    expect(pending).toHaveLength(1);
    expect(pending[0].canonical).toBe("win11.windomain.local");
    expect(pending[0].other).toBe("win11");
  });

  it("does not flag a pair the fleet roster already links", () => {
    const index = buildHostAliasIndex(
      [{ clientId: "C.1", hostname: "win11", fqdn: "win11.windomain.local" }],
      {},
    );
    expect(pendingNearDuplicates(["WIN11", "WIN11.windomain.local"], index, [])).toEqual([]);
  });

  it("does not flag a pair the analyst has merged", () => {
    const index = buildHostAliasIndex([], { win11: "win11.windomain.local" });
    expect(pendingNearDuplicates(["WIN11", "WIN11.windomain.local"], index, [])).toEqual([]);
  });

  it("does not flag a pair the analyst has dismissed", () => {
    const dismissals = [
      { canonical: "win11.windomain.local", other: "win11", dismissedAt: "t", dismissedBy: "a" },
    ];
    expect(pendingNearDuplicates(["WIN11", "WIN11.windomain.local"], EMPTY_INDEX, dismissals)).toEqual([]);
  });

  it("a dismissal of one pair does not suppress a different pair", () => {
    const dismissals = [{ canonical: "a.corp", other: "a", dismissedAt: "t", dismissedBy: "x" }];
    const pending = pendingNearDuplicates(["WIN11", "WIN11.windomain.local"], EMPTY_INDEX, dismissals);
    expect(pending).toHaveLength(1);
  });

  it("yields one pair per short/FQDN combination when a host has three spellings", () => {
    const pending = pendingNearDuplicates(
      ["win11", "win11.example.com", "win11.corp.local"],
      EMPTY_INDEX,
      [],
    );
    expect(pending).toHaveLength(2);
  });

  it("returns nothing when there is only one spelling", () => {
    expect(pendingNearDuplicates(["WIN11", "DC01"], EMPTY_INDEX, [])).toEqual([]);
  });
});

describe("HostMergeDecisionRequired", () => {
  it("carries the pairs and names itself", () => {
    const err = new HostMergeDecisionRequired([
      { canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" },
    ]);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("HostMergeDecisionRequired");
    expect(err.pairs).toHaveLength(1);
    expect(err.message).toContain("1");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analysis/hostDuplicateGate.test.ts`
Expected: FAIL — `Cannot find module '../../src/analysis/hostDuplicateGate.js'`

- [ ] **Step 3: Write the implementation**

Create `src/analysis/hostDuplicateGate.ts`:

```ts
import { findNearDuplicates, type HostAliasIndex, type NearDuplicate } from "./hostAlias.js";
import { dismissalKey, type HostDuplicateDismissal } from "./hostDuplicateDismissals.js";
import type { InvestigationState } from "./stateTypes.js";

// The pre-synthesis gate: one machine spelled two ways (WIN11 vs WIN11.windomain.local) is two
// hosts to every derivation the model reads, so synthesis is blocked until the analyst says which
// it is. Pure — the caller supplies the host names, the alias index and the dismissals.
//
// WHY THE PENDING LIST IS DERIVED RATHER THAN STORED. A merge already resolves both spellings to
// one canonical name through the alias index, so a merged pair stops being a near-duplicate with no
// bookkeeping. Storing the pending list too would mean a second copy of the truth that has to be
// invalidated on every merge, every import and every fleet refresh. Deriving it means a duplicate
// arriving on import 47 is treated exactly like one arriving on import 1.

/** Thrown by synthesize() when a case holds an unresolved near-duplicate host pair. The route layer
 *  turns this into HTTP 409 so the dashboard can render the merge panel. */
export class HostMergeDecisionRequired extends Error {
  constructor(public readonly pairs: NearDuplicate[]) {
    super(
      `${pairs.length} possible duplicate host${pairs.length === 1 ? "" : "s"} awaiting a merge decision`,
    );
    this.name = "HostMergeDecisionRequired";
  }
}

// The host names synthesis will actually read. The forensic timeline is the complete source: the
// super timeline is only touched AFTER the model call (the second-look sweep), so a host that lives
// only there cannot reach the prompt — and scanning it here would put a full table scan on every
// synthesis. See the design doc's "Source of truth" section.
export function hostNamesFromState(state: InvestigationState): string[] {
  const seen = new Set<string>();
  for (const e of state.forensicTimeline ?? []) {
    const asset = (e.asset ?? "").trim();
    if (asset) seen.add(asset);
  }
  return [...seen];
}

export function pendingNearDuplicates(
  hostNames: readonly string[],
  aliasIndex: HostAliasIndex,
  dismissals: readonly HostDuplicateDismissal[],
): NearDuplicate[] {
  const dismissed = new Set(dismissals.map((d) => dismissalKey(d.canonical, d.other)));
  return findNearDuplicates(aliasIndex, [...hostNames]).filter(
    (pair) => !dismissed.has(dismissalKey(pair.canonical, pair.other)),
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/analysis/hostDuplicateGate.test.ts`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add src/analysis/hostDuplicateGate.ts tests/analysis/hostDuplicateGate.test.ts && git commit -m "feat(hosts): derive pending near-duplicate pairs and the gate error"
```

---

### Task 3: Make the gate error non-retryable and map it to 409

Without this, `withRetry` runs the blocked synthesis four times before the analyst sees anything.

**Files:**
- Modify: `src/analysis/ai/retry.ts` (add to `isRetryableError`)
- Modify: `src/routes/presidioApproval.ts` (add a branch to `sendPipelineError`)
- Test: `tests/analysis/hostDuplicateGateWiring.test.ts`

**Interfaces:**
- Consumes: `HostMergeDecisionRequired` (Task 2)
- Produces: `sendPipelineError` now answers `409 { error: "host_merge_decision_required", pairs }`

- [ ] **Step 1: Write the failing test**

Create `tests/analysis/hostDuplicateGateWiring.test.ts`:

```ts
import { describe, it, expect, vi } from "vitest";
import type { Response } from "express";
import { withRetry } from "../../src/analysis/ai/retry.js";
import { sendPipelineError } from "../../src/routes/presidioApproval.js";
import { HostMergeDecisionRequired } from "../../src/analysis/hostDuplicateGate.js";

const PAIRS = [{ canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" as const }];

function fakeRes(): Response & { statusCode?: number; payload?: unknown } {
  const res = {
    statusCode: undefined as number | undefined,
    payload: undefined as unknown,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(body: unknown) {
      res.payload = body;
      return res;
    },
  };
  return res as unknown as Response & { statusCode?: number; payload?: unknown };
}

describe("HostMergeDecisionRequired wiring", () => {
  it("is not retried — it surfaces on the first throw", async () => {
    const fn = vi.fn(async () => {
      throw new HostMergeDecisionRequired(PAIRS);
    });
    await expect(withRetry(fn, 3, 1)).rejects.toBeInstanceOf(HostMergeDecisionRequired);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("maps to 409 with the pairs in the body", () => {
    const res = fakeRes();
    sendPipelineError(res, new HostMergeDecisionRequired(PAIRS));
    expect(res.statusCode).toBe(409);
    expect(res.payload).toEqual({ error: "host_merge_decision_required", pairs: PAIRS });
  });

  it("broadcasts ai_status error when a context is supplied", () => {
    const onAiStatus = vi.fn();
    sendPipelineError(fakeRes(), new HostMergeDecisionRequired(PAIRS), { caseId: "c1", onAiStatus });
    expect(onAiStatus).toHaveBeenCalledWith("c1", expect.objectContaining({ status: "error" }));
  });

  it("still maps an unrelated error to 500", () => {
    const res = fakeRes();
    sendPipelineError(res, new Error("boom"));
    expect(res.statusCode).toBe(500);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analysis/hostDuplicateGateWiring.test.ts`
Expected: FAIL — the retry test fails with `toHaveBeenCalledTimes(4)` (it retried), and the 409 test fails because the status is 500.

- [ ] **Step 3: Write the implementation**

In `src/analysis/ai/retry.ts`, add the import beside the existing Presidio one:

```ts
import { HostMergeDecisionRequired } from "../hostDuplicateGate.js";
```

Then inside `isRetryableError`, directly after the `PresidioApprovalRequired` line:

```ts
  // Same reasoning as the approval gate above: a merge decision is a wall, not a blip. Retrying
  // re-derives the identical pending list and delays the 409 the analyst is waiting on.
  if (err instanceof HostMergeDecisionRequired) return false;
```

In `src/routes/presidioApproval.ts`, add the import:

```ts
import { HostMergeDecisionRequired } from "../analysis/hostDuplicateGate.js";
```

Then inside `sendPipelineError`, directly after the `PresidioApprovalRequired` branch:

```ts
  if (err instanceof HostMergeDecisionRequired) {
    ctx?.onAiStatus?.(ctx.caseId, { status: "error", at: new Date().toISOString(), detail: err.message });
    return res.status(409).json({ error: "host_merge_decision_required", pairs: err.pairs });
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/analysis/hostDuplicateGateWiring.test.ts`
Expected: PASS (4 tests)

Also confirm nothing regressed: `npx vitest run tests/server/presidioRoutes.test.ts`

- [ ] **Step 5: Commit**

```bash
git add src/analysis/ai/retry.ts src/routes/presidioApproval.ts tests/analysis/hostDuplicateGateWiring.test.ts && git commit -m "feat(hosts): surface the merge gate as a 409 and never retry it"
```

---

### Task 4: Wire the three stores into the synthesis context and add the gate

The wiring exists only to serve the gate, so they ship together — the gate test is what proves the wiring works.

**Files:**
- Modify: `src/analysis/ai/pipelineOptions.ts` (three new optional fields)
- Modify: `src/analysis/pipeline.ts` (three getters in the `aiCtx.opts` block, ~line 257)
- Modify: `src/analysis/ai/synthesis.ts` (`SynthesisContext.opts` + the guard at line 450)
- Modify: `src/composition/aiProviders.ts` (`RuntimePipelineParams` + `buildRuntimePipeline`)
- Modify: `src/composition/aiRuntime.ts` (`AiRuntimeDeps` + destructure + pass through)
- Modify: `src/server.ts` (pass the two stores into `buildAiRuntime`)
- Modify: `src/composition/appOptions.ts` (declare `hostDuplicateDismissalStore`)
- Modify: `src/composition/runtimeStores.ts` (construct + return it)
- Test: `tests/analysis/hostDuplicateGateSynthesis.test.ts`

**Interfaces:**
- Consumes: `HostDuplicateDismissalStore` (Task 1); `pendingNearDuplicates`, `hostNamesFromState`, `HostMergeDecisionRequired` (Task 2); `loadHostAliasIndex` from `../hostScopeLoad.js`
- Produces: `SynthesisContext.opts` now carries `assetOverridesStore?`, `velociraptorClientStore?`, `hostDuplicateDismissalStore?`

**Note:** `buildRuntimePipeline` is called from `src/composition/aiRuntime.ts:117`, **not** from `server.ts` — `server.ts` only re-exports it. `AssetOverridesStore` takes a `CaseStore` so it can be built inline (`new AssetOverridesStore(params.store)`); `VelociraptorClientStore` is a **global** file-backed singleton and must be threaded through `params` from `server.ts`, where `rt.velociraptorClientStore` is already in scope.

- [ ] **Step 1: Write the failing test**

Create `tests/analysis/hostDuplicateGateSynthesis.test.ts`:

```ts
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { HostMergeDecisionRequired } from "../../src/analysis/hostDuplicateGate.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "suspicious logon",
    severity: "High",
    mitreTechniques: ["T1078"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

let cases: CaseStore;
let stateStore: StateStore;
let assetOverridesStore: AssetOverridesStore;
let dismissals: HostDuplicateDismissalStore;
let analyze: ReturnType<typeof vi.fn>;

async function seed(assets: string[]): Promise<void> {
  const s = emptyState("c1");
  assets.forEach((a, i) => s.forensicTimeline.push(ev(`e${i}`, a)));
  await stateStore.save("c1", s);
}

function pipeline(): AnalysisPipeline {
  return new AnalysisPipeline({
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore: dismissals,
    synthesisProvider: { name: "fake", analyze } as never,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostdupgate-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  assetOverridesStore = new AssetOverridesStore(cases);
  dismissals = new HostDuplicateDismissalStore(cases);
  analyze = vi.fn(async () => ({ text: "{}" }));
});

describe("synthesize() near-duplicate gate", () => {
  it("throws before calling the provider when a pair is unresolved", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    await expect(pipeline().synthesize("c1")).rejects.toBeInstanceOf(HostMergeDecisionRequired);
    expect(analyze).not.toHaveBeenCalled();
  });

  it("names the unresolved pair in the thrown error", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    const err = await pipeline()
      .synthesize("c1")
      .catch((e: HostMergeDecisionRequired) => e);
    expect((err as HostMergeDecisionRequired).pairs[0].canonical).toBe("win11.windomain.local");
  });

  it("does not throw once the pair is merged", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    await pipeline().synthesize("c1").catch(() => undefined);
    expect(analyze).toHaveBeenCalled();
  });

  it("does not throw once the pair is dismissed", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    await dismissals.append("c1", {
      canonical: "win11.windomain.local",
      other: "win11",
      dismissedAt: "t",
      dismissedBy: "a",
    });
    await pipeline().synthesize("c1").catch(() => undefined);
    expect(analyze).toHaveBeenCalled();
  });

  it("does not throw on a case with no near-duplicates", async () => {
    await seed(["WIN11", "DC01"]);
    await pipeline().synthesize("c1").catch(() => undefined);
    expect(analyze).toHaveBeenCalled();
  });

  it("is off when no dismissal store is configured", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    const ungated = new AnalysisPipeline({
      stateStore,
      assetOverridesStore,
      synthesisProvider: { name: "fake", analyze } as never,
      imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
    });
    await ungated.synthesize("c1").catch(() => undefined);
    expect(analyze).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analysis/hostDuplicateGateSynthesis.test.ts`
Expected: FAIL — TypeScript rejects `hostDuplicateDismissalStore` as an unknown `PipelineOptions` field, and the first test fails because nothing throws.

- [ ] **Step 3: Declare the options**

In `src/analysis/ai/pipelineOptions.ts`, add the type imports at the top beside the other `import type` lines:

```ts
import type { AssetOverridesStore } from "../assetOverrides.js";
import type { VelociraptorClientStore } from "../velociraptorClientStore.js";
import type { HostDuplicateDismissalStore } from "../hostDuplicateDismissals.js";
```

Then add the three fields at the end of the `PipelineOptions` interface, before its closing brace:

```ts
  // Analyst asset merges + the enrolled-fleet roster: together these resolve a host's short name,
  // FQDN and client id onto one canonical identity, so synthesis reads and ranks one host instead
  // of two. Absent → no resolution (the pre-gate behavior).
  assetOverridesStore?: AssetOverridesStore;
  velociraptorClientStore?: VelociraptorClientStore;
  // Pairs the analyst has judged to be different machines. Presence of this store is what ENABLES
  // the pre-synthesis merge gate: absent → the gate never runs, so CLI scripts and older tests are
  // unaffected. See analysis/hostDuplicateGate.ts.
  hostDuplicateDismissalStore?: HostDuplicateDismissalStore;
```

- [ ] **Step 4: Expose them on the AI context**

In `src/analysis/pipeline.ts`, inside the `this.aiCtx = { opts: { … } }` block, add three getters immediately before the `get retries()` getter (~line 254), matching the existing 3-line form exactly:

```ts
        get assetOverridesStore() {
          return opts.assetOverridesStore;
        },
        get velociraptorClientStore() {
          return opts.velociraptorClientStore;
        },
        get hostDuplicateDismissalStore() {
          return opts.hostDuplicateDismissalStore;
        },
```

In `src/analysis/ai/synthesis.ts`, add the type imports beside the other store type imports:

```ts
import type { AssetOverridesStore } from "../assetOverrides.js";
import type { VelociraptorClientStore } from "../velociraptorClientStore.js";
import type { HostDuplicateDismissalStore } from "../hostDuplicateDismissals.js";
```

Then add the three fields to the inline object at the end of `SynthesisContext["opts"]`, beside `onState`:

```ts
      assetOverridesStore?: AssetOverridesStore;
      velociraptorClientStore?: VelociraptorClientStore;
      hostDuplicateDismissalStore?: HostDuplicateDismissalStore;
```

- [ ] **Step 5: Add the guard**

In `src/analysis/ai/synthesis.ts`, add the imports:

```ts
import { loadHostAliasIndex } from "../hostScopeLoad.js";
import {
  HostMergeDecisionRequired,
  hostNamesFromState,
  pendingNearDuplicates,
} from "../hostDuplicateGate.js";
```

Add this helper immediately above the `synthesize` function:

```ts
// The pre-synthesis merge gate. Runs before the prompt is built so a blocked run spends no tokens
// and writes no state.
//
// RETURNS the index it had to build anyway, because every downstream render site needs the same one
// and rebuilding it per site would re-read both stores a dozen times per run. The GATE is enabled
// only when the dismissal store is wired (see PipelineOptions), but the INDEX is always built — a
// merge must still resolve host names even on an install running with the gate off.
async function resolveHostsOrThrow(
  ctx: SynthesisContext,
  caseId: string,
  state: InvestigationState,
): Promise<HostAliasIndex> {
  const aliasIndex = await loadHostAliasIndex(
    {
      ...(ctx.opts.assetOverridesStore ? { assetOverrides: ctx.opts.assetOverridesStore } : {}),
      ...(ctx.opts.velociraptorClientStore ? { fleet: ctx.opts.velociraptorClientStore } : {}),
    },
    caseId,
  );
  const dismissalStore = ctx.opts.hostDuplicateDismissalStore;
  if (!dismissalStore) return aliasIndex;
  const pending = pendingNearDuplicates(
    hostNamesFromState(state),
    aliasIndex,
    await dismissalStore.load(caseId),
  );
  if (pending.length) throw new HostMergeDecisionRequired(pending);
  return aliasIndex;
}
```

Then insert the call in `synthesize`, immediately after the empty-timeline early return (line 449). This task calls it for its throwing side effect only and discards the return; Task 8 binds the result:

```ts
  const loaded = await ctx.opts.stateStore.load(caseId);
  if (loaded.forensicTimeline.length === 0) return loaded;
  await resolveHostsOrThrow(ctx, caseId, loaded);
```

Add `import { type HostAliasIndex } from "../hostAlias.js";` alongside the other new imports.

- [ ] **Step 6: Thread the stores through composition**

In `src/composition/aiProviders.ts`, add to `RuntimePipelineParams`:

```ts
  // Global, file-backed fleet roster — threaded rather than built inline because it is not a
  // per-case CaseStore store. Feeds host alias resolution + the pre-synthesis merge gate.
  velociraptorClientStore?: ConstructorParameters<typeof AnalysisPipelineImpl>[0]["velociraptorClientStore"];
  hostDuplicateDismissalStore?: ConstructorParameters<
    typeof AnalysisPipelineImpl
  >[0]["hostDuplicateDismissalStore"];
```

And inside the `buildRuntimePipeline` object literal, beside the other per-case stores:

```ts
    assetOverridesStore: new AssetOverridesStore(params.store),
    velociraptorClientStore: params.velociraptorClientStore,
    hostDuplicateDismissalStore:
      params.hostDuplicateDismissalStore ?? new HostDuplicateDismissalStore(params.store),
```

Add the two value imports at the top of that file:

```ts
import { AssetOverridesStore } from "../analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../analysis/hostDuplicateDismissals.js";
```

In `src/composition/aiRuntime.ts`, add to `AiRuntimeDeps`:

```ts
  velociraptorClientStore?: VelociraptorClientStore;
```

with the type import `import type { VelociraptorClientStore } from "../analysis/velociraptorClientStore.js";`, add `velociraptorClientStore,` to the destructure, and add `velociraptorClientStore,` to the `buildRuntimePipeline({ … })` call.

In `src/server.ts`, add `velociraptorClientStore,` to the `buildAiRuntime({ … })` call (it is already destructured from `rt`).

In `src/composition/appOptions.ts`, declare the store beside `assetOverridesStore`:

```ts
  hostDuplicateDismissalStore?: HostDuplicateDismissalStore;
```

In `src/composition/runtimeStores.ts`, construct it beside `assetOverridesStore` and add it to the returned object:

```ts
  const hostDuplicateDismissalStore = new HostDuplicateDismissalStore(store);
```

- [ ] **Step 7: Run test to verify it passes**

Run: `npx vitest run tests/analysis/hostDuplicateGateSynthesis.test.ts`
Expected: PASS (6 tests)

Then: `npm run typecheck && npm run lint && npm run check:size`
Expected: all clean.

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat(hosts): block synthesis on an unresolved near-duplicate host pair"
```

---

### Task 5: Resolve host names in the five already-alias-aware call sites

`buildAssetGraph` and `rankHosts` already accept an `aliasIndex` — five call sites simply never pass one. These are one-argument changes.

**Files:**
- Modify: `src/analysis/synthSelect.ts:346` (signature) and `:351`, `:416` (call sites)
- Modify: `src/analysis/iocAnchors.ts:133` (signature) and `:142` (call site)
- Modify: `src/analysis/ai/synthesisMerge.ts:265` (`FindingGradeInput`) and `:289` (call site)
- Modify: `src/analysis/knownUnknowns.ts:43` (`KnownUnknownsOptions`) and `:282` (call site)
- Test: `tests/analysis/synthesisHostResolution.test.ts`

**Interfaces:**
- Consumes: `type HostAliasIndex` from `./hostAlias.js`
- Produces:
  - `buildSynthesisContext(state, scopedEvents, kevCatalog?, aliasIndex?)` — trailing optional param, so its 8 existing call sites are untouched
  - `rankConnectiveIocs(state, scopedEvents?, opts?)` where `RankConnectiveOptions` gains `aliasIndex?`
  - `FindingGradeInput` gains `aliasIndex?`
  - `KnownUnknownsOptions` gains `aliasIndex?`

- [ ] **Step 1: Write the failing test**

Create `tests/analysis/synthesisHostResolution.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { buildSynthesisContext } from "../../src/analysis/synthSelect.js";
import { rankConnectiveIocs } from "../../src/analysis/iocAnchors.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

const ALIAS = buildHostAliasIndex([], { win11: "win11.windomain.local" });

function ev(id: string, asset: string, description: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description,
    severity: "Critical",
    mitreTechniques: ["T1003.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

function splitState(): InvestigationState {
  const s = emptyState("c1");
  s.forensicTimeline.push(
    ev("a", "WIN11", "beacon to evil.example 10.0.0.9"),
    ev("b", "WIN11.windomain.local", "beacon to evil.example 10.0.0.9"),
  );
  s.iocs.push({ id: "i1", type: "domain", value: "evil.example", firstSeen: "2026-04-22T11:41:00Z" });
  return s;
}

describe("buildSynthesisContext host resolution", () => {
  it("names both spellings when no alias index is given", () => {
    const block = buildSynthesisContext(splitState(), splitState().forensicTimeline);
    expect(block).toContain("win11.windomain.local");
    expect(/\bWIN11\b(?!\.)/i.test(block)).toBe(true);
  });

  it("collapses the pair to the canonical name in COMPROMISED ASSETS", () => {
    const s = splitState();
    const block = buildSynthesisContext(s, s.forensicTimeline, undefined, ALIAS);
    const assetLines = block.slice(block.indexOf("COMPROMISED ASSETS"));
    expect(assetLines).toContain("win11.windomain.local");
    expect(/^- WIN11 \(host\)/im.test(assetLines)).toBe(false);
  });

  it("reports one host, not two, in SIGNAL CONCENTRATION", () => {
    const s = splitState();
    const block = buildSynthesisContext(s, s.forensicTimeline, undefined, ALIAS);
    const line = block.split("\n").find((l) => l.startsWith("SIGNAL CONCENTRATION")) ?? "";
    expect(line).toContain("win11.windomain.local");
    expect(line.split("win11").length - 1).toBe(1);
  });
});

describe("rankConnectiveIocs host resolution", () => {
  it("counts a split host twice without an alias index", () => {
    const s = splitState();
    const [anchor] = rankConnectiveIocs(s, s.forensicTimeline);
    expect(anchor.hosts).toHaveLength(2);
  });

  it("counts it once with an alias index, so cross-host reach is not inflated", () => {
    const s = splitState();
    const [anchor] = rankConnectiveIocs(s, s.forensicTimeline, { aliasIndex: ALIAS });
    expect(anchor.hosts).toEqual(["win11.windomain.local"]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analysis/synthesisHostResolution.test.ts`
Expected: FAIL — `buildSynthesisContext` takes 3 args (TS error on the 4th), and `RankConnectiveOptions` has no `aliasIndex`.

- [ ] **Step 3: Write the implementation**

In `src/analysis/synthSelect.ts`, add `import type { HostAliasIndex } from "./hostAlias.js";`, then change the signature and the two call sites:

```ts
export function buildSynthesisContext(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
  kevCatalog?: KevCatalog,
  aliasIndex?: HostAliasIndex,
): string {
  const graph = buildAssetGraph({ ...state, forensicTimeline: scopedEvents }, undefined, aliasIndex);
```

and

```ts
  const connectiveBlock = buildConnectiveIocDigest(
    rankConnectiveIocs(state, scopedEvents, { aliasIndex }),
  );

  const concentrationBlock = buildSignalConcentrationDigest(
    rankHosts({ ...state, forensicTimeline: scopedEvents }, { aliasIndex }),
  );
```

In `src/analysis/iocAnchors.ts`, add `import type { HostAliasIndex } from "./hostAlias.js";`, add the option and pass it:

```ts
export interface RankConnectiveOptions {
  max?: number; // cap the returned anchors (default 12)
  minHosts?: number; // hosts touched to qualify as cross-host (default 2)
  minTools?: number; // tools observing to qualify as corroborated (default 2)
  // Without this, one host spelled two ways counts as two hosts — and since the score is
  // `hosts.size * 4`, every IOC touching it is promoted on cross-host reach it does not have.
  aliasIndex?: HostAliasIndex;
}
```

```ts
  const graph = buildAssetGraph({ ...state, forensicTimeline: scopedEvents }, undefined, opts.aliasIndex);
```

In `src/analysis/ai/synthesisMerge.ts`, add `import type { HostAliasIndex } from "../hostAlias.js";`, add the field to `FindingGradeInput`:

```ts
  aliasIndex?: HostAliasIndex;
```

and pass it:

```ts
  const hostNames = new Set(
    buildAssetGraph(next, undefined, input.aliasIndex)
      .assets.filter((a) => a.type === "host")
      .map((a) => shortHost(a.name)),
  );
```

In `src/analysis/knownUnknowns.ts`, add `import type { HostAliasIndex } from "./hostAlias.js";`, add the option:

```ts
  aliasIndex?: HostAliasIndex; // resolve short-name/FQDN spellings onto one host before ranking
```

and pass it:

```ts
  const topHosts = rankHosts(state, { aliasIndex: opts.aliasIndex }).topHosts;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/analysis/synthesisHostResolution.test.ts`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(hosts): resolve host aliases in the synthesis context and IOC ranking"
```

---

### Task 6: Resolve host names in the per-event prompt tags and group suffixes

The per-event `<host:>` tags matter most: without these, the model reads both spellings in the raw event stream regardless of what the derived blocks say.

**Files:**
- Modify: `src/analysis/synthEvidence.ts:29` (`renderStructuredTags` gains a 2nd param)
- Modify: `src/analysis/ai/synthesisPromptEvents.ts` (`RenderContext`, `createTimelineSelection`, `renderPromptEvent`)
- Modify: `src/analysis/ai/deepPassRun.ts:58` (the other `renderStructuredTags` caller)
- Modify: `src/analysis/synthGroup.ts` (`GroupOptions`, `toGroup`, `groupDetections`, `collapseForPrompt`)
- Test: `tests/analysis/promptHostTags.test.ts`

**Interfaces:**
- Consumes: `type HostAliasIndex`, `resolveHost` from `hostAlias.js`
- Produces:
  - `renderStructuredTags(e: ForensicEvent, aliasIndex?: HostAliasIndex): string`
  - `GroupOptions` gains `aliasIndex?: HostAliasIndex`
  - `createTimelineSelection(state, scopedEvents, aliasIndex?)`

- [ ] **Step 1: Write the failing test**

Create `tests/analysis/promptHostTags.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { renderStructuredTags } from "../../src/analysis/synthEvidence.js";
import { collapseForPrompt } from "../../src/analysis/synthGroup.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ALIAS = buildHostAliasIndex([], { win11: "win11.windomain.local" });

function ev(id: string, asset: string, ts: string): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: "identical detection",
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

describe("renderStructuredTags", () => {
  it("emits the raw asset without an alias index", () => {
    expect(renderStructuredTags(ev("a", "WIN11", "2026-04-22T11:00:00Z"))).toContain("<host:WIN11>");
  });

  it("emits the canonical name with an alias index", () => {
    const tags = renderStructuredTags(ev("a", "WIN11", "2026-04-22T11:00:00Z"), ALIAS);
    expect(tags).toContain("<host:win11.windomain.local>");
    expect(tags).not.toContain("<host:WIN11>");
  });

  it("leaves a host with no alias untouched", () => {
    expect(renderStructuredTags(ev("a", "DC01", "2026-04-22T11:00:00Z"), ALIAS)).toContain("<host:DC01>");
  });
});

describe("collapseForPrompt group hosts", () => {
  const run = [
    ev("a", "WIN11", "2026-04-22T11:00:00Z"),
    ev("b", "WIN11.windomain.local", "2026-04-22T11:00:05Z"),
    ev("c", "WIN11", "2026-04-22T11:00:10Z"),
  ];

  it("reports two hosts without an alias index", () => {
    const collapsed = collapseForPrompt(run, { minRepeats: 2 });
    const group = [...collapsed.groupById.values()][0];
    expect(group.hosts).toHaveLength(2);
  });

  it("reports one host with an alias index", () => {
    const collapsed = collapseForPrompt(run, { minRepeats: 2, aliasIndex: ALIAS });
    const group = [...collapsed.groupById.values()][0];
    expect(group.hosts).toEqual(["win11.windomain.local"]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analysis/promptHostTags.test.ts`
Expected: FAIL — `renderStructuredTags` takes 1 arg; `GroupOptions` has no `aliasIndex`.

- [ ] **Step 3: Write the implementation**

In `src/analysis/synthEvidence.ts`, add `import { resolveHost, type HostAliasIndex } from "./hostAlias.js";` and change the host line:

```ts
export function renderStructuredTags(e: ForensicEvent, aliasIndex?: HostAliasIndex): string {
  const tags: string[] = [];
  // Resolve at RENDER time only — the stored event keeps its original spelling. Without this the
  // model reads both spellings in the raw event stream and narrates two machines regardless of
  // what the derived context blocks say.
  if (e.asset) tags.push(`<host:${clip(aliasIndex ? resolveHost(aliasIndex, e.asset) : e.asset)}>`);
```

In `src/analysis/synthGroup.ts`, add `import { resolveHost, type HostAliasIndex } from "./hostAlias.js";`, extend the options:

```ts
export interface GroupOptions {
  gapSeconds?: number;
  minRepeats?: number;
  aliasIndex?: HostAliasIndex; // fold short-name/FQDN spellings into one host in the group's host list
}
```

Change `toGroup` to accept and apply the index:

```ts
function toGroup(key: string, run: readonly ForensicEvent[], aliasIndex?: HostAliasIndex): DetectionGroup {
  const first = run[0];
  const last = run[run.length - 1];
  const hosts: string[] = [];
  const seen = new Set<string>();
  for (const e of run) {
    const raw = (e.asset ?? "").trim();
    if (!raw) continue;
    const asset = aliasIndex ? resolveHost(aliasIndex, raw) : raw;
    if (seen.has(asset.toLowerCase())) continue;
    seen.add(asset.toLowerCase());
    hosts.push(asset);
  }
```

Then pass `opts.aliasIndex` at the `toGroup(...)` call inside `groupDetections`, and confirm `collapseForPrompt` already forwards its `opts` to `groupDetections` (it does).

In `src/analysis/ai/synthesisPromptEvents.ts`, add `aliasIndex?: HostAliasIndex;` to `RenderContext`, thread it through `renderPromptEvent`:

```ts
  return `${prefix}[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${description}${renderStructuredTags(e, ctx.aliasIndex)}${groupTag}${prevTag ? ` ⟨${prevTag}⟩` : ""}`;
```

and add a trailing optional param to `createTimelineSelection`, passing it to both `collapseBursts`/`collapseForPrompt` and the `renderEvent` context:

```ts
export function createTimelineSelection(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
  aliasIndex?: HostAliasIndex,
): TimelineSelection {
```

```ts
    renderEvent: (event) => renderPromptEvent(event, { grouping, prevalenceIndex, isContext, aliasIndex }),
```

In `src/analysis/ai/deepPassRun.ts:58`, leave the call as-is — the deep pass renders a raw evidence excerpt, not the synthesis prompt, and has no alias index in scope. Add a one-line comment recording that:

```ts
        // No alias index here: the deep pass renders raw evidence excerpts, not the synthesis prompt.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/analysis/promptHostTags.test.ts`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(hosts): render one canonical host per event tag and group suffix"
```

---

### Task 7: Fix the `distinctHosts` corroboration bug

A split host reads as "seen on 2 hosts", which defeats the `distinctHosts <= 1` check and lets an uncorroborated finding escape its confidence cap. This is a correctness bug independent of the prompt.

**Files:**
- Modify: `src/analysis/findingGrounding.ts:125` (`GroundingInput`) and `:198` (the count)
- Modify: `src/analysis/ai/synthesisMerge.ts` (pass `aliasIndex` into `groundAndScoreFindings`)
- Test: `tests/analysis/findingGroundingHostAlias.test.ts`

**Interfaces:**
- Consumes: `type HostAliasIndex`, `resolveHost`
- Produces: `GroundingInput` gains `aliasIndex?: HostAliasIndex`

- [ ] **Step 1: Write the failing test**

Create `tests/analysis/findingGroundingHostAlias.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { groundAndScoreFindings } from "../../src/analysis/findingGrounding.js";
import type { Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";

const ALIAS = buildHostAliasIndex([], { win11: "win11.windomain.local" });

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "logon",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: ["f1"],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"], // ONE tool, so `corroborated` hinges on distinctHosts alone
  };
}

const finding: Finding = {
  id: "f1",
  title: "Suspicious logon",
  description: "d",
  severity: "High",
  confidence: 90,
  relatedEventIds: ["a", "b"],
  relatedIocs: [],
  mitreTechniques: [],
} as Finding;

function ground(aliasIndex?: ReturnType<typeof buildHostAliasIndex>) {
  return groundAndScoreFindings({
    findings: [finding],
    scopedEvents: [ev("a", "WIN11"), ev("b", "WIN11.windomain.local")],
    iocs: [],
    graphLinkedEventIds: new Set<string>(),
    ...(aliasIndex ? { aliasIndex } : {}),
  })[0];
}

describe("groundAndScoreFindings host aliasing", () => {
  it("counts a split host as two without an alias index", () => {
    expect(ground().corroboration?.distinctHosts).toBe(2);
  });

  it("counts it as one with an alias index", () => {
    expect(ground(ALIAS).corroboration?.distinctHosts).toBe(1);
  });

  it("applies the single-source confidence cap once the hosts collapse", () => {
    const capped = ground(ALIAS);
    expect(capped.confidence).toBeLessThan(90);
    expect(capped.confidenceReason).toContain("single-source");
  });

  it("without the index the finding wrongly escapes the cap", () => {
    expect(ground().confidence).toBe(90);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analysis/findingGroundingHostAlias.test.ts`
Expected: FAIL — TS rejects `aliasIndex` on `GroundingInput`; the "counts it as one" test reports 2.

- [ ] **Step 3: Write the implementation**

In `src/analysis/findingGrounding.ts`, add `import { resolveHost, type HostAliasIndex } from "./hostAlias.js";`, add the field to `GroundingInput`:

```ts
  // Resolves short-name/FQDN spellings onto one host before counting distinct hosts. Without it one
  // machine spelled two ways reads as corroboration across two hosts, which defeats the
  // `distinctHosts <= 1` single-source cap below and inflates the finding's confidence.
  aliasIndex?: HostAliasIndex;
```

Then in `groundAndScoreFindings`, destructure it and change the count at line 198:

```ts
  const { findings, scopedEvents, iocs, graphLinkedEventIds, sourceTrust, aliasIndex } = input;
```

```ts
    const distinctHosts = new Set(
      supporting
        .map((e) => e.asset)
        .filter((a): a is string => !!a)
        .map((a) => (aliasIndex ? resolveHost(aliasIndex, a) : a.toLowerCase())),
    ).size;
```

In `src/analysis/ai/synthesisMerge.ts`, pass the index into the grounding call inside `gradeFindings`:

```ts
  const grounded = groundAndScoreFindings({
    findings: next.findings,
    scopedEvents: inScope,
    iocs: next.iocs,
    graphLinkedEventIds: new Set(evidenceGraph.edges.flatMap((e) => e.eventIds)),
    kevCveIds: collectKevCveIds(inScope, next.iocs, kevCatalog),
    sourceTrust,
    ...(input.aliasIndex ? { aliasIndex: input.aliasIndex } : {}),
  });
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/analysis/findingGroundingHostAlias.test.ts`
Expected: PASS (4 tests)

Then run the neighbouring suite to confirm no regression: `npx vitest run tests/analysis/findingGrounding.test.ts`

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "fix(hosts): stop a split host inflating a finding's distinctHosts count"
```

---

### Task 8: Pass the alias index from synthesize() into every resolved site

Tasks 5–7 added the parameters. This task supplies the value, so the merge finally reaches the model.

**Files:**
- Modify: `src/analysis/ai/synthesis.ts` (compute the index once, pass to `prepareSynthesisRun` / `buildSynthesisPrompt` / `gradeFindings`)
- Modify: `src/analysis/ai/synthesisPrompt.ts` (accept and forward to `createTimelineSelection` + `buildSynthesisBlocks`)
- Modify: `src/analysis/ai/synthesisPromptBlocks.ts` (forward to `buildSynthesisContext`)
- Modify: `src/analysis/ai/promptBlocks.ts` (forward to `buildKnownUnknownItems`)
- Test: `tests/analysis/synthesisPromptHostMerge.test.ts`

**Interfaces:**
- Consumes: everything from Tasks 4–7
- Produces: a single `aliasIndex` computed once per synthesis run and threaded down

**Note:** `resolveHostsOrThrow` (Task 4) already returns the index; Task 4 discards it. This task
binds it — `const aliasIndex = await resolveHostsOrThrow(ctx, caseId, loaded);` — and threads it.

- [ ] **Step 1: Write the failing test**

Create `tests/analysis/synthesisPromptHostMerge.test.ts`. Build a pipeline exactly as in Task 4's test, but merge the pair first, capture the prompt the fake provider receives, and assert on it:

```ts
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

let cases: CaseStore;
let stateStore: StateStore;
let assetOverridesStore: AssetOverridesStore;
let dismissals: HostDuplicateDismissalStore;
let analyze: ReturnType<typeof vi.fn>;
let prompts: string[];

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "LSASS access",
    severity: "Critical",
    mitreTechniques: ["T1003.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostmergeprompt-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  assetOverridesStore = new AssetOverridesStore(cases);
  dismissals = new HostDuplicateDismissalStore(cases);
  prompts = [];
  analyze = vi.fn(async (req: { userPrompt?: string }) => {
    prompts.push(req.userPrompt ?? "");
    return { text: "{}" };
  });
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11.windomain.local"));
  await stateStore.save("c1", s);
});

describe("a merged host reaches the model as one machine", () => {
  it("renders only the canonical spelling in the prompt", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    const pipeline = new AnalysisPipeline({
      stateStore,
      assetOverridesStore,
      hostDuplicateDismissalStore: dismissals,
      synthesisProvider: { name: "fake", analyze } as never,
      imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
    });
    await pipeline.synthesize("c1").catch(() => undefined);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("<host:win11.windomain.local>");
    expect(prompts[0]).not.toContain("<host:WIN11>");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analysis/synthesisPromptHostMerge.test.ts`
Expected: FAIL — the prompt still contains `<host:WIN11>`.

- [ ] **Step 3: Write the implementation**

In `src/analysis/ai/synthesis.ts`, delete the `void aliasIndex;` line from Task 4 and pass the value into both consumers:

```ts
  const prompt = await buildSynthesisPrompt(ctx, {
    caseId,
    state,
    scope,
    markers,
    inWindowEvents: run.inWindowEvents,
    scopedEvents,
    observationsBlock,
    aliasIndex,
    ...run.blocks,
  });
```

and at the `gradeFindings` call site:

```ts
  gradeFindings({ next, delta, surviving, eligibleIds, sourceTrust, kevCatalog, aliasIndex })
```

In `src/analysis/ai/synthesisPrompt.ts`, add `aliasIndex?: HostAliasIndex` to `SynthesisPromptInput`, destructure it, and forward:

```ts
  const timeline = createTimelineSelection(state, scopedEvents, aliasIndex);
  const blocks = await buildSynthesisBlocks(ctx, { caseId, state, scope, markers, scopedEvents, preloaded, aliasIndex });
```

In `src/analysis/ai/synthesisPromptBlocks.ts`, accept `aliasIndex` on the input and forward it as the 4th argument to `buildSynthesisContext(state, scopedEvents, kevCatalog, aliasIndex)`.

In `src/analysis/ai/promptBlocks.ts`, forward it into `buildKnownUnknownItems(state, scopedEvents, { …opts, aliasIndex })`.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/analysis/synthesisPromptHostMerge.test.ts`
Expected: PASS (1 test)

Then the full analysis suite: `npx vitest run tests/analysis`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(hosts): thread the alias index through the whole synthesis prompt path"
```

---

### Task 9: Routes for listing, merging and dismissing pairs

**Files:**
- Create: `src/routes/hostDuplicates.ts`
- Modify: `src/composition/routeRegistry.ts` (import + register call)
- Modify: `tests/architecture/routeInventory.test.ts` (record the new layer)
- Test: `tests/server/hostDuplicatesRoutes.test.ts`

**Interfaces:**
- Consumes: `pendingNearDuplicates`, `hostNamesFromState` (Task 2); `HostDuplicateDismissalStore` (Task 1); `loadHostAliasIndex`; `RouteContext`
- Produces:
  - `registerHostDuplicateRoutes(app: Express, ctx: RouteContext): void`
  - `GET /cases/:id/host-duplicates` → `{ pending: NearDuplicate[] }`
  - `POST /cases/:id/host-duplicates/merge` body `{ canonical, other }` → `{ pending }`
  - `POST /cases/:id/host-duplicates/dismiss` body `{ canonical, other }` → `{ pending }`

**Conventions:** follow `src/routes/hostScope.ts` exactly — a `configured(res)` guard returning `501`, validation to `400` before the `try`, `catch` to `500`, and a docblock listing every route. Merge failures map to **400** (mirroring the asset-merge route, since `mergeAsset` throws only on analyst-caused conditions). Fire `options.onAssetOverrides?.(caseId)` after a successful merge — every other asset-override mutation does, and skipping it leaves the derived graph stale.

- [ ] **Step 1: Write the failing test**

Create `tests/server/hostDuplicatesRoutes.test.ts`:

```ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { createApp } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

let app: ReturnType<typeof createApp>;

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "d",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-routes-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11.windomain.local"));
  await stateStore.save("c1", s);
  app = createApp(cases, {
    stateStore,
    assetOverridesStore: new AssetOverridesStore(cases),
    hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
  });
});

describe("/cases/:id/host-duplicates", () => {
  it("lists the unresolved pair", async () => {
    const res = await request(app).get("/cases/c1/host-duplicates");
    expect(res.status).toBe(200);
    expect(res.body.pending).toHaveLength(1);
    expect(res.body.pending[0].canonical).toBe("win11.windomain.local");
  });

  it("merging clears the pair", async () => {
    const res = await request(app)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([]);
  });

  it("dismissing clears the pair", async () => {
    const res = await request(app)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([]);
  });

  it("a dismissal persists across requests", async () => {
    await request(app)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    const res = await request(app).get("/cases/c1/host-duplicates");
    expect(res.body.pending).toEqual([]);
  });

  it("rejects a request missing a host", async () => {
    const res = await request(app).post("/cases/c1/host-duplicates/merge").send({ canonical: "a.corp" });
    expect(res.status).toBe(400);
  });

  it("rejects a merge of a host into itself", async () => {
    const res = await request(app)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11", other: "win11" });
    expect(res.status).toBe(400);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/server/hostDuplicatesRoutes.test.ts`
Expected: FAIL — all requests 404 (routes not registered).

- [ ] **Step 3: Write the route module**

Create `src/routes/hostDuplicates.ts`:

```ts
import type { Express, Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import { canonicalHostName, type NearDuplicate } from "../analysis/hostAlias.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import { hostNamesFromState, pendingNearDuplicates } from "../analysis/hostDuplicateGate.js";
import type { RouteContext } from "./context.js";

/**
 * Near-duplicate host review — the pre-synthesis merge gate's UI surface.
 *   - GET  /cases/:id/host-duplicates          — pairs still awaiting a decision.
 *   - POST /cases/:id/host-duplicates/merge    — fold `other` into `canonical` (asset-graph merge).
 *   - POST /cases/:id/host-duplicates/dismiss  — record that they are genuinely different machines.
 *
 * Resolving the LAST pending pair kicks the synthesis the gate was holding.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 */
const HOST_ID_PREFIX = "host:";

export function registerHostDuplicateRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  function configured(res: Response): boolean {
    if (!options.stateStore || !options.assetOverridesStore || !options.hostDuplicateDismissalStore) {
      res.status(501).json({ error: "host-duplicate review not configured" });
      return false;
    }
    return true;
  }

  async function pending(caseId: string): Promise<NearDuplicate[]> {
    const state = await options.stateStore!.load(caseId);
    const aliasIndex = await loadHostAliasIndex(
      {
        assetOverrides: options.assetOverridesStore!,
        ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
      },
      caseId,
    );
    return pendingNearDuplicates(
      hostNamesFromState(state),
      aliasIndex,
      await options.hostDuplicateDismissalStore!.load(caseId),
    );
  }

  // Both POST bodies name the pair the same way, and both reject the same malformed input.
  function readPair(req: Request): { canonical: string; other: string } | null {
    const canonical = canonicalHostName(String(req.body?.canonical ?? ""));
    const other = canonicalHostName(String(req.body?.other ?? ""));
    if (!canonical || !other || canonical === other) return null;
    return { canonical, other };
  }

  // Both resolve paths answer with the freshly-recomputed pending list. Task 10 adds the
  // auto-synthesis kick here.
  async function respond(caseId: string, res: Response): Promise<Response> {
    return res.status(200).json({ pending: await pending(caseId) });
  }

  app.get("/cases/:id/host-duplicates", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      return res.status(200).json({ pending: await pending(req.params.id) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/host-duplicates/merge", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const pair = readPair(req);
    if (!pair) return res.status(400).json({ error: "canonical and other must be two different hosts" });
    try {
      // The alias index is keyed by host NAME; asset-override merges are keyed by asset id.
      await options.assetOverridesStore!.mergeAsset(
        req.params.id,
        `${HOST_ID_PREFIX}${pair.other}`,
        `${HOST_ID_PREFIX}${pair.canonical}`,
      );
      // Every other asset-override mutation fires this; skipping it leaves the derived graph stale.
      options.onAssetOverrides?.(req.params.id);
      return await respond(req.params.id, res);
    } catch (err) {
      // 400, not 500: mergeAsset throws only on analyst-caused conditions (self-merge, cycle).
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/host-duplicates/dismiss", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const pair = readPair(req);
    if (!pair) return res.status(400).json({ error: "canonical and other must be two different hosts" });
    try {
      await options.hostDuplicateDismissalStore!.append(req.params.id, {
        canonical: pair.canonical,
        other: pair.other,
        dismissedAt: new Date().toISOString(),
        dismissedBy: requestAuthentication(req)?.identity.displayName ?? "local",
      });
      return await respond(req.params.id, res);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
```

- [ ] **Step 4: Register the routes**

In `src/composition/routeRegistry.ts` add the import beside `registerHostScopeRoutes`, and the call immediately after `registerHostScopeRoutes(app, ctx);`. Then update `tests/architecture/routeInventory.test.ts` to record the new layer — that test snapshots the interleaved registration order and will fail until it does.

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/server/hostDuplicatesRoutes.test.ts tests/architecture/routeInventory.test.ts`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(hosts): add list/merge/dismiss routes for near-duplicate hosts"
```

---

### Task 10: Auto-run synthesis when the last pair is resolved

**Files:**
- Modify: `src/routes/hostDuplicates.ts` (kick after a resolve that empties the list)
- Test: extend `tests/server/hostDuplicatesRoutes.test.ts`

**Interfaces:**
- Consumes: `ctx.resynthesizeInBackground(caseId)` — already on `RouteContext`

- [ ] **Step 1: Write the failing test**

Append to `tests/server/hostDuplicatesRoutes.test.ts`:

**`resynthesizeInBackground` is NOT an `AppOptions` field** — `createApp` builds it internally from
`createCaptureAnalysis`, so a spy cannot be injected through `createApp(cases, {...})` (verified).
Register the route module directly against a stub `RouteContext` instead, which tests the contract
more directly anyway:

```ts
import express from "express";
import { registerHostDuplicateRoutes } from "../../src/routes/hostDuplicates.js";
import type { RouteContext } from "../../src/routes/context.js";

describe("auto-run on last resolve", () => {
  let twoPairApp: express.Express;
  let kick: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-kick-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev("a", "WIN11"),
      ev("b", "WIN11.corp.local"),
      ev("c", "DC01"),
      ev("d", "DC01.corp.local"),
    );
    await stateStore.save("c1", s);
    kick = vi.fn();
    twoPairApp = express();
    twoPairApp.use(express.json());
    registerHostDuplicateRoutes(twoPairApp, {
      store: cases,
      options: {
        stateStore,
        assetOverridesStore: new AssetOverridesStore(cases),
        hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
      },
      resynthesizeInBackground: kick,
    } as unknown as RouteContext);
  });

  it("does not kick synthesis while a pair is still unresolved", async () => {
    await request(twoPairApp)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.corp.local", other: "win11" });
    expect(kick).not.toHaveBeenCalled();
  });

  it("kicks synthesis exactly once, when the last pair resolves", async () => {
    await request(twoPairApp)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.corp.local", other: "win11" });
    await request(twoPairApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "dc01.corp.local", other: "dc01" });
    expect(kick).toHaveBeenCalledWith("c1");
    expect(kick).toHaveBeenCalledTimes(1);
  });
});
```

Add `vi` to the vitest import at the top of the file.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/server/hostDuplicatesRoutes.test.ts`
Expected: FAIL — `kick` is never called.

- [ ] **Step 3: Write the implementation**

Replace `respond` in `src/routes/hostDuplicates.ts` with:

```ts
  // Resolving the LAST pair is what lifts the gate, so that is the only moment worth a synthesis.
  // Kicking on every resolve would spend one run per pair, and every run but the last would
  // immediately re-throw on the pairs still outstanding.
  async function respond(caseId: string, res: Response): Promise<Response> {
    const remaining = await pending(caseId);
    if (remaining.length === 0) ctx.resynthesizeInBackground(caseId);
    return res.status(200).json({ pending: remaining });
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/server/hostDuplicatesRoutes.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(hosts): re-run synthesis when the last duplicate pair is resolved"
```

---

### Task 11: Detect at import completion and notify

Without this, a case with AI disabled never learns it has a duplicate, because the gate only fires inside `synthesize()`.

**Files:**
- Modify: `src/composition/captureAnalysis.ts` (`CaptureAnalysisDeps` gains `dispatchNotify`; detect before kicking synthesis)
- Modify: `src/server.ts` (pass `dispatchNotify` into `createCaptureAnalysis`)
- Test: `tests/analysis/hostDuplicateImportNotify.test.ts`

**Interfaces:**
- Consumes: `milestoneEvent(caseId, title, lines, at)` from `../analysis/notifications.js`; `dispatchNotify(event: NotificationEvent): void`
- Produces: `CaptureAnalysisDeps` gains `dispatchNotify: (event: NotificationEvent) => void`

**Note:** the per-channel `milestone` toggle **defaults to `false`** (`notifications.ts:350-353`), so this notification only reaches channels that opted in. The badge is the primary surface. Say so in the release note.

- [ ] **Step 1: Write the failing test**

Create `tests/analysis/hostDuplicateImportNotify.test.ts`:

```ts
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "d",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

let cases: CaseStore;
let stateStore: StateStore;
let dispatchNotify: ReturnType<typeof vi.fn>;

async function seed(assets: string[]): Promise<void> {
  const s = emptyState("c1");
  assets.forEach((a, i) => s.forensicTimeline.push(ev(`e${i}`, a)));
  await stateStore.save("c1", s);
}

function analysis() {
  return createCaptureAnalysis({
    store: cases,
    options: {
      stateStore,
      assetOverridesStore: new AssetOverridesStore(cases),
      hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
    } as never,
    hasAiProvider: () => false,
    getControl: async () => ({ enabled: false }) as never,
    setControl: async () => ({ enabled: false }) as never,
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify,
  });
}

const settle = () => new Promise((r) => setImmediate(r));

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-notify-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  dispatchNotify = vi.fn();
});

describe("import-time near-duplicate notification", () => {
  it("dispatches one milestone naming both spellings", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    analysis().resynthesizeInBackground("c1");
    await settle();
    expect(dispatchNotify).toHaveBeenCalledTimes(1);
    const event = dispatchNotify.mock.calls[0][0];
    expect(event.kind).toBe("milestone");
    expect(JSON.stringify(event)).toContain("win11.windomain.local");
  });

  it("stays silent on a case with no duplicates", async () => {
    await seed(["WIN11", "DC01"]);
    analysis().resynthesizeInBackground("c1");
    await settle();
    expect(dispatchNotify).not.toHaveBeenCalled();
  });

  it("stays silent once the pair is dismissed", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    await new HostDuplicateDismissalStore(cases).append("c1", {
      canonical: "win11.windomain.local",
      other: "win11",
      dismissedAt: "t",
      dismissedBy: "a",
    });
    analysis().resynthesizeInBackground("c1");
    await settle();
    expect(dispatchNotify).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analysis/hostDuplicateImportNotify.test.ts`
Expected: FAIL — `dispatchNotify` is not a `CaptureAnalysisDeps` field (TS error), and nothing dispatches.

- [ ] **Step 3: Write the implementation**

In `src/composition/captureAnalysis.ts`, add to `CaptureAnalysisDeps`:

```ts
  /** Fire a notification event (best-effort, fire-and-forget). See composition/caseNotifier.ts. */
  dispatchNotify: (event: NotificationEvent) => void;
```

with `import type { NotificationEvent } from "../analysis/notifications.js";` and `import { milestoneEvent } from "../analysis/notifications.js";`, plus the gate imports:

```ts
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import { hostNamesFromState, pendingNearDuplicates } from "../analysis/hostDuplicateGate.js";
```

Add `dispatchNotify` to the destructure at the top of `createCaptureAnalysis`, then add this helper inside the factory:

```ts
  // Tell someone the case is holding on a merge decision. The gate itself lives in synthesize(),
  // but a case with AI disabled never reaches it — and that case still needs the badge raised, so
  // detection runs here too. Fully guarded: notifications are a side channel and must never break
  // an import.
  //
  // NOTE the per-channel `milestone` toggle defaults to FALSE, so on a default configuration this
  // reaches nobody. The dashboard badge is the reliable surface; this is opt-in escalation.
  async function notifyHostDuplicates(caseId: string): Promise<void> {
    try {
      const dismissalStore = options.hostDuplicateDismissalStore;
      if (!dismissalStore || !options.stateStore || !options.assetOverridesStore) return;
      const state = await options.stateStore.load(caseId);
      const aliasIndex = await loadHostAliasIndex(
        {
          assetOverrides: options.assetOverridesStore,
          ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
        },
        caseId,
      );
      const pending = pendingNearDuplicates(
        hostNamesFromState(state),
        aliasIndex,
        await dismissalStore.load(caseId),
      );
      if (!pending.length) return;
      dispatchNotify(
        milestoneEvent(
          caseId,
          `Analysis on hold: ${pending.length} possible duplicate host${pending.length === 1 ? "" : "s"}`,
          pending.map((p) => `• ${p.other} and ${p.canonical} may be the same machine`),
          new Date().toISOString(),
        ),
      );
    } catch {
      /* never break an import on a notification */
    }
  }
```

Then call it as the **very first statement** of `resynthesizeInBackground` — above `const pipeline = options.pipeline;`, not inside the async IIFE:

```ts
  function resynthesizeInBackground(caseId: string): void {
    // FIRST, above every early return below. The two guards that follow (no pipeline, no synthesis
    // provider) are exactly the AI-disabled install this notification exists to serve: put this
    // inside the IIFE and the case that can never reach the synthesize() gate also never gets told.
    void notifyHostDuplicates(caseId);
    const pipeline = options.pipeline;
    if (!pipeline) return;
```

In `src/server.ts`, add `dispatchNotify,` to the `createCaptureAnalysis({ … })` call — it is already in scope from line 130.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/analysis/hostDuplicateImportNotify.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(hosts): flag duplicate hosts at import time and notify"
```

---

### Task 12: Dashboard badge and panel

**Files:**
- Create: `public/js/dashboard-host-duplicates.js`
- Modify: `public/dashboard.html` (script tag, badge element, panel div, section nav entry, `initHostDuplicates()` call)
- Modify: `public/js/dashboard-case-connect.js` (add to `CASE_PANEL_LOADERS`)
- Modify: `public/js/dashboard-ai-status.js` (load on `ai_status:error`)
- Test: `tests/dashboard/hostDuplicatesPanel.test.ts`

**Interfaces:**
- Consumes: `esc` / `escAttr` by bare name; `GET|POST /cases/:id/host-duplicates*`
- Produces (published on `window`): `loadHostDuplicates(caseId)`, `renderHostDuplicates(pending)`, `initHostDuplicates()`

**Conventions:** a classic-script IIFE publishing globals (**not** an ES module). `renderHostDuplicates(pending)` must be a **pure string function** with no DOM access — that is what makes it testable via `loadDashboardModule`, which runs the file in a Node `vm` context. Use one delegated click listener guarded by a dataset flag (the `dashboard-host-scope.js` pattern). Wire `loadHostDuplicates` into **both** `CASE_PANEL_LOADERS` and the `ai_status === "error"` branch — imports are fire-and-forget, so the 409 is not a reliable surface.

- [ ] **Step 1: Write the failing test**

Create `tests/dashboard/hostDuplicatesPanel.test.ts` modeled on `tests/dashboard/hostScopePanel.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  renderHostDuplicates(pending: unknown[]): string;
}

const panel = loadDashboardModule<Api>("dashboard-host-duplicates.js", ["dashboard-escape.js"]);

const pair = { canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" };

describe("host duplicates panel", () => {
  it("renders nothing when there is no pending pair", () => {
    expect(panel.renderHostDuplicates([])).toBe("");
  });

  it("names both spellings and offers both actions", () => {
    const html = panel.renderHostDuplicates([pair]);
    expect(html).toContain("win11.windomain.local");
    expect(html).toContain("data-hd-merge");
    expect(html).toContain("data-hd-dismiss");
  });

  it("says synthesis is blocked", () => {
    expect(panel.renderHostDuplicates([pair]).toLowerCase()).toContain("analysis is on hold");
  });

  it("escapes a hostile host name", () => {
    const html = panel.renderHostDuplicates([{ ...pair, other: '<img src=x onerror=alert(1)>' }]);
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/dashboard/hostDuplicatesPanel.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the panel module**

Create `public/js/dashboard-host-duplicates.js`:

```js
// Near-duplicate host review — the merge gate's UI surface.
//
// AN IIFE: this feature owns state, and a top-level `let` in a classic script joins the global
// lexical environment. NOT AN ES MODULE — the inline script calls the published names by bare name.
//
// renderHostDuplicates is a PURE string function with no DOM access, so it is testable through
// loadDashboardModule, which runs this file in a Node vm context with no document.
(function () {
  "use strict";

  let pending = [];

  function renderHostDuplicates(list) {
    if (!list || !list.length) return "";
    const rows = list
      .map(
        (d) =>
          `<div class="hd-row">` +
          `<code>${esc(d.other)}</code> and <code>${esc(d.canonical)}</code> may be the same machine. ` +
          `<button data-hd-merge="1" data-hd-canonical="${escAttr(d.canonical)}" data-hd-other="${escAttr(d.other)}" ` +
          `title="Treat these as one host. Analysis re-runs once every pair is resolved.">Same host — merge</button> ` +
          `<button data-hd-dismiss="1" data-hd-canonical="${escAttr(d.canonical)}" data-hd-other="${escAttr(d.other)}" ` +
          `title="Two different machines. You won't be asked about this pair again.">Different hosts</button>` +
          `</div>`,
      )
      .join("");
    return (
      `<div class="hd-warn"><strong>Analysis is on hold.</strong> ` +
      `${list.length} host${list.length === 1 ? " appears" : "s appear"} under more than one name. ` +
      `Until you decide, the AI would treat one machine as two — splitting its evidence and its ` +
      `timeline. Resolve each pair and analysis restarts automatically.</div>${rows}`
    );
  }

  function paint() {
    const badge = document.getElementById("hostDuplicatesBadge");
    if (badge) {
      badge.style.display = pending.length ? "" : "none";
      badge.textContent = "⚠ Duplicate hosts: " + pending.length;
    }
    const el = document.getElementById("hostDuplicatesBody");
    if (!el) return;
    el.innerHTML = renderHostDuplicates(pending);
    // One delegated listener, bound once: innerHTML is replaced on every repaint, so per-button
    // listeners would be lost each time.
    if (!el.dataset.hdBound) {
      el.addEventListener("click", onPanelClick);
      el.dataset.hdBound = "1";
    }
  }

  async function loadHostDuplicates(caseId) {
    if (!caseId) return;
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/host-duplicates`);
      if (!r.ok) return;
      const d = await r.json();
      pending = d.pending || [];
      paint();
    } catch {
      // A panel that cannot load must not take the dashboard down with it.
    }
  }

  async function resolve(caseId, action, canonical, other) {
    try {
      const r = await fetch(`/cases/${encodeURIComponent(caseId)}/host-duplicates/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ canonical: canonical, other: other }),
      });
      if (!r.ok) return;
      const d = await r.json();
      pending = d.pending || [];
      paint();
    } catch {
      /* leave the panel as it was */
    }
  }

  function onPanelClick(evt) {
    const target = evt.target && evt.target.closest ? evt.target : null;
    if (!target) return;
    const button = target.closest("[data-hd-merge], [data-hd-dismiss]");
    if (!button) return;
    const caseId = (document.getElementById("caseId") || {}).value;
    if (!caseId || !caseId.trim()) return;
    const canonical = button.getAttribute("data-hd-canonical");
    const other = button.getAttribute("data-hd-other");
    const action = button.hasAttribute("data-hd-merge") ? "merge" : "dismiss";
    if (action === "merge" && !confirm(`Treat ${other} and ${canonical} as one host?`)) return;
    void resolve(caseId.trim(), action, canonical, other);
  }

  // The badge lives in the page header, so this binds at load, not on module evaluation.
  function initHostDuplicates() {
    document.getElementById("hostDuplicatesBadge")?.addEventListener("click", () => {
      document.getElementById("sec-host-duplicates")?.scrollIntoView({ behavior: "smooth" });
    });
  }

  window.loadHostDuplicates = loadHostDuplicates;
  window.renderHostDuplicates = renderHostDuplicates;
  window.initHostDuplicates = initHostDuplicates;
})();
```

- [ ] **Step 4: Wire it into the page**

In `public/dashboard.html`, four edits:

1. A script tag beside the other feature scripts — **before** `dashboard-facade.js`, which must stay last:
   ```html
   <script src="/js/dashboard-host-duplicates.js"></script>
   ```
2. A badge button in the header toolbar, beside `#presidioPendingBadge`:
   ```html
   <button id="hostDuplicatesBadge" type="button" data-safe-style="display:none;background:#3a2a00;color:#ffcf66;border:1px solid #5a4a1a;padding:2px 8px;border-radius:10px;font-size:11px;cursor:pointer" data-tip="This case has hosts that appear under more than one name. AI analysis is on hold until you confirm whether they are the same machine.">⚠ Duplicate hosts: 0</button>
   ```
3. A section, beside `sec-host-scope`:
   ```html
   <section id="sec-host-duplicates" data-safe-style="grid-column: 1 / -1"><h2>Duplicate Hosts<span class="ev-sub">hosts seen under more than one name — analysis is on hold until each pair is confirmed as one machine or two (derived, no AI)</span></h2><div id="hostDuplicatesBody"></div></section>
   ```
   plus `{ id: "sec-host-duplicates", label: "Duplicate Hosts" },` in the section nav index list.
4. In the init block (~line 4070):
   ```js
    if (typeof initHostDuplicates === "function") initHostDuplicates();
   ```

In `public/js/dashboard-case-connect.js`, add to `CASE_PANEL_LOADERS` beside `hostScope`:

```js
      ["hostDuplicates", () => loadHostDuplicates(caseId)],
```

In `public/js/dashboard-ai-status.js`, in the `evt.status === "error"` branch beside `loadPresidioPending`:

```js
      // Same reason as the Presidio line above: an import is fire-and-forget, so a gate that fires
      // mid-import has no response to carry its 409. This is the only path it surfaces on.
      loadHostDuplicates(activeCaseId);
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/dashboard/hostDuplicatesPanel.test.ts`
Expected: PASS (4 tests)

- [ ] **Step 6: Full verification**

```bash
npm run typecheck && npm run lint && npm run check:size && npm run check:a11y && npm run check:boundaries && npm run inventory:dashboard && npm test
```

Expected: all clean, whole suite green. `check:a11y` and `inventory:dashboard` matter here specifically — this task is the only one touching `dashboard.html`.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(hosts): add the duplicate-host review badge and panel"
```

---

## Post-implementation

- [ ] Update `CHANGELOG.md`.
- [ ] Note in the release entry that the milestone notification is **opt-in per channel and off by default**, so the badge is the reliable surface.
- [ ] Re-baseline the two ledgers if the merge moved them: `npm run check:size -- --update`.
