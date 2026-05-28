# DFIR Companion Core (Evidence Path) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Node/TypeScript localhost companion's deterministic evidence path — accept screenshot captures over HTTP and reliably persist them (raw image + append-only metadata + case metadata) to a structured case folder, plus a shared perceptual-hash module for deduplication.

**Architecture:** A small Express HTTP server exposes case-management and capture-ingest endpoints. The capture-ingest path writes the raw screenshot to disk and appends one line to an append-only `captures.jsonl` audit trail BEFORE any further processing — evidence persistence never depends on analysis (which arrives in Plan 2). A `CaseStore` module owns the case-folder layout and all disk I/O. A standalone `perceptualHash` module computes and compares perceptual hashes; it lives in the companion now and is imported by the extension later (Plan 4).

**Tech Stack:** Node.js 20+, TypeScript, Express (HTTP), Zod (input validation), sharp (image decode + perceptual hash), Vitest (testing).

This is Plan 1 of 4. It produces a runnable companion that stores evidence; AI analysis, reports, dashboard, and the extension come in later plans.

---

## File Structure

```
companion/
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── src/
│   ├── types.ts                 # shared types: CaptureMetadata, CaseMeta, TriggerType
│   ├── dedup/
│   │   └── perceptualHash.ts    # computeHash(buffer), hammingDistance(a,b), isDuplicate(a,b,threshold)
│   ├── storage/
│   │   └── caseStore.ts         # CaseStore: createCase, appendCapture, saveScreenshot, paths
│   ├── ingest/
│   │   └── captureIngest.ts     # ingestCapture(store, payload): decode, save image, append metadata
│   └── server.ts                # Express app wiring routes to ingest + store
└── tests/
    ├── dedup/perceptualHash.test.ts
    ├── storage/caseStore.test.ts
    ├── ingest/captureIngest.test.ts
    └── server.test.ts
```

**Responsibilities:**
- `types.ts` — single source of truth for shared shapes used across modules.
- `perceptualHash.ts` — pure functions, no I/O; fully unit-testable.
- `caseStore.ts` — owns the case-folder layout and all filesystem writes. No HTTP, no image decoding.
- `captureIngest.ts` — orchestrates one capture: validate → decode → save image → append metadata. No HTTP framework coupling.
- `server.ts` — thin HTTP layer; parses requests, delegates to ingest/store, returns JSON.

All paths below are relative to the project root `52.43-DFIR-Companion/`.

---

## Task 1: Project scaffold

**Files:**
- Create: `companion/package.json`
- Create: `companion/tsconfig.json`
- Create: `companion/vitest.config.ts`

- [ ] **Step 1: Create `companion/package.json`**

```json
{
  "name": "dfir-companion",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "tsc",
    "test": "vitest run",
    "test:watch": "vitest",
    "dev": "tsx src/server.ts"
  },
  "dependencies": {
    "express": "^4.19.2",
    "sharp": "^0.33.4",
    "zod": "^3.23.8"
  },
  "devDependencies": {
    "@types/express": "^4.17.21",
    "@types/node": "^20.14.0",
    "@types/supertest": "^6.0.2",
    "supertest": "^7.0.0",
    "tsx": "^4.16.0",
    "typescript": "^5.5.0",
    "vitest": "^2.0.0"
  }
}
```

- [ ] **Step 2: Create `companion/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "outDir": "dist",
    "rootDir": "src",
    "types": ["node"]
  },
  "include": ["src"]
}
```

- [ ] **Step 3: Create `companion/vitest.config.ts`**

```typescript
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
```

- [ ] **Step 4: Install dependencies**

Run: `cd companion && npm install`
Expected: `node_modules` created, no error exit code.

- [ ] **Step 5: Commit**

```bash
git add companion/package.json companion/tsconfig.json companion/vitest.config.ts
git commit -m "chore: scaffold companion Node/TS project"
```

---

## Task 2: Shared types

**Files:**
- Create: `companion/src/types.ts`

- [ ] **Step 1: Create `companion/src/types.ts`**

```typescript
export type TriggerType = "timer" | "navigation" | "tab_switch" | "click";

export interface CaptureMetadata {
  caseId: string;
  sequenceNumber: number;
  timestamp: string;        // ISO-8601
  url: string;
  tabTitle: string;
  triggerType: TriggerType;
  perceptualHash: string;   // hex string
  isDuplicate: boolean;
  screenshotFile: string;   // relative filename within screenshots/, e.g. "000123_<ts>.webp"
}

export interface CaseMeta {
  caseId: string;
  name: string;
  createdAt: string;        // ISO-8601
  investigator: string;
  aiProvider: string | null;
}

// Payload the extension POSTs to the ingest endpoint.
export interface IngestPayload {
  caseId: string;
  timestamp: string;
  url: string;
  tabTitle: string;
  triggerType: TriggerType;
  imageBase64: string;      // base64-encoded screenshot bytes (webp/png)
}
```

- [ ] **Step 2: Commit**

```bash
git add companion/src/types.ts
git commit -m "feat: add shared companion types"
```

---

## Task 3: Perceptual hash module

**Files:**
- Create: `companion/src/dedup/perceptualHash.ts`
- Test: `companion/tests/dedup/perceptualHash.test.ts`

Implements an average-hash (aHash): resize to 8x8 grayscale, threshold each pixel against the mean, produce a 64-bit hash as 16 hex chars. `hammingDistance` counts differing bits; `isDuplicate` returns true when distance ≤ threshold.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from "vitest";
import sharp from "sharp";
import { computeHash, hammingDistance, isDuplicate } from "../../src/dedup/perceptualHash.js";

async function solidImage(r: number, g: number, b: number) {
  return sharp({
    create: { width: 64, height: 64, channels: 3, background: { r, g, b } },
  }).png().toBuffer();
}

describe("perceptualHash", () => {
  it("computeHash returns a 16-char hex string", async () => {
    const hash = await computeHash(await solidImage(120, 120, 120));
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
  });

  it("identical images have hamming distance 0", async () => {
    const img = await solidImage(80, 80, 80);
    const a = await computeHash(img);
    const b = await computeHash(img);
    expect(hammingDistance(a, b)).toBe(0);
  });

  it("isDuplicate is true for identical, false for clearly different", async () => {
    const grayHash = await computeHash(await solidImage(128, 128, 128));
    const sameHash = await computeHash(await solidImage(128, 128, 128));
    expect(isDuplicate(grayHash, sameHash, 5)).toBe(true);

    // A half-black/half-white image differs strongly from a flat gray image.
    const split = await sharp({
      create: { width: 64, height: 64, channels: 3, background: { r: 0, g: 0, b: 0 } },
    })
      .composite([{
        input: { create: { width: 64, height: 32, channels: 3, background: { r: 255, g: 255, b: 255 } } },
        top: 0, left: 0,
      }])
      .png().toBuffer();
    const splitHash = await computeHash(split);
    expect(isDuplicate(grayHash, splitHash, 5)).toBe(false);
  });

  it("hammingDistance throws on mismatched lengths", () => {
    expect(() => hammingDistance("ff", "ffff")).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/dedup/perceptualHash.test.ts`
Expected: FAIL — cannot resolve `../../src/dedup/perceptualHash.js` (module not yet created).

- [ ] **Step 3: Write minimal implementation**

```typescript
import sharp from "sharp";

// Average-hash: 8x8 grayscale, threshold against mean -> 64-bit hash (16 hex chars).
export async function computeHash(image: Buffer): Promise<string> {
  const { data } = await sharp(image)
    .greyscale()
    .resize(8, 8, { fit: "fill" })
    .raw()
    .toBuffer({ resolveWithObject: true });

  const pixels = Array.from(data.subarray(0, 64));
  const mean = pixels.reduce((sum, v) => sum + v, 0) / pixels.length;

  let bits = "";
  for (const v of pixels) bits += v >= mean ? "1" : "0";

  let hex = "";
  for (let i = 0; i < 64; i += 4) {
    hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  }
  return hex;
}

export function hammingDistance(a: string, b: string): number {
  if (a.length !== b.length) {
    throw new Error(`hash length mismatch: ${a.length} vs ${b.length}`);
  }
  let distance = 0;
  for (let i = 0; i < a.length; i++) {
    let nibble = parseInt(a[i], 16) ^ parseInt(b[i], 16);
    while (nibble) {
      distance += nibble & 1;
      nibble >>= 1;
    }
  }
  return distance;
}

export function isDuplicate(a: string, b: string, threshold: number): boolean {
  return hammingDistance(a, b) <= threshold;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/dedup/perceptualHash.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/dedup/perceptualHash.ts companion/tests/dedup/perceptualHash.test.ts
git commit -m "feat: add perceptual-hash dedup module"
```

---

## Task 4: CaseStore — create case + paths

**Files:**
- Create: `companion/src/storage/caseStore.ts`
- Test: `companion/tests/storage/caseStore.test.ts`

`CaseStore` is constructed with a root directory (e.g. `cases/`). `createCase` builds the folder layout and writes `case.json`. Path helpers expose the layout.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-cases-"));
});

describe("CaseStore.createCase", () => {
  it("creates the folder layout and writes case.json", async () => {
    const store = new CaseStore(root);
    const meta = await store.createCase({
      caseId: "case-001",
      name: "Test Incident",
      investigator: "yaniv",
      aiProvider: null,
    });

    expect(meta.caseId).toBe("case-001");
    expect(meta.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);

    for (const sub of ["screenshots", "metadata", "state", "reports"]) {
      const s = await stat(join(root, "case-001", sub));
      expect(s.isDirectory()).toBe(true);
    }

    const written = JSON.parse(
      await readFile(join(root, "case-001", "case.json"), "utf8"),
    );
    expect(written.name).toBe("Test Incident");
    expect(written.investigator).toBe("yaniv");
  });

  it("exposes correct paths", () => {
    const store = new CaseStore(root);
    expect(store.screenshotsDir("case-001")).toBe(join(root, "case-001", "screenshots"));
    expect(store.capturesLogPath("case-001")).toBe(join(root, "case-001", "metadata", "captures.jsonl"));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/storage/caseStore.test.ts`
Expected: FAIL — cannot resolve `caseStore.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseMeta } from "../types.js";

export interface CreateCaseInput {
  caseId: string;
  name: string;
  investigator: string;
  aiProvider: string | null;
}

export class CaseStore {
  constructor(private readonly root: string) {}

  caseDir(caseId: string): string {
    return join(this.root, caseId);
  }
  screenshotsDir(caseId: string): string {
    return join(this.caseDir(caseId), "screenshots");
  }
  metadataDir(caseId: string): string {
    return join(this.caseDir(caseId), "metadata");
  }
  stateDir(caseId: string): string {
    return join(this.caseDir(caseId), "state");
  }
  reportsDir(caseId: string): string {
    return join(this.caseDir(caseId), "reports");
  }
  capturesLogPath(caseId: string): string {
    return join(this.metadataDir(caseId), "captures.jsonl");
  }
  caseMetaPath(caseId: string): string {
    return join(this.caseDir(caseId), "case.json");
  }

  async createCase(input: CreateCaseInput): Promise<CaseMeta> {
    const meta: CaseMeta = {
      caseId: input.caseId,
      name: input.name,
      createdAt: new Date().toISOString(),
      investigator: input.investigator,
      aiProvider: input.aiProvider,
    };
    for (const dir of [
      this.screenshotsDir(input.caseId),
      this.metadataDir(input.caseId),
      this.stateDir(input.caseId),
      this.reportsDir(input.caseId),
    ]) {
      await mkdir(dir, { recursive: true });
    }
    await writeFile(this.caseMetaPath(input.caseId), JSON.stringify(meta, null, 2), "utf8");
    return meta;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/storage/caseStore.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/storage/caseStore.ts companion/tests/storage/caseStore.test.ts
git commit -m "feat: add CaseStore with case folder layout"
```

---

## Task 5: CaseStore — save screenshot + append capture metadata

**Files:**
- Modify: `companion/src/storage/caseStore.ts`
- Modify: `companion/tests/storage/caseStore.test.ts`

Add `saveScreenshot(caseId, filename, bytes)` and `appendCapture(caseId, metadata)`. `appendCapture` appends one JSON line to `captures.jsonl` (append-only audit trail) and returns the metadata. Also add `nextSequenceNumber(caseId)` that counts existing lines to assign a monotonically increasing sequence number.

- [ ] **Step 1: Write the failing test (append to existing describe block in the file)**

```typescript
import { readFile } from "node:fs/promises";
import type { CaptureMetadata } from "../../src/types.js";

describe("CaseStore evidence writes", () => {
  it("saves a screenshot to the screenshots dir", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    await store.saveScreenshot("c1", "000001_t.webp", Buffer.from([1, 2, 3, 4]));
    const written = await readFile(join(root, "c1", "screenshots", "000001_t.webp"));
    expect(Array.from(written)).toEqual([1, 2, 3, 4]);
  });

  it("appendCapture writes one JSONL line per call (append-only)", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });

    const base: Omit<CaptureMetadata, "sequenceNumber"> = {
      caseId: "c2",
      timestamp: "2026-05-28T10:00:00.000Z",
      url: "https://velociraptor.local/hunts",
      tabTitle: "Hunts",
      triggerType: "timer",
      perceptualHash: "ffffffffffffffff",
      isDuplicate: false,
      screenshotFile: "000001_t.webp",
    };

    await store.appendCapture("c2", { ...base, sequenceNumber: 1 });
    await store.appendCapture("c2", { ...base, sequenceNumber: 2, screenshotFile: "000002_t.webp" });

    const log = await readFile(store.capturesLogPath("c2"), "utf8");
    const lines = log.trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).sequenceNumber).toBe(1);
    expect(JSON.parse(lines[1]).screenshotFile).toBe("000002_t.webp");
  });

  it("nextSequenceNumber returns 1 for a new case, then increments with the log", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c3", name: "n", investigator: "i", aiProvider: null });

    expect(await store.nextSequenceNumber("c3")).toBe(1);
    await store.appendCapture("c3", {
      caseId: "c3", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
      triggerType: "timer", perceptualHash: "0000000000000000", isDuplicate: false,
      screenshotFile: "000001_t.webp", sequenceNumber: 1,
    });
    expect(await store.nextSequenceNumber("c3")).toBe(2);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/storage/caseStore.test.ts`
Expected: FAIL — `store.saveScreenshot is not a function`.

- [ ] **Step 3: Add the implementation (append these methods inside the `CaseStore` class)**

```typescript
  // Add near the top of the file with the other imports:
  // import { mkdir, writeFile, appendFile, readFile } from "node:fs/promises";
  // import { join } from "node:path";
  // import type { CaseMeta, CaptureMetadata } from "../types.js";

  async saveScreenshot(caseId: string, filename: string, bytes: Buffer): Promise<string> {
    const path = join(this.screenshotsDir(caseId), filename);
    await writeFile(path, bytes);
    return path;
  }

  async appendCapture(caseId: string, metadata: CaptureMetadata): Promise<CaptureMetadata> {
    await appendFile(this.capturesLogPath(caseId), JSON.stringify(metadata) + "\n", "utf8");
    return metadata;
  }

  async nextSequenceNumber(caseId: string): Promise<number> {
    try {
      const log = await readFile(this.capturesLogPath(caseId), "utf8");
      const lines = log.split("\n").filter((l) => l.trim().length > 0);
      return lines.length + 1;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return 1;
      throw err;
    }
  }
```

Update the import line at the top of `caseStore.ts` from:
```typescript
import { mkdir, writeFile } from "node:fs/promises";
```
to:
```typescript
import { mkdir, writeFile, appendFile, readFile } from "node:fs/promises";
import type { CaseMeta, CaptureMetadata } from "../types.js";
```
(Remove the now-duplicated `import type { CaseMeta }` line if present.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/storage/caseStore.test.ts`
Expected: PASS (5 tests total in the file).

- [ ] **Step 5: Commit**

```bash
git add companion/src/storage/caseStore.ts companion/tests/storage/caseStore.test.ts
git commit -m "feat: add screenshot save and append-only capture log to CaseStore"
```

---

## Task 6: Capture ingest orchestration

**Files:**
- Create: `companion/src/ingest/captureIngest.ts`
- Test: `companion/tests/ingest/captureIngest.test.ts`

`ingestCapture(store, payload)` validates the payload with Zod, decodes the base64 image, computes the perceptual hash, compares against the previous capture's hash to set `isDuplicate`, assigns the next sequence number, writes the screenshot to disk, then appends metadata. Evidence (image) is written before metadata so the audit line always points to a file that exists.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ingestCapture } from "../../src/ingest/captureIngest.js";

let root: string;
let store: CaseStore;

async function pngBase64(r: number, g: number, b: number): Promise<string> {
  const buf = await sharp({
    create: { width: 32, height: 32, channels: 3, background: { r, g, b } },
  }).png().toBuffer();
  return buf.toString("base64");
}

function payload(over: Partial<Record<string, unknown>> = {}) {
  return {
    caseId: "c1",
    timestamp: "2026-05-28T10:00:00.000Z",
    url: "https://velociraptor.local/hunts",
    tabTitle: "Hunts",
    triggerType: "timer",
    imageBase64: "",
    ...over,
  };
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-ingest-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
});

describe("ingestCapture", () => {
  it("persists image + metadata and returns metadata with sequence 1", async () => {
    const img = await pngBase64(50, 60, 70);
    const meta = await ingestCapture(store, payload({ imageBase64: img }));

    expect(meta.sequenceNumber).toBe(1);
    expect(meta.isDuplicate).toBe(false);
    expect(meta.perceptualHash).toMatch(/^[0-9a-f]{16}$/);

    const onDisk = await readFile(join(store.screenshotsDir("c1"), meta.screenshotFile));
    expect(onDisk.length).toBeGreaterThan(0);

    const log = (await readFile(store.capturesLogPath("c1"), "utf8")).trim().split("\n");
    expect(log).toHaveLength(1);
  });

  it("marks a near-identical second capture as duplicate", async () => {
    const img = await pngBase64(128, 128, 128);
    await ingestCapture(store, payload({ imageBase64: img }));
    const second = await ingestCapture(store, payload({ imageBase64: img }));
    expect(second.isDuplicate).toBe(true);
    expect(second.sequenceNumber).toBe(2);
  });

  it("rejects an invalid payload (missing url)", async () => {
    const bad = payload({ imageBase64: await pngBase64(1, 1, 1) });
    delete (bad as Record<string, unknown>).url;
    await expect(ingestCapture(store, bad)).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/ingest/captureIngest.test.ts`
Expected: FAIL — cannot resolve `captureIngest.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import { z } from "zod";
import type { CaptureMetadata } from "../types.js";
import type { CaseStore } from "../storage/caseStore.js";
import { computeHash, isDuplicate } from "../dedup/perceptualHash.js";

const DUP_THRESHOLD = 5;

const payloadSchema = z.object({
  caseId: z.string().min(1),
  timestamp: z.string().min(1),
  url: z.string().min(1),
  tabTitle: z.string(),
  triggerType: z.enum(["timer", "navigation", "tab_switch", "click"]),
  imageBase64: z.string().min(1),
});

// In-memory cache of the last hash per case, to decide duplicates without re-reading disk.
const lastHashByCase = new Map<string, string>();

export async function ingestCapture(
  store: CaseStore,
  rawPayload: unknown,
  threshold = DUP_THRESHOLD,
): Promise<CaptureMetadata> {
  const payload = payloadSchema.parse(rawPayload);

  const bytes = Buffer.from(payload.imageBase64, "base64");
  const hash = await computeHash(bytes);

  const previous = lastHashByCase.get(payload.caseId);
  const duplicate = previous !== undefined && isDuplicate(previous, hash, threshold);
  lastHashByCase.set(payload.caseId, hash);

  const sequenceNumber = await store.nextSequenceNumber(payload.caseId);
  const tsSafe = payload.timestamp.replace(/[:.]/g, "-");
  const screenshotFile = `${String(sequenceNumber).padStart(6, "0")}_${tsSafe}.webp`;

  // Evidence first: write the image before recording metadata.
  await store.saveScreenshot(payload.caseId, screenshotFile, bytes);

  const metadata: CaptureMetadata = {
    caseId: payload.caseId,
    sequenceNumber,
    timestamp: payload.timestamp,
    url: payload.url,
    tabTitle: payload.tabTitle,
    triggerType: payload.triggerType,
    perceptualHash: hash,
    isDuplicate: duplicate,
    screenshotFile,
  };
  await store.appendCapture(payload.caseId, metadata);
  return metadata;
}

// Exposed for test isolation.
export function _resetDedupCache(): void {
  lastHashByCase.clear();
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/ingest/captureIngest.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add companion/src/ingest/captureIngest.ts companion/tests/ingest/captureIngest.test.ts
git commit -m "feat: add capture ingest orchestration with dedup"
```

---

## Task 7: HTTP server

**Files:**
- Create: `companion/src/server.ts`
- Test: `companion/tests/server.test.ts`

Express app with two routes: `POST /cases` (create a case) and `POST /captures` (ingest a capture). The app is built by a `createApp(store)` factory so tests can inject a temp-rooted store. A `startServer` entrypoint binds to localhost only.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../src/storage/caseStore.js";
import { createApp } from "../src/server.js";

let app: ReturnType<typeof createApp>;

async function pngBase64(): Promise<string> {
  const buf = await sharp({
    create: { width: 16, height: 16, channels: 3, background: { r: 10, g: 20, b: 30 } },
  }).png().toBuffer();
  return buf.toString("base64");
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-server-"));
  app = createApp(new CaseStore(root));
});

describe("HTTP server", () => {
  it("POST /cases creates a case", async () => {
    const res = await request(app)
      .post("/cases")
      .send({ caseId: "c1", name: "Incident A", investigator: "yaniv", aiProvider: null });
    expect(res.status).toBe(201);
    expect(res.body.caseId).toBe("c1");
  });

  it("POST /captures ingests a capture and returns metadata", async () => {
    await request(app)
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const res = await request(app).post("/captures").send({
      caseId: "c1",
      timestamp: "2026-05-28T10:00:00.000Z",
      url: "https://velociraptor.local/hunts",
      tabTitle: "Hunts",
      triggerType: "timer",
      imageBase64: await pngBase64(),
    });
    expect(res.status).toBe(201);
    expect(res.body.sequenceNumber).toBe(1);
    expect(res.body.screenshotFile).toMatch(/\.webp$/);
  });

  it("POST /captures returns 400 on invalid payload", async () => {
    const res = await request(app).post("/captures").send({ caseId: "c1" });
    expect(res.status).toBe(400);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd companion && npx vitest run tests/server.test.ts`
Expected: FAIL — cannot resolve `server.js` / `createApp` not exported.

- [ ] **Step 3: Write minimal implementation**

```typescript
import express, { type Express, type Request, type Response } from "express";
import { ZodError } from "zod";
import { CaseStore } from "./storage/caseStore.js";
import { ingestCapture } from "./ingest/captureIngest.js";

export function createApp(store: CaseStore): Express {
  const app = express();
  app.use(express.json({ limit: "25mb" })); // screenshots arrive base64-encoded

  app.post("/cases", async (req: Request, res: Response) => {
    try {
      const { caseId, name, investigator, aiProvider } = req.body ?? {};
      if (!caseId || !name) {
        return res.status(400).json({ error: "caseId and name are required" });
      }
      const meta = await store.createCase({
        caseId,
        name,
        investigator: investigator ?? "unknown",
        aiProvider: aiProvider ?? null,
      });
      return res.status(201).json(meta);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/captures", async (req: Request, res: Response) => {
    try {
      const metadata = await ingestCapture(store, req.body);
      return res.status(201).json(metadata);
    } catch (err) {
      if (err instanceof ZodError) {
        return res.status(400).json({ error: "invalid payload", details: err.issues });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  return app;
}

export function startServer(casesRoot: string, port = 4773): void {
  const app = createApp(new CaseStore(casesRoot));
  app.listen(port, "127.0.0.1", () => {
    console.log(`DFIR companion listening on http://127.0.0.1:${port}`);
  });
}

// Entry point when run directly.
if (process.argv[1] && process.argv[1].endsWith("server.ts")) {
  startServer(process.env.DFIR_CASES_ROOT ?? "cases");
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd companion && npx vitest run tests/server.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full suite**

Run: `cd companion && npm test`
Expected: PASS — all tests across dedup, storage, ingest, server.

- [ ] **Step 6: Commit**

```bash
git add companion/src/server.ts companion/tests/server.test.ts
git commit -m "feat: add HTTP server with case and capture endpoints"
```

---

## Task 8: Manual smoke test + README note

**Files:**
- Create: `companion/README.md`

- [ ] **Step 1: Create `companion/README.md`**

```markdown
# DFIR Companion (Core)

Localhost server that ingests browser screenshots and stores them as forensic evidence.

## Run

    cd companion
    npm install
    DFIR_CASES_ROOT=./cases npm run dev

Server listens on http://127.0.0.1:4773 (localhost only).

## Endpoints

- `POST /cases` — `{ caseId, name, investigator, aiProvider }`
- `POST /captures` — `{ caseId, timestamp, url, tabTitle, triggerType, imageBase64 }`

## Case folder layout

    cases/<caseId>/
      case.json
      screenshots/000001_<ts>.webp
      metadata/captures.jsonl   (append-only audit trail)
      state/                    (populated in Plan 2)
      reports/                  (populated in Plan 3)

## Test

    npm test
```

- [ ] **Step 2: Manual smoke test**

Run (PowerShell), in one terminal:
```
cd companion; $env:DFIR_CASES_ROOT="./cases"; npm run dev
```
In another terminal:
```
curl -X POST http://127.0.0.1:4773/cases -H "Content-Type: application/json" -d '{"caseId":"demo","name":"Demo","investigator":"yaniv","aiProvider":null}'
```
Expected: HTTP 201 with the case metadata JSON, and a `companion/cases/demo/` folder created on disk.

- [ ] **Step 3: Commit**

```bash
git add companion/README.md
git commit -m "docs: add companion core README"
```

---

## Self-Review

**Spec coverage (Plan 1 scope = evidence path):**
- Capture metadata shape (caseId, timestamp, url, tabTitle, triggerType, perceptualHash, isDuplicate, sequenceNumber) → Task 2 + Task 6. ✓
- `captureVisibleTab` payload received over localhost → Task 7 (`POST /captures`). ✓
- Perceptual-hash dedup with tunable threshold → Task 3 (module) + Task 6 (`threshold` param). ✓
- Duplicates still saved as evidence but flagged → Task 6 (image written + `isDuplicate` set regardless). ✓
- Evidence write precedes analysis / cannot be lost to analysis → Task 6 (image saved before metadata; no AI in this plan). ✓
- Case folder layout (case.json, screenshots/, metadata/captures.jsonl, state/, reports/) → Task 4. ✓
- Append-only audit trail → Task 5 (`appendCapture` uses `appendFile`). ✓
- Sequential, gap-detectable filenames → Task 6 (`padStart(6,"0")` + sequence). ✓
- localhost-only binding → Task 7 (`listen(port, "127.0.0.1")`). ✓
- Out of scope for Plan 1 (deferred): AI analysis, investigation state, reports, dashboard, extension, IndexedDB queue. These are Plans 2–4.

**Placeholder scan:** No TBD/TODO; every code step contains full code; every run step has an exact command + expected result. ✓

**Type consistency:** `CaptureMetadata`, `CaseMeta`, `IngestPayload`, `TriggerType` defined in Task 2 and used consistently in Tasks 4–7. `CaseStore` methods (`createCase`, `screenshotsDir`, `capturesLogPath`, `saveScreenshot`, `appendCapture`, `nextSequenceNumber`) defined in Tasks 4–5 and called with matching signatures in Tasks 6–7. `computeHash`/`isDuplicate` signatures from Task 3 match calls in Task 6. ✓
