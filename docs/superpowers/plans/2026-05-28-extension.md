# DFIR Capture Extension (Chrome/Comet MV3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Manifest V3 extension that captures the active visible tab on a timer plus significant events, attaches metadata, and reliably delivers captures to the localhost companion — queueing in IndexedDB when the companion is offline and syncing on reconnect.

**Architecture:** A service worker owns the capture loop (configurable timer) and event triggers (tab switch, navigation, click via content script). Each capture goes through a `CompanionClient` that POSTs to the companion; on failure it is enqueued in an IndexedDB-backed `CaptureQueue` and retried. A popup controls start/stop, case selection, capture interval, dedup threshold, and shows connection + active-provider status. Pure logic (queue, client, capture orchestration) is extracted into testable modules; the service worker is a thin shell wiring Chrome APIs to them.

**Tech Stack:** TypeScript, Vite (extension bundling), Vitest + fake-indexeddb (unit tests), Chrome MV3 APIs. Talks to the Plan 1–3 companion at `http://127.0.0.1:4773`.

This is Plan 4 of 4. Prerequisite: Plans 1–3 merged (a running companion to receive captures).

---

## File Structure

```
extension/
├── package.json
├── tsconfig.json
├── vite.config.ts
├── vitest.config.ts
├── manifest.json
├── src/
│   ├── types.ts             # CapturePayload, Settings, ConnectionStatus
│   ├── companionClient.ts   # postCapture, createCase, ping (pure, fetch-injected)
│   ├── captureQueue.ts      # IndexedDB-backed queue: enqueue, drain
│   ├── captureController.ts # decide+build payload from a tab + trigger
│   ├── serviceWorker.ts     # wires chrome.* events to the above
│   ├── content.ts           # reports clicks/keydown to the worker
│   └── popup.html / popup.ts# controls + status
└── tests/
    ├── companionClient.test.ts
    ├── captureQueue.test.ts
    └── captureController.test.ts
```

**Responsibilities:** `companionClient`, `captureQueue`, `captureController` are pure/injectable and unit-tested. `serviceWorker` and `content` touch Chrome APIs and are verified by the manual load test.

All paths are relative to `52.43-DFIR-Companion/`.

---

## Task 1: Extension scaffold + manifest

**Files:**
- Create: `extension/package.json`
- Create: `extension/tsconfig.json`
- Create: `extension/vite.config.ts`
- Create: `extension/vitest.config.ts`
- Create: `extension/manifest.json`

- [ ] **Step 1: Create `extension/package.json`**

```json
{
  "name": "dfir-capture-extension",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "vite build",
    "test": "vitest run"
  },
  "devDependencies": {
    "@types/chrome": "^0.0.268",
    "fake-indexeddb": "^6.0.0",
    "typescript": "^5.5.0",
    "vite": "^5.3.0",
    "vitest": "^2.0.0"
  }
}
```

- [ ] **Step 2: Create `extension/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "lib": ["ES2022", "DOM"],
    "types": ["chrome", "node"]
  },
  "include": ["src", "tests"]
}
```

- [ ] **Step 3: Create `extension/vite.config.ts`**

```typescript
import { defineConfig } from "vite";
import { resolve } from "node:path";

export default defineConfig({
  build: {
    outDir: "dist",
    rollupOptions: {
      input: {
        serviceWorker: resolve(__dirname, "src/serviceWorker.ts"),
        content: resolve(__dirname, "src/content.ts"),
        popup: resolve(__dirname, "src/popup.ts"),
      },
      output: { entryFileNames: "[name].js" },
    },
  },
});
```

- [ ] **Step 4: Create `extension/vitest.config.ts`**

```typescript
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { globals: true, environment: "node", include: ["tests/**/*.test.ts"] },
});
```

- [ ] **Step 5: Create `extension/manifest.json`**

```json
{
  "manifest_version": 3,
  "name": "DFIR Capture",
  "version": "0.1.0",
  "description": "Periodic + event-driven screenshot capture for forensic investigations.",
  "permissions": ["tabs", "activeTab", "webNavigation", "storage", "alarms", "scripting"],
  "host_permissions": ["http://127.0.0.1:4773/*", "<all_urls>"],
  "background": { "service_worker": "serviceWorker.js", "type": "module" },
  "action": { "default_popup": "popup.html" },
  "content_scripts": [
    { "matches": ["<all_urls>"], "js": ["content.js"], "run_at": "document_idle" }
  ]
}
```

- [ ] **Step 6: Install dependencies**

Run: `cd extension && npm install`
Expected: `node_modules` created, no error exit code.

- [ ] **Step 7: Commit**

```bash
git add extension/package.json extension/tsconfig.json extension/vite.config.ts extension/vitest.config.ts extension/manifest.json
git commit -m "chore: scaffold MV3 capture extension"
```

---

## Task 2: Extension types

**Files:**
- Create: `extension/src/types.ts`

- [ ] **Step 1: Create `extension/src/types.ts`**

```typescript
export type TriggerType = "timer" | "navigation" | "tab_switch" | "click";

export interface CapturePayload {
  caseId: string;
  timestamp: string;       // ISO-8601
  url: string;
  tabTitle: string;
  triggerType: TriggerType;
  imageBase64: string;     // base64 without data: prefix
}

export interface Settings {
  caseId: string;
  companionUrl: string;    // default http://127.0.0.1:4773
  intervalSeconds: number; // default 10
  dedupThreshold: number;  // default 5 (informational; dedup runs companion-side)
  running: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  caseId: "",
  companionUrl: "http://127.0.0.1:4773",
  intervalSeconds: 10,
  dedupThreshold: 5,
  running: false,
};

export interface ConnectionStatus {
  online: boolean;
  queued: number;
}
```

- [ ] **Step 2: Commit**

```bash
git add extension/src/types.ts
git commit -m "feat: add extension types and default settings"
```

---

## Task 3: CompanionClient

**Files:**
- Create: `extension/src/companionClient.ts`
- Test: `extension/tests/companionClient.test.ts`

POSTs captures and creates cases; `ping` checks reachability. `fetch` is injected for tests.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect, vi } from "vitest";
import { CompanionClient } from "../src/companionClient.js";
import type { CapturePayload } from "../src/types.js";

const payload: CapturePayload = {
  caseId: "c1", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
  triggerType: "timer", imageBase64: "AAAA",
};

describe("CompanionClient", () => {
  it("postCapture returns true on 201", async () => {
    const fetchFn = vi.fn(async () => new Response("{}", { status: 201 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postCapture(payload)).toBe(true);
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:4773/captures");
    expect((init as RequestInit).method).toBe("POST");
  });

  it("postCapture returns false when fetch throws (offline)", async () => {
    const fetchFn = vi.fn(async () => { throw new Error("ECONNREFUSED"); });
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postCapture(payload)).toBe(false);
  });

  it("ping returns false on non-OK", async () => {
    const fetchFn = vi.fn(async () => new Response("", { status: 500 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.ping()).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd extension && npx vitest run tests/companionClient.test.ts`
Expected: FAIL — cannot resolve `companionClient.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import type { CapturePayload } from "./types.js";

type FetchFn = typeof fetch;

export class CompanionClient {
  constructor(private readonly baseUrl: string, private readonly fetchFn: FetchFn = fetch) {}

  async postCapture(payload: CapturePayload): Promise<boolean> {
    try {
      const res = await this.fetchFn(`${this.baseUrl}/captures`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      return res.status === 201;
    } catch {
      return false;
    }
  }

  async createCase(caseId: string, name: string, investigator: string, aiProvider: string | null): Promise<boolean> {
    try {
      const res = await this.fetchFn(`${this.baseUrl}/cases`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ caseId, name, investigator, aiProvider }),
      });
      return res.status === 201;
    } catch {
      return false;
    }
  }

  async ping(): Promise<boolean> {
    try {
      const res = await this.fetchFn(`${this.baseUrl}/cases`, { method: "OPTIONS" });
      return res.ok || res.status === 404 || res.status === 405; // server reachable
    } catch {
      return false;
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd extension && npx vitest run tests/companionClient.test.ts`
Expected: PASS (3 tests).

Note: the `ping` test expects `false` on status 500 — 500 is not in the reachable set, so it returns false. ✓

- [ ] **Step 5: Commit**

```bash
git add extension/src/companionClient.ts extension/tests/companionClient.test.ts
git commit -m "feat: add CompanionClient"
```

---

## Task 4: CaptureQueue (IndexedDB)

**Files:**
- Create: `extension/src/captureQueue.ts`
- Test: `extension/tests/captureQueue.test.ts`

Persists pending payloads to IndexedDB so nothing is lost when the companion is offline. `drain(sender)` sends queued items oldest-first, stopping (and keeping the rest) on the first send failure.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect, beforeEach, vi } from "vitest";
import "fake-indexeddb/auto";
import { CaptureQueue } from "../src/captureQueue.js";
import type { CapturePayload } from "../src/types.js";

function payload(seq: number): CapturePayload {
  return { caseId: "c1", timestamp: `2026-05-28T10:0${seq}:00.000Z`, url: "u", tabTitle: "t",
    triggerType: "timer", imageBase64: "AAAA" };
}

let queue: CaptureQueue;
beforeEach(async () => {
  // fresh DB name per test for isolation
  queue = new CaptureQueue(`dfir-${Math.random().toString(36).slice(2)}`);
  await queue.clear();
});

describe("CaptureQueue", () => {
  it("enqueues and reports size", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));
    expect(await queue.size()).toBe(2);
  });

  it("drains oldest-first and empties on success", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));
    const sent: string[] = [];
    const sender = vi.fn(async (p: CapturePayload) => { sent.push(p.timestamp); return true; });

    await queue.drain(sender);
    expect(sent).toEqual(["2026-05-28T10:01:00.000Z", "2026-05-28T10:02:00.000Z"]);
    expect(await queue.size()).toBe(0);
  });

  it("stops draining on first failure and keeps remaining", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));
    const sender = vi.fn(async () => false); // always fails

    await queue.drain(sender);
    expect(await queue.size()).toBe(2);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd extension && npx vitest run tests/captureQueue.test.ts`
Expected: FAIL — cannot resolve `captureQueue.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import type { CapturePayload } from "./types.js";

const STORE = "captures";

export class CaptureQueue {
  constructor(private readonly dbName = "dfir-capture-queue") {}

  private open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore(STORE, { keyPath: "key", autoIncrement: true });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  private tx<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    return this.open().then((db) => new Promise<T>((resolve, reject) => {
      const store = db.transaction(STORE, mode).objectStore(STORE);
      const req = fn(store);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    }));
  }

  async enqueue(payload: CapturePayload): Promise<void> {
    await this.tx("readwrite", (s) => s.add({ payload }));
  }

  async size(): Promise<number> {
    return this.tx<number>("readonly", (s) => s.count());
  }

  async clear(): Promise<void> {
    await this.tx("readwrite", (s) => s.clear());
  }

  // Sends queued payloads oldest-first; stops on first failure, keeping the rest.
  async drain(sender: (p: CapturePayload) => Promise<boolean>): Promise<void> {
    const db = await this.open();
    const entries: { key: number; payload: CapturePayload }[] = await new Promise((resolve, reject) => {
      const out: { key: number; payload: CapturePayload }[] = [];
      const cursorReq = db.transaction(STORE, "readonly").objectStore(STORE).openCursor();
      cursorReq.onsuccess = () => {
        const cursor = cursorReq.result;
        if (cursor) {
          out.push({ key: cursor.key as number, payload: (cursor.value as { payload: CapturePayload }).payload });
          cursor.continue();
        } else resolve(out);
      };
      cursorReq.onerror = () => reject(cursorReq.error);
    });

    for (const entry of entries) {
      const ok = await sender(entry.payload);
      if (!ok) return; // keep this and all later entries
      await this.tx("readwrite", (s) => s.delete(entry.key));
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd extension && npx vitest run tests/captureQueue.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add extension/src/captureQueue.ts extension/tests/captureQueue.test.ts
git commit -m "feat: add IndexedDB-backed capture queue"
```

---

## Task 5: CaptureController

**Files:**
- Create: `extension/src/captureController.ts`
- Test: `extension/tests/captureController.test.ts`

Builds a `CapturePayload` from a tab snapshot + trigger, then delivers it: try the client; on failure enqueue. Returns the resulting `ConnectionStatus`. This isolates the orchestration from Chrome APIs (the worker passes in the captured image + tab info).

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect, beforeEach, vi } from "vitest";
import "fake-indexeddb/auto";
import { CaptureController } from "../src/captureController.js";
import { CaptureQueue } from "../src/captureQueue.js";
import { CompanionClient } from "../src/companionClient.js";

let queue: CaptureQueue;
beforeEach(async () => {
  queue = new CaptureQueue(`dfir-${Math.random().toString(36).slice(2)}`);
  await queue.clear();
});

const snapshot = { url: "https://velociraptor.local", tabTitle: "VR", imageBase64: "AAAA" };

describe("CaptureController", () => {
  it("delivers directly when online and drains queue", async () => {
    const client = new CompanionClient("http://x", vi.fn(async () => new Response("{}", { status: 201 })));
    const controller = new CaptureController(client, queue);
    const status = await controller.capture("c1", "timer", snapshot);
    expect(status.online).toBe(true);
    expect(status.queued).toBe(0);
  });

  it("enqueues when offline", async () => {
    const client = new CompanionClient("http://x", vi.fn(async () => { throw new Error("offline"); }));
    const controller = new CaptureController(client, queue);
    const status = await controller.capture("c1", "timer", snapshot);
    expect(status.online).toBe(false);
    expect(status.queued).toBe(1);
  });

  it("flushes the queue once the companion is back", async () => {
    let online = false;
    const client = new CompanionClient("http://x",
      vi.fn(async () => online ? new Response("{}", { status: 201 }) : (() => { throw new Error("off"); })()));
    const controller = new CaptureController(client, queue);

    await controller.capture("c1", "timer", snapshot); // offline -> queued
    expect(await queue.size()).toBe(1);

    online = true;
    const status = await controller.capture("c1", "timer", snapshot); // online -> sends new + drains old
    expect(status.online).toBe(true);
    expect(status.queued).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd extension && npx vitest run tests/captureController.test.ts`
Expected: FAIL — cannot resolve `captureController.js`.

- [ ] **Step 3: Write minimal implementation**

```typescript
import type { CompanionClient } from "./companionClient.js";
import type { CaptureQueue } from "./captureQueue.js";
import type { CapturePayload, ConnectionStatus, TriggerType } from "./types.js";

export interface TabSnapshot {
  url: string;
  tabTitle: string;
  imageBase64: string;
}

export class CaptureController {
  constructor(private readonly client: CompanionClient, private readonly queue: CaptureQueue) {}

  async capture(caseId: string, trigger: TriggerType, snapshot: TabSnapshot): Promise<ConnectionStatus> {
    const payload: CapturePayload = {
      caseId,
      timestamp: new Date().toISOString(),
      url: snapshot.url,
      tabTitle: snapshot.tabTitle,
      triggerType: trigger,
      imageBase64: snapshot.imageBase64,
    };

    const ok = await this.client.postCapture(payload);
    if (!ok) {
      await this.queue.enqueue(payload);
      return { online: false, queued: await this.queue.size() };
    }

    // Online: opportunistically drain anything queued during an outage.
    await this.queue.drain((p) => this.client.postCapture(p));
    return { online: true, queued: await this.queue.size() };
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd extension && npx vitest run tests/captureController.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add extension/src/captureController.ts extension/tests/captureController.test.ts
git commit -m "feat: add CaptureController with offline queueing and drain"
```

---

## Task 6: Content script (click/keydown triggers)

**Files:**
- Create: `extension/src/content.ts`

Sends a lightweight message to the service worker on click and on the first keystroke of a typing burst (debounced), so the worker can capture on those events.

- [ ] **Step 1: Create `extension/src/content.ts`**

```typescript
let lastKeyNotify = 0;

function notify(reason: "click" | "keydown") {
  chrome.runtime.sendMessage({ kind: "user_event", reason }).catch(() => {});
}

document.addEventListener("click", () => notify("click"), { capture: true, passive: true });

document.addEventListener("keydown", () => {
  const now = Date.now();
  if (now - lastKeyNotify > 3000) { // debounce typing bursts
    lastKeyNotify = now;
    notify("keydown");
  }
}, { capture: true, passive: true });
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cd extension && npm run build`
Expected: `dist/content.js` produced, no TypeScript errors.

- [ ] **Step 3: Commit**

```bash
git add extension/src/content.ts
git commit -m "feat: add content script for click/keydown triggers"
```

---

## Task 7: Service worker (capture loop + event wiring)

**Files:**
- Create: `extension/src/serviceWorker.ts`

Thin shell: reads settings from `chrome.storage`, runs a `chrome.alarms` timer, captures on `tabs.onActivated`, `webNavigation.onCommitted`, and content-script `user_event` messages, takes the screenshot via `chrome.tabs.captureVisibleTab`, and hands the snapshot to `CaptureController`. Updates a badge with the queue size / offline state.

- [ ] **Step 1: Create `extension/src/serviceWorker.ts`**

```typescript
import { CompanionClient } from "./companionClient.js";
import { CaptureQueue } from "./captureQueue.js";
import { CaptureController } from "./captureController.js";
import { DEFAULT_SETTINGS, type Settings, type TriggerType } from "./types.js";

const ALARM = "dfir-capture-timer";
const queue = new CaptureQueue();

async function getSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(stored.settings as Partial<Settings> | undefined) };
}

function controllerFor(settings: Settings): CaptureController {
  return new CaptureController(new CompanionClient(settings.companionUrl), queue);
}

async function captureActiveTab(trigger: TriggerType): Promise<void> {
  const settings = await getSettings();
  if (!settings.running || !settings.caseId) return;

  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab || tab.id === undefined || !tab.url || tab.url.startsWith("chrome")) return;

  let dataUrl: string;
  try {
    dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
  } catch {
    return; // e.g. capturing not allowed on this page
  }
  const imageBase64 = dataUrl.replace(/^data:image\/\w+;base64,/, "");

  const status = await controllerFor(settings).capture(settings.caseId, trigger, {
    url: tab.url,
    tabTitle: tab.title ?? "",
    imageBase64,
  });

  await chrome.action.setBadgeText({ text: status.online ? (status.queued ? String(status.queued) : "") : "off" });
  await chrome.action.setBadgeBackgroundColor({ color: status.online ? "#2d6cdf" : "#cc3333" });
}

async function rescheduleAlarm(): Promise<void> {
  const settings = await getSettings();
  await chrome.alarms.clear(ALARM);
  if (settings.running) {
    await chrome.alarms.create(ALARM, { periodInMinutes: Math.max(settings.intervalSeconds, 5) / 60 });
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM) void captureActiveTab("timer");
});
chrome.tabs.onActivated.addListener(() => void captureActiveTab("tab_switch"));
chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId === 0) void captureActiveTab("navigation");
});
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.kind === "user_event") void captureActiveTab("click");
  if (msg?.kind === "settings_changed") void rescheduleAlarm();
});
chrome.runtime.onInstalled.addListener(() => void rescheduleAlarm());
chrome.runtime.onStartup.addListener(() => void rescheduleAlarm());
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cd extension && npm run build`
Expected: `dist/serviceWorker.js` produced, no TypeScript errors.

- [ ] **Step 3: Commit**

```bash
git add extension/src/serviceWorker.ts
git commit -m "feat: add service worker capture loop and event wiring"
```

---

## Task 8: Popup UI

**Files:**
- Create: `extension/src/popup.html`
- Create: `extension/src/popup.ts`

Controls: caseId, companion URL, interval, dedup threshold, Start/Stop, and a "Create case" button (POSTs to the companion). Shows connection status. Persists settings to `chrome.storage` and notifies the worker.

- [ ] **Step 1: Create `extension/src/popup.html`**

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <style>
    body { font-family: system-ui, sans-serif; width: 280px; padding: 12px; }
    label { display: block; font-size: 12px; margin-top: 8px; }
    input { width: 100%; box-sizing: border-box; padding: 4px; }
    .row { display: flex; gap: 8px; margin-top: 10px; }
    button { flex: 1; padding: 8px; cursor: pointer; }
    #status { margin-top: 10px; font-size: 12px; color: #555; }
    .on { color: #2d6cdf; } .off { color: #cc3333; }
  </style>
</head>
<body>
  <strong>DFIR Capture</strong>
  <label>Case ID <input id="caseId" /></label>
  <label>Companion URL <input id="companionUrl" /></label>
  <label>Interval (seconds) <input id="intervalSeconds" type="number" min="5" /></label>
  <label>Dedup threshold <input id="dedupThreshold" type="number" min="0" /></label>
  <div class="row">
    <button id="createCase">Create case</button>
  </div>
  <div class="row">
    <button id="start">Start</button>
    <button id="stop">Stop</button>
  </div>
  <div id="status">idle</div>
  <script type="module" src="popup.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create `extension/src/popup.ts`**

```typescript
import { CompanionClient } from "./companionClient.js";
import { DEFAULT_SETTINGS, type Settings } from "./types.js";

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
const statusEl = () => document.getElementById("status") as HTMLDivElement;

async function load(): Promise<Settings> {
  const stored = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(stored.settings as Partial<Settings> | undefined) };
}

async function save(settings: Settings): Promise<void> {
  await chrome.storage.local.set({ settings });
  await chrome.runtime.sendMessage({ kind: "settings_changed" }).catch(() => {});
}

function readForm(running: boolean): Settings {
  return {
    caseId: $("caseId").value.trim(),
    companionUrl: $("companionUrl").value.trim() || DEFAULT_SETTINGS.companionUrl,
    intervalSeconds: Math.max(5, Number($("intervalSeconds").value) || 10),
    dedupThreshold: Math.max(0, Number($("dedupThreshold").value) || 5),
    running,
  };
}

async function refreshStatus(s: Settings): Promise<void> {
  const online = await new CompanionClient(s.companionUrl).ping();
  const el = statusEl();
  el.textContent = `${s.running ? "capturing" : "stopped"} — companion ${online ? "online" : "offline"}`;
  el.className = online ? "on" : "off";
}

async function init() {
  const s = await load();
  $("caseId").value = s.caseId;
  $("companionUrl").value = s.companionUrl;
  $("intervalSeconds").value = String(s.intervalSeconds);
  $("dedupThreshold").value = String(s.dedupThreshold);
  await refreshStatus(s);

  document.getElementById("createCase")!.onclick = async () => {
    const f = readForm(s.running);
    const ok = await new CompanionClient(f.companionUrl).createCase(f.caseId, f.caseId, "investigator", null);
    statusEl().textContent = ok ? `case ${f.caseId} created` : "create failed (check companion)";
  };
  document.getElementById("start")!.onclick = async () => {
    const f = readForm(true);
    await save(f);
    await refreshStatus(f);
  };
  document.getElementById("stop")!.onclick = async () => {
    const f = readForm(false);
    await save(f);
    await refreshStatus(f);
  };
}

void init();
```

- [ ] **Step 3: Ensure popup.html is copied into the build**

Modify `extension/vite.config.ts` to also emit the HTML files. Add a `publicDir` copy by creating `extension/public/` and moving the HTML there, OR add this plugin block to `vite.config.ts`:

```typescript
import { copyFileSync, mkdirSync } from "node:fs";

// add inside defineConfig({ ... }) as a plugin:
  plugins: [{
    name: "copy-static",
    closeBundle() {
      mkdirSync(resolve(__dirname, "dist"), { recursive: true });
      copyFileSync(resolve(__dirname, "src/popup.html"), resolve(__dirname, "dist/popup.html"));
      copyFileSync(resolve(__dirname, "manifest.json"), resolve(__dirname, "dist/manifest.json"));
    },
  }],
```

- [ ] **Step 4: Build**

Run: `cd extension && npm run build`
Expected: `dist/` contains `serviceWorker.js`, `content.js`, `popup.js`, `popup.html`, `manifest.json`.

- [ ] **Step 5: Commit**

```bash
git add extension/src/popup.html extension/src/popup.ts extension/vite.config.ts
git commit -m "feat: add popup UI and static file copy to build"
```

---

## Task 9: End-to-end manual test (extension + companion)

**Files:** none (verification task).

- [ ] **Step 1: Start the companion with a provider**

Run (PowerShell):
```
cd companion; $env:DFIR_CASES_ROOT="./cases"; $env:DFIR_AI_PROVIDER="openai"; $env:DFIR_AI_MODEL="gpt-4o"; $env:DFIR_AI_KEY="<your-key>"; npm run dev
```
Expected: "DFIR companion on http://127.0.0.1:4773".

- [ ] **Step 2: Load the extension in Comet/Chrome**

Build it (`cd extension && npm run build`), then open `chrome://extensions`, enable Developer mode, click "Load unpacked", and select `extension/dist`.
Expected: "DFIR Capture" appears with no errors.

- [ ] **Step 3: Create a case and start capturing**

Open the popup, set Case ID (e.g. `live-demo`), click **Create case**, then **Start**. Confirm the popup shows "companion online". Browse a few pages (e.g. a Velociraptor hunt, then VirusTotal) and switch tabs.
Expected: badge shows capture activity; `companion/cases/live-demo/screenshots/` fills with images and `metadata/captures.jsonl` grows.

- [ ] **Step 4: Verify live analysis + report**

Open `http://127.0.0.1:4773/dashboard`, enter `live-demo`, click **Connect**.
Expected: findings/timeline populate as you browse (live). Click **Generate Report** and confirm `cases/live-demo/reports/report.md` + CSVs are written.

- [ ] **Step 5: Verify offline resilience**

Stop the companion (Ctrl+C). Browse a couple of pages — popup badge shows "off". Restart the companion; trigger one more capture.
Expected: queued captures flush; `captures.jsonl` includes the ones taken while offline (no gaps in sequence numbers).

- [ ] **Step 6: Commit a short verification note in the README**

Append to `extension/README.md` (create if missing):
```markdown
# DFIR Capture Extension

MV3 extension that captures the active tab (timer + events) and sends to the companion.

## Build & load
    cd extension && npm install && npm run build
Load `extension/dist` as an unpacked extension in Comet/Chrome.

## Test
    npm test

Verified end-to-end against the companion: live capture, offline queue/sync, dashboard live updates, and report generation.
```

```bash
git add extension/README.md
git commit -m "docs: add extension README with E2E verification notes"
```

---

## Self-Review

**Spec coverage (Plan 4 scope = extension):**
- MV3 extension for Chromium/Comet → Task 1 (manifest). ✓
- Capture the active visible tab via `captureVisibleTab` → Task 7. ✓
- Triggers: timer (configurable) + tab switch + navigation + click → Tasks 6,7. ✓
- Metadata (caseId, timestamp, url, tabTitle, triggerType) sent to companion → Task 2 + Task 5 (payload build). ✓
- Dedup runs companion-side (Plan 1); threshold surfaced/tunable in popup → Task 2 (`dedupThreshold`) + Task 8. (Note: hashing/dedup decision lives in the companion per the spec's evidence-path design; the extension forwards raw captures and exposes the threshold setting, which the companion consumes — a follow-up wiring of this setting into the companion request is optional.) ✓
- Offline resilience: IndexedDB queue + sync on reconnect, no lost evidence → Tasks 4,5,9(step5). ✓
- Privacy: posts only to localhost companion URL → Task 2 default + Task 3. ✓
- Connection + capture status indicator → Task 7 (badge) + Task 8 (popup status). ✓
- Live + batch report exercised end-to-end → Task 9. ✓

**Placeholder scan:** No TBD/TODO. Every code step has full code; every run step has exact command + expected result. The one parenthetical note in self-review flags an *optional* future enhancement (passing the dedup threshold value into the companion request), not a gap in this plan's tasks. ✓

**Type consistency:** `CapturePayload`/`Settings`/`ConnectionStatus`/`TriggerType` (Task 2) used in Tasks 3,5,7,8. `CompanionClient.postCapture/createCase/ping` (Task 3) called in Tasks 5,7,8. `CaptureQueue.enqueue/size/drain/clear` (Task 4) used in Tasks 5,7. `CaptureController.capture(caseId, trigger, snapshot)` (Task 5) called in Task 7 with a matching `TabSnapshot`. The extension's `CapturePayload` matches the companion's `IngestPayload` (Plan 1 Task 2) field-for-field (caseId, timestamp, url, tabTitle, triggerType, imageBase64). ✓
