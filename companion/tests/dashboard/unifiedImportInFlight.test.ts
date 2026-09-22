import { beforeEach, describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1511: one import run at a time. askMinSeverity / askImportAssetHost are promise-per-prompt on a
// single shared overlay each, so a second run opened while the first waits on a prompt overwrites
// the handlers and orphans the first promise. The overlays stop a click, but Shift+Tab + Enter
// reaches #importBtn behind the modal. The guard belongs on the loop, not the prompts: two batches
// must never run concurrently, prompt or no prompt.

interface UnifiedImportApi {
  initUnifiedImport: () => void;
}

interface FakeInput {
  files: Array<{ name: string; type: string; size: number }>;
  value: string;
  onchange: ((e: { target: FakeInput }) => Promise<void>) | null;
  click: ReturnType<typeof vi.fn>;
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (v: T) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

/** Drain the microtask queue and one macrotask tick, so an awaiting handler reaches its park point. */
const settle = () => new Promise<void>((r) => setTimeout(r, 0));

const BUSY = "an import is already running — wait for it to finish";
const csv = (name: string) => ({ name, type: "text/csv", size: 10 });

function harness(overrides: Record<string, unknown> = {}) {
  const status = { textContent: "" };
  const caseId = { value: "c1" };
  const importFile: FakeInput = { files: [], value: "", onchange: null, click: vi.fn() };
  const importBtn: { onclick: (() => void) | null } = { onclick: null };
  const els: Record<string, unknown> = { status, caseId, importFile, importBtn };
  const prompts: Array<Deferred<string | null>> = [];
  const askMinSeverity = vi.fn(() => {
    const d = deferred<string | null>();
    prompts.push(d);
    return d.promise;
  });
  const fetch = vi.fn(async () => ({
    status: 202,
    ok: true,
    json: async () => ({ kind: "csv" }),
  }));
  const api = loadDashboardModule<UnifiedImportApi>("dashboard-unified-import.js", [], {
    document: { getElementById: (id: string) => els[id] ?? null },
    importPermissionMessage: () => "",
    cancelImportProgress: () => {},
    hideImportProgress: () => {},
    showImportProgress: () => {},
    showImportProgressIndeterminate: () => {},
    fetchRawToolExts: async () => new Set<string>(),
    uploadExtOf: (n: string) => n.replace(/^.*\./, "").toLowerCase(),
    askRunToolsOnImport: () => {},
    undecodedBinaryImportHint: () => "",
    looksLikeBinaryImportName: () => false,
    readFileTextWithProgress: async () => "a,b\n1,2\n",
    fileToBase64: async () => "",
    askMinSeverity,
    fetch,
    ...overrides,
  });
  api.initUnifiedImport();
  const pick = (files: Array<{ name: string; type: string; size: number }>) => {
    importFile.files = files;
    importFile.value = "C:\\fakepath\\" + files[0].name;
    return importFile.onchange!({ target: importFile });
  };
  return { status, importFile, importBtn, prompts, askMinSeverity, fetch, pick };
}

describe("unified import: one run at a time (#1511)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("refuses a second file pick while the first run waits on the severity prompt", async () => {
    const h = harness();
    const first = h.pick([csv("one.csv")]);
    await settle();
    expect(h.askMinSeverity).toHaveBeenCalledTimes(1);
    expect(h.prompts).toHaveLength(1);

    // Second pick while the first is parked on the prompt: returns at once, says so, resets the input.
    h.status.textContent = "";
    await h.pick([csv("two.csv")]);
    expect(h.status.textContent).toBe(BUSY);
    expect(h.importFile.value).toBe("");
    expect(h.askMinSeverity).toHaveBeenCalledTimes(1);
    expect(h.fetch).not.toHaveBeenCalled();

    // The first run is still alive: answering its prompt finishes it, with its own file only.
    h.prompts[0].resolve("info");
    await first;
    expect(h.fetch).toHaveBeenCalledTimes(1);
    expect(h.status.textContent).toMatch(/imported csv/);

    // Flag cleared: a third pick proceeds to the prompt again.
    const third = h.pick([csv("three.csv")]);
    await settle();
    expect(h.askMinSeverity).toHaveBeenCalledTimes(2);
    h.prompts[1].resolve("info");
    await third;
    expect(h.fetch).toHaveBeenCalledTimes(2);
  });

  it("the import button does not open the picker while a run is in flight", async () => {
    const h = harness();
    const first = h.pick([csv("one.csv")]);
    await settle();
    h.status.textContent = "";
    h.importBtn.onclick!();
    expect(h.importFile.click).not.toHaveBeenCalled();
    expect(h.status.textContent).toBe(BUSY);

    h.prompts[0].resolve("info");
    await first;
    h.importBtn.onclick!();
    expect(h.importFile.click).toHaveBeenCalledTimes(1);
  });

  it("a cancelled prompt clears the flag", async () => {
    const h = harness();
    const first = h.pick([csv("one.csv")]);
    await settle();
    h.prompts[0].resolve(null);
    await first;
    expect(h.fetch).not.toHaveBeenCalled();
    h.status.textContent = "";
    h.importBtn.onclick!();
    expect(h.importFile.click).toHaveBeenCalledTimes(1);
    expect(h.status.textContent).toBe("");
  });

  it("an early refusal (permission) clears the flag", async () => {
    const h = harness({ importPermissionMessage: () => "no permission" });
    await h.pick([csv("one.csv")]);
    expect(h.status.textContent).toBe("no permission");
    // The button's own permission check answers first, so read the flag through the input instead.
    h.status.textContent = "";
    await h.pick([csv("two.csv")]);
    expect(h.status.textContent).toBe("no permission");
  });

  it("a thrown error clears the flag", async () => {
    const h = harness({
      fetchRawToolExts: async () => {
        throw new Error("tools/status down");
      },
    });
    await expect(h.pick([csv("one.csv")])).rejects.toThrow(/tools\/status down/);
    h.status.textContent = "";
    h.importBtn.onclick!();
    expect(h.importFile.click).toHaveBeenCalledTimes(1);
    expect(h.status.textContent).toBe("");
  });
});
