import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
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

describe("StateStore save format", () => {
  it("writes compact JSON (no pretty-print indentation)", async () => {
    const state = emptyState("c1");
    state.lastSummary = "x";
    await stateStore.save(state);

    const raw = await readFile(join(caseStore.stateDir("c1"), "investigation.json"), "utf8");
    // Compact JSON is a single line with no indentation — this is what keeps the serialize
    // cost and the ~512 MB unloadable ceiling in check on very large cases.
    expect(raw).not.toContain("\n");
    expect(raw).not.toContain('": ');
    expect(JSON.parse(raw).lastSummary).toBe("x");
  });
});

describe("StateStore load on an oversized state file", () => {
  // Node throws ERR_STRING_TOO_LONG from readFile, and V8 can throw a bare RangeError
  // ("Invalid string length") from the string machinery — both mean the same thing here.
  const oversize = [
    "Cannot create a string longer than 0x1fffffe8 characters",
    "Invalid string length",
  ];

  for (const message of oversize) {
    it(`reports an actionable error for: ${message}`, async () => {
      const store = new StateStore(caseStore, undefined, {
        readFile: async () => {
          throw new RangeError(message);
        },
      });

      await expect(store.load("c1")).rejects.toThrow(/too large to load/i);
      await expect(store.load("c1")).rejects.toThrow(/512 MB/);
      // Names the case and points at a recovery path rather than failing opaquely.
      await expect(store.load("c1")).rejects.toThrow(/c1/);
      await expect(store.load("c1")).rejects.toThrow(/backup/i);
    });
  }

  it("still returns empty state for a missing file", async () => {
    const enoent = Object.assign(new Error("nope"), { code: "ENOENT" });
    const store = new StateStore(caseStore, undefined, {
      readFile: async () => {
        throw enoent;
      },
    });

    const state = await store.load("c1");
    expect(state.caseId).toBe("c1");
    expect(state.findings).toEqual([]);
  });

  it("rethrows unrelated errors unchanged", async () => {
    const store = new StateStore(caseStore, undefined, {
      readFile: async () => {
        throw Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
      },
    });

    await expect(store.load("c1")).rejects.toThrow("EACCES: permission denied");
  });

  it("does not mistake a malformed-JSON error for an oversize file", async () => {
    const store = new StateStore(caseStore, undefined, {
      readFile: async () => "{ not json",
    });

    await expect(store.load("c1")).rejects.toThrow(/JSON/i);
    await expect(store.load("c1")).rejects.not.toThrow(/too large to load/i);
  });
});
