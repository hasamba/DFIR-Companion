import { describe, it, expect, beforeEach } from "vitest";
import { access, mkdtemp, readFile, writeFile } from "node:fs/promises";
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

  it("migrates every complete entity payload from JSON with deep equality", async () => {
    const state = emptyState("c1");
    state.updatedAt = "2026-07-30T12:00:00.000Z";
    state.lastSummary = "complete";
    state.findings = [{
      id: "f1", severity: "High", confidence: 87, confidenceReason: "two tools",
      title: "PowerShell", description: "Encoded command", relatedIocs: ["i1"],
      sourceScreenshots: ["one.png"], mitreTechniques: ["T1059.001"], relatedEventIds: ["e1"],
      firstSeen: "2026-07-30T10:00:00Z", lastUpdated: "2026-07-30T11:00:00Z", status: "dismissed",
      corroboration: { distinctTools: 2, distinctHosts: 1, intelSources: 1, graphLinked: true, verdictFirst: true },
    }];
    state.iocs = [{
      id: "i1", type: "domain", value: "example.invalid", firstSeen: "2026-07-30T10:00:00Z",
      aliasValues: ["www.example.invalid"], extractedFrom: ["e1"], note: "sinkholed",
      enrichments: [{ source: "test", verdict: "suspicious", fetchedAt: "2026-07-30T11:00:00Z", tags: ["c2"] }],
    }];
    state.forensicTimeline = [{
      id: "e1", timestamp: "2026-07-30T10:00:00Z", endTimestamp: "2026-07-30T10:01:00Z",
      description: "PowerShell connected", message: "full event message", severity: "High",
      mitreTechniques: ["T1059.001"], relatedFindingIds: ["f1"], sourceScreenshots: ["one.png"],
      asset: "HOST-1", sources: ["EDR"], artifactName: "Windows.Events", processName: "powershell.exe",
      parentName: "winword.exe", pid: 42, commandLine: "powershell -enc AAAA", dstIp: "192.0.2.1",
      port: 443, provenance: ["second-look"],
    }];
    state.openThreads = [{ id: "t1", description: "scope", status: "closed", openedAt: "a", closedAt: "b" }];
    state.timeline = [{ timestamp: "2026-07-30T10:00:00Z", windowSequence: 1, description: "reviewed", sourceScreenshots: ["one.png"] }];
    state.mitreTechniques = [{ id: "T1059.001", name: "PowerShell", findingIds: ["f1"] }];
    state.keyQuestions = [{ id: "q1", question: "How?", status: "partial", answer: "PowerShell", pointer: "e1", pinned: true }];
    state.nextSteps = [{ id: "n1", priority: "high", action: "Collect", rationale: "Confirm", pointer: "HOST-1", collect: { host: "HOST-1" } }];
    state.uncertainties = [{ topic: "entry", status: "inferred", basis: "e1", gap: "email" }];
    state.iocExcludeRules = [{ id: "x1", type: "domain", pattern: "*.example.org", addedAt: "2026-07-30T12:00:00Z" } as never];

    const legacyPath = join(caseStore.stateDir("c1"), "investigation.json");
    const original = JSON.stringify(state);
    await writeFile(legacyPath, original);

    expect(await stateStore.load("c1")).toEqual(state);
    expect(await readFile(legacyPath, "utf8")).toBe(original);
    await access(join(caseStore.stateDir("c1"), "investigation.sqlite"));
  });

  it("persists entity deletion, IOC merging, and finding dismissal across reload", async () => {
    const first = emptyState("c1");
    first.findings = [
      { id: "f1", severity: "High", title: "one", description: "one", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "a", lastUpdated: "a", status: "open" },
      { id: "f2", severity: "Low", title: "two", description: "two", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "b", lastUpdated: "b", status: "open" },
    ];
    first.iocs = [
      { id: "i1", type: "domain", value: "example.invalid", firstSeen: "a" },
      { id: "i2", type: "domain", value: "www.example.invalid", firstSeen: "b" },
    ];
    await stateStore.save(first);

    const next = {
      ...first,
      findings: [{ ...first.findings[0], status: "dismissed" as const }],
      iocs: [{ ...first.iocs[0], aliasValues: [first.iocs[1].value] }],
    };
    await stateStore.save(next);

    expect(await new StateStore(caseStore).load("c1")).toEqual(next);
  });

  it("queries indexed event fields with a stable cursor", async () => {
    const state = emptyState("c1");
    state.forensicTimeline = [
      {
        id: "e1", timestamp: "2026-07-30T10:00:00Z", description: "one", severity: "High",
        mitreTechniques: ["T1059.001"], relatedFindingIds: [], sourceScreenshots: [],
        asset: "HOST-1", artifactName: "Windows.Events", dstIp: "192.0.2.10",
      },
      {
        id: "e2", timestamp: "2026-07-30T11:00:00Z", description: "two", severity: "Low",
        mitreTechniques: ["T1078"], relatedFindingIds: [], sourceScreenshots: [],
        asset: "HOST-2", artifactName: "EDR.Processes",
      },
    ];
    await stateStore.save(state);

    expect((await stateStore.queryForensicTimeline("c1", { host: "HOST-1" })).entities.map((event) => event.id)).toEqual(["e1"]);
    expect((await stateStore.queryForensicTimeline("c1", { source: "EDR.Processes" })).entities.map((event) => event.id)).toEqual(["e2"]);
    expect((await stateStore.queryForensicTimeline("c1", { severity: "High" })).entities.map((event) => event.id)).toEqual(["e1"]);
    expect((await stateStore.queryForensicTimeline("c1", { technique: "T1059.001" })).entities.map((event) => event.id)).toEqual(["e1"]);
    expect((await stateStore.queryForensicTimeline("c1", { ioc: "192.0.2.10" })).entities.map((event) => event.id)).toEqual(["e1"]);

    const first = await stateStore.queryForensicTimeline("c1", { limit: 1 });
    const second = await stateStore.queryForensicTimeline("c1", { cursor: first.nextCursor ?? undefined, limit: 1 });
    expect(first.total).toBe(2);
    expect(second.total).toBe(2);
    expect([...first.entities, ...second.entities].map((event) => event.id)).toEqual(["e1", "e2"]);
  });

  it("keeps the main event loop responsive during a large save", async () => {
    const state = emptyState("c1");
    state.forensicTimeline = Array.from({ length: 5_000 }, (_, index) => ({
      id: `e${index}`,
      timestamp: new Date(Date.UTC(2026, 0, 1) + index * 1000).toISOString(),
      description: `event ${index}`,
      severity: "Info" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    }));
    let heartbeats = 0;
    const timer = setInterval(() => heartbeats++, 1);
    try {
      await stateStore.save(state);
    } finally {
      clearInterval(timer);
    }
    expect(heartbeats).toBeGreaterThan(0);
  });
});

describe("StateStore save format", () => {
  it("writes SQLite as the primary state and does not create a JSON mirror", async () => {
    const state = emptyState("c1");
    state.lastSummary = "x";
    await stateStore.save(state);

    const raw = await readFile(join(caseStore.stateDir("c1"), "investigation.sqlite"));
    expect(raw.subarray(0, 16).toString("utf8")).toBe("SQLite format 3\u0000");
    await expect(access(join(caseStore.stateDir("c1"), "investigation.json"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await stateStore.integrityCheck("c1")).ok).toBe(true);
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

  it("leaves malformed legacy JSON untouched and can migrate after it is repaired", async () => {
    const path = join(caseStore.stateDir("c1"), "investigation.json");
    await writeFile(path, "{ interrupted");
    await expect(stateStore.load("c1")).rejects.toThrow(/JSON/i);
    expect(await readFile(path, "utf8")).toBe("{ interrupted");
    await expect(access(join(caseStore.stateDir("c1"), "investigation.sqlite"))).rejects.toMatchObject({ code: "ENOENT" });

    const repaired = { ...emptyState("c1"), lastSummary: "recovered" };
    await writeFile(path, JSON.stringify(repaired));
    expect((await stateStore.load("c1")).lastSummary).toBe("recovered");
  });
});
