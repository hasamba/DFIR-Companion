import { describe, expect, it } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { deltaSchema, stripAiExtractedFrom } from "../../src/analysis/responseSchema.js";
import { upsertForensicEvents } from "../../src/analysis/stateMerge.js";
import { mergeFileIdentity } from "../../src/analysis/fileIdentity.js";
import { huntFieldsOf } from "../../src/analysis/huntArtifactFields.js";
import { itemVerdict } from "../../src/analysis/huntApprovalMatch.js";
import { EMPTY_INVENTORY, recordObservations } from "../../src/analysis/huntInventory.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyMarks, markInputSchema, newProfile } from "../../src/analysis/clientProfile.js";
import { HuntInventoryStore } from "../../src/analysis/huntInventoryStore.js";
import { huntSettle, type HuntSettleDeps } from "../../src/analysis/huntSettle.js";
import { getBuiltInIncidentType } from "../../src/analysis/incidentTypesData.js";
import { baselineGradesProvider } from "../../src/composition/huntBaselineGrades.js";
import { memoryHuntStore, reachedJob } from "../helpers/huntFakes.js";

// The Amcache SHA1 + size and the Autoruns signer (#2731) must survive every hop from the importer to
// the timeline row hunt grading reads — and a model must never be able to assert them.
const SHA1 = "c".repeat(40);

const amcacheRow = (host: string, extra: Record<string, unknown> = {}) => ({
  _Source: "Windows.Forensics.Amcache/InventoryApplicationFile",
  Fqdn: host,
  Timestamp: "2026-01-01T00:00:00Z",
  Name: "rclone.exe",
  FullPath: "c:\\tools\\rclone.exe",
  OriginalFileName: "rclone.exe",
  BinaryType: "pe64_amd64",
  SHA1: SHA1,
  Size: 1048576,
  ...extra,
});

// The empty AI delta every importer fills (endpointImports.ts builds the same shape).
const EMPTY_DELTA = {
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "",
};

const parse = (rows: object[]) => parseVelociraptorJson(JSON.stringify(rows), { aggregate: true }).events;

describe("file identity carry-through (#2731)", () => {
  it("the Amcache file mapper records the SHA1 with its size", () => {
    expect(parse([amcacheRow("WS-01")])[0].fileIdentity).toEqual({ sha1: SHA1, size: 1048576 });
    expect(parse([amcacheRow("WS-01", { Size: "0x100000" })])[0].fileIdentity).toEqual({
      sha1: SHA1,
      size: 1048576,
    });
    expect(parse([amcacheRow("WS-01", { Size: "" })])[0].fileIdentity).toEqual({ sha1: SHA1 });
  });

  it("the Amcache SHA1 reaches the hunt fields only within the 30 MiB limit", () => {
    const ev = (extra: Record<string, unknown>): ForensicEvent => ({
      relatedFindingIds: [],
      sourceScreenshots: [],
      ...parse([amcacheRow("WS-01", extra)])[0],
    });
    expect(huntFieldsOf(ev({}))).toMatchObject({ sha1: SHA1 });
    expect(huntFieldsOf(ev({ Size: 31_457_281 }))).toMatchObject({ sha1Unusable: "over-limit" });
    expect(huntFieldsOf(ev({ Size: 31_457_281 }))?.sha1).toBeUndefined();
    expect(huntFieldsOf(ev({ Size: "" }))).toMatchObject({ sha1Unusable: "no-size" });
  });

  it("two folded rows that disagree on the hash keep none of it, and record the conflict", () => {
    const [e] = parse([amcacheRow("WS-01"), amcacheRow("WS-01", { SHA1: "d".repeat(40) })]);
    expect(e.count).toBe(2);
    expect(e.fileIdentity).toEqual({ conflict: true });
    expect(mergeFileIdentity({ signer: "A" }, { signatureUnverified: true })).toEqual({
      conflict: true,
      signatureUnverified: true,
    });
  });

  it("a conflict stays sticky through later agreeing rows", () => {
    const a = { sha1: SHA1, size: 1 };
    const b = { sha1: "d".repeat(40), size: 1 };
    expect(mergeFileIdentity(mergeFileIdentity(a, b), a)).toEqual({ conflict: true });
    expect(mergeFileIdentity(a, mergeFileIdentity(b, a))).toEqual({ conflict: true });
  });

  // Importer → hunt fields → inventory → approval verdict (Codex review of the batch PR).
  const verdictAfter = (rows: object[]) => {
    const events = parse(rows);
    const inv = recordObservations(
      EMPTY_INVENTORY,
      events.map((e) => ({
        fields: huntFieldsOf(e)!,
        host: { key: `srv/${e.asset}`, basis: "client" as const, hostname: e.asset! },
        at: e.timestamp,
      })),
      "now",
    );
    const baseline = applyMarks(
      newProfile({ name: "Client A" }, "admin", "2026-01-01T00:00:00Z"),
      [
        markInputSchema.parse({
          verdict: "approved",
          family: "program",
          program: "rclone.exe",
          pathPattern: "\\tools",
          sha1: [SHA1],
        }),
      ],
      { by: "admin", at: "t", source: "client email" },
    ).baseline;
    const items = Object.values(inv.items);
    expect(items).toHaveLength(1);
    return itemVerdict(baseline, items[0], "2026-06-01T00:00:00.000Z");
  };

  it("approved / unapproved / approved hashes on one host never approve the item", () => {
    const v = verdictAfter([
      amcacheRow("WS-01"),
      amcacheRow("WS-01", { SHA1: "d".repeat(40) }),
      amcacheRow("WS-01"),
    ]);
    expect(v.verdict).toBe("unknown");
    expect(v.reason).toMatch(/disagree/);
  });

  it("small / over-limit / small sizes on one host never approve the item", () => {
    const v = verdictAfter([
      amcacheRow("WS-01"),
      amcacheRow("WS-01", { Size: 31_457_281 }),
      amcacheRow("WS-01"),
    ]);
    expect(v.verdict).toBe("unknown");
  });

  it("agreeing rows still approve", () => {
    expect(verdictAfter([amcacheRow("WS-01"), amcacheRow("WS-01")]).verdict).toBe("approved");
  });

  it("the delta schema keeps it, the merge writes it, and a model delta loses it", () => {
    const [e] = parse([amcacheRow("WS-01")]);
    const delta = deltaSchema.parse({ ...EMPTY_DELTA, forensicEvents: [{ ...e, id: "v1" }] });
    expect(delta.forensicEvents?.[0].fileIdentity).toEqual({ sha1: SHA1, size: 1048576 });
    const timeline: ForensicEvent[] = [];
    upsertForensicEvents(timeline, delta, { sourceScreenshots: ["x"], timestamp: "t" });
    expect(timeline[0].fileIdentity).toEqual({ sha1: SHA1, size: 1048576 });
    expect(stripAiExtractedFrom(delta).forensicEvents?.[0].fileIdentity).toBeUndefined();
  });

  it("a malformed identity is dropped at the schema, never trusted", () => {
    const delta = deltaSchema.parse({
      ...EMPTY_DELTA,
      forensicEvents: [
        {
          id: "v1",
          timestamp: "2026-01-01T00:00:00Z",
          description: "x",
          fileIdentity: { sha1: "not-hex", size: -1, signer: "" },
        },
      ],
    });
    expect(delta.forensicEvents?.[0].fileIdentity).toEqual({});
  });

  // End to end: importer → delta schema → merge → hunt settle with a SHA1-approved baseline.
  async function approvedLabelsAfterImport(size: number): Promise<string[]> {
    const parsed = parse([amcacheRow("WS-001", { Size: size }), amcacheRow("WS-002", { Size: size })]);
    const delta = deltaSchema.parse({
      ...EMPTY_DELTA,
      forensicEvents: parsed.map((e, i) => ({ ...e, id: `v${i}` })),
    });
    const rows: ForensicEvent[] = [];
    upsertForensicEvents(rows, delta, { sourceScreenshots: ["x"], timestamp: "t" });
    const profile = applyMarks(
      newProfile({ name: "Client A" }, "admin", "2026-01-01T00:00:00Z"),
      [
        markInputSchema.parse({
          verdict: "approved",
          family: "program",
          program: "rclone.exe",
          pathPattern: "\\tools",
          sha1: [SHA1],
        }),
      ],
      { by: "admin", at: "t", source: "client email" },
    );
    const dir = await mkdtemp(join(tmpdir(), "dfir-hunt-sha1-"));
    const stateStore = memoryHuntStore(rows);
    const inventoryStore = new HuntInventoryStore({ stateDir: () => dir });
    const jobs = [reachedJob(300)];
    const deps: HuntSettleDeps = {
      stateStore,
      inventoryStore,
      incidentTypeStore: { loadType: async () => getBuiltInIncidentType("threat-hunt") ?? null },
      veloHuntStore: { list: async () => jobs },
      serverSetId: () => "srv",
      env: {},
      extraGrades: baselineGradesProvider({
        links: { load: async () => ({ clientId: profile.id, linkedAt: "", linkedBy: "" }) },
        profiles: { get: async () => profile },
        inventories: inventoryStore,
        huntJobs: async () => jobs,
        peerCaseIds: async () => [],
        serverSetId: () => "srv",
        env: {},
      }),
    };
    await huntSettle(deps, "c1", rows);
    return (await inventoryStore.load("c1")).approvedLabels;
  }

  it("an imported Amcache SHA1 within 30 MiB is approved by hunt settle; a larger file is not", async () => {
    expect(await approvedLabelsAfterImport(1048576)).toEqual([expect.stringContaining("rclone.exe")]);
    expect(await approvedLabelsAfterImport(31_457_281)).toEqual([]);
  });
});
