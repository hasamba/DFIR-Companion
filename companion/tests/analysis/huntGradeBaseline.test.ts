import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gradeBaseline, mergeGrades, policySeverityFromEnv } from "../../src/analysis/huntGradeBaseline.js";
import { huntSettle, type HuntSettleDeps } from "../../src/analysis/huntSettle.js";
import { HuntInventoryStore } from "../../src/analysis/huntInventoryStore.js";
import { regradeHuntCase } from "../../src/analysis/huntRegrade.js";
import { huntFieldsOf } from "../../src/analysis/huntArtifactFields.js";
import { EMPTY_INVENTORY, recordObservations } from "../../src/analysis/huntInventory.js";
import {
  applyDomains,
  applyMarks,
  domainsInputSchema,
  markInputSchema,
  newProfile,
  type ClientProfile,
} from "../../src/analysis/clientProfile.js";
import { getBuiltInIncidentType } from "../../src/analysis/incidentTypesData.js";
import { baselineGradesProvider } from "../../src/composition/huntBaselineGrades.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { memoryHuntStore, prefetchRow, reachedJob } from "../helpers/huntFakes.js";

const H = "d".repeat(64);
const NOW = "2026-06-01T00:00:00.000Z";
const CATS = { version: "test-1", categories: { torrent: ["torrents.example"] } };

const download = (id: string, i: number, file: string, url?: string): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: `Velociraptor: Downloaded ${file} from ${url ?? "the Internet zone"} - @ WS-${String(i).padStart(3, "0")}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: `WS-${String(i).padStart(3, "0")}`,
  path: `C:\\Users\\u\\Downloads\\${file}`,
});

const inventoryOf = (rows: ForensicEvent[]) =>
  recordObservations(
    EMPTY_INVENTORY,
    rows.map((e) => ({
      fields: huntFieldsOf(e)!,
      host: { key: `srv/C.${Number(e.asset!.slice(3))}`, basis: "client" as const, hostname: e.asset! },
      at: e.timestamp,
    })),
    "now",
  );

const answered = (n: number) => new Set(Array.from({ length: n }, (_, i) => `srv/C.${i}`));

const profileWith = (
  marks: Parameters<typeof markInputSchema.parse>[0][],
  domains?: object,
): ClientProfile => {
  let p = newProfile({ name: "Client A" }, "admin", "2026-01-01T00:00:00Z");
  if (marks.length)
    p = applyMarks(
      p,
      marks.map((m) => markInputSchema.parse(m)),
      { by: "admin", at: "t", source: "client email" },
    );
  if (domains)
    p = applyDomains(p, domainsInputSchema.parse(domains), { by: "admin", at: "t", source: "client email" });
  return p;
};

const ctx = (
  rows: ForensicEvent[],
  p: ClientProfile | null,
  extra: Partial<Parameters<typeof gradeBaseline>[0]> = {},
) => ({
  inventory: inventoryOf(rows),
  answered: answered(300),
  baseline: p?.baseline ?? null,
  baselineVersion: p?.version,
  previous: null,
  categories: CATS,
  policySeverity: "Medium" as const,
  now: NOW,
  ...extra,
});

describe("baseline and policy grading (#2670)", () => {
  it("a Not-allowed program becomes a POLICY finding, labelled policy", () => {
    const p = profileWith([{ verdict: "not-allowed", family: "program", program: "utorrent.exe" }]);
    const { grades } = gradeBaseline(ctx([prefetchRow("a", 1, "utorrent.exe", "C:\\Users\\u\\AppData")], p));
    expect(grades).toEqual([expect.objectContaining({ kind: "policy", severity: "Medium" })]);
    expect(grades[0].reason).toMatch(
      /not allowed by the client \(baseline v1\)\. A policy violation, not proof/,
    );
  });

  it("Not allowed wins over Approved", () => {
    const p = profileWith([
      { verdict: "approved", family: "program", program: "x.exe", pathPattern: "\\tools", sha256: [H] },
      { verdict: "not-allowed", family: "program", program: "x.exe" },
    ]);
    const r = gradeBaseline(ctx([prefetchRow("a", 1, "x.exe")], p));
    expect(r.grades[0].kind).toBe("policy");
    expect(r.approved).toEqual([]);
  });

  it("an approved item loses its rare / new bump but keeps a policy entry's place", () => {
    const merged = mergeGrades(
      [
        { itemKey: "k", kind: "rare", severity: "Medium", label: "", reason: "", hosts: [], firstSeen: "" },
        { itemKey: "k2", kind: "rare", severity: "Medium", label: "", reason: "", hosts: [], firstSeen: "" },
        { itemKey: "k2", kind: "policy", severity: "High", label: "", reason: "", hosts: [], firstSeen: "" },
      ],
      new Set(["k"]),
    );
    expect(merged.map((g) => `${g.itemKey}:${g.kind}`)).toEqual(["k2:policy"]);
  });

  it("new since the last comparable hunt only on hosts both hunts covered — absence is never assumed", () => {
    const rows = [prefetchRow("a", 1, "anydesk.exe"), prefetchRow("b", 250, "teamviewer.exe")];
    const previous = {
      caseId: "prev",
      at: "2026-01-01T00:00:00Z",
      itemKeys: new Set<string>(),
      answered: answered(200),
    };
    const { grades } = gradeBaseline(ctx(rows, null, { previous }));
    expect(grades.map((g) => g.label)).toEqual(["anydesk.exe in \\tools"]); // WS-250 was not covered before
  });

  it("no comparable hunt → nothing is called new (a first hunt)", () => {
    expect(gradeBaseline(ctx([prefetchRow("a", 1, "x.exe")], null)).grades).toEqual([]);
  });

  it("downloads: a blocked site blocks its subdomains, never a look-alike", () => {
    const p = profileWith([], { blockedDomains: ["example.test"] });
    const g = (url: string) => gradeBaseline(ctx([download("d", 1, "setup.exe", url)], p)).grades;
    expect(g("https://dl.example.test/setup.exe")[0]).toMatchObject({ kind: "policy" });
    expect(g("https://notexample.test/setup.exe")[0]).toMatchObject({ kind: "download" });
  });

  it("downloads: a blocked category is a policy finding; an approved source is nothing", () => {
    const p = profileWith([], { blockedCategories: ["torrent"], approvedDomains: ["vendor.example"] });
    expect(
      gradeBaseline(ctx([download("d", 1, "movie.zip", "https://www.torrents.example/m.zip")], p)).grades[0]
        .reason,
    ).toMatch(/blocked category torrent \(category list test-1\)/);
    expect(
      gradeBaseline(ctx([download("d", 1, "tool.exe", "https://cdn.vendor.example/tool.exe")], p)).grades,
    ).toEqual([]);
  });

  it("downloads: no source URL is Unknown, and a runnable file is still flagged; a document is not", () => {
    const g = gradeBaseline(
      ctx([download("d", 1, "run.exe"), download("e", 2, "notes.pdf")], profileWith([])),
    ).grades;
    expect(g).toHaveLength(1);
    expect(g[0].reason).toMatch(/no source URL recorded \(Unknown\)/);
  });

  it("reads DFIR_HUNT_POLICY_SEVERITY and never allows Info", () => {
    expect(policySeverityFromEnv({ DFIR_HUNT_POLICY_SEVERITY: "high" })).toBe("High");
    expect(policySeverityFromEnv({ DFIR_HUNT_POLICY_SEVERITY: "Info" })).toBe("Medium");
  });
});

// ── end to end through the seam's grader, the pinned baseline and the re-grade ───────────────────

async function world(profile: { current: ClientProfile }, jobs: VeloHuntJob[], rows: ForensicEvent[] = []) {
  const dir = await mkdtemp(join(tmpdir(), "dfir-hunt-base-"));
  const stateStore = memoryHuntStore(rows);
  const inventoryStore = new HuntInventoryStore({ stateDir: () => dir });
  const deps: HuntSettleDeps = {
    stateStore,
    inventoryStore,
    incidentTypeStore: { loadType: async () => getBuiltInIncidentType("threat-hunt") ?? null },
    veloHuntStore: { list: async () => jobs },
    serverSetId: () => "srv",
    env: {},
    extraGrades: baselineGradesProvider({
      links: { load: async () => ({ clientId: profile.current.id, linkedAt: "", linkedBy: "" }) },
      profiles: { get: async () => profile.current },
      inventories: inventoryStore,
      huntJobs: async () => jobs,
      peerCaseIds: async () => [],
      serverSetId: () => "srv",
      env: {},
    }),
  };
  return { deps, stateStore, inventoryStore };
}

const entries = (s: ReturnType<typeof memoryHuntStore>) =>
  s.events().filter((e) => e.id.startsWith("hunt-item:"));

describe("pinned baselines and the explicit re-grade (#2670)", () => {
  it("a baseline change leaves the pinned case unchanged; the re-grade applies it and says so", async () => {
    const holder = { current: profileWith([]) };
    const rows = [prefetchRow("a", 1, "utorrent.exe")];
    const { deps, stateStore, inventoryStore } = await world(holder, [reachedJob(10)]);
    await huntSettle(deps, "c1", rows);
    expect(entries(stateStore)).toEqual([]);
    expect((await inventoryStore.load("c1")).baselineVersion).toBe(0);

    holder.current = applyMarks(
      holder.current,
      [markInputSchema.parse({ verdict: "not-allowed", family: "program", program: "utorrent.exe" })],
      {
        by: "admin",
        at: "t",
        source: "client email",
      },
    );
    await huntSettle(deps, "c1", [prefetchRow("b", 2, "other.exe")]); // a later import: still pinned to v0
    expect(entries(stateStore)).toEqual([]);

    const r = await regradeHuntCase(
      {
        ...deps,
        rows: {
          async *forensicTimelineBatches() {
            yield rows;
          },
        },
      },
      "c1",
    );
    expect(r.baselineVersion).toBe(1);
    expect(entries(stateStore).map((e) => e.description)).toEqual([
      expect.stringMatching(/^Hunt \(policy violation\): utorrent\.exe/),
    ]);
  });

  it("approval never lowers a detection grade: the imported High row stands", async () => {
    const holder = {
      current: profileWith([
        {
          verdict: "approved",
          family: "program",
          program: "rclone.exe",
          pathPattern: "\\tools",
          sha256: [H],
        },
      ]),
    };
    const det = { ...prefetchRow("det", 1, "rclone.exe"), severity: "High" as const, sha256: H };
    const { deps, stateStore } = await world(holder, [reachedJob(300)], [det]);
    await huntSettle(deps, "c1", [det]);
    expect(stateStore.events().find((e) => e.id === "det")?.severity).toBe("High");
    expect(entries(stateStore)).toEqual([]); // rare bump removed by the approval
  });

  it("the re-grade reads demoted rows from the raw record and discloses evicted observations", async () => {
    const holder = { current: profileWith([]) };
    const { deps, inventoryStore } = await world(holder, [reachedJob(10)]);
    await huntSettle(deps, "c1", [prefetchRow("gone", 3, "old.exe")]);
    const raw = [prefetchRow("raw1", 4, "late.exe")];
    const r = await regradeHuntCase(
      {
        ...deps,
        rows: { async *forensicTimelineBatches() {} },
        raw: {
          async *eventBatches() {
            yield raw;
          },
        },
      },
      "c1",
    );
    expect(r.rowsRead).toBe(1);
    expect(r.evicted).toBe(1); // old.exe on WS-003 is in the inventory but in neither record now
    const inv = (await inventoryStore.load("c1")).inventory;
    expect(
      Object.values(inv.items)
        .map((i) => i.program)
        .sort(),
    ).toEqual(["late.exe", "old.exe"]);
  });
});

describe("an unconfirmed item never goes quiet (#2670)", () => {
  it("stays on the pending list with its age after it stops being new", async () => {
    const { huntPendingSource } = await import("../../src/composition/huntBaselineGrades.js");
    const p = profileWith([]);
    const inv = (rows: ForensicEvent[]) => ({
      inventory: inventoryOf(rows),
      entryIds: [],
      grades: [],
      approvedLabels: [],
      gradedSignature: "",
    });
    const stores: Record<string, ReturnType<typeof inv>> = {
      prev: inv([{ ...prefetchRow("a", 1, "7z.exe"), timestamp: "2025-12-01T00:00:00Z" }]),
      c1: inv([prefetchRow("b", 1, "7z.exe")]),
    };
    const pending = await huntPendingSource({
      links: { load: async () => ({ clientId: p.id, linkedAt: "", linkedBy: "" }) },
      profiles: { get: async () => p },
      inventories: { load: async (id) => stores[id] },
      huntJobs: async () => [],
      peerCaseIds: async () => ["prev"],
      serverSetId: () => "srv",
    })("c1");
    expect(pending).toEqual([
      { label: "7z.exe in \\tools", hostCount: 1, firstSeen: "2025-12-01", huntsUnconfirmed: 2 },
    ]);
  });
});
