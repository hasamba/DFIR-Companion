import { describe, it, expect, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { huntSettle, type HuntSettleDeps } from "../../src/analysis/huntSettle.js";
import { HuntInventoryStore } from "../../src/analysis/huntInventoryStore.js";
import { HUNT_ENTRY_CAP, huntOverflowId } from "../../src/analysis/huntEntries.js";
import { getBuiltInIncidentType } from "../../src/analysis/incidentTypesData.js";
import { registerHuntSettle } from "../../src/analysis/huntSettleHook.js";
import { settleForensicImport } from "../../src/routes/importSettle.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { memoryHuntStore, prefetchRow, reachedJob } from "../helpers/huntFakes.js";
import { memoryRowStore } from "../helpers/memoryRowStore.js";

async function deps(jobs: VeloHuntJob[], typeId = "threat-hunt", rows: ForensicEvent[] = []) {
  const dir = await mkdtemp(join(tmpdir(), "dfir-hunt-settle-"));
  const stateStore = memoryHuntStore(rows);
  const d: HuntSettleDeps = {
    stateStore,
    inventoryStore: new HuntInventoryStore({ stateDir: () => dir }),
    incidentTypeStore: { loadType: async () => getBuiltInIncidentType(typeId) ?? null },
    veloHuntStore: { list: async () => jobs },
    serverSetId: () => "srv",
    env: {},
    now: () => "2026-01-02T00:00:00Z",
  };
  return { d, stateStore };
}

/** `common` on every one of n hosts; `rare` on the first k hosts. */
function sweep(n: number, k: number): ForensicEvent[] {
  const rows: ForensicEvent[] = [];
  for (let i = 0; i < n; i++) rows.push(prefetchRow(`c${i}`, i, "chrome.exe", "C:\\Program Files\\Google"));
  for (let i = 0; i < k; i++) rows.push(prefetchRow(`r${i}`, i, "rclone.exe", "C:\\Users\\x\\Downloads"));
  return rows;
}

const entries = (events: ForensicEvent[]) => events.filter((e) => e.id.startsWith("hunt-item:"));

describe("hunt grading at the seam (#2670)", () => {
  it("writes ONE grouped entry for a rare program, listing its hosts", async () => {
    const { d, stateStore } = await deps([reachedJob(300)]);
    await huntSettle(d, "c1", sweep(300, 3));
    const e = entries(stateStore.events());
    expect(e).toHaveLength(1);
    expect(e[0].severity).toBe("Medium");
    expect(e[0].description).toMatch(
      /^Hunt \(rare program\): rclone\.exe in \\users\\\*\\downloads — on 3 of 300 answering host\(s\): WS-000, WS-001, WS-002/,
    );
    expect(e[0].provenance?.[0]).toMatch(/hunt summary/);
  });

  it("grades nothing rare below the minimum of answering hosts", async () => {
    const { d, stateStore } = await deps([reachedJob(19)]);
    await huntSettle(d, "c1", sweep(19, 1));
    expect(entries(stateStore.events())).toEqual([]);
  });

  it("grades nothing rare when coverage is unknown (an uploaded export)", async () => {
    const { d, stateStore } = await deps([]);
    await huntSettle(d, "c1", sweep(300, 1));
    expect(entries(stateStore.events())).toEqual([]);
  });

  it("does nothing outside hunt mode", async () => {
    const { d, stateStore } = await deps([reachedJob(300)], "ransomware");
    const r = await huntSettle(d, "c1", sweep(300, 1));
    expect(r.changed).toBe(0);
    expect(entries(stateStore.events())).toEqual([]);
  });

  it("recalculates rarity as more hosts answer: an entry that stops being rare is removed", async () => {
    const jobs = [reachedJob(40)];
    const { d, stateStore } = await deps(jobs);
    await huntSettle(d, "c1", sweep(40, 2)); // 2 of 40 = 5% → rare
    expect(entries(stateStore.events())).toHaveLength(1);
    jobs[0] = reachedJob(40);
    // more hosts report the program in a later import: now 8 of 40
    await huntSettle(
      d,
      "c1",
      [2, 3, 4, 5, 6, 7].map((i) => prefetchRow(`r2-${i}`, i, "rclone.exe", "C:\\Users\\y\\Downloads")),
    );
    expect(entries(stateStore.events())).toEqual([]);
  });

  it("keeps an entry the analyst promoted even when it no longer applies", async () => {
    const { d, stateStore } = await deps([reachedJob(40)]);
    await huntSettle(d, "c1", sweep(40, 2));
    const [entry] = entries(stateStore.events());
    const [row] = await stateStore.forensicRowsById("c1", [entry.id]);
    await stateStore.updateForensicRows("c1", [
      { ...row, event: { ...row.event, promotedAt: "2026-01-03T00:00:00Z" } },
    ]);
    await huntSettle(
      d,
      "c1",
      [2, 3, 4, 5].map((i) => prefetchRow(`x${i}`, i, "rclone.exe", "C:\\Users\\z\\Downloads")),
    );
    expect(entries(stateStore.events())).toHaveLength(1);
  });

  it("caps the entries per kind with ONE visible 'N more' entry — no flood", async () => {
    const { d, stateStore } = await deps([reachedJob(300)]);
    const rows: ForensicEvent[] = [];
    for (let p = 0; p < HUNT_ENTRY_CAP + 7; p++) rows.push(prefetchRow(`p${p}`, p % 300, `tool${p}.exe`));
    await huntSettle(d, "c1", rows);
    const e = entries(stateStore.events());
    expect(e).toHaveLength(HUNT_ENTRY_CAP + 1);
    const more = e.find((x) => x.id === huntOverflowId("rare"));
    expect(more?.description).toMatch(/7 more item\(s\) not listed/);
  });

  it("never changes an imported row, detection or not", async () => {
    const detection = {
      ...prefetchRow("det", 0, "rclone.exe", "C:\\Users\\x\\Downloads"),
      severity: "High" as const,
    };
    const { d, stateStore } = await deps([reachedJob(300)], "threat-hunt", [detection]);
    await huntSettle(d, "c1", [detection, ...sweep(300, 0)]);
    expect(stateStore.events().find((e) => e.id === "det")).toEqual(detection);
  });

  it("an empty settle with unchanged coverage writes nothing", async () => {
    const { d, stateStore } = await deps([reachedJob(300)]);
    await huntSettle(d, "c1", sweep(300, 2));
    const append = vi.spyOn(stateStore, "appendForensicEvents");
    const update = vi.spyOn(stateStore, "updateForensicRows");
    expect((await huntSettle(d, "c1", [])).changed).toBe(0);
    expect(append).not.toHaveBeenCalled();
    expect(update).not.toHaveBeenCalled();
  });
});

describe("the import seam runs hunt grading after the tagger and before demote (#2670)", () => {
  it("hands the hook this import's rows, Info included, before demote removes them", async () => {
    const calls: string[] = [];
    const info: ForensicEvent = { ...prefetchRow("i1", 0, "a.exe"), severity: "Info" };
    const before = { caseId: "c1", forensicTimeline: [], iocs: [] } as unknown as InvestigationState;
    const store = memoryRowStore({
      caseId: "c1",
      forensicTimeline: [info],
      iocs: [],
    } as unknown as InvestigationState);
    registerHuntSettle(store, async (_c, added) => {
      calls.push(`hunt:${added.map((e) => `${e.id}/${e.severity}`).join(",")}`);
      return 0;
    });
    await settleForensicImport(
      {
        stateStore: store,
        autoTagImported: async () => void calls.push("tag"),
        demoteForensic: async () => {
          calls.push("demote");
          return store.demoteInfo();
        },
        superTimelineStore: { append: async (_c: string, e: ForensicEvent[]) => e.length },
      },
      "c1",
      before,
    );
    expect(calls).toEqual(["tag", "hunt:i1/Info", "demote"]);
  });
});
