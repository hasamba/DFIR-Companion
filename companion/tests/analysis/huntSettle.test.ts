import { describe, it, expect, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { huntSettle, type HuntSettleDeps } from "../../src/analysis/huntSettle.js";
import { HuntInventoryStore } from "../../src/analysis/huntInventoryStore.js";
import type { HuntInventory } from "../../src/analysis/huntInventory.js";
import { HUNT_ENTRY_CAP, huntOverflowId } from "../../src/analysis/huntEntries.js";
import { getBuiltInIncidentType } from "../../src/analysis/incidentTypesData.js";
import { registerHuntSettle } from "../../src/analysis/huntSettleHook.js";
import { regradeHuntCase } from "../../src/analysis/huntRegrade.js";
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

const TASKS = "Windows.System.TaskScheduler";
const HUNT_ARTIFACTS = ["Windows.Forensics.Prefetch", "Windows.Forensics.Amcache", TASKS];

describe("a partial artifact blocks rarity only for the kinds of item it reports (#2732)", () => {
  const cut = (name: string) => ({ name, kept: 10, total: 11 });
  const amcacheRow = (id: string, i: number, program: string, dir: string): ForensicEvent => ({
    ...prefetchRow(id, i, program, dir),
    description: `Velociraptor [Windows.Forensics.Amcache/InventoryApplicationFile]: Program file present (Amcache): ${dir}\\${program} - @ WS-${String(i).padStart(3, "0")}`,
    artifactName: "Windows.Forensics.Amcache/InventoryApplicationFile",
  });
  const rare = (events: ForensicEvent[]) =>
    entries(events)
      .map((e) => /: (\S+) in /.exec(e.description)?.[1])
      .sort();

  it("grades a rare program while an artifact that reports only autoruns is partial", async () => {
    const { d, stateStore } = await deps([
      reachedJob(300, { artifacts: HUNT_ARTIFACTS, truncatedArtifacts: [cut(TASKS)] }),
    ]);
    await huntSettle(d, "c1", sweep(300, 2));
    expect(rare(stateStore.events())).toEqual(["rclone.exe"]);
  });

  it("a cut-short Amcache blocks a program seen only in complete Prefetch: its lost rows share the item", async () => {
    // Amcache kept only rows for other programs; the rclone.exe rows lay past the cut, so the
    // inventory shows 1 of 300 hosts when Amcache may have seen it on many more.
    const { d, stateStore } = await deps([
      reachedJob(300, { artifacts: HUNT_ARTIFACTS, truncatedArtifacts: [cut("Windows.Forensics.Amcache")] }),
    ]);
    const kept = Array.from({ length: 10 }, (_, i) =>
      amcacheRow(`a${i}`, i, "chrome.exe", "C:\\Program Files\\Google"),
    );
    await huntSettle(d, "c1", [...sweep(300, 1), ...kept]);
    expect(rare(stateStore.events())).toEqual([]);
  });

  it("an unread source list of an artifact that reports programs blocks every rare program", async () => {
    const { d, stateStore } = await deps([
      reachedJob(300, {
        artifacts: HUNT_ARTIFACTS,
        unreadArtifacts: [{ name: "Windows.Forensics.Prefetch", rows: 5 }],
      }),
    ]);
    await huntSettle(d, "c1", [...sweep(300, 2), amcacheRow("a0", 0, "plink.exe", "C:\\Users\\x\\Temp")]);
    expect(rare(stateStore.events())).toEqual([]);
  });

  it("an item also reported by the partial artifact is not graded: its count is a lower bound", async () => {
    const { d, stateStore } = await deps([
      reachedJob(300, {
        artifacts: HUNT_ARTIFACTS,
        skippedArtifacts: [{ name: "Windows.Forensics.Amcache", error: "timeout" }],
      }),
    ]);
    const both = [...sweep(300, 1), amcacheRow("a0", 1, "rclone.exe", "C:\\Users\\x\\Downloads")];
    await huntSettle(d, "c1", both);
    expect(rare(stateStore.events())).toEqual([]);
  });

  it("a re-grade from the stored rows keeps the per-artifact grading", async () => {
    const jobs = [reachedJob(300, { artifacts: HUNT_ARTIFACTS, truncatedArtifacts: [cut(TASKS)] })];
    const { d, stateStore } = await deps(jobs);
    const rows = sweep(300, 2);
    await huntSettle(d, "c1", rows);
    const rowsDep = {
      async *forensicTimelineBatches() {
        yield rows;
      },
    };
    await regradeHuntCase({ ...d, rows: rowsDep }, "c1");
    expect(rare(stateStore.events())).toEqual(["rclone.exe"]);
  });

  it("a row naming an artifact the hunts did not collect is not graded while any artifact is partial", async () => {
    const { d, stateStore } = await deps([
      reachedJob(300, { artifacts: HUNT_ARTIFACTS, truncatedArtifacts: [cut(TASKS)] }),
    ]);
    const rows = sweep(300, 2).map((e) =>
      e.id.startsWith("r") ? { ...e, artifactName: "SomeOtherSource" } : e,
    );
    await huntSettle(d, "c1", rows);
    expect(rare(stateStore.events())).toEqual([]);
  });

  it("an item whose rows name no artifact is not graded while any artifact is partial", async () => {
    const { d, stateStore } = await deps([
      reachedJob(300, { artifacts: HUNT_ARTIFACTS, truncatedArtifacts: [cut(TASKS)] }),
    ]);
    const rows = sweep(300, 2).map((e) => (e.id.startsWith("r") ? { ...e, artifactName: undefined } : e));
    await huntSettle(d, "c1", rows);
    expect(rare(stateStore.events())).toEqual([]);
  });

  it("an inventory item stored before artifacts were recorded is not graded while any artifact is partial", async () => {
    const jobs = [reachedJob(300)];
    const { d, stateStore } = await deps(jobs);
    await huntSettle(d, "c1", sweep(300, 2));
    expect(rare(stateStore.events())).toEqual(["rclone.exe"]);
    await d.inventoryStore.update("c1", async (rec) => ({
      ...rec,
      inventory: {
        ...rec.inventory,
        items: Object.fromEntries(
          Object.entries(rec.inventory.items).map(([k, v]) => {
            const { artifacts: _drop, ...legacy } = v as typeof v & { artifacts?: string[] };
            return [k, legacy];
          }),
        ),
      },
    }));
    jobs[0] = reachedJob(300, {
      artifacts: HUNT_ARTIFACTS,
      truncatedArtifacts: [cut(TASKS)],
    });
    await huntSettle(d, "c1", []);
    expect(rare(stateStore.events())).toEqual([]);
  });
});

describe("a persisted known-folder GUID item joins its normalised item (#2750)", () => {
  const GUID_DIR = "{6d809377-6af0-444b-8957-a3773f02200e}\\foo"; // FOLDERID_ProgramFilesX64
  const foo = (i: number) => prefetchRow(`f${i}`, i, "foo.exe", "C:\\Program Files\\Foo");
  const fooItems = (inv: HuntInventory) =>
    Object.entries(inv.items).filter(([, v]) => v.program === "foo.exe");

  it("re-keys the stored GUID item on load and merges it, so the combined host count grades", async () => {
    const { d, stateStore } = await deps([reachedJob(300)]);
    const sweepRows = sweep(300, 0);
    await huntSettle(d, "c1", [...sweepRows, foo(0)]);
    // Rewrite the stored item into the form an inventory recorded before #2750 kept.
    await d.inventoryStore.update("c1", async (rec) => {
      const items = Object.fromEntries(
        Object.entries(rec.inventory.items).map(([k, v]) =>
          v.program === "foo.exe"
            ? [
                `program|foo.exe|${GUID_DIR}`,
                { ...v, key: `program|foo.exe|${GUID_DIR}`, pathPattern: GUID_DIR },
              ]
            : [k, v],
        ),
      );
      return { ...rec, inventory: { ...rec.inventory, items }, gradedSignature: "" };
    });
    const later = Array.from({ length: 10 }, (_, i) => foo(i + 1));
    await huntSettle(d, "c1", later);
    const rowsDep = {
      async *forensicTimelineBatches() {
        yield [...sweepRows, ...later];
      },
    };
    await regradeHuntCase({ ...d, rows: rowsDep }, "c1");

    const inv = (await d.inventoryStore.load("c1")).inventory;
    const items = fooItems(inv);
    expect(items.map(([k]) => k)).toEqual(["program|foo.exe|\\program files\\foo"]);
    expect(Object.keys(items[0][1].hosts)).toHaveLength(11);
    const fooEntries = entries(stateStore.events()).filter((e) => /foo\.exe/.test(e.description));
    expect(fooEntries, "11 of 300 hosts is over the 10-host cap: not rare, and no stale GUID entry").toEqual(
      [],
    );
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
