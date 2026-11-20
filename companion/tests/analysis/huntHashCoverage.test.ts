// One approved hash must not approve hosts whose binary was never hashed (#2670). An inventory item
// groups every host that ran a program at a path; an approval by hash covers the item only when EVERY
// host in it has its own hashed observation, every hash is approved, and nothing was dropped by a cap.
// A host seen only through a hash-less row (prefetch) stays unverified, so the item stays Unknown:
// it keeps its rare grade and stays on the client's confirm list.
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  applyMarks,
  markInputSchema,
  newProfile,
  type ClientProfile,
} from "../../src/analysis/clientProfile.js";
import { itemVerdict } from "../../src/analysis/huntApprovalMatch.js";
import { huntFieldsOf } from "../../src/analysis/huntArtifactFields.js";
import { confirmCandidates } from "../../src/analysis/huntConfirmList.js";
import { EMPTY_INVENTORY, recordObservations, type InventoryItem } from "../../src/analysis/huntInventory.js";
import { HuntInventoryStore } from "../../src/analysis/huntInventoryStore.js";
import { huntSettle, type HuntSettleDeps } from "../../src/analysis/huntSettle.js";
import { getBuiltInIncidentType } from "../../src/analysis/incidentTypesData.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { baselineGradesProvider } from "../../src/composition/huntBaselineGrades.js";
import { memoryHuntStore, prefetchRow, reachedJob } from "../helpers/huntFakes.js";

const H = "d".repeat(64);
const NOW = "2026-06-01T00:00:00.000Z";
const hashed = (id: string, i: number, sha256 = H): ForensicEvent => ({
  ...prefetchRow(id, i, "rclone.exe"),
  sha256,
});
const bare = (id: string, i: number): ForensicEvent => prefetchRow(id, i, "rclone.exe");

const approvedProfile = (): ClientProfile =>
  applyMarks(
    newProfile({ name: "Client A" }, "admin", "2026-01-01T00:00:00Z"),
    [
      markInputSchema.parse({
        verdict: "approved",
        family: "program",
        program: "rclone.exe",
        pathPattern: "\\tools",
        sha256: [H],
      }),
    ],
    { by: "admin", at: "t", source: "client email" },
  );

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

const onlyItem = (rows: ForensicEvent[]): InventoryItem => Object.values(inventoryOf(rows).items)[0];

describe("hash coverage per host (#2670)", () => {
  it("one host's approved hash does not approve a host seen only without a hash", () => {
    const item = onlyItem([hashed("a", 1), bare("b", 2)]);
    expect(itemVerdict(approvedProfile().baseline, item, NOW).verdict).toBe("unknown");
  });

  it("every host hashed with an approved hash is approved, even when it also has hash-less rows", () => {
    const item = onlyItem([hashed("a", 1), bare("a2", 1), bare("b0", 2), hashed("b", 2)]);
    expect(itemVerdict(approvedProfile().baseline, item, NOW).verdict).toBe("approved");
  });

  it("a hash list cut short by its cap is incomplete, so nothing is approved", () => {
    const rows = Array.from({ length: 25 }, (_, i) =>
      hashed(`h${i}`, i, i === 0 ? H : String(i).padStart(64, "e")),
    );
    const capped = onlyItem(rows);
    const approveAll = applyMarks(
      newProfile({ name: "Client A" }, "admin", "2026-01-01T00:00:00Z"),
      [
        markInputSchema.parse({
          verdict: "approved",
          family: "program",
          program: "rclone.exe",
          pathPattern: "\\tools",
          sha256: capped.sha256,
        }),
      ],
      { by: "admin", at: "t", source: "client email" },
    );
    expect(itemVerdict(approveAll.baseline, capped, NOW).verdict).toBe("unknown");
  });

  it("hosts dropped by the host cap leave the item incomplete", () => {
    const item = { ...onlyItem([hashed("a", 1)]), hostOverflow: 1 };
    expect(itemVerdict(approvedProfile().baseline, item, NOW).verdict).toBe("unknown");
  });

  it("an item stored before hash coverage was recorded is never approved (fails closed)", () => {
    const item = onlyItem([hashed("a", 1)]);
    const legacy: Partial<InventoryItem> = { ...item };
    delete legacy.unhashedHosts;
    delete legacy.hashesCapped;
    expect(itemVerdict(approvedProfile().baseline, legacy as InventoryItem, NOW).verdict).toBe("unknown");
  });

  it("the mixed item keeps its rare grade and stays on the client's confirm list", async () => {
    const rows = [hashed("a", 1), bare("b", 2)];
    const dir = await mkdtemp(join(tmpdir(), "dfir-hunt-hashcov-"));
    const stateStore = memoryHuntStore(rows);
    const inventoryStore = new HuntInventoryStore({ stateDir: () => dir });
    const jobs = [reachedJob(300)];
    const profile = approvedProfile();
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
    const entries = stateStore.events().filter((e) => e.id.startsWith("hunt-item:"));
    expect(entries.map((e) => e.description)).toEqual([
      expect.stringMatching(/^Hunt \(rare program\): rclone\.exe/),
    ]);
    const rec = await inventoryStore.load("c1");
    expect(rec.approvedLabels).toEqual([]);
    const pending = confirmCandidates(rec.inventory, profile.baseline, new Set(["srv/C.1", "srv/C.2"]), NOW);
    expect(pending.map((c) => c.program)).toEqual(["rclone.exe"]);
  });
});
