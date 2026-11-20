// Which other hunt cases may feed a hunt case's grading and report (#2670). The "new since last
// hunt" entries, the report's comparison and the pending-item ages all read another case linked to
// the same client — and all of them are WRITTEN into this case (forensic timeline entries, report
// files) where everyone who can read this case will see them later. So another case contributes only
// when every one of this case's readers could open it anyway: never a password-protected case, never
// a hidden sweep case, and in team mode only when it shares this case's whole audience.
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuthStore } from "../../src/auth/authStore.js";
import type { AuthIdentity } from "../../src/auth/types.js";
import { newProfile } from "../../src/analysis/clientProfile.js";
import type { HuntInventoryRecord } from "../../src/analysis/huntInventoryStore.js";
import { EMPTY_INVENTORY, recordObservations } from "../../src/analysis/huntInventory.js";
import { huntFieldsOf } from "../../src/analysis/huntArtifactFields.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { huntComparisonSource, huntPendingSource } from "../../src/composition/huntBaselineGrades.js";
import { caseRoleHolders, huntPeerCaseIds } from "../../src/composition/huntPeerCases.js";
import type { CaseMeta } from "../../src/types.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { prefetchRow, reachedJob } from "../helpers/huntFakes.js";

const meta = (caseId: string, extra: Partial<CaseMeta> = {}): CaseMeta => ({
  caseId,
  name: `Hunt ${caseId}`,
  createdAt: "2026-01-01T00:00:00Z",
  investigator: "i",
  aiProvider: null,
  ...extra,
});

const LOCK = { password: { hash: "h", salt: "s" } as unknown as CaseMeta["password"] };

describe("huntPeerCaseIds — single-user mode", () => {
  it("skips this case, password-protected cases and hidden sweep cases", async () => {
    const peers = huntPeerCaseIds({
      listCases: async () => [
        meta("c1"),
        meta("open"),
        meta("locked", LOCK),
        meta("sweep", { kind: "sweep" }),
      ],
    });
    expect(await peers("c1")).toEqual(["open"]);
  });
});

describe("huntPeerCaseIds — team mode", () => {
  let store: AuthStore;
  afterEach(() => store?.close());

  async function team() {
    store = new AuthStore(join(await mkdtemp(join(tmpdir(), "dfir-hunt-peers-")), "auth.sqlite"));
    const admin = await store.bootstrapLocalAdministrator({
      username: "admin",
      password: "correct horse battery staple",
      displayName: "Admin",
    });
    const user = (name: string): Promise<AuthIdentity> =>
      store.createLocalIdentity(
        { username: name, password: "a sufficiently long password here", displayName: name },
        admin,
      );
    return { admin, alice: await user("alice"), bob: await user("bob") };
  }

  it("a case contributes only while it shares this case's whole audience; a revoked role stops it", async () => {
    const { admin, alice, bob } = await team();
    for (const c of ["c1", "prev"]) store.setCaseRole(c, alice.id, "investigator", admin);
    const peers = huntPeerCaseIds({
      listCases: async () => [meta("c1"), meta("prev")],
      roleHolders: caseRoleHolders(store),
    });
    expect(await peers("c1")).toEqual(["prev"]);

    store.setCaseRole("c1", bob.id, "reader", admin); // bob reads c1's report but holds no role on prev
    expect(await peers("c1")).toEqual([]);

    store.setCaseRole("prev", bob.id, "reader", admin);
    expect(await peers("c1")).toEqual(["prev"]);
    store.removeCaseRole("prev", alice.id, admin); // revoked
    expect(await peers("c1")).toEqual([]);
  });

  it("an instance administrator's own case role never narrows the audience (they open every case)", async () => {
    const { admin, alice } = await team();
    for (const c of ["c1", "prev"]) store.setCaseRole(c, alice.id, "investigator", admin);
    store.setCaseRole("c1", admin.id, "administrator", admin);
    const peers = huntPeerCaseIds({
      listCases: async () => [meta("c1"), meta("prev")],
      roleHolders: caseRoleHolders(store),
    });
    expect(await peers("c1")).toEqual(["prev"]);
  });
});

// The report enrichment through the real composition sources: a locked earlier hunt adds nothing.
describe("report enrichment reads only peer cases (#2670)", () => {
  const p = newProfile({ name: "Client A" }, "admin", "2025-01-01T00:00:00Z");
  const inv = (rows: ForensicEvent[]): HuntInventoryRecord => ({
    inventory: recordObservations(
      EMPTY_INVENTORY,
      rows.map((e, i) => ({
        fields: huntFieldsOf(e)!,
        host: { key: `srv/C.${i}`, hostname: e.asset ?? "", basis: "client" as const },
        at: e.timestamp,
      })),
      "2026-01-02T00:00:00Z",
    ),
    entryIds: [],
    grades: [],
    approvedLabels: [],
    gradedSignature: "",
  });
  const old = (id: string, program: string) => ({
    ...prefetchRow(id, 1, program),
    timestamp: "2025-12-01T00:00:00Z",
  });
  const stores: Record<string, HuntInventoryRecord> = {
    prev: inv([old("a", "7z.exe"), old("x", "gone.exe")]),
    c1: inv([prefetchRow("b", 1, "7z.exe")]),
  };
  const jobs: Record<string, VeloHuntJob[]> = {
    prev: [{ ...reachedJob(3), launchedAt: "2025-12-01T00:00:00Z" }],
    c1: [{ ...reachedJob(3), launchedAt: "2026-01-02T00:00:00Z" }],
  };
  const deps = (prevMeta: CaseMeta) => ({
    links: { load: async () => ({ clientId: p.id, linkedAt: "", linkedBy: "" }) },
    profiles: { get: async () => p },
    inventories: { load: async (id: string) => stores[id] },
    huntJobs: async (id: string) => jobs[id] ?? [],
    peerCaseIds: huntPeerCaseIds({ listCases: async () => [meta("c1"), prevMeta] }),
    serverSetId: () => "srv",
  });

  it("an open earlier hunt ages the pending item and is the comparison", async () => {
    const pending = await huntPendingSource(deps(meta("prev")))("c1");
    expect(pending[0]).toMatchObject({ firstSeen: "2025-12-01", huntsUnconfirmed: 2 });
    expect(await huntComparisonSource(deps(meta("prev")))("c1")).toMatchObject({
      at: "2025-12-01T00:00:00Z",
    });
  });

  it("a password-protected earlier hunt contributes no date, no count and no comparison", async () => {
    const pending = await huntPendingSource(deps(meta("prev", LOCK)))("c1");
    expect(pending[0]).toMatchObject({ huntsUnconfirmed: 1 });
    expect(pending[0].firstSeen).not.toBe("2025-12-01");
    expect(await huntComparisonSource(deps(meta("prev", LOCK)))("c1")).toBeNull();
  });
});
