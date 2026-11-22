import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalizeInventory, mergeInventoryItems } from "../../src/analysis/huntInventoryCanon.js";
import { HuntInventoryStore } from "../../src/analysis/huntInventoryStore.js";
import {
  INVENTORY_MAX_HOSTS,
  recordObservations,
  type HuntInventory,
  type InventoryItem,
} from "../../src/analysis/huntInventory.js";

// #2750: stored inventories keep known-folder GUID keys from before the normalisation; on load they
// are re-keyed and merged into the normalised item. Synthetic hosts and programs only.

const GUID = "{6d809377-6af0-444b-8957-a3773f02200e}\\foo"; // FOLDERID_ProgramFilesX64
const NORMAL = "\\program files\\foo";

function item(pathPattern: string, hosts: string[], extra: Partial<InventoryItem> = {}): InventoryItem {
  return {
    key: `program|foo.exe|${pathPattern}`,
    family: "program",
    program: "foo.exe",
    pathPattern,
    evidence: ["execution"],
    publishers: [],
    sha256: [],
    unhashedHosts: [...hosts],
    hashesCapped: false,
    sha1: [],
    noSha1Hosts: [...hosts],
    sha1Capped: false,
    signers: [],
    unsignedHosts: [...hosts],
    signersCapped: false,
    md5: [],
    sourceUrls: [],
    artifacts: ["Windows.Registry.UserAssist"],
    hosts: Object.fromEntries(
      hosts.map((h) => [
        h,
        { hostname: h.replace("name/", ""), basis: "name" as const, firstSeen: "2026-01-02" },
      ]),
    ),
    hostOverflow: 0,
    firstSeen: "2026-01-02",
    lastSeen: "2026-01-02",
    ...extra,
  };
}

const inv = (...items: InventoryItem[]): HuntInventory => ({
  version: 1,
  items: Object.fromEntries(items.map((i) => [i.key, i])),
  full: false,
  updatedAt: "",
});

describe("canonical hunt inventory keys (#2750)", () => {
  it("re-keys a GUID item and merges it with the normalised one", () => {
    const { inventory, changed } = canonicalizeInventory(
      inv(item(GUID, ["name/ws-a"]), item(NORMAL, ["name/ws-b", "name/ws-c"], { evidence: ["presence"] })),
    );
    expect(changed).toBe(true);
    expect(Object.keys(inventory.items)).toEqual([`program|foo.exe|${NORMAL}`]);
    const m = inventory.items[`program|foo.exe|${NORMAL}`];
    expect(Object.keys(m.hosts).sort()).toEqual(["name/ws-a", "name/ws-b", "name/ws-c"]);
    expect(m.evidence.sort()).toEqual(["execution", "presence"]);
    expect(m.pathPattern).toBe(NORMAL);
  });

  it("re-keys a lone GUID item, and leaves a canonical inventory exactly as it is", () => {
    const lone = canonicalizeInventory(inv(item(GUID, ["name/ws-a"])));
    expect(Object.keys(lone.inventory.items)).toEqual([`program|foo.exe|${NORMAL}`]);
    const again = canonicalizeInventory(lone.inventory);
    expect(again.changed).toBe(false);
    expect(again.inventory).toBe(lone.inventory);
    const unknownGuid = inv(item("{00000000-0000-0000-0000-000000000000}\\x", ["name/ws-a"]));
    expect(canonicalizeInventory(unknownGuid).changed, "an unknown GUID is not touched").toBe(false);
  });

  it("passes a malformed stored item through instead of throwing on load", () => {
    const bad = {
      version: 1 as const,
      items: { x: null, y: { ...item(NORMAL, []), entries: "junk" } },
      full: false,
      updatedAt: "",
    };
    expect(() => canonicalizeInventory(bad as unknown as HuntInventory)).not.toThrow();
  });

  it("re-keys a GUID entry identity on an autorun item too", () => {
    const task = item(NORMAL, ["name/ws-a"], { entries: [{ program: "t", pathPattern: GUID }] });
    const { inventory, changed } = canonicalizeInventory(inv(task));
    expect(changed).toBe(true);
    expect(inventory.items[task.key].entries).toEqual([{ program: "t", pathPattern: NORMAL }]);
  });

  it("a merge is never more approvable than its parts", () => {
    const hashed = item(NORMAL, ["name/ws-a"], { sha256: ["aa"], unhashedHosts: [] });
    const legacy = item(GUID, ["name/ws-a", "name/ws-b"], {
      unhashedHosts: undefined,
      sha1: undefined,
      noSha1Hosts: undefined,
      artifacts: undefined,
      identityConflict: true,
    });
    const m = mergeInventoryItems(hashed, { ...legacy, pathPattern: NORMAL, key: hashed.key });
    expect(m.unhashedHosts, "a legacy part leaves hash coverage unknown").toBeUndefined();
    expect(m.noSha1Hosts).toBeUndefined();
    expect(m.sha1Capped, "a part without a SHA1 list leaves the list incomplete").toBe(true);
    expect(m.artifacts, "a part with unknown artifacts leaves them unknown").toBeUndefined();
    expect(m.identityConflict).toBe(true);
    expect(m.sha256).toEqual(["aa"]);
  });

  it("a host hashed in either part counts as hashed; one hashed in neither stays listed", () => {
    const a = item(NORMAL, ["name/ws-a", "name/ws-b"], { sha256: ["aa"], unhashedHosts: ["name/ws-b"] });
    const b = item(NORMAL, ["name/ws-b", "name/ws-c"], { unhashedHosts: ["name/ws-b", "name/ws-c"] });
    expect(mergeInventoryItems(a, b).unhashedHosts?.sort()).toEqual(["name/ws-b", "name/ws-c"]);
    const c = item(NORMAL, ["name/ws-b"], { sha256: ["bb"], unhashedHosts: [] });
    expect(mergeInventoryItems(a, c).unhashedHosts).toEqual([]);
  });

  // #2820: hardening against a stored item that lacks these fields (a hand-edited or corrupted file).
  it("keeps the last-seen date when the other part of a merge has none", () => {
    const whole = item(NORMAL, ["name/ws-a"], { lastSeen: "2026-03-04" });
    const partial = item(NORMAL, ["name/ws-b"], { lastSeen: undefined });
    expect(mergeInventoryItems(whole, partial).lastSeen).toBe("2026-03-04");
    expect(mergeInventoryItems(partial, whole).lastSeen).toBe("2026-03-04");
    const newer = item(NORMAL, ["name/ws-b"], { lastSeen: "2026-05-06" });
    expect(mergeInventoryItems(whole, newer).lastSeen, "two real dates still give the later").toBe(
      "2026-05-06",
    );
  });

  it("counts a missing host overflow as zero in a merge, and still adds the hosts it drops", () => {
    const counted = item(NORMAL, ["name/ws-a"], { hostOverflow: 3 });
    const uncounted = item(NORMAL, ["name/ws-b"], { hostOverflow: undefined });
    expect(mergeInventoryItems(counted, uncounted).hostOverflow).toBe(3);
    expect(mergeInventoryItems(uncounted, counted).hostOverflow).toBe(3);
    const full = item(
      NORMAL,
      Array.from({ length: INVENTORY_MAX_HOSTS }, (_, i) => `name/ws-${i}`),
      { hostOverflow: 3, unhashedHosts: [], noSha1Hosts: [], unsignedHosts: [] },
    );
    const extra = item(NORMAL, ["name/extra-a", "name/extra-b"], { hostOverflow: undefined });
    expect(mergeInventoryItems(full, extra).hostOverflow, "two hosts over the cap").toBe(5);
  });

  it("counts a missing host overflow as zero when a new observation lands on the item", () => {
    const stored = item(NORMAL, ["name/ws-a"], { hostOverflow: undefined });
    const next = recordObservations(
      inv(stored),
      [
        {
          fields: {
            evidence: "execution",
            program: "foo.exe",
            pathPattern: NORMAL,
            path: `${NORMAL}\\foo.exe`,
            publisherVerified: false,
            host: "ws-b",
          },
          host: { key: "name/ws-b", basis: "name", hostname: "ws-b" },
          at: "2026-01-03",
        },
      ],
      "2026-01-03",
    );
    expect(next.items[stored.key].hostOverflow).toBe(0);
  });

  it("drops a merge destination's stored grade too (its host count changed)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-hunt-canon-"));
    const store = new HuntInventoryStore({ stateDir: () => dir });
    const destGrade = { itemKey: `program|foo.exe|${NORMAL}`, kind: "rare", label: "foo.exe" };
    const record = {
      inventory: inv(item(NORMAL, ["name/ws-a"]), item(GUID, ["name/ws-b", "name/ws-c"])),
      entryIds: [],
      grades: [destGrade],
      approvedLabels: [],
      gradedSignature: "sig",
    };
    await writeFile(join(dir, "hunt-inventory.json"), JSON.stringify(record));
    const loaded = await store.load("c1");
    expect(Object.keys(loaded.inventory.items)).toEqual([`program|foo.exe|${NORMAL}`]);
    expect(loaded.grades, "the destination's old 'rare' grade must not survive the merge").toEqual([]);
  });

  it("the store re-keys on load and clears the grading signature so the next settle re-grades", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-hunt-canon-"));
    const store = new HuntInventoryStore({ stateDir: () => dir });
    const staleGrade = { itemKey: `program|foo.exe|${GUID}`, kind: "rare", label: "foo.exe" };
    const record = {
      inventory: inv(item(GUID, ["name/ws-a"])),
      entryIds: [],
      grades: [staleGrade],
      approvedLabels: [],
    };
    await writeFile(join(dir, "hunt-inventory.json"), JSON.stringify({ ...record, gradedSignature: "sig" }));
    const loaded = await store.load("c1");
    expect(Object.keys(loaded.inventory.items)).toEqual([`program|foo.exe|${NORMAL}`]);
    expect(loaded.gradedSignature).toBe("");
    expect(loaded.grades, "a grade on the old GUID key is dropped until the re-grade").toEqual([]);
    const canonical = {
      inventory: inv(item(NORMAL, ["name/ws-a"])),
      entryIds: [],
      grades: [],
      approvedLabels: [],
    };
    await writeFile(
      join(dir, "hunt-inventory.json"),
      JSON.stringify({ ...canonical, gradedSignature: "sig" }),
    );
    expect((await store.load("c1")).gradedSignature, "a canonical inventory keeps its signature").toBe("sig");
  });
});
