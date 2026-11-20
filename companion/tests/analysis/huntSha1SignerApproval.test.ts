// Client approvals by Amcache SHA1 and by verified Autoruns signer (#2731).
//   - Amcache hashes only the first 30 MiB of a file, so a SHA1 approval covers a file only when Amcache
//     recorded its size and it is within that limit. A larger or unsized file stays Unknown and says why.
//   - Every host must be covered by an algorithm the approval names: a host seen only through SHA1 is
//     not covered by a SHA-256-only approval, and the reverse.
//   - A signer approval covers an item only when EVERY host has a verified observation by that signer,
//     no other signer was seen, and no signature check failed.
import { describe, expect, it } from "vitest";
import { applyMarks, markInputSchema, newProfile, type MarkInput } from "../../src/analysis/clientProfile.js";
import { AMCACHE_SHA1_MAX_BYTES, type FileIdentity } from "../../src/analysis/fileIdentity.js";
import { itemVerdict } from "../../src/analysis/huntApprovalMatch.js";
import { huntFieldsOf } from "../../src/analysis/huntArtifactFields.js";
import { confirmCandidates } from "../../src/analysis/huntConfirmList.js";
import { EMPTY_INVENTORY, recordObservations, type InventoryItem } from "../../src/analysis/huntInventory.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const NOW = "2026-06-01T00:00:00.000Z";
const S1 = "1".repeat(40);
const S1B = "2".repeat(40);
const H256 = "d".repeat(64);
const SMALL = 1_000_000;

const host = (i: number) => `WS-${String(i).padStart(3, "0")}`;

const amcacheRow = (id: string, i: number, fileIdentity?: FileIdentity, sha256?: string): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: `Velociraptor [Windows.Forensics.Amcache]: Program file present (Amcache): c:\\tools\\rclone.exe - @ ${host(i)}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: host(i),
  path: "c:\\tools\\rclone.exe",
  ...(fileIdentity ? { fileIdentity } : {}),
  ...(sha256 ? { sha256 } : {}),
});

const autorunRow = (id: string, i: number, fileIdentity?: FileIdentity): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: `Velociraptor [Windows.Sysinternals.Autoruns]: Autorun entry (Autoruns): Updater — c:\\program files\\vendor\\updater.exe - @ ${host(i)}`,
  severity: "Low",
  mitreTechniques: ["T1547"],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: host(i),
  path: "c:\\program files\\vendor\\updater.exe",
  artifactName: "Windows.Sysinternals.Autoruns",
  ...(fileIdentity ? { fileIdentity } : {}),
});

const onlyItem = (rows: ForensicEvent[]): InventoryItem => {
  const inv = recordObservations(
    EMPTY_INVENTORY,
    rows.map((e) => ({
      fields: huntFieldsOf(e)!,
      host: { key: `srv/${e.asset}`, basis: "client" as const, hostname: e.asset! },
      at: e.timestamp,
    })),
    "now",
  );
  const items = Object.values(inv.items);
  expect(items).toHaveLength(1);
  return items[0];
};

const baselineWith = (input: Partial<MarkInput>) =>
  applyMarks(
    newProfile({ name: "Client A" }, "admin", "2026-01-01T00:00:00Z"),
    [
      markInputSchema.parse({
        verdict: "approved",
        family: "program",
        program: "rclone.exe",
        pathPattern: "\\tools",
        ...input,
      }),
    ],
    { by: "admin", at: "t", source: "client email" },
  ).baseline;

describe("Amcache SHA1 approvals (#2731)", () => {
  const sha1Mark = baselineWith({ sha1: [S1] });

  it("approves when every host has an approved SHA1 of a file within 30 MiB", () => {
    const item = onlyItem([
      amcacheRow("a", 1, { sha1: S1, size: SMALL }),
      amcacheRow("b", 2, { sha1: S1, size: AMCACHE_SHA1_MAX_BYTES }),
    ]);
    expect(itemVerdict(sha1Mark, item, NOW).verdict).toBe("approved");
  });

  it("a file over 30 MiB stays Unknown, and the reason says why", () => {
    const item = onlyItem([amcacheRow("a", 1, { sha1: S1, size: AMCACHE_SHA1_MAX_BYTES + 1 })]);
    const v = itemVerdict(sha1Mark, item, NOW);
    expect(v.verdict).toBe("unknown");
    expect(v.reason).toMatch(/30 MiB/);
  });

  it("a SHA1 without a recorded size stays Unknown, and the reason says why", () => {
    const item = onlyItem([amcacheRow("a", 1, { sha1: S1 })]);
    const v = itemVerdict(sha1Mark, item, NOW);
    expect(v.verdict).toBe("unknown");
    expect(v.reason).toMatch(/no file size/);
  });

  it("one oversize observation on another host keeps the item Unknown", () => {
    const item = onlyItem([
      amcacheRow("a", 1, { sha1: S1, size: SMALL }),
      amcacheRow("b", 2, { sha1: S1, size: AMCACHE_SHA1_MAX_BYTES * 2 }),
    ]);
    expect(itemVerdict(sha1Mark, item, NOW).verdict).toBe("unknown");
  });

  it("a later oversize observation of the SAME host keeps it Unknown, across two imports", () => {
    const obs = (e: ForensicEvent) => ({
      fields: huntFieldsOf(e)!,
      host: { key: "srv/WS-001", basis: "client" as const, hostname: e.asset! },
      at: e.timestamp,
    });
    const first = recordObservations(
      EMPTY_INVENTORY,
      [obs(amcacheRow("a", 1, { sha1: S1, size: SMALL }))],
      "t1",
    );
    const [ok] = Object.values(first.items);
    expect(itemVerdict(sha1Mark, ok, NOW).verdict).toBe("approved");
    const second = recordObservations(
      first,
      [obs(amcacheRow("a2", 1, { sha1: S1B, size: AMCACHE_SHA1_MAX_BYTES + 1 }))],
      "t2",
    );
    const [grown] = Object.values(second.items);
    expect(itemVerdict(sha1Mark, grown, NOW).verdict).toBe("unknown");
  });

  it("a different SHA1 on any host is not covered", () => {
    const item = onlyItem([
      amcacheRow("a", 1, { sha1: S1, size: SMALL }),
      amcacheRow("b", 2, { sha1: S1B, size: SMALL }),
    ]);
    expect(itemVerdict(sha1Mark, item, NOW).verdict).toBe("unknown");
    expect(itemVerdict(baselineWith({ sha1: [S1, S1B] }), item, NOW).verdict).toBe("approved");
  });

  it("a host seen only through SHA1 is not covered by a SHA-256-only approval", () => {
    const item = onlyItem([
      amcacheRow("a", 1, undefined, H256),
      amcacheRow("b", 2, { sha1: S1, size: SMALL }),
    ]);
    expect(itemVerdict(baselineWith({ sha256: [H256] }), item, NOW).verdict).toBe("unknown");
  });

  it("a host seen only through SHA-256 is not covered by a SHA1-only approval", () => {
    const item = onlyItem([
      amcacheRow("a", 1, undefined, H256),
      amcacheRow("b", 2, { sha1: S1, size: SMALL }),
    ]);
    expect(itemVerdict(sha1Mark, item, NOW).verdict).toBe("unknown");
  });

  it("an approval naming both algorithms covers hosts seen through either", () => {
    const item = onlyItem([
      amcacheRow("a", 1, undefined, H256),
      amcacheRow("b", 2, { sha1: S1, size: SMALL }),
    ]);
    expect(itemVerdict(baselineWith({ sha256: [H256], sha1: [S1] }), item, NOW).verdict).toBe("approved");
  });

  it("an item stored before SHA1 coverage was recorded is never approved by SHA1", () => {
    const item = onlyItem([amcacheRow("a", 1, { sha1: S1, size: SMALL })]);
    const legacy: InventoryItem = { ...item, noSha1Hosts: undefined, sha1Capped: undefined };
    expect(itemVerdict(sha1Mark, legacy, NOW).verdict).toBe("unknown");
  });

  it("the confirm list carries the usable SHA1 and the reason an unusable one is ignored", () => {
    const inv = recordObservations(
      EMPTY_INVENTORY,
      [amcacheRow("a", 1, { sha1: S1, size: SMALL })].map((e) => ({
        fields: huntFieldsOf(e)!,
        host: { key: "srv/a", basis: "client" as const, hostname: e.asset! },
        at: e.timestamp,
      })),
      "now",
    );
    const [c] = confirmCandidates(
      inv,
      { marks: [], blockedDomains: [], approvedDomains: [], blockedCategories: [] },
      new Set(),
      NOW,
    );
    expect(c.sha1).toEqual([S1]);
    const big = recordObservations(
      EMPTY_INVENTORY,
      [amcacheRow("a", 1, { sha1: S1, size: AMCACHE_SHA1_MAX_BYTES + 1 })].map((e) => ({
        fields: huntFieldsOf(e)!,
        host: { key: "srv/a", basis: "client" as const, hostname: e.asset! },
        at: e.timestamp,
      })),
      "now",
    );
    const [b] = confirmCandidates(
      big,
      { marks: [], blockedDomains: [], approvedDomains: [], blockedCategories: [] },
      new Set(),
      NOW,
    );
    expect(b.sha1).toEqual([]);
    expect(b.reason).toMatch(/30 MiB/);
  });
});

describe("verified signer approvals (#2731)", () => {
  const signerMark = applyMarks(
    newProfile({ name: "Client A" }, "admin", "2026-01-01T00:00:00Z"),
    [
      markInputSchema.parse({
        verdict: "approved",
        family: "autorun",
        program: "updater.exe",
        pathPattern: "\\program files\\vendor",
        signer: "Vendor Inc",
      }),
    ],
    { by: "admin", at: "t", source: "client email" },
  ).baseline;

  it("approves when every host is verified by the approved signer", () => {
    const item = onlyItem([
      autorunRow("a", 1, { signer: "Vendor Inc" }),
      autorunRow("b", 2, { signer: "Vendor Inc" }),
    ]);
    expect(itemVerdict(signerMark, item, NOW).verdict).toBe("approved");
  });

  it("one signed host never approves an unsigned host", () => {
    const item = onlyItem([autorunRow("a", 1, { signer: "Vendor Inc" }), autorunRow("b", 2)]);
    expect(itemVerdict(signerMark, item, NOW).verdict).toBe("unknown");
  });

  it("a host verified by a different signer is not covered", () => {
    const item = onlyItem([
      autorunRow("a", 1, { signer: "Vendor Inc" }),
      autorunRow("b", 2, { signer: "Other Ltd" }),
    ]);
    expect(itemVerdict(signerMark, item, NOW).verdict).toBe("unknown");
  });

  it("a failed signature check anywhere keeps the item Unknown", () => {
    const item = onlyItem([
      autorunRow("a", 1, { signer: "Vendor Inc" }),
      autorunRow("b", 2, { signer: "Vendor Inc" }),
      autorunRow("b2", 2, { signatureUnverified: true }),
    ]);
    expect(itemVerdict(signerMark, item, NOW).verdict).toBe("unknown");
  });

  it("an approval never lowers a Not allowed verdict", () => {
    const item = onlyItem([autorunRow("a", 1, { signer: "Vendor Inc" })]);
    const both = {
      ...signerMark,
      marks: [
        ...signerMark.marks,
        {
          ...signerMark.marks[0],
          id: "no",
          verdict: "not-allowed" as const,
          pathPattern: "",
          signer: undefined,
        },
      ],
    };
    expect(itemVerdict(both, item, NOW).verdict).toBe("not-allowed");
  });
});
