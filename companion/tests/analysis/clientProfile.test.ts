import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyDomains,
  applyMarks,
  baselineAt,
  domainsInputSchema,
  markInputSchema,
  newProfile,
} from "../../src/analysis/clientProfile.js";
import { ClientProfileStore } from "../../src/analysis/clientProfileStore.js";
import { itemVerdict } from "../../src/analysis/huntApprovalMatch.js";
import { HuntProfileNames } from "../../src/analysis/huntMaskNames.js";

const H = "c".repeat(64);
const mark = (verdict: "approved" | "not-allowed" | "unknown", program = "7z.exe") =>
  markInputSchema.parse({
    verdict,
    family: "program",
    program,
    pathPattern: "\\program files\\7-zip",
    sha256: [H],
  });

describe("client profile baseline (#2670)", () => {
  const base = newProfile({ name: "Client A" }, "admin", "2026-01-01T00:00:00Z");

  it("every edit is a numbered version with who, when and the source in the audit log", () => {
    const p = applyMarks(base, [mark("approved")], {
      by: "alice",
      at: "2026-01-02T00:00:00Z",
      source: "client email 2026-01-02",
    });
    expect(p.version).toBe(1);
    expect(p.baseline.marks[0]).toMatchObject({
      verdict: "approved",
      recordedBy: "alice",
      source: "client email 2026-01-02",
    });
    expect(p.audit.at(-1)).toMatchObject({ by: "alice", action: "marks", version: 1 });
    expect(p.audit.at(-1)?.detail).toMatch(/1 approved.*client email 2026-01-02/);
  });

  it("an approval is reversible: Unknown removes it, as a new audited version", () => {
    const a = applyMarks(base, [mark("approved")], { by: "a", at: "t1", source: "s" });
    const b = applyMarks(a, [mark("unknown")], { by: "a", at: "t2", source: "s2" });
    expect(b.baseline.marks).toEqual([]);
    expect(b.version).toBe(2);
    expect(b.audit.at(-1)?.detail).toMatch(/1 reset to unknown/);
  });

  it("keeps each version's snapshot, so a pinned case reads its old baseline exactly", () => {
    const a = applyMarks(base, [mark("approved")], { by: "a", at: "t1", source: "s" });
    const b = applyMarks(a, [mark("not-allowed")], { by: "a", at: "t2", source: "s" });
    expect(baselineAt(b, 1)?.marks[0].verdict).toBe("approved");
    expect(baselineAt(b, 2)?.marks[0].verdict).toBe("not-allowed");
  });

  it("validates domains strictly and never drops a bad one silently", () => {
    expect(domainsInputSchema.safeParse({ blockedDomains: ["example.test", "not a domain"] }).success).toBe(
      false,
    );
    const p = applyDomains(
      base,
      domainsInputSchema.parse({ blockedDomains: ["Example.TEST"], blockedCategories: ["torrent"] }),
      {
        by: "a",
        at: "t",
        source: "s",
      },
    );
    expect(p.baseline.blockedDomains).toEqual(["example.test"]);
  });

  it("refuses a malformed hash instead of dropping it", () => {
    expect(
      markInputSchema.safeParse({ verdict: "approved", family: "program", program: "x", sha256: ["zz"] })
        .success,
    ).toBe(false);
  });

  it("refuses an approval with no path, naming the program and what to do instead (#2747)", () => {
    const r = markInputSchema.safeParse({ verdict: "approved", family: "installed", program: "7-Zip 23.01" });
    expect(r.success).toBe(false);
    expect(r.error?.issues[0].path).toEqual(["pathPattern"]);
    expect(r.error?.issues[0].message).toMatch(
      /"7-zip 23.01": no file path or hash; approve the program's files instead, or mark it Not allowed/,
    );
  });

  it("still accepts Not allowed and Unknown marks with no path (#2747)", () => {
    for (const verdict of ["not-allowed", "unknown"] as const)
      expect(
        markInputSchema.safeParse({ verdict, family: "installed", program: "7-Zip 23.01" }).success,
      ).toBe(true);
  });

  it("an empty-path approval stored before #2747 still loads and stays Unknown", async () => {
    const store = new ClientProfileStore(await mkdtemp(join(tmpdir(), "dfir-clients-")));
    const p = newProfile({ name: "Client A" }, "admin", "2026-01-01T00:00:00Z");
    const old = {
      id: "old",
      verdict: "approved" as const,
      family: "installed" as const,
      program: "7-zip 23.01",
      pathPattern: "",
      sha256: [],
      note: "",
      source: "client email",
      recordedBy: "admin",
      recordedAt: "2026-01-01T00:00:00Z",
    };
    await store.create({ ...p, baseline: { ...p.baseline, marks: [old] } });
    const loaded = await store.get(p.id);
    expect(loaded?.baseline.marks).toEqual([old]);
    const item = {
      family: "installed" as const,
      program: "7-zip 23.01",
      pathPattern: "",
      sha256: [],
      unhashedHosts: [],
      hashesCapped: false,
    };
    const v = itemVerdict(loaded!.baseline, item, "2026-06-01T00:00:00Z");
    expect(v.verdict).toBe("unknown");
    expect(v.reason).toMatch(/cannot be approved: no file path or hash/);
  });

  it("persists outside the case and refuses path-like ids", async () => {
    const store = new ClientProfileStore(await mkdtemp(join(tmpdir(), "dfir-clients-")));
    await store.create(base);
    expect((await store.get(base.id))?.name).toBe("Client A");
    expect(await store.get("../etc/passwd")).toBeNull();
    expect((await store.list()).map((p) => p.id)).toEqual([base.id]);
  });
});

describe("masking of client-profile values (#2670)", () => {
  it("registers the linked client's name and domains, and only for its own cases", async () => {
    const profile = applyDomains(
      newProfile({ name: "Client A" }, "a", "t"),
      domainsInputSchema.parse({ blockedDomains: ["blocked.example"], approvedDomains: ["ok.example"] }),
      { by: "a", at: "t", source: "s" },
    );
    const names = new HuntProfileNames(
      { load: async () => ({ hosts: ["WS-01"], usernames: ["bob"] }) },
      { load: async (c) => (c === "linked" ? { clientId: profile.id, linkedAt: "", linkedBy: "" } : null) },
      { get: async (id) => (id === profile.id ? profile : null) },
    );
    const linked = await names.load("linked");
    expect(linked.hosts).toEqual(
      expect.arrayContaining(["WS-01", "Client A", "blocked.example", "ok.example"]),
    );
    expect(linked.usernames).toEqual(["bob"]);
    expect((await names.load("other")).hosts).toEqual(["WS-01"]);
  });
});
