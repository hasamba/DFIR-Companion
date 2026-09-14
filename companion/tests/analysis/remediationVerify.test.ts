import { describe, expect, it } from "vitest";
import {
  boundaryWindow,
  normaliseArtifact,
  receiptNeedsOverride,
  taskLinkState,
  validateBoundaryInput,
  type RemediationBoundary,
} from "../../src/analysis/remediationBoundary.js";
import {
  commandLinePaths,
  COVERED_ROWS_MIN,
  matchArtifact,
  receiptIsStale,
  resolveSpellings,
  verifyBoundary,
  type VerifyInput,
} from "../../src/analysis/remediationVerify.js";
import { classifyHit, familyOf } from "../../src/analysis/remediationShapes.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { upgradeForensicEvent } from "../../src/analysis/canonicalEvent.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #930 item 9 (#969): the verify returns FACTS — hits by rule, what each row is, coverage per
// family — and never a negative verdict; the status is the analyst's, against a receipt.

const T = "2026-06-01T00:00:00.000Z";
const NOW = "2026-06-10T00:00:00.000Z";
const at = (h: number) => new Date(Date.parse(T) + h * 3_600_000).toISOString();
const PATH = "C:\\Users\\a\\Downloads\\evil.exe";

const ev = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: "e",
  timestamp: at(1),
  description: "d",
  severity: "Low",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS-042",
  sources: ["Sysmon"],
  ...over,
});
const start = (over: Partial<ForensicEvent> = {}): ForensicEvent =>
  ev({
    id: over.id ?? "s1",
    path: PATH,
    processName: "evil.exe",
    description: "Process create: evil.exe",
    canonical: { event: { category: "process", type: "start" }, file: { path: PATH } } as never,
    ...over,
  });
const boundary = (over: Partial<RemediationBoundary> = {}): RemediationBoundary => ({
  id: "rb-1",
  host: "ws-042",
  artifact: { kind: "path", value: PATH },
  remediatedAt: T,
  windowHours: 168,
  declaredAt: T,
  status: "unreviewed",
  evidence: [],
  receipts: [],
  ...over,
});
const input = (over: Partial<VerifyInput> = {}): VerifyInput => ({
  boundary: boundary(),
  now: NOW,
  forensic: [],
  superRows: [],
  superTruncated: false,
  superMeta: { rows: 0, generation: 1, hosts: [], hostsTruncated: false, atCap: false },
  superMetaAfter: { rows: 0, generation: 1 },
  forensicMeta: { rows: 0, updatedAt: T },
  forensicMetaAfter: { rows: 0, updatedAt: T },
  lastImportedAt: "",
  ...over,
});

describe("the boundary", () => {
  it("validates every field and names the failure; hashes lowercase, domains lowercase, ips parse", () => {
    const ok = validateBoundaryInput(
      { host: " WS-042 ", artifact: { kind: "hash", value: "ABCDEF".repeat(10) + "abcd" }, remediatedAt: T },
      NOW,
    );
    expect(ok.ok && ok.boundary.artifact.value).toBe("abcdef".repeat(10) + "abcd");
    expect(ok.ok && ok.boundary.windowHours).toBe(168);
    expect(ok.ok && ok.boundary.host).toBe("WS-042");
    expect(normaliseArtifact("hash", "xyz")).toMatchObject({ ok: false });
    expect(normaliseArtifact("ip", "300.1.1.1")).toMatchObject({ ok: false });
    expect(normaliseArtifact("ip", "10.0.0.7")).toMatchObject({ ok: true, value: "10.0.0.7" });
    expect(normaliseArtifact("domain", "C2.Evil.Example.")).toMatchObject({
      ok: true,
      value: "c2.evil.example",
    });
    expect(normaliseArtifact("domain", "not a domain")).toMatchObject({ ok: false });
    expect(normaliseArtifact("banana", "x")).toMatchObject({ ok: false });
    expect(
      validateBoundaryInput({ host: "", artifact: { kind: "path", value: "x" }, remediatedAt: T }, NOW),
    ).toMatchObject({ ok: false, error: "host is required" });
    expect(
      validateBoundaryInput(
        { host: "h", artifact: { kind: "path", value: "x" }, remediatedAt: "yesterday" },
        NOW,
      ),
    ).toMatchObject({ ok: false });
    expect(
      validateBoundaryInput(
        { host: "h", artifact: { kind: "path", value: "x" }, remediatedAt: T, windowHours: 0 },
        NOW,
      ),
    ).toMatchObject({ ok: false });
    expect(
      validateBoundaryInput(
        { host: "h", artifact: { kind: "path", value: "x" }, remediatedAt: T, windowHours: 721 },
        NOW,
      ),
    ).toMatchObject({ ok: false });
    expect(
      validateBoundaryInput(
        { host: "h", artifact: { kind: "path", value: "x" }, remediatedAt: "2027-01-01T00:00:00Z" },
        NOW,
      ),
    ).toMatchObject({ ok: false });
  });
  it("the window is clipped at now and says whether it is still open", () => {
    expect(boundaryWindow({ remediatedAt: T, windowHours: 168 }, NOW)).toMatchObject({ open: false });
    const open = boundaryWindow({ remediatedAt: T, windowHours: 720 }, NOW);
    expect(open.open).toBe(true);
    expect(open.toMs).toBe(Date.parse(NOW));
  });
  it("a task link is id + sourceKey; a title change is 'text changed', not orphaned", () => {
    const task = { id: "t1", sourceKey: "k1", title: "Remove the dropper" };
    expect(taskLinkState(task, [{ id: "t1", sourceKey: "k1", title: "Remove the dropper" }])).toBe("linked");
    expect(taskLinkState(task, [{ id: "t1", sourceKey: "k1", title: "Remove the dropper (reworded)" }])).toBe(
      "text-changed",
    );
    expect(taskLinkState(task, [{ id: "t1", sourceKey: "other", title: "Remove the dropper" }])).toBe(
      "orphaned",
    );
    expect(taskLinkState(task, [])).toBe("orphaned");
    expect(taskLinkState(undefined, [])).toBe("none");
  });
});

describe("host spellings", () => {
  it("equal canonical names pair; short labels under two domains never pair; a fleet alias adds a spelling", () => {
    const known = ["WS-042", "ws-042.corp.example", "ws-042.other.example", "WS-043"];
    expect(resolveSpellings("ws-042", known)).toEqual(["WS-042"]);
    expect(resolveSpellings("WS-042.corp.example", known)).toEqual(["ws-042.corp.example"]);
    const index = buildHostAliasIndex(
      [{ clientId: "C.1", hostname: "WS-042", fqdn: "ws-042.corp.example" }],
      {},
    );
    expect(resolveSpellings("ws-042", known, index)).toEqual(["WS-042", "ws-042.corp.example"]);
    expect(resolveSpellings("ws-042", known, index)).not.toContain("ws-042.other.example");
  });
});

describe("matching by rule", () => {
  it("path: full path exact under separators and case; basename only weak; command-line tokens", () => {
    expect(matchArtifact(start({ path: "c:/users/a/downloads/EVIL.EXE" }), "path", PATH)).toMatchObject({
      strength: "exact",
    });
    expect(
      matchArtifact(start({ path: "C:\\Other\\evil.exe", canonical: undefined }), "path", PATH),
    ).toMatchObject({ strength: "weak" });
    expect(
      matchArtifact(start({ path: "C:\\Other\\good.exe", canonical: undefined }), "path", PATH),
    ).toBeNull();
    expect(commandLinePaths('"C:\\Temp\\evil.exe" -x C:\\data\\f.txt')).toEqual([
      "C:\\Temp\\evil.exe",
      "C:\\data\\f.txt",
    ]);
    const cmd = ev({
      commandLine: `"${PATH}" -x`,
      canonical: { event: { category: "process", type: "start" } } as never,
    });
    expect(matchArtifact(cmd, "path", PATH)).toMatchObject({ strength: "exact", on: "commandLine" });
    expect(matchArtifact(cmd, "path", "C:\\Other\\evil.exe")).toMatchObject({ strength: "weak" });
  });
  it("hash: case-folded both sides, exact only; account: equal domains exact, one unqualified side weak, other domain no match", () => {
    const sha = "A".repeat(64);
    expect(matchArtifact(ev({ sha256: sha }), "hash", sha.toLowerCase())).toMatchObject({
      strength: "exact",
    });
    expect(matchArtifact(ev({ sha256: "b".repeat(64) }), "hash", sha.toLowerCase())).toBeNull();
    const acct = (name: string) =>
      ev({ canonical: { event: { category: "authentication", type: "logon" }, account: { name } } as never });
    expect(matchArtifact(acct("CORP\\svc"), "account", "corp\\SVC")).toMatchObject({ strength: "exact" });
    expect(matchArtifact(acct("LAB\\svc"), "account", "CORP\\svc")).toBeNull();
    expect(matchArtifact(acct("svc"), "account", "CORP\\svc")).toMatchObject({ strength: "weak" });
    expect(matchArtifact(acct("svc@corp.example"), "account", "svc@corp.example")).toMatchObject({
      strength: "exact",
    });
    // A conflicting candidate first does not hide the exact one after it (code round 1).
    const two = ev({
      canonical: {
        event: { category: "authentication", type: "logon" },
        account: { name: "LAB\\svc" },
        actor: { kind: "account", name: "CORP\\svc" },
      } as never,
    });
    expect(matchArtifact(two, "account", "CORP\\svc")).toMatchObject({ strength: "exact", on: "actor" });
    // SHA-1 is refused at declaration: no row carries one, so it could never match.
    expect(normaliseArtifact("hash", "a".repeat(40))).toMatchObject({ ok: false });
  });
  it("domain / ip: addresses exact, description token weak on word boundaries; service/task/regkey by name", () => {
    expect(matchArtifact(ev({ dstIp: "10.0.0.7" }), "ip", "10.0.0.7")).toMatchObject({
      strength: "exact",
      on: "dstIp",
    });
    expect(
      matchArtifact(ev({ description: "beacon to c2.evil.example:443" }), "domain", "c2.evil.example"),
    ).toMatchObject({ strength: "weak" });
    expect(matchArtifact(ev({ description: "notc2.evil.example" }), "domain", "c2.evil.example")).toBeNull();
    expect(
      matchArtifact(
        ev({
          canonical: {
            event: { category: "service", type: "service" },
            service: { name: "EvilSvc" },
          } as never,
        }),
        "service",
        "evilsvc",
      ),
    ).toMatchObject({ strength: "exact" });
    expect(
      matchArtifact(ev({ description: "Scheduled task \\Updater created" }), "task", "\\Updater"),
    ).toMatchObject({ strength: "weak" });
  });
});

describe("what a hit is (real importer shapes)", () => {
  const sysmon = parseSiemExport(
    JSON.stringify([
      {
        "@timestamp": at(1),
        log_name: "Microsoft-Windows-Sysmon/Operational",
        computer_name: "WS-042",
        event_id: 1,
        event_data: {
          Image: PATH,
          CommandLine: `"${PATH}"`,
          ParentImage: "C:\\Windows\\explorer.exe",
          Hashes: `SHA256=${"a".repeat(64)}`,
        },
      },
      {
        "@timestamp": at(2),
        log_name: "Microsoft-Windows-Windows Defender/Operational",
        computer_name: "WS-042",
        event_id: 1116,
        event_data: { "Threat Name": "Trojan:Win32/X", Path: `file:_${PATH}` },
      },
    ]),
  ).events.map((e) => upgradeForensicEvent(e as unknown as ForensicEvent));
  it("a Sysmon 1 is activity; a Defender 1116 is a detection; Prefetch/Amcache/ShimCache are presence; an MFT row older than the boundary is a listing", () => {
    expect(classifyHit(sysmon[0], Date.parse(T)).cls).toBe("activity");
    expect(classifyHit(sysmon[1], Date.parse(T)).cls).toBe("detection");
    for (const src of ["Prefetch", "Amcache", "ShimCache"]) {
      const e = upgradeForensicEvent(ev({ sources: [src], path: PATH, processName: "evil.exe" }));
      expect(classifyHit(e, Date.parse(T)), src).toMatchObject({ cls: "presence" });
    }
    const mft = upgradeForensicEvent(ev({ sources: ["MFT"], path: PATH, fileModified: at(-48) }));
    expect(classifyHit(mft, Date.parse(T)).cls).toBe("listing-of-older-object");
    const mftNewer = upgradeForensicEvent(ev({ sources: ["MFT"], path: PATH, fileModified: at(3) }));
    expect(classifyHit(mftNewer, Date.parse(T)).cls).toBe("unclassified");
    // A Sysmon 11 keys `path` to the creating image; the created file is in the text — a weak
    // description match — and the untyped `other/event` from Sysmon reads as activity.
    const sysmon11 = parseSiemExport(
      JSON.stringify([
        {
          "@timestamp": at(2),
          log_name: "Microsoft-Windows-Sysmon/Operational",
          computer_name: "WS-042",
          event_id: 11,
          event_data: { TargetFilename: PATH, Image: "C:\\Windows\\explorer.exe" },
        },
      ]),
    ).events.map((e) => upgradeForensicEvent(e as unknown as ForensicEvent))[0];
    expect(matchArtifact(sysmon11, "path", PATH)).toMatchObject({ strength: "weak", on: "description" });
    expect(classifyHit(sysmon11, Date.parse(T))).toMatchObject({ cls: "activity" });
    const unknown = ev({ canonical: { event: { category: "email", type: "message" } } as never });
    expect(classifyHit(unknown, Date.parse(T))).toMatchObject({
      cls: "unclassified",
      note: "shape email/message is not in the table",
    });
    expect(familyOf(sysmon[0])).toBe("process");
    expect(familyOf(sysmon[1])).toBe("defender");
  });
});

describe("verifyBoundary — facts, never a verdict", () => {
  it("finds the start after the boundary on an alias spelling, classifies it, reports coverage per family, and says no negative", () => {
    const rows = [
      start({ id: "s0", timestamp: at(-2) }), // before the boundary: not a hit
      start({ id: "s1", timestamp: at(5), asset: "ws-042" }),
      start({ id: "s2", timestamp: at(6), asset: "WS-043" }), // another host
      ev({ id: "u1", timestamp: "", asset: "WS-042" }), // undated
    ];
    const facts = verifyBoundary(
      input({
        forensic: rows,
        superMeta: { rows: 0, generation: 1, hosts: ["WS-042"], hostsTruncated: false, atCap: false },
      }),
    );
    expect(facts.spellings).toEqual(["WS-042", "ws-042"]);
    expect(facts.hits.map((h) => h.id)).toEqual(["s1"]);
    expect(facts.hits[0]).toMatchObject({ cls: "activity", strength: "exact", store: "forensic" });
    expect(facts.undated).toBe(1);
    expect(facts.families.find((f) => f.family === "process")).toMatchObject({
      relevant: true,
      rowsInWindow: 1,
      state: "partial",
    });
    expect(facts.coverageGapped).toBe(true);
    expect(facts.sentence).toContain("Only you can say the foothold is gone");
    expect(JSON.stringify(facts)).not.toMatch(/clean|no recurrence|foothold is gone\b(?!\.")/);
    expect(facts.receipt.hitIds).toEqual(["s1"]);
    // The receipt holds ids and counts, never a row's text.
    expect(JSON.stringify(facts.receipt)).not.toContain("Process create");
  });
  it("coverage: a family is covered only with enough rows spanning most of the window", () => {
    const many = Array.from({ length: COVERED_ROWS_MIN }, (_, i) =>
      ev({
        id: `p${i}`,
        timestamp: at(1 + (i * 166) / (COVERED_ROWS_MIN - 1)),
        path: "C:\\x\\other.exe",
        canonical: { event: { category: "process", type: "start" } } as never,
      }),
    );
    const covered = verifyBoundary(input({ forensic: many }));
    expect(covered.families.find((f) => f.family === "process")!.state).toBe("covered");
    const few = verifyBoundary(input({ forensic: many.slice(0, 3) }));
    expect(few.families.find((f) => f.family === "process")!.state).toBe("partial");
    const clustered = verifyBoundary(
      input({ forensic: many.map((e, i) => ({ ...e, timestamp: at(1 + i / 60) })) }),
    );
    expect(clustered.families.find((f) => f.family === "process")!.state).toBe("partial");
    expect(covered.coverageGapped).toBe(true); // file-listing and defender still absent for a path
  });
  it("the forensic copy wins the union; super rows count as super; truncation, cap, inconsistency and the late-import note are said", () => {
    const superCopy = start({ id: "s1", timestamp: at(5), description: "raw copy" });
    const forensicCopy = start({ id: "s1", timestamp: at(5), description: "curated copy" });
    const facts = verifyBoundary(
      input({
        forensic: [forensicCopy],
        superRows: [superCopy, start({ id: "s9", timestamp: at(7) })],
        superTruncated: true,
        superMeta: { rows: 100_000, generation: 3, hosts: ["WS-042"], hostsTruncated: false, atCap: true },
        superMetaAfter: { rows: 100_000, generation: 4 },
        lastImportedAt: at(9),
      }),
    );
    expect(facts.hits.map((h) => [h.id, h.store, h.description])).toEqual([
      ["s1", "forensic", "curated copy"],
      ["s9", "super", "Process create: evil.exe"],
    ]);
    // The receipt keeps forensic ids only; a raw row is a count until the analyst attaches it.
    expect(facts.receipt.hitIds).toEqual(["s1"]);
    expect(facts.receipt.superHitTotal).toBe(1);
    expect(facts.truncated).toBe(true);
    expect(facts.retentionNote).toContain("retention cap");
    expect(facts.inconsistent).toBe(true);
    expect(facts.lateImportNote).toContain("cannot be told from one present before it");
    expect(facts.lateImportNote).toContain(at(9));
    expect(receiptNeedsOverride(facts.receipt)).toEqual(
      expect.arrayContaining(["the read was truncated", "the stores changed while the read ran"]),
    );
  });
  it("with alignment on, recorded times stand and a hit that crosses the boundary once corrected is flagged; the receipt goes stale when a store moves", () => {
    const offsets = new Map([["ws-042", 6 * 3_600_000]]); // the host's clock runs 6 h fast
    const facts = verifyBoundary(
      input({
        forensic: [start({ id: "s1", timestamp: at(5) }), start({ id: "s2", timestamp: at(30) })],
        offsets,
        forensicMeta: { rows: 2, updatedAt: T },
        forensicMetaAfter: { rows: 2, updatedAt: T },
      }),
    );
    expect(facts.clock).toMatchObject({ alignment: "on", offsetMs: 6 * 3_600_000 });
    expect(facts.hits.find((h) => h.id === "s1")!.changesSideWhenAligned).toBe(true);
    expect(facts.hits.find((h) => h.id === "s2")!.changesSideWhenAligned).toBeUndefined();
    expect(facts.hits.find((h) => h.id === "s1")!.timestamp).toBe(at(5));
    expect(
      receiptIsStale(facts.receipt, {
        forensic: { rows: 2, updatedAt: T },
        super: { rows: 0, generation: 1 },
      }),
    ).toBe(false);
    expect(
      receiptIsStale(facts.receipt, {
        forensic: { rows: 2, updatedAt: T },
        super: { rows: 0, generation: 2 },
      }),
    ).toBe(true);
    expect(
      receiptIsStale(facts.receipt, {
        forensic: { rows: 3, updatedAt: T },
        super: { rows: 0, generation: 1 },
      }),
    ).toBe(true);
    // The forensic store moving during the read marks the receipt inconsistent too.
    const moved = verifyBoundary(
      input({ forensicMeta: { rows: 2, updatedAt: T }, forensicMetaAfter: { rows: 3, updatedAt: at(1) } }),
    );
    expect(moved.inconsistent).toBe(true);
    expect(moved.receipt.highWater.forensic).toEqual({ rows: 3, updatedAt: at(1) });
    // More distinct host spellings than the read: truncated, said why.
    const hosts = verifyBoundary(
      input({ superMeta: { rows: 0, generation: 1, hosts: [], hostsTruncated: true, atCap: false } }),
    );
    expect(hosts.truncated).toBe(true);
    expect(hosts.truncatedBy).toContain("distinct host spellings");
  });
});
