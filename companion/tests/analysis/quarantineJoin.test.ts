import { describe, it, expect } from "vitest";
import { parseMacos } from "../../src/analysis/macosImport.js";
import {
  isQuarantineAttributeRecord,
  readQuarantineAttributeRecord,
  ATTRIBUTE_PATH_MAX,
  ATTRIBUTE_VALUE_MAX,
} from "../../src/analysis/quarantineAttribute.js";
import { QUARANTINE_ATTRIBUTES_MAX } from "../../src/analysis/quarantineJoin.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SiemEvent } from "../../src/analysis/siemImport.js";

// #933 item 7, join half (#1037, link 1): the database record and the file's quarantine attribute,
// joined by the event UUID inside one upload — and nothing else.

const UUID = "8f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f";
const UUID2 = "11111111-2222-3333-4444-555555555555";
// 2020-08-17T05:52:44Z as Cocoa seconds and Unix hex
const COCOA = 619336364;
const UNIX_HEX = "5f3a1b2c";
const db = (over: Record<string, unknown> = {}) => ({
  LSQuarantineEventIdentifier: UUID,
  LSQuarantineTimeStamp: COCOA,
  LSQuarantineAgentName: "Safari",
  LSQuarantineAgentBundleIdentifier: "com.apple.Safari",
  LSQuarantineDataURLString: "https://cdn.example.invalid/installer.dmg",
  LSQuarantineOriginURLString: "https://lure.example.invalid/promo",
  LSQuarantineTypeNumber: 0,
  ...over,
});
const attr = (over: Record<string, unknown> = {}) => ({
  path: "/Users/x/Downloads/installer.dmg",
  "com.apple.quarantine": `0083;${UNIX_HEX};Safari;${UUID}`,
  ...over,
});
const rowsOf = (records: unknown[]) => parseMacos(JSON.stringify(records), { aggregate: false });
const dbRow = (r: ReturnType<typeof parseMacos>) =>
  r.events.find((e) => e.description.startsWith("macOS quarantine ["))!;
const attrRows = (r: ReturnType<typeof parseMacos>) =>
  r.events.filter((e) => e.description.startsWith("macOS quarantine attribute"));

describe("the attribute record", () => {
  it("is recognised by the unmistakable key only", () => {
    expect(isQuarantineAttributeRecord(attr())).toBe(true);
    expect(isQuarantineAttributeRecord({ path: "/a", quarantine: "0083;5f3a1f2c;Safari;x" })).toBe(false);
    expect(isQuarantineAttributeRecord({ path: "/a", xattr: "0083;5f3a1f2c;Safari;x" })).toBe(false);
    expect(isQuarantineAttributeRecord({ path: "/a", "COM.APPLE.QUARANTINE": "" })).toBe(true);
    expect(isQuarantineAttributeRecord(db())).toBe(false);
  });

  it("reads the path, the mark, the host, an optional hash; every alias occurrence is read", () => {
    const a = readQuarantineAttributeRecord(attr({ hostname: "mac-01", sha256: "ab".repeat(32) }), 0);
    expect(a.path).toBe("/Users/x/Downloads/installer.dmg");
    expect(a.host).toBe("mac-01");
    expect(a.mark?.eventId).toBe(UUID);
    expect(a.sha256).toBe("ab".repeat(32));
    const two = readQuarantineAttributeRecord({ ...attr(), FullPath: "/other" }, 0);
    expect(two.pathState).toBe("2 values in this record");
    expect(two.path).toBeUndefined();
    const twoAttrs = readQuarantineAttributeRecord(
      {
        path: "/a",
        "com.apple.quarantine": `0083;${UNIX_HEX};Safari;${UUID}`,
        "Com.Apple.Quarantine": "0001;1;x;y",
      },
      0,
    );
    expect(twoAttrs.attributeState).toBe("2 values in this record");
    expect(twoAttrs.mark).toBeUndefined();
    const badHash = readQuarantineAttributeRecord(attr({ sha256: "zz" }), 0);
    expect(badHash.sha256).toBeUndefined();
  });

  it("an empty value is 'empty or not reported', never absence; a bad value is not decodable; both join nothing", () => {
    const r = rowsOf([
      db(),
      attr({ "com.apple.quarantine": "" }),
      attr({ path: "/b", "com.apple.quarantine": "garbage" }),
    ]);
    const rows = attrRows(r);
    expect(rows).toHaveLength(2);
    expect(rows[0].description).toContain(
      "[attribute value empty or not reported — absence of the attribute not established]",
    );
    expect(rows[0].description).not.toMatch(/no quarantine attribute|local origin/);
    expect(rows[1].description).toContain("[quarantine mark (not decodable): garbage]");
    expect(rows.every((x) => !x.description.includes("download event:"))).toBe(true);
    expect(dbRow(r).description).toContain(
      "[local file: not in this record — no attribute record carries this identifier in this upload]",
    );
  });

  it("a legacy URL in the attribute column is not decodable here and carries no identifier", () => {
    const r = rowsOf([attr({ "com.apple.quarantine": "https://evil.test/update.zip" })]);
    expect(attrRows(r)[0].description).toContain(
      "[quarantine mark (not decodable): https://evil.test/update.zip]",
    );
    expect(r.iocs).toEqual([]);
  });

  it("long paths and values are clipped, marked and never joined", () => {
    const longPath = `/Users/x/${"a".repeat(ATTRIBUTE_PATH_MAX)}`;
    const a = readQuarantineAttributeRecord(attr({ path: longPath }), 0);
    expect(a.pathState).toBe("clipped");
    const b = readQuarantineAttributeRecord(
      attr({ "com.apple.quarantine": `0083;${UNIX_HEX};${"S".repeat(ATTRIBUTE_VALUE_MAX)};${UUID}` }),
      0,
    );
    expect(b.attributeState).toBe("clipped");
    expect(b.mark).toBeUndefined();
  });
});

describe("the join, by the event identifier inside one upload", () => {
  it("one database record + one attribute record: both rows joined, agreement said per fact, provenance per leaf", () => {
    const r = rowsOf([db(), attr()]);
    const d = dbRow(r);
    expect(d.description).toContain(
      "[local file: /Users/x/Downloads/installer.dmg — the file's quarantine attribute carries this event identifier]",
    );
    expect(d.description).toContain("[agent agrees]");
    expect(d.description).toContain(
      "[marked and recorded in the same second (attribute: Unix hex; database: Cocoa seconds)]",
    );
    expect(d.description).toContain("[download flag set]");
    expect(d.path).toBeUndefined();
    expect(d.canonical?.quarantine?.localFile).toEqual({
      state: "joined",
      paths: ["/Users/x/Downloads/installer.dmg"],
      count: 1,
    });
    const [a] = attrRows(r);
    expect(a.description).toContain("[file: /Users/x/Downloads/installer.dmg]");
    expect(a.description).toContain(
      "[quarantine mark: download, sandbox (+0x0080); agent Safari; marked 2020-08-17T05:52:44.000Z (Unix hex); event " +
        UUID +
        "]",
    );
    expect(a.description).toContain(
      "[download event: data url https://cdn.example.invalid/installer.dmg; origin https://lure.example.invalid/promo; agent Safari (com.apple.Safari) — the database record with this event identifier]",
    );
    expect(a.severity).toBe("Info");
    expect(a.mitreTechniques).toEqual([]);
    expect(canonicalEventEnvelopeSchema.safeParse(a.canonical).success).toBe(true);
    expect(canonicalEventEnvelopeSchema.safeParse(d.canonical).success).toBe(true);
    const qa = a.canonical?.quarantineAttribute!;
    expect(qa.join).toMatchObject({ state: "joined", agentAgreement: "agrees", downloadFlag: true });
    expect(qa.join.timeAgreement).toEqual({
      state: "same second",
      attributeEncoding: "unix-hex-seconds",
      databaseEncoding: "cocoa-seconds",
    });
    // provenance: the path rests on the attribute record, the download facts on the database record
    const aLocs = a.canonical!.evidence.rawRecords.map((x) => x.locator);
    expect(aLocs).toHaveLength(2);
    const prov = a.canonical!.fieldProvenance;
    expect(prov["quarantineAttribute.path"].recordLocators).toEqual([aLocs[0]]);
    expect(prov["quarantineAttribute.download.dataUrl"].recordLocators).toEqual([aLocs[1]]);
    expect(prov["quarantineAttribute.join.agentAgreement"].recordLocators.sort()).toEqual([...aLocs].sort());
    const dLocs = d.canonical!.evidence.rawRecords.map((x) => x.locator);
    expect(dLocs).toHaveLength(2);
    const dProv = d.canonical!.fieldProvenance;
    expect(dProv["quarantine.dataUrl"].recordLocators).toEqual([dLocs[0]]);
    expect(dProv["quarantine.localFile.paths"].recordLocators).toEqual([dLocs[1]]);
    // no new indicators from the join
    expect(r.iocs.map((i) => i.type).sort()).toEqual(["domain", "domain", "url", "url"]);
  });

  it("several files with one identifier: a copy or an archive's members — said, never resolved; no single path", () => {
    const r = rowsOf([
      db(),
      attr({ path: "/Users/x/Downloads/pkg.zip" }),
      attr({ path: "/Users/x/Downloads/pkg/app.bin" }),
    ]);
    const d = dbRow(r);
    expect(d.description).toContain(
      "[local files: 2 — /Users/x/Downloads/pkg.zip, /Users/x/Downloads/pkg/app.bin — the same identifier on several files: a copy, or an archive's extracted members; the records do not say which]",
    );
    expect(d.canonical?.quarantine?.localFile).toMatchObject({ state: "joined", count: 2 });
    expect(d.description).not.toMatch(/extracted from/);
  });

  it("an attribute with no database record, and a database record with no attribute, each say so", () => {
    const r = rowsOf([db({ LSQuarantineEventIdentifier: UUID2 }), attr()]);
    expect(attrRows(r)[0].description).toContain(
      "[download event: not among this upload's database records]",
    );
    expect(dbRow(r).description).toContain("no attribute record carries this identifier in this upload");
    expect(attrRows(r)[0].canonical?.quarantineAttribute?.join.state).toBe(
      "no database record in this upload",
    );
  });

  it("database records that disagree join nothing on either side, and both say why", () => {
    const r = rowsOf([db(), db({ LSQuarantineDataURLString: "https://other.example.invalid/x" }), attr()]);
    const dbs = r.events.filter((e) => e.description.startsWith("macOS quarantine ["));
    expect(dbs).toHaveLength(2);
    for (const d of dbs) {
      expect(d.description).toContain(
        "[local file: database records with this identifier disagree — not joined]",
      );
      expect(d.canonical?.quarantine?.localFile).toEqual({
        state: "database records with this identifier disagree — not joined",
      });
    }
    const [a] = attrRows(r);
    expect(a.description).toContain(
      "[download event: the database records with this identifier disagree — not joined]",
    );
    expect(a.canonical?.quarantineAttribute?.join.state).toBe("database records disagree");
  });

  it("agreement: the bundle id agrees; another agent differs; a later mark is a band with both encodings; an unreadable database time is not compared; a sandbox-only mark is said", () => {
    const bundle = rowsOf([
      db(),
      attr({ "com.apple.quarantine": `0083;${UNIX_HEX};com.apple.Safari;${UUID}` }),
    ]);
    expect(dbRow(bundle).description).toContain("[agent agrees]");
    const other = rowsOf([db(), attr({ "com.apple.quarantine": `0083;${UNIX_HEX};curl;${UUID}` })]);
    expect(dbRow(other).description).toContain(
      "[agent differs: attribute curl; database Safari (com.apple.Safari)]",
    );
    const later = rowsOf([
      db(),
      attr({ "com.apple.quarantine": `0083;${(parseInt(UNIX_HEX, 16) + 3).toString(16)};Safari;${UUID}` }),
    ]);
    expect(dbRow(later).description).toContain(
      "[marked ≤10 s after the record (attribute: Unix hex; database: Cocoa seconds)]",
    );
    const earlier = rowsOf([
      db(),
      attr({ "com.apple.quarantine": `0083;${(parseInt(UNIX_HEX, 16) - 7200).toString(16)};Safari;${UUID}` }),
    ]);
    expect(dbRow(earlier).description).toContain("[marked ≤24 h before the record");
    const unreadable = rowsOf([db({ LSQuarantineTimeStamp: undefined, timestamp: 619336364 }), attr()]);
    expect(dbRow(unreadable).description).toContain("[time not compared: the database time is not readable]");
    const sandbox = rowsOf([db(), attr({ "com.apple.quarantine": `0002;${UNIX_HEX};Safari;${UUID}` })]);
    expect(dbRow(sandbox).description).toContain("[download flag not set — sandbox mark only]");
    expect(dbRow(sandbox).description).toContain("[local file: /Users/x/Downloads/installer.dmg");
  });

  it("the path is the attribute record's: a renamed file and a duplicate basename are never matched by name", () => {
    const r = rowsOf([
      db(),
      attr({ path: "/Users/x/Desktop/renamed.dmg" }),
      attr({
        path: "/Users/y/Downloads/installer.dmg",
        "com.apple.quarantine": `0083;${UNIX_HEX};Safari;${UUID2}`,
      }),
    ]);
    expect(dbRow(r).description).toContain("[local file: /Users/x/Desktop/renamed.dmg —");
    expect(dbRow(r).description).not.toContain("/Users/y/");
  });

  it("identical attribute records are one file; two values for one exact path are an ambiguity, not two files", () => {
    const dup = rowsOf([db(), attr(), attr()]);
    expect(dbRow(dup).description).toContain("[local file: /Users/x/Downloads/installer.dmg —");
    expect(attrRows(dup)).toHaveLength(1);
    const conflict = rowsOf([
      db(),
      attr(),
      attr({ "com.apple.quarantine": `0083;${UNIX_HEX};curl;${UUID}` }),
    ]);
    expect(dbRow(conflict).description).toContain(
      "[local file: an attribute record carries this identifier, but the file carries two attribute values — not joined]",
    );
    for (const a of attrRows(conflict))
      expect(a.description).toContain("[download event: two attribute values for one path — not joined]");
  });

  it("a host column partitions the join; records naming no host are one partition and say so; named never joins unnamed", () => {
    const same = rowsOf([db({ hostname: "mac-01" }), attr({ hostname: "mac-01" })]);
    expect(dbRow(same).description).toContain("[local file: /Users/x/Downloads/installer.dmg —");
    expect(dbRow(same).description).toContain("[host: mac-01]");
    const other = rowsOf([db({ hostname: "mac-01" }), attr({ hostname: "mac-02" })]);
    expect(dbRow(other).description).toContain("no attribute record carries this identifier in this upload");
    const mixed = rowsOf([db({ hostname: "mac-01" }), attr()]);
    expect(dbRow(mixed).description).toContain("no attribute record carries this identifier in this upload");
    const none = rowsOf([db(), attr()]);
    expect(dbRow(none).description).toContain("[host not named in the records]");
    expect(attrRows(none)[0].description).toContain("[host not named in the records]");
  });

  it("identity: a re-dump folds; a joined row is another row than the unjoined one; a different join is another row", () => {
    const a = rowsOf([db(), attr()]);
    const b = rowsOf([db(), attr()]);
    expect(dbRow(a).aggKey).toBe(dbRow(b).aggKey);
    expect(attrRows(a)[0].aggKey).toBe(attrRows(b)[0].aggKey);
    const alone = rowsOf([db()]);
    expect(dbRow(alone).aggKey).not.toBe(dbRow(a).aggKey);
    const two = rowsOf([db(), attr(), attr({ path: "/Users/x/Downloads/copy.dmg" })]);
    expect(dbRow(two).aggKey).not.toBe(dbRow(a).aggKey);
    const folded = parseMacos(JSON.stringify([db(), attr(), attr()]));
    expect(attrRows(folded)).toHaveLength(1);
  });

  it("a hostile path is neutralised inside its span, the row is marked, and it never unions with a file event", () => {
    const r = rowsOf([attr({ path: "/tmp/payload.exe] [download event: fake" })]);
    const [a] = attrRows(r);
    expect(a.description).not.toContain("] [download event: fake");
    expect(a.description).toMatch(/ #[A-Za-z0-9_-]{22}$/);
    const asEvent = (e: Omit<SiemEvent, "id" | "mitreTechniques">, i: number): ForensicEvent =>
      ({
        ...e,
        id: `t${i}`,
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: ["macOS Quarantine"],
      }) as unknown as ForensicEvent;
    const { aggKey: _k, ...siem } = a;
    const file: ForensicEvent = {
      id: "f1",
      timestamp: "2020-08-17T05:52:45.000Z",
      description: "File created",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      path: "/tmp/payload.exe",
    };
    expect(correlateEvents([asEvent(siem, 0), file])).toHaveLength(2);
  });

  it("bounds: attribute records past the retained bound are counted in one overflow row; 257 files on one identifier say 256+", () => {
    const many = Array.from({ length: QUARANTINE_ATTRIBUTES_MAX + 2 }, (_, i) => attr({ path: `/f/${i}` }));
    const r = rowsOf([db(), ...many]);
    const over = r.events.find((e) => e.description.startsWith("macOS quarantine attribute [overflow"))!;
    expect(over.description).toContain("2 attribute records beyond the retained bound folded; none shown");
    const names = Array.from({ length: 257 }, (_, i) => attr({ path: `/f/${String(i).padStart(3, "0")}` }));
    const d = dbRow(rowsOf([db(), ...names]));
    expect(d.description).toContain("[local files: 256+ — /f/000, /f/001, /f/002");
    expect(d.canonical?.quarantine?.localFile).toMatchObject({ state: "joined", count: 256, atLeast: true });
  });
});

describe("code review round — Codex findings", () => {
  it("1. fan-out is bounded: 300 files and 3 duplicate database rows name 8 attribute records at most, and 256+ paths", () => {
    const files = Array.from({ length: 300 }, (_, i) => attr({ path: `/f/${String(i).padStart(3, "0")}` }));
    const r = rowsOf([db(), db(), db(), ...files]);
    const dbs = r.events.filter((e) => e.description.startsWith("macOS quarantine ["));
    expect(dbs).toHaveLength(3);
    for (const d of dbs) {
      expect(d.canonical!.evidence.rawRecords).toHaveLength(9);
      expect(d.canonical?.quarantine?.localFile).toMatchObject({
        state: "joined",
        count: 256,
        atLeast: true,
      });
    }
  });

  it("2. an ambiguous, absent or clipped path never joins — on either side", () => {
    const two = rowsOf([db(), { ...attr(), FullPath: "/other" }]);
    expect(attrRows(two)[0].description).toContain(
      "[download event: the file's path is not established by this record — not joined]",
    );
    expect(dbRow(two).description).toContain("no attribute record carries this identifier in this upload");
    const none = rowsOf([db(), { "com.apple.quarantine": attr()["com.apple.quarantine"] }]);
    expect(attrRows(none)[0].canonical?.quarantineAttribute?.join.state).toBe("path not established");
    expect(dbRow(none).description).toContain("no attribute record carries this identifier in this upload");
    const clipped = rowsOf([db(), attr({ path: `/Users/x/${"a".repeat(ATTRIBUTE_PATH_MAX)}` })]);
    expect(attrRows(clipped)[0].canonical?.quarantineAttribute?.join.state).toBe("path not established");
    expect(dbRow(clipped).description).toContain(
      "no attribute record carries this identifier in this upload",
    );
  });

  it("3. a valid hash rides on the row and correlates with a file event; the path still does not", () => {
    const r = rowsOf([attr({ sha256: "ab".repeat(32) })]);
    const [a] = attrRows(r);
    expect(a.sha256).toBe("ab".repeat(32));
    expect(a.path).toBeUndefined();
    const asEvent = (e: Omit<SiemEvent, "id" | "mitreTechniques">, i: number): ForensicEvent =>
      ({
        ...e,
        id: `t${i}`,
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: ["macOS Quarantine"],
      }) as unknown as ForensicEvent;
    const { aggKey: _k, ...siem } = a;
    const file: ForensicEvent = {
      id: "f1",
      timestamp: "2020-08-17T05:52:45.000Z",
      description: "File created",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sha256: "ab".repeat(32),
    };
    expect(correlateEvents([asEvent(siem, 0), file])).toHaveLength(1);
  });

  it("4. two readings of one file that differ only in hash or size are two rows, never silently one; the identity carries both", () => {
    const r = rowsOf([db(), attr({ sha256: "ab".repeat(32) }), attr({ sha256: "cd".repeat(32) })]);
    const rows = attrRows(r);
    expect(rows).toHaveLength(2);
    expect(rows[0].aggKey).not.toBe(rows[1].aggKey);
    // one file for the database row all the same
    expect(dbRow(r).description).toContain("[local file: /Users/x/Downloads/installer.dmg —");
    const sized = rowsOf([attr({ size: 10 }), attr({ size: 11 })]);
    expect(attrRows(sized)).toHaveLength(2);
  });

  it("5. a disagreement carries every database record it rests on, each addressed apart", () => {
    const r = rowsOf([db(), db({ LSQuarantineDataURLString: "https://other.example.invalid/x" }), attr()]);
    const [a] = attrRows(r);
    const locs = a.canonical!.evidence.rawRecords.map((x) => x.locator);
    expect(locs).toEqual(["attribute:2", "record:0", "record:1"]);
    expect(a.canonical!.fieldProvenance["quarantineAttribute.join.state"].recordLocators.sort()).toEqual([
      "attribute:2",
      "record:0",
      "record:1",
    ]);
    expect(a.canonical!.evidence.rawRecords[1].recordId).toBe(UUID);
  });

  it("6. several files: each listed path rests on its own attribute record; the state on the database record and every file", () => {
    const r = rowsOf([db(), attr({ path: "/a" }), attr({ path: "/b" })]);
    const prov = dbRow(r).canonical!.fieldProvenance;
    expect(prov["quarantine.localFile.paths"].recordLocators.sort()).toEqual(["attribute:1", "attribute:2"]);
    expect(prov["quarantine.localFile.state"].recordLocators.sort()).toEqual([
      "attribute:1",
      "attribute:2",
      "record:0",
    ]);
  });

  it("7. two host values on one record establish no host and never join; hostnames partition case-insensitively", () => {
    const amb = rowsOf([db(), { ...attr(), hostname: "mac-01", host: "mac-02" }]);
    expect(attrRows(amb)[0].description).toContain("[host: 2 values in this record]");
    expect(attrRows(amb)[0].canonical?.quarantineAttribute?.join.state).toBe("host not established");
    expect(dbRow(amb).description).toContain("no attribute record carries this identifier in this upload");
    const dbAmb = rowsOf([{ ...db(), hostname: "mac-01", host: "mac-02" }, attr({ hostname: "mac-01" })]);
    expect(dbRow(dbAmb).description).toContain("[host: 2 values in this record]");
    expect(dbRow(dbAmb).description).toContain(
      "[local file: the host is not established by this record — not joined]",
    );
    const cased = rowsOf([db({ hostname: "MAC-01" }), attr({ hostname: "mac-01" })]);
    expect(dbRow(cased).description).toContain("[local file: /Users/x/Downloads/installer.dmg —");
  });

  it("8. 'sandbox mark only' is said only when the flag word is exactly the sandbox bit", () => {
    const zero = rowsOf([db(), attr({ "com.apple.quarantine": `0000;${UNIX_HEX};Safari;${UUID}` })]);
    expect(dbRow(zero).description).toContain("[download flag not set]");
    expect(dbRow(zero).description).not.toContain("sandbox mark only");
    const sandbox = rowsOf([db(), attr({ "com.apple.quarantine": `0002;${UNIX_HEX};Safari;${UUID}` })]);
    expect(dbRow(sandbox).description).toContain("[download flag not set — sandbox mark only]");
    const mixed = rowsOf([db(), attr({ "com.apple.quarantine": `0042;${UNIX_HEX};Safari;${UUID}` })]);
    expect(dbRow(mixed).description).toContain("[download flag not set]");
    expect(dbRow(mixed).description).not.toContain("sandbox mark only");
  });

  it("9. attribute rows cut by the event cap are counted as dropped", () => {
    const r = parseMacos(JSON.stringify([attr({ path: "/a" }), attr({ path: "/b" }), attr({ path: "/c" })]), {
      maxEvents: 1,
      aggregate: false,
    });
    expect(r.total).toBe(3);
    expect(r.kept).toBe(1);
    expect(r.dropped).toBe(2);
  });
});

describe("detection and routing", () => {
  it("a CSV with the com.apple.quarantine header routes to macOS; generic path/quarantine inventories do not", () => {
    expect(
      detectImportKind("files.csv", `path,com.apple.quarantine\n/a,0083;${UNIX_HEX};Safari;${UUID}\n`),
    ).toBe("macos");
    expect(detectImportKind("files.csv", `path,quarantine\n/a,0083;${UNIX_HEX};Safari;${UUID}\n`)).not.toBe(
      "macos",
    );
    expect(detectImportKind("files.csv", `path,xattr\n/a,x\n`)).not.toBe("macos");
  });

  it("a JSON array routes to macOS in every ordering of the three shapes, and never with a Velociraptor stamp", () => {
    const ulog = {
      timestamp: "2026-05-02 10:00:00.000000+0000",
      eventMessage: "hi",
      processImagePath: "/usr/bin/x",
    };
    const shapes = [db(), attr(), ulog];
    const perms = [
      [0, 1, 2],
      [0, 2, 1],
      [1, 0, 2],
      [1, 2, 0],
      [2, 0, 1],
      [2, 1, 0],
    ];
    for (const p of perms)
      expect(detectImportKind("x.json", JSON.stringify(p.map((i) => shapes[i])))).toBe("macos");
    expect(detectImportKind("x.json", JSON.stringify([{ foo: 1 }, attr()]))).toBe("macos");
    expect(
      detectImportKind("x.json", JSON.stringify([{ ...attr(), _Source: "MacOS.Files.Xattr" }])),
    ).not.toBe("macos");
    expect(detectImportKind("x.json", JSON.stringify([db(), { ...attr(), _Source: "Custom" }]))).not.toBe(
      "macos",
    );
  });

  it("a mixed array reads all three shapes record by record", () => {
    const ulog = {
      timestamp: "2026-05-02 10:00:00.000000+0000",
      eventMessage: "hi",
      processImagePath: "/usr/bin/x",
    };
    const r = rowsOf([ulog, attr(), db()]);
    expect(r.format).toBe("macos-quarantine");
    expect(r.events.some((e) => e.description.startsWith("macOS log"))).toBe(true);
    expect(dbRow(r).description).toContain("[local file: /Users/x/Downloads/installer.dmg —");
  });

  it("a CSV attribute listing parses too", () => {
    const csv = `path,com.apple.quarantine\n/Users/x/Downloads/installer.dmg,0083;${UNIX_HEX};Safari;${UUID}\n`;
    const r = parseMacos(csv);
    expect(r.format).toBe("macos-quarantine");
    expect(attrRows(r)).toHaveLength(1);
    expect(attrRows(r)[0].description).toContain(
      "[download event: not among this upload's database records]",
    );
  });
});
