import { describe, it, expect } from "vitest";
import {
  fileReference,
  parseReasons,
  pairRenames,
  summarizeLifecycle,
  orderByUsn,
  type UsnRecord,
} from "../../src/analysis/usnLifecycle.js";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";

const rec = (over: Partial<UsnRecord> = {}): UsnRecord => ({
  name: "evil.exe",
  entry: "12345",
  sequence: "2",
  parentEntry: "5",
  parentSequence: "5",
  usn: "1000",
  timestamp: "2026-01-01T10:00:00Z",
  reasons: ["FILE_CREATE"],
  volume: "C:",
  parentPath: "C:\\Users\\jdoe\\Downloads",
  ...over,
});

describe("fileReference — the identity that survives a rename", () => {
  it("combines volume, entry and sequence", () => {
    expect(fileReference(rec())).toBe("C:|12345-2");
  });

  // NTFS reallocates MFT entries. Keying on the entry alone stitches a deleted file's history onto
  // whatever took its place.
  it("separates a reused entry from the file that previously held it", () => {
    expect(fileReference(rec({ sequence: "2" }))).not.toBe(fileReference(rec({ sequence: "3" })));
  });

  it("separates the same entry number on two volumes", () => {
    expect(fileReference(rec({ volume: "C:" }))).not.toBe(fileReference(rec({ volume: "D:" })));
  });
});

describe("parseReasons", () => {
  it("normalizes the separators different parsers emit", () => {
    expect(parseReasons("FileCreate|DataExtend|Close").sort()).toEqual(
      ["CLOSE", "DATA_EXTEND", "FILE_CREATE"].sort(),
    );
    expect(parseReasons("FILE_CREATE, CLOSE").sort()).toEqual(["CLOSE", "FILE_CREATE"]);
  });

  it("keeps an unrecognised reason rather than dropping it", () => {
    expect(parseReasons("SOME_NEW_REASON")).toContain("SOME_NEW_REASON");
  });

  it("handles an empty field", () => {
    expect(parseReasons("")).toEqual([]);
  });
});

describe("pairRenames", () => {
  const oldName = rec({ name: "invoice.pdf", usn: "1000", reasons: ["RENAME_OLD_NAME"] });
  const newName = rec({ name: "svchost.exe", usn: "1008", reasons: ["RENAME_NEW_NAME"] });

  it("links the two halves into one rename", () => {
    const [p] = pairRenames([oldName, newName]);
    expect(p.oldName).toBe("invoice.pdf");
    expect(p.newName).toBe("svchost.exe");
    expect(p.timestamp).toBe(newName.timestamp);
  });

  it("notes when a rename made a file executable that was not", () => {
    const [p] = pairRenames([oldName, newName]);
    expect(p.severity).toBe("Low");
    expect(p.note).toContain("not executable before the rename");
  });

  it("notes the reverse — an executable renamed to look like something else", () => {
    const a = rec({ name: "tool.exe", usn: "1", reasons: ["RENAME_OLD_NAME"] });
    const b = rec({ name: "notes.txt", usn: "2", reasons: ["RENAME_NEW_NAME"] });
    expect(pairRenames([a, b])[0].note).toContain("does not look like one");
  });

  it("grades an ordinary rename as evidence, not a finding", () => {
    const a = rec({ name: "a.txt", usn: "1", reasons: ["RENAME_OLD_NAME"] });
    const b = rec({ name: "b.txt", usn: "2", reasons: ["RENAME_NEW_NAME"] });
    expect(pairRenames([a, b])[0].severity).toBe("Info");
  });

  // The journal rolls over, so a collection routinely begins or ends mid-rename.
  it("drops an unpaired half rather than guessing the missing name", () => {
    expect(pairRenames([oldName])).toEqual([]);
    expect(pairRenames([newName])).toEqual([]);
  });

  it("does not pair records belonging to two different files", () => {
    const other = rec({ name: "svchost.exe", entry: "999", usn: "1008", reasons: ["RENAME_NEW_NAME"] });
    expect(pairRenames([oldName, other])).toEqual([]);
  });

  // A reused entry number is a different file.
  it("does not pair across a sequence-number change", () => {
    const reused = rec({ name: "x.exe", sequence: "9", usn: "1008", reasons: ["RENAME_NEW_NAME"] });
    expect(pairRenames([oldName, reused])).toEqual([]);
  });

  it("does not report a hard-link change as a rename to the same name", () => {
    const a = rec({ name: "same.txt", usn: "1", reasons: ["RENAME_OLD_NAME"] });
    const b = rec({ name: "same.txt", usn: "2", reasons: ["RENAME_NEW_NAME"] });
    expect(pairRenames([a, b])).toEqual([]);
  });

  // The USN orders records; the timestamp does not, and two records can share one.
  it("pairs in journal order even when the timestamps are identical", () => {
    const a = rec({ name: "a.txt", usn: "50", reasons: ["RENAME_OLD_NAME"] });
    const b = rec({ name: "b.txt", usn: "20", reasons: ["RENAME_NEW_NAME"] });
    // b precedes a in the journal, so there is no old-name to pair it with.
    expect(pairRenames([a, b])).toEqual([]);
  });
});

describe("summarizeLifecycle", () => {
  it("collects every name one file was known under, in journal order", () => {
    const s = summarizeLifecycle([
      rec({ name: "a.tmp", usn: "1", reasons: ["FILE_CREATE"] }),
      rec({ name: "b.exe", usn: "2", reasons: ["RENAME_NEW_NAME"] }),
    ]);
    expect(s[0].names).toEqual(["a.tmp", "b.exe"]);
    expect(s[0].note).toContain("a.tmp → b.exe");
  });

  it("unions the reasons across records without ordering them", () => {
    const s = summarizeLifecycle([
      rec({ usn: "1", reasons: ["FILE_CREATE", "DATA_EXTEND"] }),
      rec({ usn: "2", reasons: ["FILE_DELETE", "CLOSE"] }),
    ]);
    expect(s[0].reasons.sort()).toEqual(["CLOSE", "DATA_EXTEND", "FILE_CREATE", "FILE_DELETE"]);
    expect(s[0].note).toContain("order inside one is not a sequence");
  });

  // Rollover, not absence of the event.
  it("says a missing creation record is explained by rollover", () => {
    const s = summarizeLifecycle([rec({ reasons: ["DATA_OVERWRITE"] })]);
    expect(s[0].createdSeen).toBe(false);
    expect(s[0].note).toContain("rollover");
  });

  it("reports a deletion record as present without calling it a deletion time", () => {
    const s = summarizeLifecycle([rec({ reasons: ["FILE_DELETE"] })]);
    expect(s[0].deletedSeen).toBe(true);
    expect(s[0].note).toContain("deletion record is present");
  });

  it("keeps two files with the same entry but different sequences apart", () => {
    const s = summarizeLifecycle([rec({ sequence: "2" }), rec({ sequence: "3", name: "other.txt" })]);
    expect(s).toHaveLength(2);
  });
});

// Reachability: the module is only worth anything if the importer feeds it.
describe("wired into the KAPE USN importer", () => {
  const csv = (rows: string[][]) =>
    [
      "Name,Extension,EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,SourceFile",
      ...rows.map((r) => r.join(",")),
    ].join("\n");

  it("reconstructs a rename from the two halves", () => {
    const text = csv([
      [
        "invoice.pdf",
        ".pdf",
        "12345",
        "2",
        "5",
        "5",
        "1000",
        "2026-01-01 10:00:00",
        "RenameOldName",
        "C:\\$Extend\\$J",
      ],
      [
        "svchost.exe",
        ".exe",
        "12345",
        "2",
        "5",
        "5",
        "1008",
        "2026-01-01 10:00:01",
        "RenameNewName",
        "C:\\$Extend\\$J",
      ],
    ]);
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("UsnJrnl");
    const rename = r.events.find((e) => /renamed from/.test(e.description));
    expect(rename).toBeDefined();
    expect(rename!.description).toContain("invoice.pdf");
    expect(rename!.description).toContain("svchost.exe");
    expect(rename!.description).toContain("not executable before the rename");
  });

  it("keeps the file reference on ordinary records so two same-named files stay apart", () => {
    const text = csv([
      ["a.txt", ".txt", "111", "1", "5", "5", "10", "2026-01-01 10:00:00", "FileCreate", "C:\\$Extend\\$J"],
      ["a.txt", ".txt", "222", "1", "5", "5", "11", "2026-01-01 10:00:01", "FileCreate", "C:\\$Extend\\$J"],
    ]);
    const r = parseKapeCsv(text);
    expect(r.events).toHaveLength(2);
    expect(r.events[0].description).toContain("[file 111-1]");
  });

  // A journal record names a FILE, not a process. The old mapper ran every journal filename through
  // addProc, so `report.docx` became a process indicator AND a processName — which correlation
  // groups on, so unrelated events about unrelated documents merged.
  //
  // A bare filename with no directory is not a usable indicator either, and addFile declines it on
  // purpose. So the correct outcome is NO indicator, rather than a wrong one.
  it("never turns a journal filename into a process indicator", () => {
    const text = csv([
      [
        "report.docx",
        ".docx",
        "1",
        "1",
        "5",
        "5",
        "10",
        "2026-01-01 10:00:00",
        "FileCreate",
        "C:\\$Extend\\$J",
      ],
    ]);
    const r = parseKapeCsv(text);
    expect(r.iocs.some((i) => i.type === "process")).toBe(false);
    expect(r.events[0].processName).toBeUndefined();
  });

  it("does not invent a rename when only one half survived the journal", () => {
    const text = csv([
      [
        "gone.tmp",
        ".tmp",
        "9",
        "1",
        "5",
        "5",
        "10",
        "2026-01-01 10:00:00",
        "RenameOldName",
        "C:\\$Extend\\$J",
      ],
    ]);
    expect(parseKapeCsv(text).events.some((e) => /renamed from/.test(e.description))).toBe(false);
  });
});

describe("moves and lifecycle, end to end", () => {
  const csvL = (rows: string[][]) =>
    [
      "Name,Extension,EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,ParentPath,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,Volume",
      ...rows.map((r) => r.join(",")),
    ].join("\n");

  // A move keeps the name and changes the parent. Discarding same-name pairs as hard links threw
  // away every move — which is most of what this item exists to show.
  it("reports a move as a move, not as a discarded hard link", () => {
    const text = csvL([
      [
        "payload.exe",
        ".exe",
        "77",
        "1",
        "10",
        "1",
        "C:\\Users\\jdoe\\Downloads",
        "100",
        "2026-01-01 10:00:00",
        "RenameOldName",
        "C",
      ],
      [
        "payload.exe",
        ".exe",
        "77",
        "1",
        "20",
        "1",
        "C:\\ProgramData\\Startup",
        "101",
        "2026-01-01 10:00:01",
        "RenameNewName",
        "C",
      ],
    ]);
    const move = parseKapeCsv(text).events.find((e) => /moved from/.test(e.description));
    expect(move).toBeDefined();
    expect(move!.description).toContain("Downloads");
    expect(move!.description).toContain("Startup");
  });

  it("still treats a same-name, same-parent pair as a hard-link change", () => {
    const text = csvL([
      [
        "same.txt",
        ".txt",
        "77",
        "1",
        "10",
        "1",
        "C:\\Temp",
        "100",
        "2026-01-01 10:00:00",
        "RenameOldName",
        "C",
      ],
      [
        "same.txt",
        ".txt",
        "77",
        "1",
        "10",
        "1",
        "C:\\Temp",
        "101",
        "2026-01-01 10:00:01",
        "RenameNewName",
        "C",
      ],
    ]);
    expect(parseKapeCsv(text).events.some((e) => /moved from|renamed from/.test(e.description))).toBe(false);
  });

  // Anti-forensics: Windows does not routinely delete individual Prefetch files.
  it("raises a deleted Prefetch file as removed execution evidence", () => {
    const text = csvL([
      [
        "EVIL.EXE-1234.pf",
        ".pf",
        "88",
        "1",
        "10",
        "1",
        "C:\\Windows\\Prefetch",
        "200",
        "2026-01-01 11:00:00",
        "FileDelete|Close",
        "C",
      ],
    ]);
    const e = parseKapeCsv(text).events.find((x) => /lifecycle/.test(x.description));
    expect(e?.severity).toBe("Medium");
    expect(e?.mitreTechniques).toContain("T1070.004");
    expect(e?.description).toContain("removes execution evidence");
  });

  it("does not raise an ordinary file deletion", () => {
    const text = csvL([
      [
        "notes.txt",
        ".txt",
        "88",
        "1",
        "10",
        "1",
        "C:\\Temp",
        "200",
        "2026-01-01 11:00:00",
        "FileDelete|Close",
        "C",
      ],
    ]);
    expect(parseKapeCsv(text).events.every((e) => e.severity === "Info")).toBe(true);
  });

  // A browser writes x.exe.crdownload and renames it on completion; an installer extracts to .tmp.
  it("does not grade a completed download as a suspicious rename", () => {
    const text = csvL([
      [
        "setup.exe.crdownload",
        ".crdownload",
        "99",
        "1",
        "10",
        "1",
        "C:\\Users\\jdoe\\Downloads",
        "300",
        "2026-01-01 12:00:00",
        "RenameOldName",
        "C",
      ],
      [
        "setup.exe",
        ".exe",
        "99",
        "1",
        "10",
        "1",
        "C:\\Users\\jdoe\\Downloads",
        "301",
        "2026-01-01 12:00:01",
        "RenameNewName",
        "C",
      ],
    ]);
    const r = parseKapeCsv(text).events.find((e) => /renamed from/.test(e.description));
    expect(r?.severity).toBe("Info");
  });
});

describe("orderByUsn — a USN is 64-bit", () => {
  it("orders values beyond the safe-integer range correctly", () => {
    const a = { usn: "9007199254740993" };
    const b = { usn: "9007199254740992" };
    // Number() collapses these two to the same double.
    expect(Number(a.usn)).toBe(Number(b.usn));
    expect(orderByUsn([a, b])).toEqual([b, a]);
  });

  it("keeps an unusable USN in input order rather than sorting it to the front", () => {
    const rows = [{ usn: "" }, { usn: "5" }, { usn: "1" }];
    expect(orderByUsn(rows).map((r) => r.usn)).toEqual(["", "1", "5"]);
  });
});
