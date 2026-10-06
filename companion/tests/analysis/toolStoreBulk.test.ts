import { describe, it, expect } from "vitest";
import { runVelociraptorBulk, type BulkImportSink } from "../../src/analysis/ingest/velociraptorBulk.js";
import { linkToolStoreFolders, TOOL_STORE_MARKER } from "../../src/analysis/toolStoreFolder.js";
import { demoteBelowSeverity } from "../../src/analysis/forensicGate.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

// #1970 code review: the bulk Velociraptor path demotes each batch before the next one arrives, so
// the tool-folder check never saw the Info file rows of a staged kit. The same collection must give
// the same raised rows and notes through the whole-file order (merge-all → correlate → demote) and
// through the bulk path, whatever the batch size. Every fixture is synthetic.

const DIR = "C:\\Users\\Public\\Music";
const NO_EVICTION = { count: 0, setAside: 0, from: "", to: "" };

let seq = 0;
function mftRow(file: string, folder = DIR, host = "WS01") {
  const n = ++seq;
  const t = new Date(Date.UTC(2026, 0, 1, 0, 0, n)).toISOString();
  const path = `\\\\.\\${folder}\\${file}`;
  return {
    Fqdn: host,
    EntryNumber: n,
    InUse: true,
    OSPath: path,
    FileName: file,
    FileSize: 10,
    IsDir: false,
    Created0x10: t,
    LastModified0x10: t,
    LastRecordChange0x10: t,
    LastAccess0x10: t,
  };
}

// Benign, distinct, letter-only names: the MFT agg key folds digits, so numbered names would collapse.
let fill = 0;
const letters = (n: number) => n.toString(26).replace(/[0-9]/g, (d) => "qrstuvwxyz"[Number(d)]);
const filler = (n: number) => Array.from({ length: n }, () => mftRow(`notes${letters(++fill)}.txt`));

function memorySink(batchRows: number, gate: Severity = "Low", promote?: (e: ForensicEvent) => boolean) {
  const sink = {
    minBytes: 0,
    batchRows,
    forensic: [] as ForensicEvent[],
    superRows: [] as ForensicEvent[],
    async beginRun() {
      return 0;
    },
    async rollback() {
      return { forensic: 0, super: 0, tags: 0 };
    },
    async appendForensic(_c: string, events: ForensicEvent[]) {
      sink.forensic.push(...events);
      return events.length;
    },
    async appendSuper(_c: string, events: ForensicEvent[]) {
      sink.superRows.push(...events);
      return { retained: events.length, evicted: NO_EVICTION };
    },
    async openTagger() {
      if (!promote) return null;
      return {
        rulesHash: "stub",
        async apply(_c: string, events: ForensicEvent[]) {
          const out = events.map((e) => (promote(e) ? { ...e, severity: "High" as const } : e));
          return { events: out, matched: out.filter((e, i) => e !== events[i]).length };
        },
      };
    },
    async forensicMinSeverity() {
      return gate;
    },
    log() {},
  } satisfies BulkImportSink & { forensic: ForensicEvent[]; superRows: ForensicEvent[] };
  return sink;
}

const text = (rows: object[]) => JSON.stringify({ "Windows.NTFS.MFT": rows });
const opts = {
  label: "0018_velo-flow_Windows.NTFS.MFT.json",
  idPrefix: "18",
  importedAt: "2026-09-20T07:00:00.000Z",
};

// The whole-file order over the same events: every row merged, the correlation chain's rule, then
// the demote.
const wholeFile = (all: ForensicEvent[], gate: Severity = "Low") =>
  demoteBelowSeverity(linkToolStoreFolders(all), gate).kept;

const shape = (rows: ForensicEvent[]) =>
  rows
    .map((e) => ({ id: e.id, severity: e.severity, description: e.description }))
    .sort((a, b) => a.id.localeCompare(b.id));

async function bulk(rows: object[], batchRows: number, gate: Severity = "Low") {
  const sink = memorySink(batchRows, gate);
  await runVelociraptorBulk(sink, "c1", text(rows), opts, "forensic");
  return sink;
}

describe("the tool-folder check on the bulk import path (#1970 review)", () => {
  // PsExec early, AdFind in the middle, WinRAR at the end: each tool in a different batch at size 4.
  const kit = () => [
    mftRow("PsExec.exe"),
    ...filler(4),
    mftRow("AdFind.exe"),
    mftRow("PsExec.exe", `${DIR}\\old`), // a different folder: does not count
    ...filler(3),
    mftRow("WinRAR.exe"),
  ];

  it("raises the same rows with the same notes as the whole-file order, across batch boundaries", async () => {
    const rows = kit();
    const reference = await bulk(rows, 10_000); // one batch: the whole file in hand
    const expected = wholeFile(reference.superRows);
    expect(expected).toHaveLength(3);
    for (const e of expected) {
      expect(e.severity).toBe("Medium");
      expect(e.description).toContain(TOOL_STORE_MARKER);
    }
    for (const size of [1, 2, 4, 5]) {
      const sink = await bulk(rows, size);
      expect(shape(sink.forensic)).toEqual(shape(expected));
      // The raw record still holds every row once, as imported.
      expect(sink.superRows).toHaveLength(reference.superRows.length);
    }
  });

  it("two tools in one folder raise nothing, in either path", async () => {
    const rows = [mftRow("PsExec.exe"), ...filler(5), mftRow("AdFind.exe")];
    const reference = await bulk(rows, 10_000);
    expect(wholeFile(reference.superRows)).toEqual([]);
    expect((await bulk(rows, 2)).forensic).toEqual([]);
  });

  it("a gate above Medium keeps the raised rows out, as the demote would", async () => {
    const rows = kit();
    const reference = await bulk(rows, 10_000, "High");
    expect(wholeFile(reference.superRows, "High")).toEqual([]);
    expect((await bulk(rows, 3, "High")).forensic).toEqual([]);
  });

  it("raises one row per tool: the earliest binary of one product", async () => {
    const rows = [mftRow("PsExec.exe"), mftRow("AdFind.exe"), mftRow("PSEXESVC.exe"), mftRow("WinRAR.exe")];
    const reference = await bulk(rows, 10_000);
    const expected = wholeFile(reference.superRows);
    expect(expected).toHaveLength(3);
    expect(shape((await bulk(rows, 1)).forensic)).toEqual(shape(expected));
  });

  it("never writes a row twice when the tagger already kept one tool", async () => {
    const rows = kit();
    const isPsExec = (e: ForensicEvent) => /PsExec\.exe$/.test(e.path ?? "") && !/old/.test(e.path ?? "");
    const sink = memorySink(2, "Low", isPsExec);
    await runVelociraptorBulk(sink, "c1", text(rows), opts, "forensic");
    const ids = sink.forensic.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(sink.forensic).toHaveLength(3);
    // The tagger's row went in with its batch; its note is added by the import's final merge.
    expect(sink.forensic.find(isPsExec)?.severity).toBe("High");
    expect(sink.forensic.filter((e) => e.severity === "Medium")).toHaveLength(2);
  });
});
