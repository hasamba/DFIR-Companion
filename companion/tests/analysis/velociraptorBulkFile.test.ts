import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  runVelociraptorBulk,
  textRowSource,
  type BulkImportSink,
  type BulkRowSource,
  type BulkRunHandle,
} from "../../src/analysis/ingest/velociraptorBulk.js";
import { fileRowSource } from "../../src/analysis/ingest/velociraptorFileImport.js";
import type { RowStreamItem } from "../../src/analysis/velociraptorRowStream.js";

// #2705: the bulk Velociraptor driver reads its rows from a FILE as well as from a string, so a JSON
// Lines export past V8's string ceiling imports in batches. Synthetic rows, an in-memory sink.

const NO_EVICTION = { count: 0, setAside: 0, from: "", to: "" };

function notebookRow(n: number): Record<string, unknown> {
  return {
    EventTime: new Date(Date.UTC(2026, 7, 13, 22, 0, n)).toISOString(),
    Computer: "HOSTNAME_1.lab.local",
    Detection: {
      Name: "T1567.002-Use of 32-bit LOLBINs",
      EventId: "^(4688)$",
      Regex: "syswow64",
      Ignore: "",
    },
    Channel: "Security",
    EventID: 4688,
    EventData: {
      SubjectUserName: "HOSTNAME_1$",
      NewProcessId: 1000 + n,
      NewProcessName: `C:\\Windows\\SysWOW64\\tool${String.fromCharCode(97 + (n % 26))}.exe`,
      ParentProcessName: "C:\\Windows\\System32\\svchost.exe",
    },
    Message: "A new process has been created.",
    FlowId: "F.EXAMPLEFLOW01.H",
    ClientId: "C.0123456789abcdef",
    Fqdn: "HOSTNAME_1.lab.local",
  };
}

const ndjson = (rows: object[]): string => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";

async function fileOf(content: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-vr-bulk-file-"));
  const path = join(dir, "sb_evtx.json");
  await writeFile(path, content, "utf8");
  return path;
}

interface MemorySink extends BulkImportSink {
  forensic: ForensicEvent[];
  superRows: ForensicEvent[];
  rollbacks: BulkRunHandle[];
}

function memorySink(batchRows = 5000): MemorySink {
  const sink: MemorySink = {
    minBytes: 0,
    batchRows,
    forensic: [],
    superRows: [],
    rollbacks: [],
    async beginRun() {
      return 0;
    },
    async rollback(_caseId, run) {
      sink.rollbacks.push(run);
      const f = sink.forensic.length;
      const s = sink.superRows.length;
      sink.forensic = sink.forensic.filter((e) => e.importBatchId !== run.importBatchId);
      sink.superRows = sink.superRows.filter((e) => e.importBatchId !== run.importBatchId);
      return { forensic: f - sink.forensic.length, super: s - sink.superRows.length, tags: 0 };
    },
    async appendForensic(_caseId, events) {
      sink.forensic.push(...events);
      return events.length;
    },
    async appendSuper(_caseId, events) {
      sink.superRows.push(...events);
      return { retained: events.length, evicted: NO_EVICTION };
    },
    async openTagger() {
      return null;
    },
    async forensicMinSeverity() {
      return "Low";
    },
    log() {},
  };
  return sink;
}

const opts = (signal?: AbortSignal) => ({
  label: "0007_sb_evtx.json",
  idPrefix: "7",
  importedAt: "2026-11-19T07:00:00.000Z",
  ...(signal ? { signal } : {}),
});

const shape = (e: ForensicEvent) => ({
  id: e.id,
  description: e.description,
  severity: e.severity,
  mitre: e.mitreTechniques,
  ts: e.timestamp,
});

describe("runVelociraptorBulk — from a JSON Lines file (#2705)", () => {
  it("imports a file exactly as it imports the same text", async () => {
    const text = ndjson(Array.from({ length: 12 }, (_, i) => notebookRow(i)));
    const path = await fileOf(text);
    const fromText = memorySink(5);
    const fromFile = memorySink(5);
    const a = await runVelociraptorBulk(fromText, "c1", textRowSource(text), opts(), "forensic");
    const b = await runVelociraptorBulk(
      fromFile,
      "c1",
      fileRowSource(path, Buffer.byteLength(text)),
      opts(),
      "forensic",
    );
    expect(b!.rows).toBe(a!.rows);
    expect(b!.events).toBe(a!.events);
    expect(b!.batches).toBe(a!.batches);
    expect(b!.format).toBe("ndjson");
    expect(fromFile.forensic.map(shape)).toEqual(fromText.forensic.map(shape));
    expect(fromFile.superRows.length).toBe(fromText.superRows.length);
  });

  it("keeps the notebook detection's Medium verdict and MITRE technique on the file path", async () => {
    const text = ndjson([notebookRow(1), notebookRow(2)]);
    const sink = memorySink();
    await runVelociraptorBulk(sink, "c1", fileRowSource(await fileOf(text), text.length), opts(), "forensic");
    const hit = sink.forensic.find((e) => /Velociraptor detection: T1567\.002/.test(e.description));
    expect(hit, JSON.stringify(sink.forensic.map((e) => e.description))).toBeDefined();
    expect(hit!.severity).toBe("Medium");
    expect(hit!.mitreTechniques).toContain("T1567.002");
  });

  it("rolls back the batches already written when the reader fails part-way through the file", async () => {
    const good = ndjson(Array.from({ length: 30 }, (_, i) => notebookRow(i)));
    const text = good + JSON.stringify({ pad: "x".repeat(4000) }) + "\n";
    const sink = memorySink(5);
    const source = fileRowSource(await fileOf(text), text.length, { maxRecordBytes: 2048 });
    await expect(runVelociraptorBulk(sink, "c1", source, opts(), "forensic")).rejects.toThrow(/record 31/);
    expect(sink.rollbacks).toHaveLength(1);
    expect(sink.forensic).toEqual([]);
    expect(sink.superRows).toEqual([]);
  });
});

describe("runVelociraptorBulk — a cancel during the evidence pass stops the run (#2705)", () => {
  it("rethrows the AbortError instead of swallowing it, and never starts the mapping pass", async () => {
    const rows = Array.from({ length: 20 }, (_, i) => notebookRow(i));
    const ctl = new AbortController();
    let opened = 0;
    let mappedPulled = 0;
    // The driver opens the mapping stream first, then the evidence stream.
    const source: BulkRowSource = {
      bytes: 1000,
      open() {
        const which = ++opened;
        async function* gen(): AsyncGenerator<RowStreamItem, void, undefined> {
          for (let i = 0; i < rows.length; i++) {
            if (which === 1) mappedPulled++;
            if (which === 2 && i === 3) ctl.abort();
            yield { row: rows[i], offset: (i + 1) * 50 };
          }
        }
        return { format: "ndjson", rows: gen() };
      },
    };
    const sink = memorySink(2);
    await expect(runVelociraptorBulk(sink, "c1", source, opts(ctl.signal), "forensic")).rejects.toMatchObject(
      {
        name: "AbortError",
      },
    );
    expect(mappedPulled).toBe(0);
    expect(sink.forensic).toEqual([]);
  });
});

describe("runVelociraptorBulk — Cancel reaches the file reader (#2705 review)", () => {
  it("stops in the evidence pass on a malformed tail and rolls the run back", async () => {
    const tail = "{}\nnot json\n".repeat(200_000);
    const text = ndjson([notebookRow(1)]) + tail + ndjson([notebookRow(2)]);
    const path = await fileOf(text);
    const ctl = new AbortController();
    const sink = memorySink();
    // The run's first log line is written before the evidence pass: cancel there.
    sink.log = (msg: string) => {
      if (/bulk path/.test(msg)) ctl.abort();
    };
    const source = fileRowSource(path, text.length, { signal: ctl.signal });
    await expect(runVelociraptorBulk(sink, "c1", source, opts(ctl.signal), "forensic")).rejects.toMatchObject(
      {
        name: "AbortError",
      },
    );
    expect(sink.rollbacks).toHaveLength(1);
    expect(sink.forensic).toEqual([]);
  });
});
