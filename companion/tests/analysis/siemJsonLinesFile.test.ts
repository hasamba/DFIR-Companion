// #2823: a SIEM / EDR JSON Lines file streamed from disk builds exactly what the whole-text SIEM
// importer builds from the same file — events, IOCs, counts, host, clock dispute, debug summary and the
// source-artifact hash — while never holding the file as one string. Synthetic data only.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseSiemExport, type SiemImportOptions } from "../../src/analysis/siemImport.js";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { decodeImportedText } from "../../src/ingest/decodeText.js";
import {
  parseSiemJsonLinesFile,
  probeSiemJsonLinesHead,
  siemRecordFromLine,
} from "../../src/analysis/siemJsonLinesFile.js";
import { readDecodedText, textLines } from "../../src/analysis/streamedTextFile.js";
import { sourceArtifactHash } from "../../src/analysis/canonicalEvent.js";
import { access, CMD, create, G, HOST, PWSH, T0 } from "./fixtures/osBehaviourRows.js";

let dir: string;
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "siem-jsonl-"));
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

let n = 0;
async function fileOf(content: string | Buffer): Promise<string> {
  const path = join(dir, `f${n++}.jsonl`);
  await writeFile(path, content);
  return path;
}

const ts = (i: number) => new Date(Date.UTC(2026, 2, 1, 10, 0, i % 60, i % 1000)).toISOString();
const sysmon = (eid: number, i: number, ed: Record<string, string>, host = "WS-01"): object => ({
  "@timestamp": ts(i),
  log_name: "Microsoft-Windows-Sysmon/Operational",
  computer_name: host,
  event_id: eid,
  event_data: ed,
});
const security = (eid: number, i: number, ed: Record<string, string>): object => ({
  "@timestamp": ts(i),
  log_name: "Security",
  computer_name: "DC-01",
  event_id: eid,
  event_data: ed,
});

/** A synthetic mixed export: process, network, DNS (with variant overflow), logons, generic rows. */
function mixedRows(count: number): object[] {
  const rows: object[] = [];
  for (let i = 0; i < count; i++) {
    switch (i % 9) {
      case 0:
        rows.push(
          sysmon(1, i, {
            Image: `C:\\Users\\Public\\tool${i % 7}.exe`,
            CommandLine: `tool${i % 7}.exe -enc ${"QQ".repeat(i % 5)} http://198.51.100.${i % 50}/p`,
            ProcessId: String(1000 + (i % 13)),
            Hashes: `SHA256=${(i % 4).toString(16).repeat(64)}`,
          }),
        );
        break;
      case 1:
        rows.push(
          sysmon(3, i, {
            Image: "C:\\Windows\\System32\\svchost.exe",
            Protocol: "tcp",
            Initiated: "true",
            DestinationIp: `203.0.113.${i % 30}`,
            DestinationPort: "443",
          }),
        );
        break;
      case 2:
        rows.push(
          sysmon(22, i, {
            Image: "C:\\Windows\\System32\\svchost.exe",
            ProcessId: "1234",
            QueryName: `host${i % 3}.example.test`,
            QueryResults: `::ffff:203.0.113.${i % 40};`,
          }),
        );
        break;
      case 3:
        rows.push(
          security(4624, i, {
            TargetUserName: `user${i % 6}`,
            TargetDomainName: "LAB",
            LogonType: i % 2 ? "10" : "3",
            IpAddress: `192.0.2.${i % 20}`,
          }),
        );
        break;
      case 4:
        rows.push({ _source: security(4625, i, { TargetUserName: "admin", IpAddress: "192.0.2.77" }) });
        break;
      case 5:
        rows.push({
          timestamp: ts(i),
          host: { name: "fw-01" },
          message: `deny 198.51.100.${i % 9} evil${i % 4}.example.test`,
          severity: "high",
        });
        break;
      case 6:
        rows.push(
          security(7045, i, { ServiceName: `Svc${i % 3}`, ServiceFileName: "C:\\Windows\\Temp\\svc.exe" }),
        );
        break;
      case 7:
        rows.push(
          sysmon(10, i, {
            SourceImage: "C:\\Temp\\loader.exe",
            TargetImage: "C:\\Windows\\System32\\lsass.exe",
          }),
        );
        break;
      default:
        rows.push(
          sysmon(1, i, {
            Image: "C:\\Windows\\System32\\cmd.exe",
            CommandLine: "cmd.exe /c whoami",
            ProcessId: "4242",
            UtcTime: "2019-05-03 13:45:52.000",
          }),
        );
    }
  }
  return rows;
}

const jsonl = (rows: object[], nl = "\n") => rows.map((r) => JSON.stringify(r)).join(nl) + nl;

async function both(content: string | Buffer, opts: SiemImportOptions = {}) {
  const path = await fileOf(content);
  const wholeDebug = createImportDebugRecorder();
  const streamDebug = createImportDebugRecorder();
  const text = decodeImportedText(Buffer.isBuffer(content) ? content : Buffer.from(content));
  const whole = parseSiemExport(text, { ...opts, debug: wholeDebug });
  const streamed = await parseSiemJsonLinesFile(path, { ...opts, debug: streamDebug });
  return { whole, streamed, wholeDebug: wholeDebug.summary(), streamDebug: streamDebug.summary(), path };
}

describe("parseSiemJsonLinesFile matches parseSiemExport", () => {
  it.each([
    ["default options", {}],
    ["a small cap", { maxEvents: 25 }],
    ["aggregation off", { aggregate: false }],
    ["a severity floor", { minSeverity: "Medium" as const }],
    ["a small IOC cap", { maxIocs: 7 }],
  ])("on a mixed export with %s", async (_label, opts) => {
    const { whole, streamed, wholeDebug, streamDebug } = await both(jsonl(mixedRows(900)), opts);
    expect(whole.format).toBe("ndjson");
    expect(streamed).toEqual(whole);
    expect(streamDebug).toEqual(wholeDebug);
  });

  it("on DNS rows past the variant cap, with connections before and after them", async () => {
    const rows: object[] = [];
    for (let i = 0; i < 60; i++) {
      rows.push(
        sysmon(3, i, {
          Image: "C:\\x\\a.exe",
          Protocol: "tcp",
          Initiated: "true",
          DestinationIp: `203.0.113.${i}`,
          DestinationPort: "443",
        }),
      );
      rows.push(
        sysmon(22, i, {
          Image: "C:\\x\\a.exe",
          ProcessId: "7",
          QueryName: "c2.example.test",
          QueryResults: `::ffff:203.0.113.${i};`,
        }),
      );
    }
    const { whole, streamed } = await both(jsonl(rows));
    expect(streamed).toEqual(whole);
  });

  it("without the OS-behaviour rules the whole-text SIEM importer does not run (#1621)", async () => {
    // A parent's handle to its own child at creation: the rules would lower the EID 10; SIEM keeps it.
    const child = create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.pwsh, PWSH, `${HOST}\\vagrant`);
    const own = access(T0 + 50, PWSH, G.pwsh, CMD, G.cmd);
    const { whole, streamed } = await both(jsonl([child, own, ...mixedRows(20)]), {
      minSeverity: "Info",
      aggregate: false,
    });
    expect(streamed).toEqual(whole);
  });

  it("on CRLF and bare-CR line ends, blank, malformed and bulk-action lines, and a UTF-8 BOM", async () => {
    const rows = mixedRows(60).map((r) => JSON.stringify(r));
    const content =
      "\uFEFF" +
      rows.slice(0, 20).join("\r\n") +
      "\r\n\r\n   \r\nnot json at all\r\n" +
      '{"index":{"_index":"winlogbeat"}}\n' +
      rows.slice(20, 40).join("\r") +
      "\r{}\n" +
      rows.slice(40).join("\n");
    const { whole, streamed } = await both(content);
    expect(whole.format).toBe("ndjson");
    expect(streamed).toEqual(whole);
  });

  it("hashes invalid UTF-8 and multi-byte text the way the whole decode does", async () => {
    const rows = mixedRows(30).map((r) => JSON.stringify(r));
    const content = Buffer.concat([
      Buffer.from(rows.slice(0, 10).join("\n") + "\n"),
      Buffer.from([0xc3, 0x28, 0x0a, 0xf0, 0x9f, 0x98, 0x80, 0x0a]), // invalid pair, then an emoji line
      Buffer.from(JSON.stringify({ ...mixedRows(1)[0], note: "naïve 🚀 日本" }) + "\n"),
      Buffer.from(rows.slice(10).join("\n")),
      Buffer.from([0xe2, 0x82]), // a truncated sequence at EOF
    ]);
    const { whole, streamed } = await both(content);
    expect(streamed).toEqual(whole);
  });

  it("returns null when the JSON Lines branch yields nothing, so the caller reads whole", async () => {
    const pretty = '{}\n{\n  "event_id": 1,\n  "computer_name": "WS-01"\n}\n';
    const { whole, streamed } = await both(pretty);
    expect(whole.format).toBe("concatenated-json");
    expect(streamed).toBeNull();
  });
});

describe("streamed reading stays in parts", () => {
  it("never yields a chunk longer than the read size, and a multi-byte char split across reads decodes once", async () => {
    const text = "é".repeat(5000) + "\n" + "日".repeat(3000);
    const path = await fileOf(text);
    const streamed = readDecodedText(path, { chunkBytes: 1001 });
    const parts: string[] = [];
    for await (const c of streamed.chunks) parts.push(c);
    expect(Math.max(...parts.map((p) => p.length))).toBeLessThanOrEqual(1001);
    expect(parts.length).toBeGreaterThan(10);
    expect(parts.join("")).toBe(text);
    expect(streamed.sourceArtifactHash()).toBe(sourceArtifactHash(text));
  });

  it("splits lines across chunk edges exactly like the whole text", async () => {
    const text = "a\r\nbb\rccc\n\n" + "x".repeat(3000) + "\r\nlast";
    async function* chunked(): AsyncGenerator<string> {
      for (let i = 0; i < text.length; i += 7) yield text.slice(i, i + 7);
    }
    const lines: string[] = [];
    for await (const l of textLines(chunked())) if (l) lines.push(l);
    expect(lines).toEqual(text.split(/\r\n|\r|\n/).filter(Boolean));
  });

  it("reads a line the way extractRecords does", () => {
    expect(siemRecordFromLine('  {"_source":{"a":1}}  ')).toEqual({ a: 1 });
    expect(siemRecordFromLine("{}")).toBeNull();
    expect(siemRecordFromLine("nope")).toBeNull();
    expect(siemRecordFromLine("   ")).toBeNull();
  });
});

describe("probeSiemJsonLinesHead", () => {
  async function probe(content: string | Buffer): Promise<boolean> {
    const fh = await open(await fileOf(content), "r");
    try {
      return await probeSiemJsonLinesHead(fh);
    } finally {
      await fh.close();
    }
  }

  it("accepts JSON Lines, after leading blank lines and a BOM", async () => {
    expect(await probe('{"a":1}\n{"a":2}\n')).toBe(true);
    expect(await probe('\uFEFF\n  \r\n{"a":1}\r{"a":2}')).toBe(true);
  });

  it("refuses a single JSON document, an array, a pretty object and a lone line", async () => {
    expect(await probe('[{"a":1},\n{"a":2}]')).toBe(false);
    expect(await probe('{\n  "hits": {"hits": []}\n}')).toBe(false);
    expect(await probe('{"a":1}\n')).toBe(false);
    expect(await probe('{"a":1}\n   \n\t\n')).toBe(false);
  });

  it("refuses a malformed first line and UTF-16", async () => {
    expect(await probe('garbage\n{"a":1}\n')).toBe(false);
    expect(await probe(Buffer.from([0xff, 0xfe, 0x7b, 0x00, 0x7d, 0x00]))).toBe(false);
  });

  it("looks past a long whitespace tail for the next record", async () => {
    expect(await probe('{"a":1}\n' + " ".repeat(3 * 1024 * 1024) + '\n{"a":2}')).toBe(true);
  });
});
