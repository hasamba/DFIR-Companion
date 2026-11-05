import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  DecompressionLimitError,
  gunzipHead,
  openCloudRecordStream,
} from "../../src/analysis/cloudStreamReader.js";
import { JsonRecordScanner } from "../../src/analysis/jsonRecordStream.js";

// #2303 — the streaming cloud reader: never the whole file, every repair counted.

async function file(name: string, body: string | Buffer): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-cloudstream-"));
  const path = join(dir, name);
  await writeFile(path, body);
  return path;
}

async function readAll(path: string, opts: Parameters<typeof openCloudRecordStream>[1] = {}) {
  const stream = await openCloudRecordStream(path, opts);
  const rows: Array<Record<string, unknown>> = [];
  for await (const r of stream.records) rows.push(r);
  return { rows, stats: stream.stats() };
}

const ual = (i: number) => ({ Id: `id-${i}`, Operation: "FileAccessed", UserId: `u${i}@example.com` });

describe("openCloudRecordStream (#2303)", () => {
  it("reads a MES UAL CSV whose AuditData JSON cell spans lines", async () => {
    const audit = JSON.stringify({ Operation: "New-InboxRule", Note: "line1\nline2" }).replace(/"/g, '""');
    const csv =
      `"RecordType","CreationDate","UserIds","Operations","AuditData"\r\n` +
      `"ExchangeAdmin","2026-10-01T00:00:00","a@example.com","New-InboxRule","${audit}"\r\n` +
      `"ExchangeAdmin","2026-10-01T00:01:00","b@example.com","Set-Mailbox","{""Operation"":""Set-Mailbox""}"\r\n`;
    const { rows, stats } = await readAll(await file("ual.csv", csv));
    expect(stats.format).toBe("csv");
    expect(rows).toHaveLength(2);
    expect(JSON.parse(String(rows[0].AuditData)).Note).toBe("line1\nline2");
    expect(rows[1].Operations).toBe("Set-Mailbox");
  });

  it("applies the importer's CSV row adapter", async () => {
    const { rows } = await readAll(await file("x.csv", "a,b\n1,2\n"), {
      adapt: (r) => ({ ...r, seen: true }),
    });
    expect(rows).toEqual([{ a: "1", b: "2", seen: true }]);
  });

  it("reads JSON lines and counts a broken line without losing the rest", async () => {
    const body =
      [ual(1), ual(2)].map((r) => JSON.stringify(r)).join("\n") +
      '\n{"Id":"broken"\n' +
      JSON.stringify(ual(3)) +
      "\n";
    const { rows, stats } = await readAll(await file("ual.jsonl", body));
    expect(rows.map((r) => r.Id)).toEqual(["id-1", "id-2", "id-3"]);
    expect(stats.format).toBe("jsonl");
    expect(stats.repairs.garbageSkipped).toBe(1);
  });

  it("reads a top-level array and a pretty-printed one", async () => {
    const rows1 = (await readAll(await file("a.json", JSON.stringify([ual(1), ual(2)])))).rows;
    const rows2 = (await readAll(await file("b.json", JSON.stringify([ual(1), ual(2)], null, 2)))).rows;
    expect(rows1).toHaveLength(2);
    expect(rows2).toEqual(rows1);
  });

  it("streams the record array of a wrapper, whatever keys come before it", async () => {
    const ct = { Records: [{ eventName: "A" }, { eventName: "B" }] };
    const graph = {
      "@odata.context": "x",
      meta: { value: [1, 2] },
      value: [{ id: "1" }],
      "@odata.nextLink": "y",
    };
    expect((await readAll(await file("ct.json", JSON.stringify(ct)))).rows.map((r) => r.eventName)).toEqual([
      "A",
      "B",
    ]);
    expect((await readAll(await file("g.json", JSON.stringify(graph)))).rows).toEqual([{ id: "1" }]);
  });

  it("joins concatenated documents and counts the seam, skipping trailing garbage", async () => {
    const body = JSON.stringify([ual(1)]) + JSON.stringify([ual(2)]) + "\nnot json at all";
    const { rows, stats } = await readAll(await file("c.json", body));
    expect(rows).toHaveLength(2);
    expect(stats.repairs.documentsJoined).toBe(1);
    expect(stats.repairs.garbageSkipped).toBe(1);
  });

  it("strips and counts a UTF-8 BOM", async () => {
    const { rows, stats } = await readAll(await file("bom.json", "﻿" + JSON.stringify([ual(1)])));
    expect(rows).toHaveLength(1);
    expect(stats.repairs.bomStripped).toBe(1);
  });

  it("decompresses a CloudTrail .json.gz object as downloaded", async () => {
    const ct = {
      Records: Array.from({ length: 50 }, (_, i) => ({ eventID: `e${i}`, eventName: "ListBuckets" })),
    };
    const gz = gzipSync(JSON.stringify(ct));
    const path = await file("123456789012_CloudTrail_us-east-1_x.json.gz", gz);
    const { rows, stats } = await readAll(path);
    expect(rows).toHaveLength(50);
    expect(stats.gzip).toBe(true);
    expect(stats.bytesRead).toBe(gz.length);
    expect(stats.bytesDecoded).toBe(Buffer.byteLength(JSON.stringify(ct)));
    expect((await gunzipHead(path, 20)).toString()).toBe(JSON.stringify(ct).slice(0, 20));
  });

  it("refuses a decompression bomb past the ratio guard", async () => {
    const bomb = gzipSync(Buffer.alloc(4 * 1024 * 1024, 0x20)); // ~4 KB → 4 MB of spaces
    const path = await file("bomb.json.gz", bomb);
    const limits = { maxRatio: 100, slackBytes: 1024 * 1024, maxOutputBytes: 1 << 30 };
    await expect(readAll(path, { gzipLimits: limits })).rejects.toBeInstanceOf(DecompressionLimitError);
  });

  it("refuses output past the absolute ceiling whatever the ratio", async () => {
    const path = await file("big.json.gz", gzipSync(JSON.stringify([ual(1), ual(2), ual(3)])));
    const limits = { maxRatio: 1e9, slackBytes: 0, maxOutputBytes: 10 };
    await expect(readAll(path, { gzipLimits: limits })).rejects.toThrow(/decompression bomb/);
  });

  it("an empty file yields nothing", async () => {
    const { rows, stats } = await readAll(await file("e.json", "  \n "));
    expect(rows).toEqual([]);
    expect(stats.format).toBe("empty");
  });
});

describe("JsonRecordScanner chunking (#2303)", () => {
  const scan = (chunks: string[], max = 1 << 20) => {
    const out: unknown[] = [];
    const s = new JsonRecordScanner((r) => out.push(r), max);
    for (const c of chunks) s.push(c);
    return { out, counts: s.end() };
  };

  it("gives the same records whatever the chunk boundaries", () => {
    const text = JSON.stringify({ Records: [{ a: 'x"}]', b: [1, { c: "{" }] }, { a: "y" }] });
    const whole = scan([text]).out;
    for (let size = 1; size < 12; size++) {
      const chunks = text.match(new RegExp(`[\\s\\S]{1,${size}}`, "g"))!;
      expect(scan(chunks).out).toEqual(whole);
    }
    expect(whole).toHaveLength(2);
  });

  it("skips and counts a record over the bound without holding it", () => {
    const { out, counts } = scan([JSON.stringify([{ big: "x".repeat(500) }, { ok: 1 }])], 100);
    expect(out).toEqual([{ ok: 1 }]);
    expect(counts.oversizeSkipped).toBe(1);
  });

  it("counts a truncated tail", () => {
    const { out, counts } = scan(['[{"a":1},{"b":']);
    expect(out).toEqual([{ a: 1 }]);
    expect(counts.garbageSkipped).toBe(1);
  });

  it("unwraps one-line wrapper documents on JSON lines", () => {
    const a = JSON.stringify({ x: 1 });
    const b = JSON.stringify({ Records: [{ y: 1 }, { y: 2 }] });
    const { out, counts } = scan([`${a}\n${b}\n`]);
    expect(out).toEqual([{ x: 1 }, { y: 1 }, { y: 2 }]);
    expect(counts.documentsJoined).toBe(1);
  });
});
