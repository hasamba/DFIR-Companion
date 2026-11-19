import { describe, it, expect } from "vitest";
import { mkdtemp, open, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  openVelociraptorFileRowStream,
  probeNdjsonFileHead,
} from "../../src/analysis/velociraptorFileRowStream.js";

// #2705: Velociraptor JSON Lines read from disk a record at a time, so a file past V8's ~512 MB
// string ceiling still imports. The reader must agree with the in-memory NDJSON reader on what a
// row is (blank and malformed lines skipped, Elastic `_source` unwrapped, BOM stripped) and bound
// how much of one record it will hold.

async function fileOf(content: string | Buffer): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-vr-file-"));
  const path = join(dir, "export.json");
  await writeFile(path, content);
  return path;
}

async function rowsOf(path: string, maxRecordBytes?: number) {
  const out: { row: Record<string, unknown>; offset: number }[] = [];
  const stream = openVelociraptorFileRowStream(path, maxRecordBytes ? { maxRecordBytes } : {});
  for await (const item of stream.rows) out.push(item);
  return out;
}

async function probe(content: string | Buffer, maxRecordBytes?: number) {
  const fh = await open(await fileOf(content), "r");
  try {
    return await probeNdjsonFileHead(fh, maxRecordBytes);
  } finally {
    await fh.close();
  }
}

describe("openVelociraptorFileRowStream (#2705)", () => {
  it("yields one row per line, with the byte offset just past it", async () => {
    const text = '{"a":1}\n{"a":2}\n';
    const rows = await rowsOf(await fileOf(text));
    expect(rows.map((r) => r.row)).toEqual([{ a: 1 }, { a: 2 }]);
    expect(rows.map((r) => r.offset)).toEqual([8, 16]);
  });

  it("skips blank, malformed and empty-object lines, unwraps _source, and reads CRLF and a last line with no newline", async () => {
    const text = '{"a":1}\r\n\r\nnot json\n{}\n{"_source":{"b":2}}\n{"c":3}';
    const rows = await rowsOf(await fileOf(text));
    expect(rows.map((r) => r.row)).toEqual([{ a: 1 }, { b: 2 }, { c: 3 }]);
  });

  it("strips a UTF-8 BOM from the first record", async () => {
    const buf = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"a":1}\n{"a":2}\n')]);
    expect((await rowsOf(await fileOf(buf))).map((r) => r.row)).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("keeps a multi-byte character that a read chunk boundary splits", async () => {
    // 1 MB of padding puts the é across the reader's first chunk boundary.
    const pad = "x".repeat((1 << 20) - 12);
    const text = `{"p":"${pad}é"}\n{"a":2}\n`;
    const rows = await rowsOf(await fileOf(text));
    expect((rows[0].row.p as string).endsWith("é")).toBe(true);
    expect(rows[1].row).toEqual({ a: 2 });
  });

  it("refuses a record longer than the bound with a sentence that says what is wrong", async () => {
    const text = `{"a":1}\n{"p":"${"x".repeat(5000)}"}\n`;
    await expect(rowsOf(await fileOf(text), 1024)).rejects.toThrow(/record 2 is over .*JSON Lines/);
  });

  it("refuses a UTF-16 file and says to convert it", async () => {
    const buf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('{"a":1}\n', "utf16le")]);
    await expect(rowsOf(await fileOf(buf))).rejects.toThrow(/UTF-8/);
  });

  it("opens nothing until it is read, and stops cleanly when the caller breaks early", async () => {
    const path = await fileOf('{"a":1}\n{"a":2}\n{"a":3}\n');
    const unread = openVelociraptorFileRowStream(path);
    expect(unread.format).toBe("ndjson");
    const stream = openVelociraptorFileRowStream(path);
    for await (const item of stream.rows) {
      expect(item.row).toEqual({ a: 1 });
      break;
    }
    expect(await stream.rows.next()).toEqual({ done: true, value: undefined });
  });
});

describe("probeNdjsonFileHead (#2705)", () => {
  it("is ndjson when the first line is a whole JSON object and more follows", async () => {
    expect(await probe('{"a":1}\n{"a":2}\n')).toBe("ndjson");
  });

  it("is ndjson when the first record is far longer than the 256 KB head sample", async () => {
    expect(await probe(`{"p":"${"x".repeat(600_000)}"}\n{"a":2}\n`)).toBe("ndjson");
  });

  it("is ndjson after a UTF-8 BOM", async () => {
    expect(
      await probe(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"a":1}\n{"a":2}\n')])),
    ).toBe("ndjson");
  });

  it("is not ndjson for a top-level array, a pretty-printed artifact map, or one line with nothing after", async () => {
    expect(await probe('[{"a":1},\n{"a":2}]\n')).toBe("not-ndjson");
    expect(await probe('{\n  "Windows.NTFS.MFT": [{"a":1}]\n}\n')).toBe("not-ndjson");
    expect(await probe('{"Windows.NTFS.MFT":[{"a":1}]}')).toBe("not-ndjson");
  });

  it("is not ndjson — not an error — when no newline comes within the record bound", async () => {
    expect(await probe(`{"p":"${"x".repeat(5000)}"}\n{"a":2}\n`, 1024)).toBe("not-ndjson");
  });

  it("names a UTF-16 file by its byte-order mark, either endianness", async () => {
    expect(await probe(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('{"a":1}\n', "utf16le")]))).toBe(
      "utf16",
    );
    expect(await probe(Buffer.from([0xfe, 0xff, 0x00, 0x7b]))).toBe("utf16");
  });
});

// Codex review of #2705: the reader yields only parsed objects, so a valid row followed by a long
// malformed or empty-object tail never gave the caller a turn to see Cancel — the whole tail was read.
describe("openVelociraptorFileRowStream — Cancel stops the read (#2705 review)", () => {
  it("throws AbortError on the next chunk once the signal fires, mid-tail, and ends the reader", async () => {
    const tail = "{}\nnot json\n".repeat(400_000); // ~4.4 MB that yields no row
    const path = await fileOf(`{"a":1}\n${tail}{"b":2}\n`);
    const ctl = new AbortController();
    const stream = openVelociraptorFileRowStream(path, { signal: ctl.signal });
    expect((await stream.rows.next()).value?.row).toEqual({ a: 1 });
    ctl.abort();
    await expect(stream.rows.next()).rejects.toMatchObject({ name: "AbortError" });
    expect(await stream.rows.next()).toEqual({ done: true, value: undefined });
  });

  it("does not open the file at all when the signal has already fired", async () => {
    const ctl = new AbortController();
    ctl.abort();
    const stream = openVelociraptorFileRowStream(join(tmpdir(), "does-not-exist-2705.json"), {
      signal: ctl.signal,
    });
    await expect(stream.rows.next()).rejects.toMatchObject({ name: "AbortError" });
  });
});
