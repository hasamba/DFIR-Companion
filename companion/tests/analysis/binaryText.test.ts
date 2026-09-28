import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { binaryContentImportHint, looksLikeBinaryText } from "../../src/analysis/binaryText.js";
import { decodeImportedText } from "../../src/ingest/decodeText.js";

// #1802: a binary import must be refused on its DECODED text, so a UTF-16 Windows export (NUL bytes
// in every other position on disk) still imports once its BOM is honoured.

const CSV = "Timestamp,Computer,EventID,Details\r\n2026-05-20 09:00:00,WS-01,4624,Logon\r\n";

function utf16le(text: string): Buffer {
  return Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]);
}

function utf16be(text: string): Buffer {
  return Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(text, "utf16le").swap16()]);
}

describe("looksLikeBinaryText", () => {
  it("passes plain UTF-8 text, CSV and JSON", () => {
    expect(looksLikeBinaryText(CSV)).toBe(false);
    expect(looksLikeBinaryText('{"a":1,"b":"two"}\n')).toBe(false);
    expect(looksLikeBinaryText("")).toBe(false);
  });

  it("passes a UTF-16LE and a UTF-16BE CSV with a BOM once decoded", () => {
    expect(looksLikeBinaryText(decodeImportedText(utf16le(CSV.repeat(50))))).toBe(false);
    expect(looksLikeBinaryText(decodeImportedText(utf16be(CSV.repeat(50))))).toBe(false);
  });

  it("passes a log with ANSI colour escapes and a few invalid UTF-8 bytes (a Latin-1 name)", () => {
    const line = "\x1b[31mERROR\x1b[0m login failed for Jos\ufffd from 192.0.2.4\n";
    expect(looksLikeBinaryText(line.repeat(100))).toBe(false);
  });

  it("passes a log with a NUL-padded block from an unclean shutdown", () => {
    const text =
      "May 28 09:00:01 host sshd[1]: ok\n".repeat(40) + "\0".repeat(4096) + "May 28 09:05:00 host boot\n";
    expect(looksLikeBinaryText(text)).toBe(false);
  });

  it("refuses NUL-interleaved text (UTF-16 without a BOM read as UTF-8)", () => {
    expect(looksLikeBinaryText(Buffer.from(CSV.repeat(20), "utf16le").toString("utf8"))).toBe(true);
  });

  it("refuses random bytes decoded as UTF-8", () => {
    const bytes = Buffer.alloc(4096);
    let x = 12345;
    for (let i = 0; i < bytes.length; i++) {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      bytes[i] = x & 0xff;
    }
    expect(looksLikeBinaryText(bytes.toString("utf8"))).toBe(true);
  });

  it("refuses by magic: PE (MZ + control bytes), ELF, zip, gzip, raw EVTX, SQLite", () => {
    const tail = "A".repeat(4000);
    expect(looksLikeBinaryText("MZ\x90\0\x03\0\0\0" + tail)).toBe(true);
    expect(looksLikeBinaryText("\x7fELF\x02\x01\x01" + tail)).toBe(true);
    expect(looksLikeBinaryText("PK\x03\x04" + tail)).toBe(true);
    expect(looksLikeBinaryText("\x1f\ufffd\x08" + tail)).toBe(true); // gzip 1f 8b 08 as UTF-8
    expect(looksLikeBinaryText("ElfFile\0" + tail)).toBe(true);
    expect(looksLikeBinaryText("SQLite format 3\0" + tail)).toBe(true);
  });

  it("refuses an all-ASCII PDF", () => {
    const pdf =
      "%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n";
    expect(looksLikeBinaryText(pdf)).toBe(true);
  });

  it("does not treat a text line that merely starts with MZ or PK as binary", () => {
    expect(looksLikeBinaryText("MZ-Server,started\n" + CSV)).toBe(false);
    expect(looksLikeBinaryText("PKI rollover complete\n")).toBe(false);
  });

  it.runIf(existsSync("/usr/bin/true"))("refuses a real executable read as text", () => {
    expect(looksLikeBinaryText(readFileSync("/usr/bin/true").toString("utf8"))).toBe(true);
  });
});

describe("binaryContentImportHint", () => {
  it("names the file and says nothing was read", () => {
    const hint = binaryContentImportHint("payload.exe", "MZ\x90\0\x03\0");
    expect(hint).toContain('"payload.exe"');
    expect(hint).toMatch(/nothing in it was read/);
    expect(hint).toMatch(/UTF-16/);
  });

  it("is undefined for text", () => {
    expect(binaryContentImportHint("a.csv", CSV)).toBeUndefined();
  });
});
