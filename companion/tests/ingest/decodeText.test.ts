import { describe, it, expect } from "vitest";
import { decodeImportedText } from "../../src/ingest/decodeText.js";
import { parseWerReport } from "../../src/analysis/werImport.js";

const WER = "EventType=APPCRASH\nSig[0].Name=Application Name\nSig[0].Value=evil.exe\nAppPath=C:\\Windows\\Temp\\evil.exe\n";

describe("decodeImportedText", () => {
  it("decodes plain UTF-8 unchanged", () => {
    expect(decodeImportedText(Buffer.from("hello", "utf8"))).toBe("hello");
  });

  it("strips a UTF-8 byte-order mark instead of leaving it in the first field", () => {
    const buf = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("EventType=X", "utf8")]);
    expect(decodeImportedText(buf)).toBe("EventType=X");
  });

  // The case that made this necessary: Report.wer is written UTF-16LE.
  it("decodes UTF-16LE so a real Report.wer parses", () => {
    const buf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(WER, "utf16le")]);
    const text = decodeImportedText(buf);
    expect(text).toContain("EventType=APPCRASH");
    expect(parseWerReport(text)?.appName).toBe("evil.exe");
  });

  it("decodes UTF-16BE by swapping the byte pairs", () => {
    const body = Buffer.from("EventType=X", "utf16le");
    const buf = Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(body).swap16()]);
    expect(decodeImportedText(buf)).toBe("EventType=X");
  });

  // The UTF-32LE mark begins with the UTF-16LE one. Decoding such a file as UTF-16 would produce
  // confident nonsense; there is no UTF-32 decoder here, so it falls through and stays obviously
  // wrong rather than plausibly wrong.
  it("does not read a UTF-32LE mark as UTF-16LE", () => {
    const buf = Buffer.from([0xff, 0xfe, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00]);
    expect(decodeImportedText(buf)).not.toBe(buf.subarray(2).toString("utf16le"));
  });

  it("shows what the old utf8 decode did to a UTF-16LE report", () => {
    const buf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(WER, "utf16le")]);
    // The regression this guards: read as utf8 the file is NUL-interleaved and parses to nothing.
    expect(parseWerReport(buf.toString("utf8"))?.appName ?? "").not.toBe("evil.exe");
    expect(parseWerReport(decodeImportedText(buf))?.appName).toBe("evil.exe");
  });
});
