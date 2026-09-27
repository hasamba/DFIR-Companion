import { describe, it, expect } from "vitest";
import {
  assembleSupportBundle,
  buildSupportReadme,
  rowFromMessage,
  tailLines,
  type SupportBundleParts,
} from "../../src/analysis/supportBundleZip.js";
import { readZip } from "../../src/analysis/zipArchive.js";

function parts(over: Partial<SupportBundleParts> = {}): SupportBundleParts {
  return {
    generatedAt: "2026-09-27T10:00:00.000Z",
    version: "0.0.0-test",
    diagnosticsText: "diag",
    supportJson: "{}",
    sessionLog: { text: "s\n", truncated: false },
    debugLog: { text: "d\n", truncated: false },
    imports: [],
    importsOmitted: [],
    summary: { HOST: 2, CASE: 0 },
    withheldCases: 0,
    ...over,
  };
}

describe("tailLines", () => {
  it("returns the whole buffer when it fits", () => {
    expect(tailLines(Buffer.from("a\nb\n"), 100)).toEqual({ text: "a\nb\n", truncated: false });
  });

  it("drops the partial first line so a cut value never survives as a fragment", () => {
    const buf = Buffer.from("key=sk-SECRETVALUE-123\nnext line\nlast\n");
    const { text, truncated } = tailLines(buf, 20);
    expect(truncated).toBe(true);
    expect(text).toBe("next line\nlast\n".slice(-text.length));
    expect(text).not.toContain("SECRET");
    expect(text.startsWith("next") || text.startsWith("last")).toBe(true);
  });

  it("never splits a multi-byte character", () => {
    const buf = Buffer.from("שלום עולם\nשורה\n", "utf8");
    const { text } = tailLines(buf, 12);
    expect(text).not.toContain("�");
  });

  it("returns nothing when the tail holds no line break", () => {
    expect(tailLines(Buffer.from("x".repeat(50)), 10)).toEqual({ text: "", truncated: true });
  });
});

describe("rowFromMessage", () => {
  it("reads a row number only when the message states one", () => {
    expect(rowFromMessage("Unexpected token at line 42")).toBe(42);
    expect(rowFromMessage("bad record #7")).toBe(7);
    expect(rowFromMessage("EEXIST: file already exists")).toBeUndefined();
  });
});

describe("support bundle README and layout", () => {
  it("lists counts, never values, and says why a part is missing", () => {
    const readme = buildSupportReadme(
      parts({
        caseLog: { text: "", truncated: false, omitted: "the case is password-protected and locked." },
      }),
    );
    expect(readme).toContain("HOST: 2");
    expect(readme).not.toContain("CASE: 0");
    expect(readme).toContain("logs/case.log: not included — the case is password-protected and locked.");
  });

  it("writes only the parts that exist", () => {
    const zip = assembleSupportBundle(
      parts({
        debugLog: { text: "", truncated: false, omitted: "off" },
        imports: [
          { at: "t", kind: "csv", caseToken: "ANON_CASE_1", fileToken: "ANON_FILE_1.csv", error: "e" },
        ],
      }),
    );
    const names = readZip(zip).map((e) => e.path);
    expect(names).toEqual([
      "README.txt",
      "diagnostics.txt",
      "support.json",
      "redaction-summary.json",
      "logs/session.log",
      "imports/failure-1.json",
    ]);
  });
});

describe("readFileTail", () => {
  it("reads only the end of a large file", async () => {
    const { mkdtemp, writeFile } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { readFileTail } = await import("../../src/reports/supportBundleBuilder.js");
    const dir = await mkdtemp(join(tmpdir(), "dfir-tail-"));
    const path = join(dir, "big.log");
    await writeFile(path, "old line\n".repeat(200_000) + "newest line\n");
    const tail = await readFileTail(path, 64);
    expect(tail.bytes.length).toBe(64);
    expect(tail.size).toBeGreaterThan(1_000_000);
    expect(tail.bytes.toString("utf8").endsWith("newest line\n")).toBe(true);
  });
});
