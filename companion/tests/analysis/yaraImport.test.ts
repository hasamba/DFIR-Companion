import { describe, it, expect } from "vitest";
import { looksLikeYara, parseYaraOutput } from "../../src/analysis/yaraImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

describe("looksLikeYara", () => {
  it("recognizes header-only match output", () => {
    expect(looksLikeYara("EvilRule C:\\evidence\\a.dll\nOtherRule /tmp/b.bin")).toBe(true);
  });
  it("recognizes -s string-line output", () => {
    const t = "EvilRule /tmp/a.bin\n0x1a2b:$s1: 4d 5a 90 00\n0x3c4d:$s2: bad";
    expect(looksLikeYara(t)).toBe(true);
  });
  it("rejects arbitrary prose", () => {
    expect(looksLikeYara("The quick brown fox\nJumped over the lazy dog")).toBe(false);
  });
  it("rejects empty", () => {
    expect(looksLikeYara("")).toBe(false);
  });
});

describe("parseYaraOutput", () => {
  it("parses a header-only match into a Medium file-match event + file IOC", () => {
    const r = parseYaraOutput("EvilRule C:\\evidence\\a.dll");
    expect(r.total).toBe(1);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toMatch(/YARA: EvilRule matched C:\\evidence\\a\.dll/);
    expect(r.events[0].path).toBe("C:\\evidence\\a.dll");
    expect(r.iocs).toEqual([{ type: "file", value: "C:\\evidence\\a.dll" }]);
  });

  it("parses tags and attaches -s string lines to the header", () => {
    const t = [
      "EvilRule [apt,trojan] /tmp/a.bin",
      "0x1a2b:$mz: 4d 5a 90 00",
      "0x3c4d:$str: bad",
    ].join("\n");
    const r = parseYaraOutput(t);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toMatch(/\[apt, trojan\]/);
    expect(r.events[0].description).toMatch(/\$mz, \$str/);
  });

  it("extracts MITRE from tags/meta and hash from meta", () => {
    const t = 'BadDoc [T1059] [author="me",sha256="AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",description="drops T1204.002"] /x/doc.docm';
    const r = parseYaraOutput(t);
    expect(r.events[0].mitreTechniques.sort()).toEqual(["T1059", "T1204.002"]);
    expect(r.events[0].sha256).toBe("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    expect(r.iocs.find((i) => i.type === "hash")?.value).toBe("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    expect(r.iocs.find((i) => i.type === "file")?.value).toBe("/x/doc.docm");
  });

  it("bumps severity to High on score>=70 and Critical on score>=90 or threat_level", () => {
    expect(parseYaraOutput('R1 [score=75] /a').events[0].severity).toBe("High");
    expect(parseYaraOutput('R2 [score=95] /a').events[0].severity).toBe("Critical");
    expect(parseYaraOutput('R3 [threat_level="high"] /a').events[0].severity).toBe("High");
    expect(parseYaraOutput('R4 [severity="critical"] /a').events[0].severity).toBe("Critical");
    expect(parseYaraOutput('R5 [score=10] /a').events[0].severity).toBe("Medium");
  });

  it("handles a meta value containing a comma inside quotes", () => {
    const r = parseYaraOutput('R [description="drops a, then b",score=80] /a.bin');
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].description).toMatch(/YARA: R matched \/a\.bin/);
  });

  it("aggregates duplicate (rule,file) matches", () => {
    const t = "Dup /a.bin\nDup /a.bin\nDup /a.bin";
    const r = parseYaraOutput(t, { aggregate: true });
    expect(r.total).toBe(3);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(3);
  });

  it("routes YARA output through detectImportKind", () => {
    expect(detectImportKind("scan.txt", "EvilRule /tmp/a.bin\n0x10:$s: hit")).toBe("yara");
  });
});
