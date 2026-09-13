import { describe, it, expect } from "vitest";
import {
  boundOrigins,
  cleanOriginName,
  intelOrigins,
  lineageOf,
  originFamily,
  originsFactor,
  originsTag,
  type LineageInput,
} from "../../src/analysis/intelLineage.js";

const vt: LineageInput = {
  source: "VirusTotal",
  verdict: "malicious",
  originKind: "aggregate",
  origins: ["VirusTotal"],
};
const threatfox: LineageInput = {
  source: "ThreatFox",
  provider: "Hunting.ch",
  verdict: "malicious",
  originKind: "first-party",
  origins: ["abuse.ch"],
};
const urlhaus: LineageInput = { ...threatfox, source: "URLhaus" };
const mispByAbuse: LineageInput = {
  source: "MISP",
  verdict: "malicious",
  originKind: "relay",
  origins: ["abuse.ch"],
};
const mispNobody: LineageInput = { source: "MISP", verdict: "suspicious", originKind: "relay", origins: [] };

describe("intelOrigins — the five guardrails (#933 item 18)", () => {
  it("1. two feeds copying one report count as one origin", () => {
    const o = intelOrigins([mispByAbuse, threatfox]);
    expect(o.hits).toBe(2);
    expect(o.origins).toEqual(["abuse.ch"]);
    expect(o.folded).toBe(1);
    expect(o.unrecorded).toBe(0);
    expect(originsFactor(o, "lone-intel")).toBe(
      "single intel origin (abuse.ch — 2 hits: MISP, ThreatFox), not seen in a Medium+ event in this case (unverified lead)",
    );
    expect(originsTag(o, "lone-intel")).toBe("[lone-intel: 2 hits, 1 origin]");
  });

  it("2. a relay record created by a provider we also query is that provider's origin (circular)", () => {
    const octi: LineageInput = {
      source: "OpenCTI",
      verdict: "malicious",
      originKind: "relay",
      origins: ["VirusTotal"],
    };
    const o = intelOrigins([octi, vt]);
    expect(o.origins).toEqual(["VirusTotal"]);
    expect(o.folded).toBe(1);
  });

  it("3. an unattributed record is not recorded and never counts", () => {
    const alone = intelOrigins([mispNobody]);
    expect(alone.origins).toEqual([]);
    expect(alone.unrecorded).toBe(1);
    expect(originsFactor(alone, "lone-intel")).toBe(
      "1 hit with lineage not recorded (MISP) — not counted as an origin; re-check with force to record the creator",
    );
    expect(originsTag(alone, "lone-intel")).toBe("[lone-intel: lineage not recorded]");
    const mixed = intelOrigins([vt, mispNobody]);
    expect(mixed.origins).toEqual(["VirusTotal"]);
    expect(mixed.unrecorded).toBe(1);
    expect(originsFactor(mixed, "lone-intel")).toBe(
      "single intel origin (VirusTotal), not seen in a Medium+ event in this case (unverified lead); 1 hit with lineage not recorded (MISP) — not counted as an origin; re-check with force to record the creator",
    );
  });

  it("4. one origin making a weak claim is one origin; the record's own measure is untouched", () => {
    const cs: LineageInput = {
      source: "CrowdStrike Intel",
      provider: "CrowdStrike",
      verdict: "suspicious",
      originKind: "first-party",
      origins: ["CrowdStrike"],
    };
    const o = intelOrigins([cs]);
    expect(o.origins).toEqual(["CrowdStrike"]);
    expect(originsTag(o, "lone-intel")).toBe("[lone-intel: 1 named origin]");
    expect(originsFactor(o, "lone-intel")).toBe(
      "single intel origin (CrowdStrike), not seen in a Medium+ event in this case (unverified lead)",
    );
  });

  it("5. two distinct names are two named origins — never called independent", () => {
    const o = intelOrigins([vt, urlhaus]);
    expect(o.origins).toEqual(["VirusTotal", "abuse.ch"]);
    expect(originsFactor(o, "multi-origin")).toBe(
      "intel verdict from 2 named origins (VirusTotal, abuse.ch) — independence not established",
    );
    expect(originsTag(o, "multi-origin")).toBe(
      "[multi-origin: 2 named origins — VirusTotal, abuse.ch; independence not established]",
    );
    expect(originsFactor(o, "multi-origin")).not.toMatch(/independent[^c]/);
  });

  it("a local Medium+ event is the only thing called corroboration, even for an unrecorded hit", () => {
    expect(originsFactor(intelOrigins([mispNobody]), "corroborated")).toBe(
      "intel verdict (lineage not recorded) carried by a Medium+ event in this case",
    );
    expect(originsFactor(intelOrigins([vt, urlhaus]), "corroborated")).toBe(
      "intel verdict (2 named origins: VirusTotal, abuse.ch) carried by a Medium+ event in this case",
    );
    expect(originsTag(intelOrigins([vt]), "corroborated")).toBe(
      "[corroborated: carried by a Medium+ event in this case]",
    );
  });
});

describe("intelOrigins — legacy records, folding, bounds", () => {
  it("reads a pre-change record through the inferred adapter table", () => {
    expect(lineageOf({ source: "VirusTotal", verdict: "malicious" })).toEqual({
      kind: "aggregate",
      origins: ["VirusTotal"],
      inferred: true,
    });
    expect(lineageOf({ source: "ThreatFox", provider: "Hunting.ch", verdict: "malicious" })).toEqual({
      kind: "first-party",
      origins: ["abuse.ch"],
      inferred: true,
    });
    // The relay platforms never recorded a creator: not recorded, never the platform's own name.
    expect(lineageOf({ source: "MISP", verdict: "malicious" })).toEqual({
      kind: "relay",
      origins: [],
      inferred: true,
    });
    expect(lineageOf({ source: "OpenCTI", verdict: "malicious" })?.origins).toEqual([]);
    expect(lineageOf({ source: "YETI", verdict: "malicious" })?.origins).toEqual([]);
  });

  it("legacy VT + legacy MISP is one named origin and one unrecorded hit", () => {
    const o = intelOrigins([
      { source: "VirusTotal", verdict: "malicious" },
      { source: "MISP", verdict: "malicious" },
    ]);
    expect(o.origins).toEqual(["VirusTotal"]);
    expect(o.unrecorded).toBe(1);
    expect(o.unrecordedVia).toEqual(["MISP"]);
  });

  it("an adapter the table does not know is not recorded (it can only lower the count)", () => {
    const o = intelOrigins([
      { provider: "A", source: "A", verdict: "malicious" },
      { provider: "B", source: "B", verdict: "suspicious" },
    ]);
    expect(o.origins).toEqual([]);
    expect(o.unrecorded).toBe(2);
  });

  it("folds only built-in aliases, case-insensitively; other names fold on exact equality", () => {
    expect(originFamily("ThreatFox")).toBe("abuse.ch");
    expect(originFamily("URLHAUS")).toBe("abuse.ch");
    expect(originFamily("Feodo Tracker")).toBe("abuse.ch");
    expect(originFamily("CIRCL.lu")).toBe("CIRCL");
    expect(originFamily("Acme CERT")).toBe("acme cert");
    expect(originFamily("Acme CERT ")).toBe("acme cert");
    expect(originFamily("Acme-CERT")).toBe("acme-cert"); // no fuzzy match
    const o = intelOrigins([
      { source: "MISP", verdict: "malicious", originKind: "relay", origins: ["Acme CERT"] },
      { source: "OpenCTI", verdict: "malicious", originKind: "relay", origins: ["acme cert"] },
      { source: "OpenCTI", verdict: "malicious", originKind: "relay", origins: ["Acme-CERT"] },
    ]);
    expect(o.origins).toEqual(["Acme CERT", "Acme-CERT"]);
    expect(o.folded).toBe(1);
  });

  it("a relay-controlled name spelling a known family folds DOWN, never up", () => {
    const spoof: LineageInput = {
      source: "MISP",
      verdict: "malicious",
      originKind: "relay",
      origins: ["virustotal"],
    };
    expect(intelOrigins([vt, spoof]).origins).toEqual(["VirusTotal"]);
  });

  it("a stated relay record with several creators counts each family once", () => {
    const o = intelOrigins([
      {
        source: "MISP",
        verdict: "malicious",
        originKind: "relay",
        origins: ["abuse.ch", "Acme CERT", "ThreatFox"],
      },
    ]);
    expect(o.origins).toEqual(["abuse.ch", "Acme CERT"]);
    expect(o.folded).toBe(0);
  });

  it("only malicious/suspicious records are hits; context providers never count", () => {
    const o = intelOrigins([
      { source: "GeoIP", verdict: "unknown" },
      { source: "Hashlookup", verdict: "harmless", originKind: "first-party", origins: ["Hashlookup"] },
      vt,
    ]);
    expect(o.hits).toBe(1);
    expect(o.origins).toEqual(["VirusTotal"]);
  });

  it("does not mutate its input", () => {
    const rec: LineageInput = Object.freeze({
      source: "MISP",
      verdict: "malicious",
      originKind: "relay",
      origins: Object.freeze(["abuse.ch"]) as unknown as string[],
    });
    const input = Object.freeze([rec]);
    expect(() => intelOrigins(input)).not.toThrow();
    expect(rec.origins).toEqual(["abuse.ch"]);
  });

  it("cleans a creator name: control characters out, whitespace collapsed, 80 chars max", () => {
    expect(cleanOriginName("abuse.ch\u0000\n evil")).toBe("abuse.ch evil");
    expect(cleanOriginName("  CIRCL   ")).toBe("CIRCL");
    expect(cleanOriginName("x".repeat(200))).toHaveLength(80);
    expect(cleanOriginName(42)).toBe("");
  });

  it("bounds a record to five distinct creators and says how many were cut", () => {
    const names = ["a", "b", "B", "c", "d", "e", "f", "g", "", "\u0001"];
    expect(boundOrigins(names)).toEqual({ origins: ["a", "b", "c", "d", "e"], moreOrigins: 2 });
    expect(boundOrigins(["a"])).toEqual({ origins: ["a"] });
  });
});
