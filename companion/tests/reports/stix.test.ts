import { describe, it, expect } from "vitest";
import { buildStixBundle, iocToStixPattern, type StixObject } from "../../src/reports/stix.js";
import { emptyState, type Finding, type IOC } from "../../src/analysis/stateTypes.js";

function ioc(overrides: Partial<IOC>): IOC {
  return { id: "i1", type: "ip", value: "1.2.3.4", firstSeen: "2026-05-20T09:00:00Z", ...overrides };
}

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1", severity: "High", title: "A finding", description: "d",
    relatedIocs: [], sourceScreenshots: [], mitreTechniques: [],
    firstSeen: "2026-05-20T09:00:00Z", lastUpdated: "2026-05-20T10:00:00Z", status: "open",
    ...overrides,
  };
}

// Pull objects of a given STIX type out of a built bundle.
function ofType(objects: StixObject[], type: string): StixObject[] {
  return objects.filter((o) => o.type === type);
}

const UUID_ID = /^[a-z-]+--[a-f0-9]{8}-[a-f0-9]{4}-5[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

describe("iocToStixPattern", () => {
  it("maps each IOC kind to the right STIX observable pattern", () => {
    expect(iocToStixPattern(ioc({ type: "ip", value: "10.0.0.1" }))).toBe("[ipv4-addr:value = '10.0.0.1']");
    expect(iocToStixPattern(ioc({ type: "ip", value: "2001:db8::1" }))).toBe("[ipv6-addr:value = '2001:db8::1']");
    expect(iocToStixPattern(ioc({ type: "domain", value: "evil.com" }))).toBe("[domain-name:value = 'evil.com']");
    expect(iocToStixPattern(ioc({ type: "url", value: "http://evil.com/x" }))).toBe("[url:value = 'http://evil.com/x']");
    expect(iocToStixPattern(ioc({ type: "file", value: "bad.exe" }))).toBe("[file:name = 'bad.exe']");
    expect(iocToStixPattern(ioc({ type: "process", value: "powershell -enc AAA" }))).toBe("[process:command_line = 'powershell -enc AAA']");
  });

  it("picks the hash algorithm from the digest length", () => {
    expect(iocToStixPattern(ioc({ type: "hash", value: "d".repeat(32) }))).toBe(`[file:hashes.'MD5' = '${"d".repeat(32)}']`);
    expect(iocToStixPattern(ioc({ type: "hash", value: "a".repeat(40) }))).toBe(`[file:hashes.'SHA-1' = '${"a".repeat(40)}']`);
    expect(iocToStixPattern(ioc({ type: "hash", value: "b".repeat(64) }))).toBe(`[file:hashes.'SHA-256' = '${"b".repeat(64)}']`);
  });

  it("returns null for an unrecognizable hash length and a blank value", () => {
    expect(iocToStixPattern(ioc({ type: "hash", value: "abc123" }))).toBeNull();
    expect(iocToStixPattern(ioc({ type: "ip", value: "   " }))).toBeNull();
  });

  it("sniffs an `other` IOC into email / url / ip / domain, else null", () => {
    expect(iocToStixPattern(ioc({ type: "other", value: "ceo@victim.com" }))).toBe("[email-addr:value = 'ceo@victim.com']");
    expect(iocToStixPattern(ioc({ type: "other", value: "evil.io" }))).toBe("[domain-name:value = 'evil.io']");
    expect(iocToStixPattern(ioc({ type: "other", value: "free-text not an ioc" }))).toBeNull();
  });

  it("escapes single quotes and backslashes inside the pattern literal", () => {
    expect(iocToStixPattern(ioc({ type: "file", value: "C:\\Temp\\a'b.exe" }))).toBe("[file:name = 'C:\\\\Temp\\\\a\\'b.exe']");
  });
});

describe("buildStixBundle", () => {
  it("produces a valid, non-empty bundle even for an empty case", () => {
    const bundle = buildStixBundle(emptyState("c1"));
    expect(bundle.type).toBe("bundle");
    expect(bundle.id).toMatch(/^bundle--[a-f0-9-]{36}$/);
    // Always: a producer identity + the report.
    expect(ofType(bundle.objects, "identity")).toHaveLength(1);
    const report = ofType(bundle.objects, "report")[0];
    expect(report).toBeDefined();
    expect((report.object_refs as string[]).length).toBeGreaterThan(0);
    expect(report.report_types).toEqual(["threat-report"]);
    // Every object is a well-formed STIX 2.1 SDO/SRO.
    for (const o of bundle.objects) {
      expect(o.spec_version).toBe("2.1");
      expect(o.id).toMatch(UUID_ID);
      expect(typeof o.created).toBe("string");
      expect(typeof o.modified).toBe("string");
    }
  });

  it("is deterministic — re-exporting an unchanged case yields a byte-identical bundle", () => {
    const state = emptyState("c1");
    state.iocs.push(ioc({ id: "i1", type: "domain", value: "evil.com" }));
    state.findings.push(finding({ relatedIocs: ["i1"], mitreTechniques: ["T1071"] }));
    state.mitreTechniques.push({ id: "T1071", name: "Application Layer Protocol", findingIds: ["f1"] });
    state.updatedAt = "2026-05-20T12:00:00.000Z";
    expect(JSON.stringify(buildStixBundle(state))).toBe(JSON.stringify(buildStixBundle(state)));
  });

  it("emits one indicator per mappable IOC and skips the unmappable", () => {
    const state = emptyState("c1");
    state.iocs.push(
      ioc({ id: "i1", type: "ip", value: "1.2.3.4" }),
      ioc({ id: "i2", type: "domain", value: "evil.com" }),
      ioc({ id: "i3", type: "other", value: "definitely not mappable text" }),
    );
    const indicators = ofType(buildStixBundle(state).objects, "indicator");
    expect(indicators).toHaveLength(2);
    expect(indicators.map((i) => i.pattern)).toContain("[ipv4-addr:value = '1.2.3.4']");
    expect(indicators.every((i) => i.pattern_type === "stix")).toBe(true);
  });

  it("carries the worst threat-intel verdict into indicator_types and the description, plus valid_from", () => {
    const state = emptyState("c1");
    state.iocs.push(ioc({
      id: "i1", type: "hash", value: "b".repeat(64), firstSeen: "2026-05-19T08:00:00.000Z",
      enrichments: [
        { source: "VirusTotal", verdict: "suspicious", score: "5/70", fetchedAt: "t" },
        { source: "MalwareBazaar", verdict: "malicious", score: "family hit", fetchedAt: "t" },
      ],
    }));
    const ind = ofType(buildStixBundle(state).objects, "indicator")[0];
    expect(ind.indicator_types).toEqual(["malicious-activity"]); // worst wins
    expect(ind.description).toContain("malicious");
    expect(ind.description).toContain("VirusTotal: suspicious (5/70)");
    expect(ind.valid_from).toBe("2026-05-19T08:00:00.000Z");
  });

  it("emits one attack-pattern per technique with a MITRE external reference", () => {
    const state = emptyState("c1");
    state.mitreTechniques.push({ id: "T1059.001", name: "PowerShell", findingIds: [] });
    state.findings.push(finding({ mitreTechniques: ["T1486"] })); // technique with no name in the list
    const aps = ofType(buildStixBundle(state).objects, "attack-pattern");
    const ps = aps.find((a) => (a.external_references as Array<{ external_id: string }>)[0].external_id === "T1059.001")!;
    expect(ps.name).toBe("PowerShell");
    expect((ps.external_references as Array<{ source_name: string }>)[0].source_name).toBe("mitre-attack");
    const ransom = aps.find((a) => (a.external_references as Array<{ external_id: string }>)[0].external_id === "T1486")!;
    expect(ransom.name).toBe("T1486"); // falls back to the id when no name is known
  });

  it("links indicator →indicates→ attack-pattern from a finding's IOCs and techniques", () => {
    const state = emptyState("c1");
    state.iocs.push(ioc({ id: "i1", type: "domain", value: "c2.evil.com" }));
    state.mitreTechniques.push({ id: "T1071", name: "Application Layer Protocol", findingIds: ["f1"] });
    state.findings.push(finding({ id: "f1", relatedIocs: ["i1"], mitreTechniques: ["T1071"] }));
    const objects = buildStixBundle(state).objects;
    const rel = ofType(objects, "relationship").find((r) => r.relationship_type === "indicates")!;
    const indicator = ofType(objects, "indicator")[0];
    const ap = ofType(objects, "attack-pattern")[0];
    expect(rel.source_ref).toBe(indicator.id);
    expect(rel.target_ref).toBe(ap.id);
  });

  it("adds the victim identity only when an organization is given, and stamps created_by_ref", () => {
    const withOrg = buildStixBundle(emptyState("c1"), { organization: "Acme Corp" });
    const ids = ofType(withOrg.objects, "identity");
    expect(ids).toHaveLength(2);
    const producer = ids.find((i) => i.created_by_ref === undefined)!; // the producer references no-one
    const victim = ids.find((i) => i.created_by_ref !== undefined)!;
    expect(producer.name).toBe("DFIR Companion");
    expect(victim.name).toBe("Acme Corp");
    expect(victim.created_by_ref).toBe(producer.id);
    // Without an org, only the producer identity exists.
    expect(ofType(buildStixBundle(emptyState("c1")).objects, "identity")).toHaveLength(1);
  });

  it("derives malware SDOs from enrichment family tags and links indicator →indicates→ malware", () => {
    const state = emptyState("c1");
    state.iocs.push(ioc({
      id: "i1", type: "hash", value: "c".repeat(64),
      enrichments: [{ source: "ThreatFox", verdict: "malicious", tags: ["Emotet", "Loader"], fetchedAt: "t" }],
    }));
    const objects = buildStixBundle(state).objects;
    const malware = ofType(objects, "malware");
    expect(malware.map((m) => m.name).sort()).toEqual(["Emotet", "Loader"]);
    expect(malware.every((m) => m.is_family === true)).toBe(true);
    const indicator = ofType(objects, "indicator")[0];
    const rels = ofType(objects, "relationship").filter((r) => malware.some((m) => m.id === r.target_ref));
    expect(rels).toHaveLength(2);
    expect(rels.every((r) => r.source_ref === indicator.id)).toBe(true);
  });

  it("names the report from the incident id when provided", () => {
    const plain = ofType(buildStixBundle(emptyState("c1")).objects, "report")[0];
    expect(plain.name).toBe("DFIR Companion — c1");
    const withId = ofType(buildStixBundle(emptyState("c1"), { incidentId: "IR-2026-007" }).objects, "report")[0];
    expect(withId.name).toBe("Incident IR-2026-007 — c1");
  });
});
