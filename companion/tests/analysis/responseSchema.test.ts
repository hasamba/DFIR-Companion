import { describe, it, expect } from "vitest";
import { deltaSchema, stripAiExtractedFrom } from "../../src/analysis/responseSchema.js";

describe("deltaSchema", () => {
  it("parses a valid delta", () => {
    const delta = deltaSchema.parse({
      findings: [{
        id: "f1", severity: "High", title: "Suspicious PowerShell",
        description: "Encoded command observed", relatedIocs: [], mitreTechniques: ["T1059.001"],
        status: "open",
      }],
      iocs: [{ id: "i1", type: "process", value: "powershell.exe" }],
      mitreTechniques: [{ id: "T1059.001", name: "PowerShell" }],
      threadsOpened: [{ id: "t1", description: "trace parent process" }],
      threadsClosed: [],
      timelineNote: "Reviewed process list on WIN-01",
      summary: "Found encoded PowerShell on WIN-01",
    });
    expect(delta.findings[0].id).toBe("f1");
  });

  it("degrades unexpected enum values instead of rejecting the whole response", () => {
    // A model returning a novel severity / IOC type must NOT nuke the entire synthesis.
    const delta = deltaSchema.parse({
      findings: [{ id: "f1", severity: "Catastrophic", title: "x", description: "y",
        relatedIocs: [], mitreTechniques: [], status: "weird" }],
      iocs: [
        { id: "i1", type: "malware", value: "evil.exe" },  // unlisted type
        { id: "i2", type: "tool", value: "nxc" },
      ],
      mitreTechniques: [], threadsOpened: [], threadsClosed: [],
      timelineNote: "n", summary: "s",
    });
    expect(delta.findings[0].severity).toBe("Medium"); // fallback
    expect(delta.findings[0].status).toBe("open");      // fallback
    expect(delta.iocs.map((i) => i.type)).toEqual(["other", "other"]);
    expect(delta.iocs.map((i) => i.value)).toEqual(["evil.exe", "nxc"]); // kept, not dropped
  });

  it("parses confidence + confidenceReason on a finding", () => {
    const delta = deltaSchema.parse({
      findings: [{
        id: "f1", severity: "High", confidence: 85, confidenceReason: "Two tools corroborate the hash",
        title: "x", description: "y", relatedIocs: [], mitreTechniques: [], status: "open",
      }],
      iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [], timelineNote: "n", summary: "s",
    });
    expect(delta.findings[0].confidence).toBe(85);
    expect(delta.findings[0].confidenceReason).toBe("Two tools corroborate the hash");
  });

  it("falls back confidence/confidenceReason to undefined instead of rejecting on a bad type", () => {
    const delta = deltaSchema.parse({
      findings: [{
        id: "f1", severity: "High", confidence: "very sure", confidenceReason: 12345,
        title: "x", description: "y", relatedIocs: [], mitreTechniques: [], status: "open",
      }],
      iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [], timelineNote: "n", summary: "s",
    });
    expect(delta.findings[0].confidence).toBeUndefined();
    expect(delta.findings[0].confidenceReason).toBeUndefined();
  });
});

describe("deltaSchema — iocs.extractedFrom", () => {
  const base = {
    findings: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
    timelineNote: "", summary: "", forensicEvents: [],
  };

  it("accepts an ioc with extractedFrom", () => {
    const parsed = deltaSchema.parse({
      ...base,
      iocs: [{ id: "i1", type: "domain", value: "evil.example.com", extractedFrom: ["e001", "e002"] }],
    });
    expect(parsed.iocs[0].extractedFrom).toEqual(["e001", "e002"]);
  });

  it("accepts an ioc without extractedFrom (existing AI-synthesis shape)", () => {
    const parsed = deltaSchema.parse({ ...base, iocs: [{ id: "i1", type: "ip", value: "1.2.3.4" }] });
    expect(parsed.iocs[0].extractedFrom).toBeUndefined();
  });
});

describe("stripAiExtractedFrom", () => {
  const base = {
    findings: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
    timelineNote: "", summary: "", forensicEvents: [],
  };

  it("removes a forged extractedFrom from every ioc", () => {
    // Simulates a model (possibly influenced by prompt-injected evidence content) fabricating
    // extractedFrom pointing at a real event id it read from the prompt context, to be rendered
    // as an authoritative "linked" provenance claim it never actually earned.
    const parsed = deltaSchema.parse({
      ...base,
      iocs: [
        { id: "i1", type: "domain", value: "evil.example.com", extractedFrom: ["e042"] },
        { id: "i2", type: "ip", value: "1.2.3.4" },
      ],
    });
    const result = stripAiExtractedFrom(parsed);
    expect(result.iocs[0].extractedFrom).toBeUndefined();
    expect("extractedFrom" in result.iocs[0]).toBe(false); // key actually removed, not just set to undefined
    expect(result.iocs[1].extractedFrom).toBeUndefined();
    // Everything else on the ioc is preserved untouched.
    expect(result.iocs[0]).toEqual({ id: "i1", type: "domain", value: "evil.example.com" });
  });

  it("is a no-op when no ioc carries extractedFrom", () => {
    const parsed = deltaSchema.parse({ ...base, iocs: [{ id: "i1", type: "ip", value: "1.2.3.4" }] });
    const result = stripAiExtractedFrom(parsed);
    expect(result.iocs).toEqual(parsed.iocs);
  });

  it("does not mutate the input delta (immutable)", () => {
    const parsed = deltaSchema.parse({
      ...base,
      iocs: [{ id: "i1", type: "domain", value: "evil.example.com", extractedFrom: ["e042"] }],
    });
    stripAiExtractedFrom(parsed);
    expect(parsed.iocs[0].extractedFrom).toEqual(["e042"]); // original untouched
  });
});
