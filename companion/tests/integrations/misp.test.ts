import { describe, it, expect } from "vitest";
import { pushCaseToMisp } from "../../src/integrations/misp/mispPush.js";
import type { MispPushInput } from "../../src/integrations/misp/mispPush.js";
import type { MispPushClientLike, MispEventCreate, MispAttrRef, MispAttrBody } from "../../src/integrations/misp/mispPushClient.js";
import { emptyState, type InvestigationState, type IOC, type Finding } from "../../src/analysis/stateTypes.js";

function ioc(over: Partial<IOC> & { value: string; type: IOC["type"] }): IOC {
  return { id: over.value, firstSeen: "2026-06-08T00:00:00Z", ...over };
}

function finding(over: Partial<Finding> & { id: string; title: string }): Finding {
  return {
    severity: "High", description: "", relatedIocs: [], sourceScreenshots: [],
    mitreTechniques: [], firstSeen: "2026-06-08T00:00:00Z", lastUpdated: "2026-06-08T00:00:00Z",
    status: "open", ...over,
  };
}

// ---- recording mock client --------------------------------------------------

class MockMispClient implements MispPushClientLike {
  pinged = false;
  createdEvents: MispEventCreate[] = [];
  addedTags: { eventId: string; tag: string }[] = [];
  addedAttributes: { eventId: string; body: MispAttrBody }[] = [];
  existingAttrs: MispAttrRef[] = [];
  existingEventId: string | null = null;
  private seq = 1;

  async ping() { this.pinged = true; }
  async findEventByTag(_tag: string) { return this.existingEventId; }
  async createEvent(body: MispEventCreate) {
    this.createdEvents.push(body);
    return String(this.seq++);
  }
  async addTagToEvent(eventId: string, tag: string) { this.addedTags.push({ eventId, tag }); }
  async listAttributes(_eventId: string) { return this.existingAttrs; }
  async addAttribute(eventId: string, body: MispAttrBody) { this.addedAttributes.push({ eventId, body }); }
}

function sampleState(): InvestigationState {
  return {
    ...emptyState("case-alpha"),
    iocs: [
      ioc({ value: "8.8.8.8", type: "ip" }),
      ioc({ value: "evil.com", type: "domain" }),
      ioc({ value: "d41d8cd98f00b204e9800998ecf8427e", type: "hash" }),
    ],
    findings: [finding({ id: "f1", title: "C2 beacon", severity: "High", mitreTechniques: ["T1071", "T1059"] })],
  };
}

// ---- orchestrator tests -----------------------------------------------------

describe("pushCaseToMisp", () => {
  it("pings, creates event, attaches case tag, adds attributes and MITRE tags", async () => {
    const m = new MockMispClient();
    const res = await pushCaseToMisp(m, { caseId: "case-alpha", state: sampleState() }, { baseUrl: "https://misp.example.org/" });

    expect(m.pinged).toBe(true);
    expect(res.created).toBe(true);
    expect(res.eventId).toBe("1");
    expect(res.eventInfo).toBe("DFIR Companion: case-alpha");

    // Idempotency tag is attached
    const caseTags = m.addedTags.filter((t) => t.tag === "dfir-companion:case-case-alpha");
    expect(caseTags).toHaveLength(1);
    expect(caseTags[0].eventId).toBe("1");

    // IOCs pushed as attributes
    expect(res.attributes.added).toBe(3);
    expect(res.attributes.existing).toBe(0);
    const attrTypes = m.addedAttributes.map((a) => a.body.type);
    expect(attrTypes).toContain("ip-dst");
    expect(attrTypes).toContain("domain");
    expect(attrTypes).toContain("md5");    // 32-char hash → md5

    // MITRE tags
    const mitreTags = m.addedTags.filter((t) => t.tag.startsWith("mitre-attack:"));
    expect(mitreTags.map((t) => t.tag)).toContain("mitre-attack:T1071");
    expect(mitreTags.map((t) => t.tag)).toContain("mitre-attack:T1059");

    // Event URL built from baseUrl + eventId
    expect(res.eventUrl).toBe("https://misp.example.org/events/view/1");
    expect(res.warnings).toHaveLength(0);
  });

  it("finds the existing event by tag and skips creation on re-push", async () => {
    const m = new MockMispClient();
    m.existingEventId = "42";   // prior push already exists
    const res = await pushCaseToMisp(m, { caseId: "case-alpha", state: sampleState() });
    expect(res.created).toBe(false);
    expect(res.eventId).toBe("42");
    expect(m.createdEvents).toHaveLength(0);
  });

  it("deduplicates attributes already present in the event (by value, case-insensitive)", async () => {
    const m = new MockMispClient();
    m.existingEventId = "10";
    m.existingAttrs = [{ type: "ip-dst", value: "8.8.8.8" }];  // already pushed
    const res = await pushCaseToMisp(m, { caseId: "case-alpha", state: sampleState() });
    expect(res.attributes.existing).toBe(1);
    expect(res.attributes.added).toBe(2);   // evil.com + hash are new
    const newValues = m.addedAttributes.map((a) => a.body.value);
    expect(newValues).not.toContain("8.8.8.8");
  });

  it("maps SHA-256 hash to sha256 type and SHA-1 to sha1", async () => {
    const m = new MockMispClient();
    const state = {
      ...emptyState("c1"),
      iocs: [
        ioc({ value: "a".repeat(64), type: "hash" }),    // sha256
        ioc({ value: "b".repeat(40), type: "hash" }),    // sha1
      ],
    };
    await pushCaseToMisp(m, { caseId: "c1", state });
    const types = m.addedAttributes.map((a) => a.body.type);
    expect(types).toContain("sha256");
    expect(types).toContain("sha1");
  });

  it("skips 'other' IOC type and records a warning", async () => {
    const m = new MockMispClient();
    const state = { ...emptyState("c2"), iocs: [ioc({ value: "mystery-value", type: "other" })] };
    const res = await pushCaseToMisp(m, { caseId: "c2", state });
    expect(res.attributes.skipped).toBe(1);
    expect(res.attributes.added).toBe(0);
    expect(res.warnings.some((w) => w.includes("mystery-value"))).toBe(true);
  });

  it("derives threat level from worst finding severity", async () => {
    const m = new MockMispClient();
    const highState = { ...emptyState("c3"), iocs: [], findings: [finding({ id: "f1", title: "t", severity: "High" })] };
    await pushCaseToMisp(m, { caseId: "c3", state: highState });
    expect(m.createdEvents[0].threat_level_id).toBe("1");   // High/Critical → 1

    const m2 = new MockMispClient();
    const medState = { ...emptyState("c4"), iocs: [], findings: [finding({ id: "f1", title: "t", severity: "Medium" })] };
    await pushCaseToMisp(m2, { caseId: "c4", state: medState });
    expect(m2.createdEvents[0].threat_level_id).toBe("2");

    const m3 = new MockMispClient();
    await pushCaseToMisp(m3, { caseId: "c5", state: emptyState("c5") }); // no findings
    expect(m3.createdEvents[0].threat_level_id).toBe("4");  // Undefined
  });

  it("respects distribution and analysis options", async () => {
    const m = new MockMispClient();
    await pushCaseToMisp(m, { caseId: "c6", state: emptyState("c6") }, { distribution: "1", analysis: "2" });
    expect(m.createdEvents[0].distribution).toBe("1");
    expect(m.createdEvents[0].analysis).toBe("2");
  });

  it("defaults to distribution=0 (org only) and analysis=1 (ongoing)", async () => {
    const m = new MockMispClient();
    await pushCaseToMisp(m, { caseId: "c7", state: emptyState("c7") });
    expect(m.createdEvents[0].distribution).toBe("0");
    expect(m.createdEvents[0].analysis).toBe("1");
  });

  it("sets to_ids=true for ip/domain/hash/url IOCs and false for file/process", async () => {
    const m = new MockMispClient();
    const state = {
      ...emptyState("c8"),
      iocs: [
        ioc({ value: "1.2.3.4", type: "ip" }),
        ioc({ value: "evil.exe", type: "file" }),
        ioc({ value: "http://x.com/p", type: "url" }),
      ],
    };
    await pushCaseToMisp(m, { caseId: "c8", state });
    const attrMap = Object.fromEntries(m.addedAttributes.map((a) => [a.body.type, a.body.to_ids]));
    expect(attrMap["ip-dst"]).toBe(true);
    expect(attrMap["filename"]).toBe(false);
    expect(attrMap["url"]).toBe(true);
  });
});
