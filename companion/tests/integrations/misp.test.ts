import { describe, it, expect } from "vitest";
import { pushCaseToMisp } from "../../src/integrations/misp/mispPush.js";
import type { MispPushInput } from "../../src/integrations/misp/mispPush.js";
import type { MispPushClientLike, MispEventCreate, MispAttrRef, MispAttrBody } from "../../src/integrations/misp/mispPushClient.js";
import { emptyState, type InvestigationState, type IOC, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ioc(over: Partial<IOC> & { value: string; type: IOC["type"] }): IOC {
  return { id: over.value, firstSeen: "2026-06-08T00:00:00Z", ...over };
}

function event(over: Partial<ForensicEvent> & { id: string; timestamp: string; description: string }): ForensicEvent {
  return {
    severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    ...over,
  };
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

  // #177 — MISP validates every attribute value and rejects a malformed one with a 403 that reads
  // like a permissions failure. The push must send the bare indicator, keep the annotation as the
  // attribute comment, and refuse locally (with the real reason) anything still unusable.
  describe("IOC value hygiene (#177)", () => {
    it("sends the bare indicator and carries the host label in the attribute comment", async () => {
      const m = new MockMispClient();
      const state = { ...emptyState("c-ip"), iocs: [ioc({ value: "10.10.20.15 (DC01)", type: "ip" })] };
      const res = await pushCaseToMisp(m, { caseId: "c-ip", state });

      expect(res.attributes).toMatchObject({ added: 1, skipped: 0 });
      expect(m.addedAttributes[0].body).toMatchObject({
        type: "ip-dst", value: "10.10.20.15", comment: "DC01",
      });
    });

    it("prefers an explicit IOC note over one derived from the value", async () => {
      const m = new MockMispClient();
      const state = {
        ...emptyState("c-note"),
        iocs: [ioc({ value: "10.10.20.30", type: "ip", note: "FS01 — file server" })],
      };
      await pushCaseToMisp(m, { caseId: "c-note", state });
      expect(m.addedAttributes[0].body.comment).toBe("FS01 — file server");
    });

    it("maps hash type from the repaired value, not the annotated one", async () => {
      const m = new MockMispClient();
      const sha = "a".repeat(64);
      const state = { ...emptyState("c-h"), iocs: [ioc({ value: `${sha} (dropper)`, type: "hash" })] };
      await pushCaseToMisp(m, { caseId: "c-h", state });
      expect(m.addedAttributes[0].body).toMatchObject({ type: "sha256", value: sha, comment: "dropper" });
    });

    it("dedupes the annotated form against the bare value already on the event", async () => {
      const m = new MockMispClient();
      m.existingAttrs = [{ type: "ip-dst", value: "10.10.20.15" }];
      const state = { ...emptyState("c-dup"), iocs: [ioc({ value: "10.10.20.15 (DC01)", type: "ip" })] };
      const res = await pushCaseToMisp(m, { caseId: "c-dup", state });
      expect(res.attributes).toMatchObject({ added: 0, existing: 1 });
      expect(m.addedAttributes).toHaveLength(0);
    });

    it("skips a value that is still invalid for its type, naming the reason locally", async () => {
      const m = new MockMispClient();
      const state = {
        ...emptyState("c-bad"),
        // 66 hex chars — not a recognised digest length; MISP would reject it.
        iocs: [ioc({ value: "cafe0001002003004005006007008009000a000b000c000d000e000f0010001100", type: "hash" })],
      };
      const res = await pushCaseToMisp(m, { caseId: "c-bad", state });
      expect(res.attributes).toMatchObject({ added: 0, skipped: 1 });
      expect(m.addedAttributes).toHaveLength(0);
      expect(res.warnings.some((w) => w.includes("not a valid hash value"))).toBe(true);
    });

    it("truncates a mis-typed text blob in the warning instead of quoting it whole", async () => {
      const m = new MockMispClient();
      const blob = `.PARAMETER Identity\n${"A display name for the GPO. ".repeat(40)}`;
      const state = { ...emptyState("c-blob"), iocs: [ioc({ value: blob, type: "ip" })] };
      const res = await pushCaseToMisp(m, { caseId: "c-blob", state });

      expect(res.attributes).toMatchObject({ added: 0, skipped: 1 });
      const warning = res.warnings.find((w) => w.includes("not a valid ip value"));
      expect(warning).toBeDefined();
      expect(warning!.length).toBeLessThan(200);
      expect(warning).not.toContain("\n");
    });
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

  it("pushes the forensic timeline as attributes carrying first_seen/last_seen", async () => {
    const m = new MockMispClient();
    const state = {
      ...emptyState("c9"),
      forensicTimeline: [
        event({ id: "e1", timestamp: "2026-06-08T01:00:00Z", description: "Malicious process launched", asset: "HOST-01", sources: ["Velociraptor"], mitreTechniques: ["T1059"] }),
        event({ id: "e2", timestamp: "2026-06-08T02:00:00Z", endTimestamp: "2026-06-08T02:05:00Z", description: "C2 beacon burst", count: 12 }),
      ],
    };
    const res = await pushCaseToMisp(m, { caseId: "c9", state });

    expect(res.timeline.added).toBe(2);
    expect(res.timeline.existing).toBe(0);
    const texts = m.addedAttributes.filter((a) => a.body.type === "text");
    expect(texts).toHaveLength(2);
    const e1 = texts.find((a) => a.body.value.includes("Malicious process launched"))!;
    expect(e1.body.first_seen).toBe("2026-06-08T01:00:00Z");
    expect(e1.body.category).toBe("Internal reference");
    expect(e1.body.comment).toContain("asset: HOST-01");
    expect(e1.body.comment).toContain("source: Velociraptor");
    expect(e1.body.comment).toContain("mitre: T1059");

    const e2 = texts.find((a) => a.body.value.includes("C2 beacon burst"))!;
    expect(e2.body.last_seen).toBe("2026-06-08T02:05:00Z");
    expect(e2.body.comment).toContain("occurrences: 12");
  });

  it("dedupes timeline events already present on re-push (idempotent)", async () => {
    const m = new MockMispClient();
    m.existingEventId = "77";
    const state = {
      ...emptyState("c10"),
      forensicTimeline: [event({ id: "e1", timestamp: "2026-06-08T01:00:00Z", description: "Malicious process launched" })],
    };
    // Pre-seed the exact value the mapper would produce for this event.
    m.existingAttrs = [{ type: "text", value: "[2026-06-08T01:00:00Z] Malicious process launched" }];

    const res = await pushCaseToMisp(m, { caseId: "c10", state });
    expect(res.timeline.existing).toBe(1);
    expect(res.timeline.added).toBe(0);
    expect(m.addedAttributes.filter((a) => a.body.type === "text")).toHaveLength(0);
  });

  it("caps an oversized timeline, keeping the most severe events", async () => {
    const m = new MockMispClient();
    const noise = Array.from({ length: 20 }, (_, i) =>
      event({ id: `info${i}`, timestamp: `2026-06-08T00:00:${String(i).padStart(2, "0")}Z`, description: `noise ${i}`, severity: "Info" }));
    const critical = event({ id: "crit", timestamp: "2026-06-08T23:00:00Z", description: "ransomware deployed", severity: "Critical" });
    const state = { ...emptyState("c12"), forensicTimeline: [...noise, critical] };

    const res = await pushCaseToMisp(m, { caseId: "c12", state }, { timelineLimit: 5 });

    expect(res.timeline.added).toBe(5);
    // 21 events, 5 pushed -> 16 dropped by the cap.
    expect(res.timeline.skipped).toBe(16);
    expect(res.warnings.some((w) => w.includes("timeline truncated"))).toBe(true);
    // The Critical event must survive the cut even though it is last chronologically.
    const values = m.addedAttributes.filter((a) => a.body.type === "text").map((a) => a.body.value);
    expect(values.some((v) => v.includes("ransomware deployed"))).toBe(true);
  });

  it("aborts the timeline push after repeated MISP failures instead of retrying every event", async () => {
    const m = new MockMispClient();
    let calls = 0;
    m.addAttribute = async () => { calls += 1; throw new Error("MISP HTTP 500"); };
    const state = {
      ...emptyState("c13"),
      forensicTimeline: Array.from({ length: 500 }, (_, i) =>
        event({ id: `e${i}`, timestamp: `2026-06-08T01:00:00Z`, description: `event ${i}` })),
    };

    const res = await pushCaseToMisp(m, { caseId: "c13", state });

    // Bails out after the consecutive-failure threshold rather than calling all 500 times.
    expect(calls).toBe(10);
    expect(res.timeline.added).toBe(0);
    expect(res.timeline.skipped).toBe(500);
    expect(res.warnings.some((w) => w.includes("aborted after"))).toBe(true);
  });

  it("skips timeline events with an unparseable timestamp and records a warning", async () => {
    const m = new MockMispClient();
    const state = {
      ...emptyState("c11"),
      forensicTimeline: [event({ id: "e1", timestamp: "not-a-date", description: "bad event" })],
    };
    const res = await pushCaseToMisp(m, { caseId: "c11", state });
    expect(res.timeline.skipped).toBe(1);
    expect(res.timeline.added).toBe(0);
    expect(res.warnings.some((w) => w.includes("e1"))).toBe(true);
  });
});
