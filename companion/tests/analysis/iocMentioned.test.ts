import { describe, it, expect } from "vitest";
import {
  isMentionedIoc,
  mentionedNote,
  mentionedSuffix,
  MENTIONED_NOTE,
  mentionedLabel,
  iocValueLabel,
} from "../../src/analysis/iocMentioned.js";
import { buildSynthesisContext } from "../../src/analysis/synthSelect.js";
import { scoreIocs } from "../../src/analysis/iocRiskScore.js";
import { emptyState, type ForensicEvent, type IOC } from "../../src/analysis/stateTypes.js";

// #1461. A network IOC whose value came from FREE TEXT (a command line, a script block, a message)
// is a lead the loader was TOLD about, not an address the host CONTACTED. Every network consumer
// that renders such an IOC goes through these helpers so the wording lives in one place.

function ioc(over: Partial<IOC>): IOC {
  return { id: "i1", type: "ip", value: "91.191.209.46", firstSeen: "", ...over };
}

describe("iocMentioned (#1461)", () => {
  it("isMentionedIoc is true only for a network IOC with the exact `mentioned` provenance", () => {
    expect(isMentionedIoc(ioc({ provenance: "mentioned" }))).toBe(true);
    expect(isMentionedIoc(ioc({ type: "domain", value: "evil.example", provenance: "mentioned" }))).toBe(
      true,
    );
    expect(
      isMentionedIoc(ioc({ type: "url", value: "http://evil.example/x", provenance: "mentioned" })),
    ).toBe(true);
    // A mentioned hash has its own words (iocMentionedHash.ts, #1459) — never "no network record".
    expect(isMentionedIoc(ioc({ type: "hash", value: "a".repeat(64), provenance: "mentioned" }))).toBe(false);
    expect(isMentionedIoc(ioc({}))).toBe(false);
    expect(isMentionedIoc(ioc({ provenance: "client-reported" }))).toBe(false);
    expect(isMentionedIoc(undefined)).toBe(false);
  });

  it("the note says what the IOC is and what it is not", () => {
    expect(MENTIONED_NOTE).toBe("referenced in free text; no network record");
    expect(mentionedNote(ioc({ provenance: "mentioned" }))).toBe(MENTIONED_NOTE);
    expect(mentionedNote(ioc({}))).toBe("");
  });

  it("the suffix is the parenthesised note for a table cell, empty otherwise", () => {
    expect(mentionedSuffix(ioc({ provenance: "mentioned" }))).toBe(` (${MENTIONED_NOTE})`);
    expect(mentionedSuffix(ioc({}))).toBe("");
    expect(mentionedSuffix(ioc({ provenance: "client-reported" }))).toBe("");
  });
});

describe("iocMentioned labels (#1461)", () => {
  it("mentionedLabel appends the note only when the derived flag is set", () => {
    expect(mentionedLabel("91.191.209.46", true)).toBe(`91.191.209.46 (${MENTIONED_NOTE})`);
    expect(mentionedLabel("203.0.113.5", undefined)).toBe("203.0.113.5");
    expect(mentionedLabel("203.0.113.5", false)).toBe("203.0.113.5");
  });

  it("iocValueLabel keeps the #1266 client-reported suffix and adds the #1461 note", () => {
    expect(iocValueLabel({ type: "ip", value: "1.2.3.4", provenance: "client-reported" })).toBe(
      "1.2.3.4 (client-reported)",
    );
    expect(iocValueLabel({ type: "ip", value: "1.2.3.4", provenance: "mentioned" })).toBe(
      `1.2.3.4 (${MENTIONED_NOTE})`,
    );
    expect(iocValueLabel({ type: "ip", value: "1.2.3.4" })).toBe("1.2.3.4");
    expect(iocValueLabel({ type: "hash", value: "abc", provenance: "mentioned" })).toBe("abc");
  });
});

// #1471 finding 4: the #1459 corroboration bypass was hash-only. `iocHasBehavioralEvent` matches by
// description substring, so the Medium/High command line that MENTIONS the address was its own
// "behavioural" event and the synthesis read `<ip> = malicious (VT) [corroborated]` with nothing
// saying the host was only told about it. A mentioned network IOC now gets the hash's treatment:
// no corroboration from the event that carries it, and the note on the line / in the factors.
const MENTIONED_IP = "91.191.209.46";
const LOADER_TEXT = `Velociraptor Sigma: Suspicious Loader - CommandLine=loader.exe --reported-meterpreter-stage ${MENTIONED_IP} --port 12385`;

function mentionedNetworkCase(over: Partial<IOC> = {}): {
  state: ReturnType<typeof emptyState>;
  ioc: IOC;
  event: ForensicEvent;
} {
  const state = emptyState("c1");
  const ioc: IOC = {
    id: "i1",
    type: "ip",
    value: MENTIONED_IP,
    firstSeen: "2026-02-10T09:00:00Z",
    provenance: "mentioned",
    extractedFrom: ["e1"],
    enrichments: [{ source: "VT", verdict: "malicious", score: "12/90", fetchedAt: "2026-02-11T00:00:00Z" }],
    ...over,
  };
  const event: ForensicEvent = {
    id: "e1",
    timestamp: "2026-02-10T09:00:00Z",
    description: LOADER_TEXT.replace(MENTIONED_IP, ioc.value),
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS-07",
  };
  state.iocs.push(ioc);
  state.forensicTimeline.push(event);
  return { state, ioc, event };
}

describe("#1471 -- a mentioned network IOC does not corroborate itself", () => {
  it("the synthesis IOC context reads [lone-intel] with the note, never [corroborated]", () => {
    const { state } = mentionedNetworkCase();
    const ctx = buildSynthesisContext(state, state.forensicTimeline);
    expect(ctx).toContain("THREAT-INTEL VERDICTS");
    expect(ctx).toMatch(new RegExp(`${MENTIONED_IP} = malicious \\(VT 12/90\\) \\[lone-intel`));
    expect(ctx).not.toMatch(new RegExp(`${MENTIONED_IP} = malicious \\(VT 12/90\\) \\[corroborated`));
    const line = ctx.split("\n").find((l) => l.includes(`${MENTIONED_IP} = malicious`))!;
    expect(line).toContain(` — ${MENTIONED_NOTE}`);
  });

  it("the same IP from a network record still reads [corroborated] with no note (the control)", () => {
    const { state } = mentionedNetworkCase();
    const { provenance: _p, ...plain } = state.iocs[0];
    state.iocs[0] = plain;
    const ctx = buildSynthesisContext(state, state.forensicTimeline);
    expect(ctx).toMatch(new RegExp(`${MENTIONED_IP} = malicious \\(VT 12/90\\) \\[corroborated`));
    expect(ctx).not.toContain(MENTIONED_NOTE);
  });

  it("the composite risk score never counts the mention as corroboration and pins the tier", () => {
    const { state } = mentionedNetworkCase();
    const risk = scoreIocs(state.iocs, state.forensicTimeline, { hostNames: new Set() })["i1"];
    expect(risk.factors.join(" | ")).not.toMatch(/carried by a Medium\+ event|corroborated/);
    // Pinned: lone-intel (2) + High event (2) = 4 → high. The self-corroborated read scored 6 —
    // the same tier, one short of critical — so the factor list is what makes a later change
    // visible. The severity factor keeps its wording for a mentioned IOC on purpose: the #1459
    // mentioned hash reads the same way, so rewording both belongs to one later change.
    expect(risk.score).toBe("high");
    expect(risk.factors).toEqual([
      "1 hit with lineage not recorded (VT) — not counted as an origin; re-check with force to record the creator (current reputation, measured 2026-02-11)",
      `address mentioned in free text; ${MENTIONED_NOTE}`,
      "seen in a High-severity event",
    ]);
  });

  it("a mentioned domain and url get the same note", () => {
    const domain = mentionedNetworkCase({ type: "domain", value: "stage.example.net" });
    const url = mentionedNetworkCase({ type: "url", value: "http://stage.example.net/x" });
    for (const { state, ioc } of [domain, url]) {
      const risk = scoreIocs(state.iocs, state.forensicTimeline, { hostNames: new Set() })["i1"];
      expect(risk.factors).toContain(`address mentioned in free text; ${MENTIONED_NOTE}`);
      expect(risk.factors.join(" | ")).not.toMatch(/corroborated/);
      const ctx = buildSynthesisContext(state, state.forensicTimeline);
      expect(ctx).toMatch(
        new RegExp(`${ioc.value.replace(/[./]/g, "\\$&")} = malicious \\(VT 12/90\\) \\[lone-intel`),
      );
    }
  });
});
