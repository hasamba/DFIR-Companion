// The synthesis prompt must record the first OBSERVED entry as its own finding and keep the origin of
// the credential or foothold as a separate, honest question. Before this, "initial access" was asked
// only as a "vector" question, so a case whose first visible act was a valid-account logon from a
// rogue host got "unknown" and no entry finding at all.
import { describe, it, expect } from "vitest";
import { SYNTHESIS_PROMPT } from "../../../src/analysis/ai/prompts/synthesis.js";

interface PromptShape {
  findings: Array<{ id: string; title: string; mitreTechniques: string[]; relatedEventIds: string[] }>;
  keyQuestions: Array<{ id: string; question: string; relatedFindingIds: string[] }>;
  uncertainties: Array<{ topic: string; status: string }>;
}

// The prompt wraps its sentences across array lines, so prose checks read one-space text.
const FLAT = SYNTHESIS_PROMPT.replace(/\s+/g, " ");

function shapeExample(): PromptShape {
  const start = SYNTHESIS_PROMPT.indexOf('{\n  "findings"');
  expect(start).toBeGreaterThan(-1);
  return JSON.parse(SYNTHESIS_PROMPT.slice(start)) as PromptShape;
}

describe("SYNTHESIS_PROMPT — first observed entry", () => {
  it("asks for an Initial access finding for the earliest observed attacker access event", () => {
    expect(FLAT).toMatch(/FIRST OBSERVED ENTRY/);
    expect(FLAT).toMatch(/"Initial access: </);
  });

  it("writes the entry finding even when the origin of the credential or foothold is unknown", () => {
    expect(FLAT).toMatch(/even when (how|the origin)[^.]*unknown/i);
  });

  it("does not force a finding: none when unsupported, at most one per intrusion, competing candidates kept", () => {
    expect(FLAT).toMatch(/at most ONE[^.]*per distinct intrusion/i);
    expect(FLAT).toMatch(/omit it when[^.]*(no entry|not supported|unsupported)/i);
    expect(FLAT).toMatch(/competing candidate/i);
  });

  it("separates a lateral pivot from entry", () => {
    expect(FLAT).toMatch(/already (evidenced|shown) as attacker-controlled/i);
    expect(FLAT).toMatch(/"First observed attacker access: /);
  });

  it("requires affirmative evidence of entry before the Initial access title", () => {
    expect(FLAT).toMatch(/only on AFFIRMATIVE evidence of entry into the environment/);
    expect(FLAT).toMatch(/source is external/);
    expect(FLAT).toMatch(/unmanaged or rogue host/);
  });

  it("does not let an access from a managed host establish entry", () => {
    expect(FLAT).toMatch(/managed host that has its own events[^.]*does NOT establish entry/);
    expect(FLAT).toMatch(/keep environment entry unresolved in uncertainties/);
  });

  it("caps confidence when the only basis is missing source telemetry", () => {
    expect(FLAT).toMatch(/no telemetry here[^.]*confidence below 60/);
  });

  it("scopes the claim to the evidence shown", () => {
    expect(FLAT).toMatch(/earliest[^.]*in the evidence (you are )?shown/i);
  });

  it("keeps q_initial_access (id and text) and adds q_first_entry", () => {
    const ids = shapeExample().keyQuestions.map((q) => q.id);
    expect(ids).toContain("q_initial_access");
    expect(ids).toContain("q_first_entry");
    const initial = shapeExample().keyQuestions.find((q) => q.id === "q_initial_access");
    expect(initial?.question).toBe("What was the initial access vector?");
  });

  it("ties q_first_entry to the entry finding in the shape example", () => {
    const shape = shapeExample();
    const entry = shape.findings.find((f) => f.title.startsWith("Initial access:"));
    expect(entry).toBeDefined();
    expect(entry?.relatedEventIds.length).toBeGreaterThan(0);
    const q = shape.keyQuestions.find((k) => k.id === "q_first_entry");
    expect(q?.relatedFindingIds).toContain(entry?.id);
  });

  it("records the entry and the vector as separate uncertainty topics", () => {
    const topics = shapeExample().uncertainties.map((u) => u.topic);
    expect(topics).toContain("first observed entry");
    expect(topics).toContain("initial access vector");
  });

  it("keeps the standard-question list naming both questions", () => {
    expect(FLAT).toMatch(/first observed entry; initial access vector/);
  });
});

describe("SYNTHESIS_PROMPT — failed-logon source attribution", () => {
  it("attributes a failed logon to a host only when the row names that host as its source", () => {
    expect(FLAT).toMatch(
      /do not attribute a failed logon to an attacker host unless the row names that host as its source/i,
    );
  });

  it("treats a source-less self-workstation disabled-account failure as a local probe", () => {
    expect(FLAT).toMatch(
      /no source address[^.]*workstation name is the host being logged on to[^.]*disabled account \(substatus 0xc0000072\)/i,
    );
    expect(FLAT).toMatch(/local probe by a process on that host/i);
  });

  it("dates a guessing finding from its own first failure and never implies guessing before entry without one", () => {
    expect(FLAT).toMatch(/Date a guessing finding from its own first failure from that source/);
    expect(FLAT).toMatch(/guessing began before the first attacker access/i);
  });
});

describe("SYNTHESIS_PROMPT — entry finding needs established attacker activity", () => {
  it("does not treat the organisation's own VPN address as external evidence", () => {
    expect(FLAT).toMatch(/address the organisation's own VPN assigned is NOT external evidence by itself/);
  });

  it("does not write the entry finding from a lone alert the other evidence explains or contradicts", () => {
    expect(FLAT).toMatch(/only when the timeline establishes attacker activity/);
    expect(FLAT).toMatch(/lone alert or risk flag[^.]*explains or contradicts/i);
    expect(FLAT).toMatch(/record the entry as 'inferred' or 'speculated' in uncertainties/);
  });

  it("allows 'confirmed' for the entry only when the entry itself is directly evidenced as attacker activity", () => {
    expect(FLAT).toMatch(
      /entry can be 'confirmed' only when the entry event itself is directly evidenced as attacker activity/,
    );
  });
});

describe("SYNTHESIS_PROMPT — missing source telemetry never confirms the entry", () => {
  it("records the entry as inferred, not confirmed, when the only basis is missing source telemetry", () => {
    expect(FLAT).toMatch(
      /no telemetry here[^.]*confidence below 60\. Record the first observed entry as 'inferred', not 'confirmed', in uncertainties/,
    );
  });
});
