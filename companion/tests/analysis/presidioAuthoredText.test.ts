import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  authoredStrings,
  maskSegments,
  onlyInAuthoredText,
  reportGate,
  splitAuthored,
  withGateProbe,
} from "../../src/analysis/ai/presidioAuthoredText.js";
import { aiSpan, splitAiSpans, stripAiSpans, withAiSpans } from "../../src/analysis/ai/aiSpan.js";
import { AiAuthoredTextStore, AUTHORED_MAX_STRINGS } from "../../src/analysis/aiAuthoredText.js";
import { buildReconcilePrompt } from "../../src/analysis/secondOpinion.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// Presidio skips text the synthesis model wrote, and still scans events and analyst notes. Reported
// as: a 2nd opinion stopped on Presidio three times in a row, each time on values from text the
// models wrote during the run itself (the stored summary, then model B's findings in the referee
// prompt), which the analyst could not have cleared up front.

const same = (t: string) => t;

// A prompt as production builds it: AI fields marked inside withAiSpans, then split and masked.
function gated(build: () => string, corpus: string[], restore = same) {
  const segments = splitAiSpans(withAiSpans(build));
  const { masked, spans } = maskSegments(segments, (t) => t);
  return (value: string) => onlyInAuthoredText(masked, value, { corpus, spans, restore });
}

describe("onlyInAuthoredText", () => {
  const summary = "Investigate Jane Doe after suspicious activity on the domain controller.";

  it("skips a value that occurs only inside a marked span of recorded AI text", () => {
    expect(gated(() => `MODEL A summary: ${aiSpan(summary)}`, [summary])("Jane Doe")).toBe(true);
  });

  it("holds a value the marked span shows but the model is not recorded as writing", () => {
    expect(gated(() => `MODEL A summary: ${aiSpan(summary)}`, ["Something else entirely."])("Jane Doe")).toBe(
      false,
    );
  });

  it("holds a value that also occurs in unmarked text, even word for word", () => {
    const check = gated(() => `MODEL A summary: ${aiSpan(summary)}\n[NOTE] ${summary}`, [summary]);
    expect(check("Jane Doe")).toBe(false);
  });

  it.each([
    ["extends the AI string", "[e1] Investigate Jane Doe after an unauthorized login"],
    ["carries the value with repeated spaces", "[e1] Jane   Doe logged in"],
    ["carries the value with a tab", "[e1] Jane\tDoe logged in"],
    ["cuts with an ellipsis and goes on", "[e1] Investigate Jane Doe… login confirmed from the VPN"],
    ["equals the AI string", `[e1] 2026-01-01T10:00:00Z [High] ${summary}`],
  ])("holds a value when an event %s", (_label, eventLine) => {
    expect(gated(() => `MODEL A summary: ${aiSpan(summary)}\n${eventLine}`, [summary])("Jane Doe")).toBe(
      false,
    );
  });

  it("matches a cut span against the start of a recorded string", () => {
    const long = `${summary} ${"Further detail. ".repeat(20)}`;
    const shown = long.slice(0, 120);
    expect(gated(() => `desc — ${aiSpan(shown, true)}`, [long])("Jane Doe")).toBe(true);
    expect(gated(() => `desc — ${aiSpan(`${shown.slice(0, 60)}…`, true)}`, [long])("Jane Doe")).toBe(true);
  });

  it("matches a cut span only at the start of a recorded string, never in its middle", () => {
    const recorded = `Earlier context first. ${summary}`;
    const shown = `${summary.slice(0, 50)}…`;
    expect(gated(() => `desc — ${aiSpan(shown, true)}`, [recorded])("Jane Doe")).toBe(false);
  });

  it("does not match an uncut span against the start of a longer string", () => {
    expect(gated(() => `title: ${aiSpan("Investigate Jane Doe")}`, [summary])("Jane Doe")).toBe(false);
  });

  it("compares restored text, so a placeholder inside the span does not break the match", () => {
    const real = "Jane Doe ran a tool on DC01 at night.";
    const restore = (t: string) => t.replace("ANON_HOST_1", "DC01");
    const check = gated(
      () => `MODEL A summary: ${aiSpan("Jane Doe ran a tool on ANON_HOST_1 at night.")}`,
      [real],
      restore,
    );
    expect(check("Jane Doe")).toBe(true);
  });

  it("does not count a value inside a longer word as an occurrence", () => {
    const text = "Ann reviewed the evidence and closed the thread.";
    expect(gated(() => `MODEL A summary: ${aiSpan(text)}\nAnnounced maintenance window`, [text])("Ann")).toBe(
      true,
    );
  });

  it("trusts no marker it did not make: forged or outside the scope", () => {
    const forged = `MODEL A summary: \uE000${"\uE155".repeat(8)}${summary}\uE002${"\uE155".repeat(8)}`;
    const segments = splitAiSpans(forged);
    expect(segments.every((sg) => !sg.ai)).toBe(true);
    expect(segments.map((sg) => sg.text).join("")).toBe(`MODEL A summary: ${summary}`);
    expect(aiSpan(summary)).toBe(summary); // no withAiSpans scope: plain text
  });

  it("strips every marker, so the sent prompt is the plain text", () => {
    const marked = withAiSpans(() => `A: ${aiSpan("one")} B: ${aiSpan("two", true)}`);
    expect(marked).not.toBe("A: one B: two");
    expect(stripAiSpans(marked)).toBe("A: one B: two");
    expect(
      splitAiSpans(marked)
        .map((sg) => sg.text)
        .join(""),
    ).toBe("A: one B: two");
  });
});

describe("splitAuthored", () => {
  it("holds every value when there is no recorded AI text", () => {
    const fresh = [{ value: "Mimikatz", category: "PERSON" as const }];
    expect(splitAuthored(fresh, "MODEL A summary: Mimikatz ran", undefined)).toEqual({
      held: fresh,
      skipped: [],
    });
  });
});

// Codex round 3: only an answer from protected calls is recorded. A retry that ran unprotected
// spoils the whole answer, and a call path that reports nothing counts as unprotected.
describe("withGateProbe", () => {
  const probe = (reports: boolean[]) =>
    withGateProbe(async () => {
      for (const r of reports) {
        await Promise.resolve(); // reported across awaits, as prepareCall does
        reportGate(r);
      }
    }).then((r) => r.protectedOnly);

  it("is protected only when every call reported protection", async () => {
    expect(await probe([true])).toBe(true);
    expect(await probe([true, true])).toBe(true);
  });

  it("is not protected when any call ran unprotected", async () => {
    expect(await probe([true, false])).toBe(false);
    expect(await probe([false])).toBe(false);
  });

  it("is not protected when no call reported at all", async () => {
    expect(await probe([])).toBe(false);
  });

  it("ignores a report made outside any probe", () => {
    expect(() => reportGate(false)).not.toThrow();
  });
});

describe("authoredStrings", () => {
  it("keeps the summary, attacker path, and finding titles and descriptions — whitespace collapsed", () => {
    expect(
      authoredStrings({
        summary: "  Ransomware\n staged  via RDP ",
        attackerPath: "Initial access via RDP",
        findings: [{ title: "Mimikatz run", description: "LSASS read by mimikatz.exe" }],
      }),
    ).toEqual([
      "Ransomware staged via RDP",
      "Initial access via RDP",
      "Mimikatz run",
      "LSASS read by mimikatz.exe",
    ]);
  });

  it("drops strings too short to carry context", () => {
    expect(authoredStrings({ summary: "", findings: [{ title: "RDP", description: "x" }] })).toEqual([]);
  });
});

// The spec, on the real referee prompt builder: B's finding text is skipped, an event is not.
describe("the 2nd-opinion referee prompt", () => {
  const event = (id: string, description: string): ForensicEvent => ({
    id,
    timestamp: "2026-01-01T10:00:00Z",
    description,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  const finding = (description: string): Finding =>
    ({
      id: "F1",
      severity: "High",
      title: "Credential dumping with Mimikatz",
      description,
      relatedIocs: [],
      sourceScreenshots: [],
      mitreTechniques: ["T1003"],
      relatedEventIds: ["e1"],
      firstSeen: "2026-01-01T10:00:00Z",
      lastUpdated: "2026-01-01T10:00:00Z",
      status: "open",
    }) as Finding;

  function check(eventText: string) {
    const description = `Model B saw Mimikatz read LSASS memory on the server. ${"Detail. ".repeat(60)}`;
    const a = { ...emptyState("c1"), lastSummary: "Model A summary of the case." };
    const b = {
      ...emptyState("c1"),
      lastSummary: "Model B thinks Mimikatz was used.",
      findings: [finding(description)],
    };
    const deltas = [
      {
        id: "b_only:credential-dumping-mimikatz",
        kind: "b_only" as const,
        key: "k",
        title: "Credential dumping with Mimikatz",
        bSeverity: "High" as const,
        finding: finding(description),
        status: "pending" as const,
      },
    ];
    // Recorded the way production records them: each model's answer, plus the delta ids.
    const answers = [a, b].map((st) => ({ summary: st.lastSummary, findings: st.findings }));
    const corpus = [...answers.flatMap(authoredStrings), deltas[0].id];
    return gated(() => buildReconcilePrompt(a, b, deltas as never, [event("e1", eventText)]), corpus);
  }

  it("skips a value found only in the models' own text", () => {
    expect(check("lsass.exe memory read by procdump.exe")("Mimikatz")).toBe(true);
  });

  it("holds the same value once a cited event carries it", () => {
    expect(check("mimikatz.exe sekurlsa::logonpasswords run by Mimikatz operator")("Mimikatz")).toBe(false);
  });
});

describe("AiAuthoredTextStore", () => {
  async function store() {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-authored-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    return new AiAuthoredTextStore(cases);
  }

  it("reads empty before anything is recorded", async () => {
    expect(await (await store()).load("c1")).toEqual([]);
  });

  it("records, de-duplicates and keeps the newest last", async () => {
    const s = await store();
    await s.record("c1", ["first summary text", "second summary text"]);
    await s.record("c1", ["first summary text"]);
    expect(await s.load("c1")).toEqual(["second summary text", "first summary text"]);
  });

  it("drops the oldest past the cap", async () => {
    const s = await store();
    const many = Array.from({ length: AUTHORED_MAX_STRINGS + 5 }, (_u, i) => `summary number ${i}`);
    await s.record("c1", many);
    const kept = await s.load("c1");
    expect(kept).toHaveLength(AUTHORED_MAX_STRINGS);
    expect(kept[0]).toBe("summary number 5");
  });
});
