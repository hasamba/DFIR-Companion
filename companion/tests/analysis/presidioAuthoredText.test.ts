import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  authoredStrings,
  onlyInAuthoredText,
  splitAuthored,
  type AuthoredText,
} from "../../src/analysis/ai/presidioAuthoredText.js";
import { AiAuthoredTextStore, AUTHORED_MAX_STRINGS } from "../../src/analysis/aiAuthoredText.js";
import { buildReconcilePrompt } from "../../src/analysis/secondOpinion.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// Presidio skips text the synthesis model wrote, and still scans events and analyst notes. Reported
// as: a 2nd opinion stopped on Presidio three times in a row, each time on values from text the
// models wrote during the run itself (the stored summary, then model B's findings in the referee
// prompt), which the analyst could not have cleared up front.

const same = (t: string) => t;
const authored = (corpus: string[], restore = same): AuthoredText => ({ corpus, restore });

describe("onlyInAuthoredText", () => {
  const summary = "The operator ran Mimikatz on the domain controller and dumped credentials.";

  it("skips a value that occurs only inside AI-written text", () => {
    const prompt = `MODEL A summary: ${summary}\n\nDISAGREEMENTS (0):`;
    expect(onlyInAuthoredText(prompt, "Mimikatz", authored([summary]))).toBe(true);
  });

  it("holds a value that also occurs in an event line", () => {
    const prompt = `MODEL A summary: ${summary}\n  - [e1] 10:00 Mimikatz.exe started by svc_backup`;
    expect(onlyInAuthoredText(prompt, "Mimikatz", authored([summary]))).toBe(false);
  });

  it("holds a value the AI never wrote", () => {
    expect(onlyInAuthoredText(`Jane Doe signed in`, "Jane Doe", authored([summary]))).toBe(false);
  });

  it("holds a value that does not occur in the prompt at all", () => {
    expect(onlyInAuthoredText("nothing here", "Mimikatz", authored([summary]))).toBe(false);
  });

  it("holds a value alone on a line, with no context to compare", () => {
    expect(onlyInAuthoredText("Mimikatz", "Mimikatz", authored([summary]))).toBe(false);
  });

  it("matches across collapsed whitespace and a clipped end", () => {
    const description = `Credential theft.\nThe attacker used   Mimikatz to read LSASS memory ${"x".repeat(300)}`;
    const prompt = `finding — ${description.replace(/\s+/g, " ").slice(0, 60)}…`;
    expect(
      onlyInAuthoredText(prompt, "Mimikatz", authored(authoredStrings({ findings: [{ description }] }))),
    ).toBe(true);
  });

  it("does not skip a short AI title that appears in an event's running text", () => {
    const prompt = `  - [e1] 10:00 Mimikatz run by svc_backup on the server`;
    expect(onlyInAuthoredText(prompt, "Mimikatz", authored(["Mimikatz run"]))).toBe(false);
  });

  it("holds a value whose only shared context is a common phrase", () => {
    const prompt = `MODEL A summary: ${summary}\n  - [e2] Process created by user Mimikatz on the domain controller`;
    expect(onlyInAuthoredText(prompt, "Mimikatz", authored([summary]))).toBe(false);
  });

  it("holds an event that shares the rest of an AI string which opens with the value", () => {
    const ai = "Mimikatz on the domain controller dumped the credentials of every user.";
    const prompt = `MODEL A summary: ${ai}\n  - [e2] Process created by user Mimikatz on the domain controller`;
    expect(onlyInAuthoredText(prompt, "Mimikatz", authored([ai]))).toBe(false);
  });

  it("holds an event that repeats the start of an AI sentence, then goes its own way", () => {
    const ai = "The operator ran Mimikatz against the file server at night.";
    const prompt = `MODEL A summary: ${ai}\n  - [e3] The operator ran Mimikatz against the backup server`;
    expect(onlyInAuthoredText(prompt, "Mimikatz", authored([ai]))).toBe(false);
  });

  // Codex adversarial review, finding 1: a new event that starts with recorded AI text and goes on.
  it("holds an event that extends a recorded AI string", () => {
    const prompt = `[e1] Investigate Jane Doe after an unauthorized login`;
    expect(onlyInAuthoredText(prompt, "Jane Doe", authored(["Investigate Jane Doe"]))).toBe(false);
  });

  // Codex adversarial review, finding 2: the event's occurrence differs only in its whitespace.
  it.each([
    ["repeated spaces", "Jane   Doe"],
    ["a tab", "Jane\tDoe"],
  ])("holds a value an event carries with %s", (_label, spelled) => {
    const prompt = `MODEL A summary: Investigate Jane Doe\n[e1] ${spelled} logged in`;
    expect(onlyInAuthoredText(prompt, "Jane Doe", authored(["Investigate Jane Doe"]))).toBe(false);
  });

  it("holds an event that carries a recorded AI string mid-sentence, unframed", () => {
    const prompt = `[e1] 10:00 analyst wrote Investigate Jane Doe (ticket 4)`;
    expect(onlyInAuthoredText(prompt, "Jane Doe", authored(["Investigate Jane Doe"]))).toBe(false);
  });

  it("holds a value when an event's description equals a recorded AI string", () => {
    const prompt = `[e1] 2026-01-01T10:00:00Z [High] Investigate Jane Doe`;
    const ai = { ...authored(["Investigate Jane Doe"]), events: ["Investigate  Jane Doe"] };
    expect(onlyInAuthoredText(prompt, "Jane Doe", ai)).toBe(false);
  });

  it("holds a value when a recorded AI string quotes an event", () => {
    const prompt = `MODEL A summary: The log shows Jane Doe signed in at 10:00 from the VPN.`;
    const ai = {
      ...authored(["The log shows Jane Doe signed in at 10:00 from the VPN."]),
      events: ["Jane Doe signed in at 10:00"],
    };
    expect(onlyInAuthoredText(prompt, "Jane Doe", ai)).toBe(false);
  });

  it("matches a short title quoted whole", () => {
    const prompt = `[d1] (B-only finding) "Mimikatz run" [severity High]: Model B raised this.`;
    expect(onlyInAuthoredText(prompt, "Mimikatz", authored(["Mimikatz run"]))).toBe(true);
  });

  it("compares the restored prompt line, so placeholders do not break the match", () => {
    const real = "Mimikatz ran on DC01 under the backup account.";
    const prompt = "MODEL A summary: Mimikatz ran on ANON_HOST_1 under the backup account.";
    const restore = (t: string) => t.replace("ANON_HOST_1", "DC01");
    expect(onlyInAuthoredText(prompt, "Mimikatz", authored([real], restore))).toBe(true);
  });

  it("does not count a value inside a longer word as an occurrence", () => {
    const text = "Ann reviewed the evidence and closed the thread.";
    // "Announced" holds "Ann" but is not an occurrence of it; the real one is in AI text.
    const prompt = `MODEL A summary: ${text}\nAnnounced maintenance window`;
    expect(onlyInAuthoredText(prompt, "Ann", authored([text]))).toBe(true);
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

  function prompt(eventText: string): { text: string; corpus: string[] } {
    const description = `Model B saw Mimikatz read LSASS memory on the server. ${"Detail. ".repeat(60)}`;
    const a = { ...emptyState("c1"), lastSummary: "Model A summary of the case." };
    const b = {
      ...emptyState("c1"),
      lastSummary: "Model B thinks Mimikatz was used.",
      findings: [finding(description)],
    };
    const deltas = [
      {
        id: "d1",
        kind: "b_only" as const,
        key: "k",
        title: "Credential dumping with Mimikatz",
        bSeverity: "High" as const,
        finding: finding(description),
        status: "pending" as const,
      },
    ];
    const text = buildReconcilePrompt(a, b, deltas as never, [event("e1", eventText)]);
    // Recorded the way production records them: from each model's answer, whose field is `summary`.
    const answers = [a, b].map((st) => ({ summary: st.lastSummary, findings: st.findings }));
    return { text, corpus: answers.flatMap(authoredStrings) };
  }

  it("skips a value found only in the models' own text", () => {
    const { text, corpus } = prompt("lsass.exe memory read by procdump.exe");
    expect(text).toContain("Mimikatz");
    expect(onlyInAuthoredText(text, "Mimikatz", authored(corpus))).toBe(true);
  });

  it("holds the same value once a cited event carries it", () => {
    const { text, corpus } = prompt("mimikatz.exe sekurlsa::logonpasswords run by Mimikatz operator");
    expect(onlyInAuthoredText(text, "Mimikatz", authored(corpus))).toBe(false);
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
