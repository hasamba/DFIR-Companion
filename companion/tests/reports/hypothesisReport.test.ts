import { describe, it, expect } from "vitest";
import { hypothesesSection } from "../../src/reports/hypothesisReport.js";
import type { Hypothesis } from "../../src/analysis/hypothesis.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #933 item 22 — the report's conclusion names what it rests on, and never a probability.

function h(partial: Partial<Hypothesis> & { id: string; title: string }): Hypothesis {
  return {
    description: "",
    expectedOutcome: "",
    status: "open",
    relatedTechniques: [],
    relatedEventIds: [],
    relatedIocIds: [],
    contradictingEventIds: [],
    discriminator: "",
    exhausted: false,
    exhaustedReason: "",
    assignee: "",
    notes: "",
    source: "synthesis",
    analystTouched: false,
    needsReview: false,
    reviewReason: "",
    alternativeIds: [],
    excludedEvidence: [],
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    statusHistory: [],
    ...partial,
  };
}

function ev(id: string, description: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-01-02T03:04:05Z",
    description,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Velociraptor"],
    ...extra,
  };
}

function render(hyps: Hypothesis[], events: ForensicEvent[]): string {
  const lines: string[] = [];
  hypothesesSection(hyps, events, lines);
  return lines.join("\n");
}

describe("hypothesesSection — distinguishing evidence, alternatives, unresolved", () => {
  const events = [
    ev("e1", "winword.exe spawned powershell.exe", { yearInferred: true }),
    ev("e2", "VPN logon for jdoe"),
    ev("e3", "outbound 443 to 203.0.113.9"),
  ];

  it("names the distinguishing observation, the alternative it separates from, and the record's own uncertainty", () => {
    const md = render(
      [
        h({
          id: "phish",
          title: "Initial access was phishing",
          status: "supported",
          relatedEventIds: ["e1", "e2"],
        }),
        h({
          id: "vpn",
          title: "Initial access was VPN",
          relatedEventIds: ["e2"],
          contradictingEventIds: ["e1"],
        }),
      ],
      events,
    );
    expect(md).toContain("### Initial access was phishing — Supported\n");
    expect(md).toContain("Distinguishing evidence — each separates this from a named alternative:");
    expect(md).toContain(
      "2026-01-02T03:04:05Z — winword.exe spawned powershell.exe _[year inferred, not read from the record]_ — separates this from 'Initial access was VPN'",
    );
    expect(md).toContain("Alternatives considered: 'Initial access was VPN' (Open)");
    expect(md).toContain(
      "Not distinguishing: 1 supporting observation(s) consistent with the alternatives that assessed them",
    );
    expect(md).toContain(
      "Unresolved: rests on one distinguishing observation, and that observation's own record carries an uncertainty: year inferred, not read from the record.",
    );
    expect(md).toContain(
      "Counts are counts of observations. They are not a probability that the explanation is true.",
    );
    expect(md).not.toMatch(/%|probab(?!ility that the explanation)|likel|confiden|score/i);
  });

  it("qualifies a supported conclusion on the status line when nothing separates it, and when it stands alone", () => {
    const shared = render(
      [
        h({ id: "a", title: "A", status: "supported", relatedEventIds: ["e2"] }),
        h({ id: "b", title: "B", relatedEventIds: ["e2"] }),
      ],
      events,
    );
    expect(shared).toContain("### A — Supported — no observation separates it from an alternative");
    expect(shared).toContain(
      "Distinguishing evidence: none — no supporting observation separates this from an alternative.",
    );
    const alone = render([h({ id: "a", title: "A", status: "supported", relatedEventIds: ["e2"] })], events);
    expect(alone).toContain("### A — Supported — no alternative offered");
    expect(alone).toContain("Alternatives considered: none — this is the only explanation offered");
  });

  it("prints the exclusion audit trail and the review reason, flattening multi-line text onto its line", () => {
    const md = render(
      [
        h({
          id: "a",
          title: "Exfiltration over HTTPS",
          status: "supported",
          needsReview: true,
          reviewReason: "the latest synthesis cites e2 against this",
          relatedEventIds: ["e3", "e2", "gone"],
          excludedEvidence: [
            { eventId: "e2", reason: "same session\nas e3", by: "alice", excludedAt: "2026-02-01T10:00:00Z" },
            {
              eventId: "gone",
              reason: "noise",
              by: "bob",
              excludedAt: "2026-02-02T10:00:00Z",
              restoredAt: "2026-02-03T00:00:00Z",
              restoredBy: "unlinked",
            },
          ],
        }),
        h({ id: "b", title: "B", contradictingEventIds: ["e3"] }),
      ],
      events,
    );
    expect(md).toContain(
      "### Exfiltration over HTTPS — Supported — review required: the latest synthesis cites e2 against this",
    );
    expect(md).toContain(
      "Excluded from this assessment by the analyst (the observation and its link were kept):",
    );
    expect(md).toContain(
      "- alice on 2026-02-01: 2026-01-02T03:04:05Z — VPN logon for jdoe — same session as e3",
    );
    expect(md).toContain(
      "- bob on 2026-02-02: `gone` — observation no longer in the timeline — noise (restored 2026-02-03, unlinked)",
    );
    expect(md).toContain("`gone` (not in this report's timeline (out of scope or marked false positive))");
    expect(md).toContain(
      "Unresolved: rests on one distinguishing observation; 1 linked observation(s) not counted",
    );
  });
});
