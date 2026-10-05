import { describe, it, expect } from "vitest";
import { groundAndScoreFindings } from "../../src/analysis/findingGrounding.js";
import {
  selfDisclaimedPhrase,
  SELF_DISCLAIMED_SEVERITY_FLOOR,
} from "../../src/analysis/selfDisclaimedSubject.js";
import { findingCautionLine } from "../../src/reports/findingCaution.js";
import type { Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1944: a finding whose own text says its subject is not in the evidence, and that guesses at it
// ("probably", "likely"), is an open question, not a High finding. It is capped at Medium.

function f(p: Partial<Finding>): Finding {
  return {
    id: "f1",
    severity: "High",
    title: "A finding",
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
    ...p,
  };
}
function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-01-01T00:00:00Z",
    description: "x",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WEB01",
    ...p,
  };
}
function ground(findings: Finding[], scopedEvents: ForensicEvent[] = [ev({})]): Finding[] {
  return groundAndScoreFindings({ findings, scopedEvents, iocs: [], graphLinkedEventIds: new Set() });
}

const SKIMMER_TITLE = "Card skimmer planted in payment pages";
const SKIMMER_TEXT =
  "The attacker probably planted a card skimmer in the payment pages. The modified pages are not in the evidence.";

describe("selfDisclaimedPhrase", () => {
  it("returns the disclaimer phrase when a guessing word is also present", () => {
    expect(selfDisclaimedPhrase(SKIMMER_TEXT)).toMatch(/not in the evidence/i);
  });
  it("matches the other disclaimer shapes", () => {
    expect(
      selfDisclaimedPhrase("Data likely staged; the archive is absent from the collection."),
    ).not.toBeNull();
    expect(
      selfDisclaimedPhrase("Files may have been exfiltrated; the share was not collected."),
    ).not.toBeNull();
    expect(
      selfDisclaimedPhrase("Possibly modified; the config is not present in the provided data."),
    ).not.toBeNull();
  });
  it("returns null without a guessing word", () => {
    expect(
      selfDisclaimedPhrase("Security log cleared (EID 1102); the cleared records are not in the evidence."),
    ).toBeNull();
  });
  it("returns null without a disclaimer phrase", () => {
    expect(selfDisclaimedPhrase("The attacker likely used this tool to dump credentials.")).toBeNull();
  });
  it("does not read 'unlikely' as a guessing word", () => {
    expect(selfDisclaimedPhrase("Tampering is unlikely; the old binary is not in the evidence.")).toBeNull();
  });
});

describe("groundAndScoreFindings — self-disclaimed subject gate (#1944)", () => {
  it("caps a High finding that disclaims its subject and guesses, with a reason and the flag", () => {
    const out = ground([f({ title: SKIMMER_TITLE, description: SKIMMER_TEXT, relatedEventIds: ["e1"] })]);
    expect(out[0].severity).toBe(SELF_DISCLAIMED_SEVERITY_FLOOR);
    expect(out[0].severity).toBe("Medium");
    expect(out[0].selfDisclaimed).toBe(true);
    expect(out[0].confidenceReason).toMatch(/its subject is not in the evidence/i);
  });

  it("caps a Critical finding with the same text at Medium", () => {
    const out = ground([
      f({ severity: "Critical", title: SKIMMER_TITLE, description: SKIMMER_TEXT, relatedEventIds: ["e1"] }),
    ]);
    expect(out[0].severity).toBe("Medium");
  });

  it("keeps High on an impact finding that names a written file and disclaims nothing", () => {
    const out = ground(
      [
        f({
          title: "Web shell written to payment folder",
          description: "w3wp.exe wrote C:\\inetpub\\pay\\checkout.aspx; the file is in the evidence.",
          relatedEventIds: ["e1"],
        }),
      ],
      [ev({ description: "w3wp.exe wrote C:\\inetpub\\pay\\checkout.aspx" })],
    );
    expect(out[0].severity).toBe("High");
    expect(out[0].selfDisclaimed).toBeUndefined();
  });

  it("keeps High on a log-clear finding whose lost records are not in the evidence but which does not guess", () => {
    const out = ground([
      f({
        title: "Security log cleared",
        description: "Security log cleared (EID 1102); the cleared records are not in the evidence.",
        relatedEventIds: ["e1"],
      }),
    ]);
    expect(out[0].severity).toBe("High");
    expect(out[0].selfDisclaimed).toBeUndefined();
  });

  it("never raises a Medium or Low finding, but still records the flag", () => {
    const out = ground([
      f({ id: "m", severity: "Medium", description: SKIMMER_TEXT, relatedEventIds: ["e1"] }),
      f({ id: "l", severity: "Low", description: SKIMMER_TEXT, relatedEventIds: ["e1"] }),
    ]);
    expect(out[0].severity).toBe("Medium");
    expect(out[1].severity).toBe("Low");
    expect(out[0].selfDisclaimed).toBe(true);
  });

  it("clears a stale flag on recompute when the text no longer disclaims", () => {
    const out = ground(
      [
        f({
          title: "Web shell written",
          description: "w3wp.exe wrote checkout.aspx.",
          selfDisclaimed: true,
          relatedEventIds: ["e1"],
        }),
      ],
      [ev({ description: "w3wp.exe wrote C:\\inetpub\\pay\\checkout.aspx" })],
    );
    expect(out[0].selfDisclaimed).toBeUndefined();
    expect(out[0].severity).toBe("High");
  });

  it("is idempotent across two passes", () => {
    const once = ground([f({ title: SKIMMER_TITLE, description: SKIMMER_TEXT, relatedEventIds: ["e1"] })]);
    const twice = ground(once);
    expect(twice[0].severity).toBe("Medium");
    expect(twice[0].selfDisclaimed).toBe(true);
  });

  it("fires on an ungrounded finding too", () => {
    const out = ground([
      f({ title: SKIMMER_TITLE, description: SKIMMER_TEXT, relatedEventIds: ["missing"] }),
    ]);
    expect(out[0].ungrounded).toBe(true);
    expect(out[0].selfDisclaimed).toBe(true);
    expect(out[0].severity).toBe("Medium");
  });

  it("prints a caution badge in the report", () => {
    const out = ground([f({ title: SKIMMER_TITLE, description: SKIMMER_TEXT, relatedEventIds: ["e1"] })]);
    expect(findingCautionLine(out[0])).toMatch(/Subject not in evidence/);
  });
});
