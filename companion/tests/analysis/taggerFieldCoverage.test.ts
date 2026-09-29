import { describe, it, expect } from "vitest";
import { compileText } from "../../src/analysis/taggerStore.js";
import { createFieldCoverage, fieldCoverageHint } from "../../src/analysis/tagger.js";
import { ruleFields } from "../../src/analysis/taggerRules.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const RULE = compileText(
  "r:\n  all:\n    - { field: message, contains: 'x' }\n  any:\n    - { field: port, equals: '3389' }\n    - { field: message, exists: true }\n  none:\n    - { field: sources, contains: 'y' }\n  tags: ['t']\n",
);

describe("ruleFields", () => {
  it("lists every referenced field once, in order", () => {
    expect(ruleFields(RULE.rules[0])).toEqual(["message", "port", "sources"]);
  });
});

describe("createFieldCoverage", () => {
  it("counts non-empty values per referenced field across batches", () => {
    const cov = createFieldCoverage(RULE);
    cov.add([ev({ id: "a", message: "hi" }), ev({ id: "b", message: "" })]);
    cov.add([ev({ id: "c", port: 3389, sources: ["Hayabusa"] })]);
    expect(cov.scanned()).toBe(3);
    expect(cov.counts()).toEqual({ message: 1, port: 1, sources: 1 });
  });
});

describe("fieldCoverageHint", () => {
  it("names each empty field and suggests description", () => {
    expect(fieldCoverageHint({ message: 0 }, 7)).toBe('0 of 7 events have "message"; try "description"');
  });

  it("suggests description only for free-text fields", () => {
    expect(fieldCoverageHint({ description: 0, sha256: 0 }, 3)).toBe(
      '0 of 3 events have "description". 0 of 3 events have "sha256"',
    );
  });

  it("says the values matched nothing when every field is filled", () => {
    expect(fieldCoverageHint({ message: 4 }, 7)).toBe(
      '"message" is filled on 4 of 7 events, but no value matched the condition',
    );
  });

  it("reports an empty scope", () => {
    expect(fieldCoverageHint({ message: 0 }, 0)).toBe("No events in the tagger scope");
  });
});
