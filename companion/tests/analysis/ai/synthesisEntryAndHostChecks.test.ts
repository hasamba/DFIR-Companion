// Two checks synthesis must make before giving a negative answer (#2080). It answered the initial
// access vector "unknown" while the earliest attacker event's parent command line showed the delivery,
// and it called a host "not compromised" while an attacker account creation on that host was sent.
import { describe, it, expect } from "vitest";
import { SYNTHESIS_PROMPT } from "../../../src/analysis/ai/prompts/synthesis.js";

// The prompt wraps its sentences across array lines, so prose checks read one-space text.
const FLAT = SYNTHESIS_PROMPT.replace(/\s+/g, " ");

describe("SYNTHESIS_PROMPT — lineage check before 'initial access unknown'", () => {
  it("reads the parent command line of the earliest confirmed attacker event first", () => {
    expect(FLAT).toMatch(/Before marking q_initial_access 'unknown'[^.]*parent command line/i);
    expect(FLAT).toMatch(/earliest confirmed attacker event/i);
  });

  it("reads the parent's own process-creation row when it was shown", () => {
    expect(FLAT).toMatch(/parent's own process-creation row/i);
  });

  it("asks the answer to say what the lineage shows", () => {
    expect(FLAT).toMatch(/say what they show/i);
  });
});

describe("SYNTHESIS_PROMPT — host evidence before 'not compromised'", () => {
  it("checks account creation, remote sessions and attacker tooling on the host", () => {
    expect(FLAT).toMatch(/Before calling a host not compromised/i);
    expect(FLAT).toMatch(/account creation/i);
    expect(FLAT).toMatch(/remote sessions?/i);
    expect(FLAT).toMatch(/tooling/i);
  });

  it("scopes the check to evidence tied to the attacker, not routine admin work", () => {
    expect(FLAT).toMatch(/tied to the attacker/i);
  });

  it("uses the scoped negative instead of 'not compromised'", () => {
    expect(FLAT).toMatch(/no attacker activity in the events shown/i);
  });
});
