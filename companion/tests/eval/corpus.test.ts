import { describe, expect, it } from "vitest";
import { loadGoldenCorpus } from "./corpus.js";
import { runCorpusCase } from "./harness.js";
import { mockProvider } from "./harness.js";
import { passesCaseQuality, scoreCaseQuality, type QualityOutput } from "./qualityScorer.js";

const REQUIRED_SCENARIOS = [
  "ransomware",
  "bec",
  "insider-threat",
  "lateral-movement",
  "linux",
  "cloud-identity",
  "email",
  "memory",
  "network",
  "clean",
];

describe("versioned production golden corpus (#378)", () => {
  it("documents safe provenance and covers the required investigative scenarios", async () => {
    const corpus = await loadGoldenCorpus();
    expect(corpus.schemaVersion).toBe(1);
    expect(corpus.version).toBe("1.1.0");
    expect(new Set(corpus.cases.map((fixture) => fixture.scenario))).toEqual(new Set(REQUIRED_SCENARIOS));
    expect(corpus.cases.every((fixture) => fixture.provenance.origin === "synthetic")).toBe(true);
    expect(corpus.cases.every((fixture) => fixture.provenance.containsClientData === false)).toBe(true);
    expect(corpus.license).toBe("AGPL-3.0-only");
  });

  it("includes clean abstention, incomplete evidence, contradictions, and prompt injection", async () => {
    const corpus = await loadGoldenCorpus();
    const traits = new Set(corpus.cases.flatMap((fixture) => fixture.traits));
    expect(corpus.cases.some((fixture) => fixture.golden.expectAbstention)).toBe(true);
    expect(traits.has("incomplete-evidence")).toBe(true);
    expect(traits.has("contradictory-sources")).toBe(true);
    expect(traits.has("prompt-injection")).toBe(true);
  });

  for (const scenario of REQUIRED_SCENARIOS) {
    it(`${scenario}: canned output passes exact evidence-grounded quality gates`, async () => {
      const corpus = await loadGoldenCorpus();
      const fixture = corpus.cases.find((candidate) => candidate.scenario === scenario);
      expect(fixture).toBeDefined();
      if (!fixture) return;
      const output = await runCorpusCase(fixture, mockProvider(fixture.canned));
      expect(passesCaseQuality(scoreCaseQuality(fixture.golden, output))).toBe(true);
    });
  }

  // #1579: a real model run (claude-sonnet-5) got these three right in its own words and the literal
  // phrase match scored them as misses. The golden terms test the concept, so these phrasings — copied
  // from that run — must earn credit, while a step that drops the concept must still miss.
  describe("credits a real model's equivalent phrasing (#1579)", () => {
    it("network-egress-gap: an action that gathers no evidence earns no credit (review counterexample)", async () => {
      const golden = await goldenFor("network-egress-gap");
      const action = "Confirm WS-11 is enrolled in EDR before reconnecting it to the network";
      expect(
        scoreCaseQuality(golden, outputWith({ nextSteps: [{ action, rationale: "", pointer: "" }] }))
          .nextSteps.missed,
      ).toContain("collect-edr-network");
    });

    const step = (action: string) => ({ action, rationale: "", pointer: "" });
    const outputWith = (parts: Partial<QualityOutput>): QualityOutput => ({
      evidenceEventIds: [],
      claims: [],
      iocs: [],
      uncertainties: [],
      nextSteps: [],
      ...parts,
    });
    const goldenFor = async (id: string) => {
      const fixture = (await loadGoldenCorpus()).cases.find((candidate) => candidate.id === id);
      if (!fixture) throw new Error(`corpus case ${id} missing`);
      return fixture.golden;
    };

    it.each([
      [
        "cloud-vpn-contradiction",
        "review-cloud-audit",
        "Pull the full identity-provider sign-in log for user-b around 12:00Z",
      ],
      [
        "cloud-vpn-contradiction",
        "review-cloud-audit",
        "Review the cloud tenant sign-in and audit log for user-b around 12:00:00Z to determine whether the sign-in was allowed",
      ],
      [
        "network-egress-gap",
        "collect-edr-network",
        "Correlate the TLS session on ws-11 to the responsible process using Sysmon Event ID 3 / EDR network-to-process mapping",
      ],
    ])("%s: next step %s", async (caseId, stepId, action) => {
      const golden = await goldenFor(caseId);
      expect(
        scoreCaseQuality(golden, outputWith({ nextSteps: [step(action)] })).nextSteps.missed,
      ).not.toContain(stepId);
      const offTopic = step("Check firewall logs for the same window");
      expect(scoreCaseQuality(golden, outputWith({ nextSteps: [offTopic] })).nextSteps.missed).toContain(
        stepId,
      );
    });

    it("linux-ssh-compromise: 'root account compromised' + a sudoers finding cover the root-compromise claim", async () => {
      const golden = await goldenFor("linux-ssh-compromise");
      const claim = (id: string, title: string, evidenceEventIds: string[]) => ({
        id,
        title,
        description: "",
        evidenceEventIds,
        confidence: 90,
        confidenceReason: "direct log evidence",
      });
      const output = outputWith({
        claims: [
          claim("f2", "Root account compromised via SSH following brute-force success", ["lin-e2"]),
          claim("f3", "Unrestricted sudoers.d entry added immediately after compromise", ["lin-e3"]),
        ],
      });
      expect(scoreCaseQuality(golden, output).claims.missed).not.toContain("linux-root-compromise");
    });

    it("linux-ssh-compromise: 'root-level shell access' + a sudoers finding, from a second real run", async () => {
      const golden = await goldenFor("linux-ssh-compromise");
      const claim = (id: string, title: string, description: string, evidenceEventIds: string[]) => ({
        id,
        title,
        description,
        evidenceEventIds,
        confidence: 90,
        confidenceReason: "direct log evidence",
      });
      const output = outputWith({
        claims: [
          claim(
            "f2",
            "Successful Root SSH Authentication Following Brute-Force",
            "The attacker obtained direct root-level shell access to the host over the network.",
            ["lin-e2"],
          ),
          claim("f3", "Unrestricted Sudoers Entry Added for Persistence/Privilege Escalation", "", [
            "lin-e3",
          ]),
        ],
      });
      expect(scoreCaseQuality(golden, output).claims.missed).not.toContain("linux-root-compromise");
      // The evidence still has to be the right events: the same words citing only the brute-force row miss.
      // Root access plus a sudoers change is not enough on its own: the claim must call it an attack.
      const noCompromise = outputWith({
        claims: [
          claim("f2", "Root SSH login", "An SSH login for root was accepted.", ["lin-e2"]),
          claim("f3", "Sudoers entry added", "", ["lin-e3"]),
        ],
      });
      expect(scoreCaseQuality(golden, noCompromise).claims.missed).toContain("linux-root-compromise");
      const wrongEvidence = outputWith({
        claims: [claim("f1", "Root SSH brute-force then sudoers change", "", ["lin-e1"])],
      });
      expect(scoreCaseQuality(golden, wrongEvidence).claims.missed).toContain("linux-root-compromise");
    });
  });
});
