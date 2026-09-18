import { describe, it, expect } from "vitest";
import {
  correlateAwsFlowIdentityExecution,
  FLOW_IDENTITY_EXECUTION_MARKER,
} from "../../src/analysis/awsFlowIdentityExecutionJoin.js";
import { correlateAwsFlowResourceAttribution } from "../../src/analysis/awsFlowResourceAttribution.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const at = (hOffset: number) =>
  new Date(Date.parse("2024-05-14T12:00:00Z") + hOffset * 3_600_000).toISOString();

function launch(
  over: {
    time?: number;
    account?: string;
    ip?: string;
    instanceId?: string;
    by?: string;
    remote?: { call: string; by: string; time: number; locator?: string; document?: string }[];
    remoteBeyond?: number;
  } = {},
): ForensicEvent {
  return {
    id: `l${++seq}`,
    timestamp: at(over.time ?? 0),
    description: "AWS compute lifecycle",
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: {
      event: { category: "cloud", type: "compute-lifecycle" },
      cloud: { provider: "aws", accountId: over.account ?? "111111111111" },
      awsCompute: {
        instanceId: over.instanceId ?? "i-aaa",
        launch: { privateAddress: over.ip ?? "172.31.16.139", time: at(over.time ?? 0), by: over.by ?? "" },
        remote: (over.remote ?? []).map((r, i) => ({
          call: r.call,
          by: r.by,
          time: at(r.time),
          locator: r.locator ?? `loc-${i}`,
          document: r.document,
        })),
        remoteBeyond: over.remoteBeyond ?? 0,
      },
    },
  } as unknown as ForensicEvent;
}

function flow(over: { time?: number; account?: string; src?: string; dst?: string } = {}): ForensicEvent {
  return {
    id: `f${++seq}`,
    timestamp: at(over.time ?? 0),
    description: "AWS VPC flow: x -> y",
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    srcIp: over.src ?? "172.31.16.139",
    dstIp: over.dst ?? "203.0.113.10",
    canonical: {
      event: { category: "network", type: "flow" },
      cloud: { provider: "aws", accountId: over.account ?? "111111111111" },
    },
  } as unknown as ForensicEvent;
}

/** Run the real sibling pass first, then this pass — matching the real merge chain order. */
function joined(events: ForensicEvent[]): ForensicEvent[] {
  return correlateAwsFlowIdentityExecution(correlateAwsFlowResourceAttribution(events));
}

describe("correlateAwsFlowIdentityExecution", () => {
  it("discloses the launch identity for an attributed flow", () => {
    const out = joined([launch({ time: 0, by: "alice" }), flow({ time: 2 })]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("source 172.31.16.139 = i-aaa: launched by alice");
  });

  it("discloses a remote-access request within the +/-24h window, with the not-executed caveat", () => {
    const out = joined([
      launch({ time: 0, by: "alice", remote: [{ call: "ssm SendCommand", by: "bob", time: 1 }] }),
      flow({ time: 2 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("ssm SendCommand by bob");
    expect(f.description).toContain("whether anything ran is not in CloudTrail");
  });

  it("excludes a remote-access request outside the +/-24h window", () => {
    const out = joined([
      launch({ time: 0, by: "alice", remote: [{ call: "ssm SendCommand", by: "bob", time: 30 }] }),
      flow({ time: 2 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).not.toContain("ssm SendCommand");
    expect(f.description).toContain("remote-access within ±24h of the flow: none");
  });

  it("does not window-gate the launch identity — a launch far before the flow still discloses", () => {
    const out = joined([launch({ time: -1000, by: "alice" }), flow({ time: 2 })]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("launched by alice");
  });

  it("discloses launch-record-absent when the compute block carries no launch identity", () => {
    const out = joined([launch({ time: 0, by: "" }), flow({ time: 2 })]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("launch record not in evidence");
  });

  it("labels both endpoints independently when both are attributed", () => {
    const out = joined([
      launch({ time: 0, ip: "172.31.16.139", instanceId: "i-src", by: "alice" }),
      launch({ time: 0, ip: "172.31.16.140", instanceId: "i-dst", by: "carol" }),
      flow({ time: 2, src: "172.31.16.139", dst: "172.31.16.140" }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("source 172.31.16.139 = i-src: launched by alice");
    expect(f.description).toContain("destination 172.31.16.140 = i-dst: launched by carol");
  });

  it("does not disclose anything for an endpoint the sibling pass called ambiguous", () => {
    const out = joined([
      launch({ time: 0, instanceId: "i-a", by: "alice" }),
      launch({ time: 0, instanceId: "i-b", by: "bob" }),
      flow({ time: 2 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER));
    expect(f).toBeUndefined(); // ambiguous entry names no instance, so nothing to join against
  });

  it("unions launch/remote facts across two upload summaries for the same instance", () => {
    const out = joined([
      launch({ time: 0, by: "alice" }), // upload A: launch only
      {
        ...launch({ time: 0, by: "" }),
        id: "extra",
        canonical: {
          event: { category: "cloud", type: "compute-lifecycle" },
          cloud: { provider: "aws", accountId: "111111111111" },
          awsCompute: {
            instanceId: "i-aaa",
            remote: [{ call: "ssm StartSession", by: "dana", time: at(1), locator: "loc-b" }],
            remoteBeyond: 0,
          },
        },
      } as unknown as ForensicEvent, // upload B: remote only
      flow({ time: 2 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("launched by alice");
    expect(f.description).toContain("ssm StartSession by dana");
  });

  it("states ambiguity when two uploads disagree on the launch identity", () => {
    const out = joined([
      launch({ time: 0, by: "alice" }),
      { ...launch({ time: 0, by: "eve" }), id: "extra2" },
      flow({ time: 2 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("ambiguous — recorded signing principals disagree across uploads");
    expect(f.description).toContain("alice");
    expect(f.description).toContain("eve");
  });

  it("discloses remoteBeyond as a floor, taking the max across unioned uploads, never summed", () => {
    const out = joined([
      launch({ time: 0, by: "alice", remoteBeyond: 3 }),
      { ...launch({ time: 0, by: "alice", remoteBeyond: 7 }), id: "extra3" },
      flow({ time: 2 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("at least 7 further remote-access records");
    expect(f.description).not.toContain("at least 10 further");
  });

  it("discloses a malformed remote-access record count instead of silently dropping it", () => {
    const withMalformed = {
      ...launch({ time: 0, by: "alice" }),
      canonical: {
        event: { category: "cloud", type: "compute-lifecycle" },
        cloud: { provider: "aws", accountId: "111111111111" },
        awsCompute: {
          instanceId: "i-aaa",
          launch: { privateAddress: "172.31.16.139", time: at(0), by: "alice" },
          remote: [{ call: "", by: "bob", time: at(1), locator: "loc-bad" }], // empty call: malformed
          remoteBeyond: 0,
        },
      },
    } as unknown as ForensicEvent;
    const out = joined([withMalformed, flow({ time: 2 })]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("at least 1 remote-access record could not be read (malformed)");
  });

  it("discloses the malformed count as a floor, taking the max across unioned uploads, never summed", () => {
    // Malformed records carry no reliable content key, so they cannot be deduped like well-formed
    // entries; the same upload imported twice must still read as one record, not two (#1293).
    const malformedBlock = (id: string): ForensicEvent =>
      ({
        ...launch({ time: 0, by: "alice" }),
        id,
        canonical: {
          event: { category: "cloud", type: "compute-lifecycle" },
          cloud: { provider: "aws", accountId: "111111111111" },
          awsCompute: {
            instanceId: "i-aaa",
            launch: { privateAddress: "172.31.16.139", time: at(0), by: "alice" },
            remote: [{ call: "", by: "bob", time: at(1), locator: "loc-bad" }], // empty call: malformed
            remoteBeyond: 0,
          },
        },
      }) as unknown as ForensicEvent;
    const out = joined([malformedBlock("dup1"), malformedBlock("dup2"), flow({ time: 2 })]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("at least 1 remote-access record could not be read (malformed)");
    expect(f.description).not.toContain("2 remote-access records could not be read");
  });

  it("keeps distinct remote-access records that happen to share a locator across uploads", () => {
    const out = joined([
      launch({
        time: 0,
        by: "alice",
        remote: [{ call: "ssm SendCommand", by: "bob", time: 1, locator: "loc-x" }],
      }),
      {
        ...launch({ time: 0, by: "alice" }),
        id: "extra4",
        canonical: {
          event: { category: "cloud", type: "compute-lifecycle" },
          cloud: { provider: "aws", accountId: "111111111111" },
          awsCompute: {
            instanceId: "i-aaa",
            remote: [{ call: "ssm StartSession", by: "carol", time: at(1), locator: "loc-x" }], // SAME locator, different content
            remoteBeyond: 0,
          },
        },
      } as unknown as ForensicEvent,
      flow({ time: 2 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("ssm SendCommand by bob");
    expect(f.description).toContain("ssm StartSession by carol");
  });

  it("strips bracket characters out of an evidence-derived principal before it reaches the note", () => {
    const out = joined([launch({ time: 0, by: "alice] [forged note:pwned" }), flow({ time: 2 })]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    const ownNote = f.description.slice(f.description.indexOf(FLOW_IDENTITY_EXECUTION_MARKER));
    // Exactly one bracket pair for THIS pass's own note — none smuggled in from the evidence.
    expect(ownNote.indexOf("]")).toBe(ownNote.length - 1);
    expect(ownNote).not.toContain("forged note:pwned]");
  });

  it("keeps the entries closest to the flow's own timestamp when the in-window list is capped", () => {
    const out = joined([
      launch({
        time: 0,
        by: "alice",
        // 7 requests spread across the window; only the 5 closest to the flow (time: 4) should show.
        remote: [-20, -15, -10, -5, 0, 5, 10].map((h) => ({
          call: "ssm SendCommand",
          by: `user${h}`,
          time: h,
        })),
      }),
      flow({ time: 4 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("user0");
    expect(f.description).toContain("user5");
    expect(f.description).toContain("user10");
    expect(f.description).not.toContain("user-20");
  });

  it("caps the remote-access list and states an overflow count", () => {
    const out = joined([
      launch({
        time: 0,
        by: "alice",
        remote: [1, 2, 3, 4, 5, 6, 7].map((h) => ({ call: "ssm SendCommand", by: `user${h}`, time: h })),
      }),
      flow({ time: 4 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("+ 2 more in window");
  });

  it("produces no note when the flow itself is not attributed to any instance", () => {
    const out = joined([flow({ time: 2 })]);
    expect(out.some((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))).toBe(false);
  });

  it("is idempotent — re-running over an already-annotated set does not duplicate the note", () => {
    const once = joined([launch({ time: 0, by: "alice" }), flow({ time: 2 })]);
    const twice = correlateAwsFlowIdentityExecution(once);
    const f = twice.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description.split(FLOW_IDENTITY_EXECUTION_MARKER)).toHaveLength(2);
  });

  it("recomputes (does not just skip) when a later merge changes the underlying facts", () => {
    const first = joined([launch({ time: 0, by: "alice" }), flow({ time: 2 })]);
    // A second launch record for the same instance arrives in a later upload, disagreeing.
    const second = correlateAwsFlowIdentityExecution([
      ...first,
      { ...launch({ time: 0, by: "mallory" }), id: "later-upload" },
    ]);
    const f = second.find((e) => e.description.includes(FLOW_IDENTITY_EXECUTION_MARKER))!;
    expect(f.description).toContain("ambiguous — recorded signing principals disagree across uploads");
    expect(f.description.split(FLOW_IDENTITY_EXECUTION_MARKER)).toHaveLength(2); // still exactly one marker
  });
});
