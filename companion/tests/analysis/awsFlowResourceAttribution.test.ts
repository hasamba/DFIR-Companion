import { describe, it, expect } from "vitest";
import {
  correlateAwsFlowResourceAttribution,
  FLOW_ATTRIBUTION_MARKER,
} from "../../src/analysis/awsFlowResourceAttribution.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const at = (hOffset: number) =>
  new Date(Date.parse("2024-05-14T12:00:00Z") + hOffset * 3_600_000).toISOString();

function launch(
  over: { time?: number; account?: string; ip?: string; instanceId?: string } = {},
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
        launch: { privateAddress: over.ip ?? "172.31.16.139", time: at(over.time ?? 0) },
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

describe("correlateAwsFlowResourceAttribution", () => {
  it("attributes a flow's private-IP endpoint to the instance launched on that (account, IP)", () => {
    const out = correlateAwsFlowResourceAttribution([launch({ time: 0 }), flow({ time: 2 })]);
    const f = out.find((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER))!;
    expect(f).toBeDefined();
    expect(f.description).toContain("source 172.31.16.139 = i-aaa");
  });

  it("never attributes the public endpoint (not a private IPv4 address)", () => {
    const out = correlateAwsFlowResourceAttribution([
      launch({ time: 0, ip: "203.0.113.10" }), // not actually private, but pretend it were tracked
      flow({ time: 2 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER));
    // dst (203.0.113.10) is a public IP — never attributed regardless of what's "tracked"
    expect(f?.description ?? "").not.toContain("destination 203.0.113.10");
  });

  it("does not attribute when no compute-lifecycle evidence exists at all", () => {
    const input = [flow({ time: 2 })];
    const out = correlateAwsFlowResourceAttribution(input);
    expect(out).toEqual(input);
  });

  it("does not attribute a flow BEFORE any tracked launch on that key", () => {
    const out = correlateAwsFlowResourceAttribution([launch({ time: 5 }), flow({ time: 0 })]);
    const f = out.find((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER));
    expect(f).toBeUndefined();
  });

  it("never collides two different accounts sharing the same private IP", () => {
    const out = correlateAwsFlowResourceAttribution([
      launch({ time: 0, account: "222222222222", instanceId: "i-other-account" }),
      flow({ time: 2, account: "111111111111" }), // different account, same IP
    ]);
    const f = out.find((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER));
    expect(f).toBeUndefined();
  });

  it("a later launch on the same (account, IP) supersedes an earlier one — no termination time needed", () => {
    const out = correlateAwsFlowResourceAttribution([
      launch({ time: 0, instanceId: "i-first" }),
      launch({ time: 5, instanceId: "i-second" }),
      flow({ time: 6 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER))!;
    expect(f.description).toContain("= i-second");
    expect(f.description).not.toContain("= i-first");
  });

  it("states ambiguity, names no instance, when two launches tie at the exact same time", () => {
    const out = correlateAwsFlowResourceAttribution([
      launch({ time: 0, instanceId: "i-a" }),
      launch({ time: 0, instanceId: "i-b" }),
      flow({ time: 2 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER))!;
    expect(f.description).toContain("ambiguous");
  });

  it("attributes both endpoints independently when both are tracked instances", () => {
    const out = correlateAwsFlowResourceAttribution([
      launch({ time: 0, ip: "172.31.16.139", instanceId: "i-src" }),
      launch({ time: 0, ip: "172.31.16.140", instanceId: "i-dst" }),
      flow({ time: 2, src: "172.31.16.139", dst: "172.31.16.140" }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER))!;
    expect(f.description).toContain("source 172.31.16.139 = i-src");
    expect(f.description).toContain("destination 172.31.16.140 = i-dst");
  });

  it("is idempotent — re-running over an already-annotated set does not duplicate the note", () => {
    const once = correlateAwsFlowResourceAttribution([launch({ time: 0 }), flow({ time: 2 })]);
    const twice = correlateAwsFlowResourceAttribution(once);
    const f = twice.find((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER))!;
    expect(f.description.split(FLOW_ATTRIBUTION_MARKER)).toHaveLength(2); // exactly one marker
  });

  it("duplicate/overlapping CloudTrail uploads for the same instance dedupe to one interval", () => {
    // Two summary rows for the SAME instance (e.g. re-imported), slightly different launch times.
    const out = correlateAwsFlowResourceAttribution([
      launch({ time: 0, instanceId: "i-aaa" }),
      launch({ time: 1, instanceId: "i-aaa" }), // same instance, later-seen launch record
      flow({ time: 2 }),
    ]);
    const f = out.find((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER))!;
    expect(f.description).toContain("= i-aaa");
    expect(f.description).not.toContain("ambiguous");
  });
});
