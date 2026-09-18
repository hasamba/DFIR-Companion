import { describe, it, expect } from "vitest";
import {
  correlateAwsFlowSensitiveData,
  formatSensitiveDataFragment,
  FLOW_SENSITIVE_DATA_MARKER,
  type FlowSensitiveDataSummary,
} from "../../src/analysis/awsFlowSensitiveDataJoin.js";
import { correlateAwsFlowResourceAttribution } from "../../src/analysis/awsFlowResourceAttribution.js";
import { correlateAwsFlowIdentityExecution } from "../../src/analysis/awsFlowIdentityExecutionJoin.js";
import {
  BULK_READ_MARKER,
  groupBulkReads,
  readCloudRecord,
  summarizeBulkReads,
} from "../../src/analysis/cloudBulkRead.js";
import { DERIVED_NOTE_NAMES } from "../../src/analysis/derivedNote.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const T0 = Date.parse("2024-05-14T12:00:00Z");
const at = (hOffset: number) => new Date(T0 + hOffset * 3_600_000).toISOString();

const INSTANCE = "i-1234567890abcdef0";
const OTHER_INSTANCE = "i-0fedcba0987654321";
const ACCOUNT = "111111111111";

function launch(
  over: { time?: number; account?: string; ip?: string; instanceId?: string } = {},
): ForensicEvent {
  return {
    id: `l${++seq}`,
    timestamp: at(over.time ?? -48),
    description: "AWS compute lifecycle",
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: {
      event: { category: "cloud", type: "compute-lifecycle" },
      cloud: { provider: "aws", accountId: over.account ?? ACCOUNT },
      awsCompute: {
        instanceId: over.instanceId ?? INSTANCE,
        launch: { privateAddress: over.ip ?? "172.31.16.139", time: at(over.time ?? -48), by: "alice" },
        remote: [],
        remoteBeyond: 0,
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
      cloud: { provider: "aws", accountId: over.account ?? ACCOUNT },
    },
  } as unknown as ForensicEvent;
}

interface ReadOver {
  time?: number;
  account?: string;
  session?: string;
  role?: string;
  protocol?: string | null;
  mechanism?: string | null;
  credentialId?: string | null;
  ip?: string;
  resource?: string;
  action?: string;
  principalId?: string;
}

function read(over: ReadOver = {}): ForensicEvent {
  const session = over.session ?? INSTANCE;
  return {
    id: `r${++seq}`,
    timestamp: at(over.time ?? -1),
    description: "AWS GetObject (s3) by app-role from 10.0.1.5",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: {
      event: { category: "cloud", type: "api", action: over.action ?? "GetObject", outcome: "success" },
      actor: {
        kind: "cloud_principal",
        name: over.role ?? "app-role",
        id: over.principalId ?? `AROAEXAMPLE:${session}`,
      },
      cloud: {
        provider: "aws",
        accountId: over.account ?? ACCOUNT,
        principalId: over.principalId ?? `AROAEXAMPLE:${session}`,
        resource: over.resource ?? "corp-data/report.pdf",
      },
      authentication: {
        ...(over.mechanism === null ? {} : { mechanism: over.mechanism ?? "AssumedRole" }),
        ...(over.protocol === null ? {} : { protocol: over.protocol ?? "IMDSv2" }),
        ...(over.credentialId === null ? {} : { credentialId: over.credentialId ?? "ASIAEXAMPLEKEY1" }),
      },
      network: { source: { address: over.ip ?? "10.0.1.5", provenance: "edge-observed" } },
    },
  } as unknown as ForensicEvent;
}

/** 60 distinct-object reads in one hour, so the shipped bulk-read pass emits a summary. */
function manyReads(n: number, over: ReadOver = {}): ForensicEvent[] {
  return Array.from({ length: n }, (_v, i) =>
    read({
      ...over,
      resource: `${over.resource ?? "corp-data"}/file-${i}.csv`,
      time: (over.time ?? -1) + i * 0.01,
    }),
  );
}

/** The real merge-chain order: bulk summaries, then attribution, then identity, then this pass. */
function chain(events: ForensicEvent[]): ForensicEvent[] {
  return correlateAwsFlowSensitiveData(
    correlateAwsFlowIdentityExecution(correlateAwsFlowResourceAttribution(summarizeBulkReads(events))),
  );
}

function noteOf(out: ForensicEvent[]): string | undefined {
  return out.find((e) => e.description.includes(FLOW_SENSITIVE_DATA_MARKER))?.description;
}

function summaryOf(out: ForensicEvent[]): ForensicEvent {
  return out.find((e) => e.description.includes(BULK_READ_MARKER))!;
}

describe("correlateAwsFlowSensitiveData", () => {
  it("joins an attributed flow to a bulk-read summary signed with the instance's own IMDS-delivered credentials", () => {
    const out = chain([launch(), ...manyReads(60), flow({ time: 0 })]);
    const summary = summaryOf(out);
    const note = noteOf(out)!;
    expect(note).toContain(
      `source 172.31.16.139 = ${INSTANCE}: bulk read summary ${summary.id} within ±24h of the flow`,
    );
    expect(note).toContain("60 objects across 1 container (corp-data)");
    expect(note).toContain(
      "signed with instance-role credentials CloudTrail records as delivered to this instance (IMDSv2, role app-role, key ASIAEXAMPLEKEY1)",
    );
    expect(note).toContain("from 10.0.1.5 — not the instance's attributed address");
    expect(note).toContain(
      "a read signed with this instance's credentials is not shown to be caused by this flow",
    );
    expect(note).not.toContain("measured on a prefix");
  });

  it("says 'from the instance's own attributed address' when the reader's source address is the endpoint's", () => {
    const out = chain([launch(), ...manyReads(60, { ip: "172.31.16.139" }), flow({ time: 0 })]);
    expect(noteOf(out)).toContain("from 172.31.16.139 — the instance's own attributed address");
  });

  it("does not join a session whose credentials were not IMDS-delivered (no protocol), even if named like an instance", () => {
    const out = chain([launch(), ...manyReads(60, { protocol: null }), flow({ time: 0 })]);
    expect(summaryOf(out)).toBeDefined();
    expect(noteOf(out)).toBeUndefined();
  });

  it("does not join a session whose name is not an instance id", () => {
    const out = chain([launch(), ...manyReads(60, { session: "alice" }), flow({ time: 0 })]);
    expect(noteOf(out)).toBeUndefined();
  });

  it("does not join a session that is not AssumedRole", () => {
    const out = chain([launch(), ...manyReads(60, { mechanism: "IAMUser" }), flow({ time: 0 })]);
    expect(noteOf(out)).toBeUndefined();
  });

  it("does not join a colon-less principalId", () => {
    const out = chain([launch(), ...manyReads(60, { principalId: INSTANCE }), flow({ time: 0 })]);
    expect(noteOf(out)).toBeUndefined();
  });

  it("does not join reads in another account", () => {
    const out = chain([launch(), ...manyReads(60, { account: "222222222222" }), flow({ time: 0 })]);
    expect(noteOf(out)).toBeUndefined();
  });

  it("does not join a credential-less group", () => {
    const out = chain([launch(), ...manyReads(60, { credentialId: null }), flow({ time: 0 })]);
    expect(noteOf(out)).toBeUndefined();
  });

  it("joins IMDSv1-delivered credentials and names the protocol", () => {
    const out = chain([launch(), ...manyReads(60, { protocol: "IMDSv1" }), flow({ time: 0 })]);
    expect(noteOf(out)).toContain("(IMDSv1, role app-role");
  });

  it("windows the join at ±24h inclusive of the read window's nearest edge", () => {
    // Reads end ~ -30h + 0.6h: outside.
    expect(noteOf(chain([launch(), ...manyReads(60, { time: -30 }), flow({ time: 0 })]))).toBeUndefined();
    // Reads at -2h: inside.
    expect(noteOf(chain([launch(), ...manyReads(60, { time: -2 }), flow({ time: 0 })]))).toBeDefined();
    // Read window ending exactly 24h before the flow: inside (inclusive).
    const ending24h = manyReads(60, { time: -24 - 59 * 0.01 });
    expect(noteOf(chain([launch(), ...ending24h, flow({ time: 0 })]))).toBeDefined();
    // One millisecond further: outside.
    const flowLater = flow({ time: 0 });
    flowLater.timestamp = new Date(T0 + 1).toISOString();
    expect(noteOf(chain([launch(), ...ending24h, flowLater]))).toBeUndefined();
  });

  it("does not join a group the bulk-read pass graded as expected (no summary emitted)", () => {
    const events = [launch(), ...manyReads(60), flow({ time: 0 })];
    const withSummaries = summarizeBulkReads(events, { expectedPrincipals: ["app-role"] });
    expect(withSummaries.some((e) => e.description.includes(BULK_READ_MARKER))).toBe(false);
    const out = correlateAwsFlowSensitiveData(
      correlateAwsFlowIdentityExecution(correlateAwsFlowResourceAttribution(withSummaries)),
    );
    expect(noteOf(out)).toBeUndefined();
  });

  it("does not join an enumeration-only group", () => {
    const listOnly = Array.from({ length: 60 }, (_v, i) =>
      read({ action: "ListObjects", resource: `bucket-${i}`, time: -1 + i * 0.01 }),
    );
    const out = chain([launch(), ...listOnly, flow({ time: 0 })]);
    expect(noteOf(out)).toBeUndefined();
  });

  it("labels both endpoints independently when both are attributed to instances with their own reads", () => {
    const out = chain([
      launch({ ip: "172.31.16.139", instanceId: INSTANCE }),
      launch({ ip: "172.31.16.140", instanceId: OTHER_INSTANCE }),
      ...manyReads(60, { session: INSTANCE, credentialId: "ASIAKEYAAAA", resource: "bucket-a" }),
      ...manyReads(60, {
        session: OTHER_INSTANCE,
        credentialId: "ASIAKEYBBBB",
        resource: "bucket-b",
        ip: "10.0.1.6",
      }),
      flow({ time: 0, src: "172.31.16.139", dst: "172.31.16.140" }),
    ]);
    const note = noteOf(out)!;
    expect(note).toContain(`source 172.31.16.139 = ${INSTANCE}: bulk read summary`);
    expect(note).toContain(`destination 172.31.16.140 = ${OTHER_INSTANCE}: bulk read summary`);
    expect(note).toContain("(bucket-a)");
    expect(note).toContain("(bucket-b)");
  });

  it("skips every recomputed group that shares one summary id (key omits the credential), never guessing which the pass kept", () => {
    // Two credentials, same role, same address, same client, first read in the same second: the
    // shipped summaryId collides and the pass kept one summary; the pointer is ambiguous.
    const a = manyReads(60, { credentialId: "ASIAKEYAAAA" });
    const b = manyReads(60, { credentialId: "ASIAKEYBBBB", session: OTHER_INSTANCE });
    const out = chain([launch(), ...a, ...b, flow({ time: 0 })]);
    expect(groupBulkReads([...a, ...b])).toHaveLength(2);
    expect(noteOf(out)).toBeUndefined();
  });

  it("skips a credential whose rows disagree on the instance session", () => {
    const rows = [
      ...manyReads(59),
      read({ session: OTHER_INSTANCE, resource: "corp-data/file-59.csv", time: -1 + 59 * 0.01 }),
    ];
    const out = chain([launch(), ...rows, flow({ time: 0 })]);
    expect(summaryOf(out)).toBeDefined();
    expect(noteOf(out)).toBeUndefined();
  });

  it("caps at five summaries per endpoint, closest to the flow first, and counts the overflow", () => {
    const reads: ForensicEvent[] = [];
    for (let k = 0; k < 6; k += 1) {
      // Six separate one-hour sessions, each its own credential, spread 3h apart.
      reads.push(...manyReads(60, { credentialId: `ASIAKEY${k}`, time: -20 + k * 3 }));
    }
    const out = chain([launch(), ...reads, flow({ time: 0 })]);
    const note = noteOf(out)!;
    expect(note.match(/bulk read summary /gu)).toHaveLength(5);
    expect(note).toContain("+ 1 more in window");
    expect(note).not.toContain("ASIAKEY0"); // the farthest from the flow is the one dropped
  });

  it("bounds the container list to three names and says how many more", () => {
    const reads = Array.from({ length: 60 }, (_v, i) =>
      read({ resource: `bucket-${i % 5}/file-${i}.csv`, time: -1 + i * 0.01 }),
    );
    const out = chain([launch(), ...reads, flow({ time: 0 })]);
    expect(noteOf(out)).toMatch(/across 5 containers \(bucket-\d, bucket-\d, bucket-\d, …\)/u);
  });

  it("says the group was measured on a prefix when the bulk-read pass truncated it", () => {
    const endpoint = { label: "source" as const, ip: "172.31.16.139", instanceId: INSTANCE };
    const entry: FlowSensitiveDataSummary = {
      summaryId: "cloud-bulk-read-x",
      first: at(-2),
      last: at(-1),
      firstMs: T0 - 2 * 3_600_000,
      lastMs: T0 - 3_600_000,
      objectCount: 20_000,
      containerCount: 2,
      containers: ["a", "b"],
      sourceIp: "10.0.1.5",
      role: "app-role",
      credentialId: "ASIAEXAMPLEKEY1",
      protocol: "IMDSv2",
      truncated: true,
    };
    const fragment = formatSensitiveDataFragment(endpoint, [entry], T0)!;
    expect(fragment).toContain("20000 objects across 2 containers (a, b)");
    expect(fragment).toContain("; measured on a prefix of its records");
    expect(formatSensitiveDataFragment(endpoint, [{ ...entry, truncated: false }], T0)).not.toContain(
      "prefix",
    );
    expect(formatSensitiveDataFragment(endpoint, [{ ...entry, sourceIp: "" }], T0)).toContain(
      "from an address the rows do not record",
    );
    // A window that starts 24h+1ms after the flow is outside; exactly 24h after is inside.
    const late = { ...entry, firstMs: T0 + 24 * 3_600_000 + 1, lastMs: T0 + 25 * 3_600_000 };
    expect(formatSensitiveDataFragment(endpoint, [late], T0)).toBeNull();
    expect(
      formatSensitiveDataFragment(endpoint, [{ ...late, firstMs: T0 + 24 * 3_600_000 }], T0),
    ).not.toBeNull();
  });

  it("strips brackets from evidence-derived strings before they enter the note", () => {
    const out = chain([
      launch(),
      ...manyReads(60, { role: "app-[role]", resource: "corp[data]" }),
      flow({ time: 0 }),
    ]);
    const note = noteOf(out)!;
    expect(note).toContain("role app-role");
    expect(note).toContain("(corpdata)");
    // The note is one bracket-delimited unit: exactly one "[" opens it and one "]" closes it.
    const inner = note.slice(note.indexOf(FLOW_SENSITIVE_DATA_MARKER));
    expect(inner.slice(1)).not.toContain("[");
    expect(inner.indexOf("]")).toBe(inner.length - 1);
  });

  it("re-runs idempotently and strips a stale note when the reads disappear", () => {
    const events = [launch(), ...manyReads(60), flow({ time: 0 })];
    const once = chain(events);
    const twice = correlateAwsFlowSensitiveData(once);
    expect(noteOf(twice)).toBe(noteOf(once));
    expect(noteOf(twice)!.match(/\[flow sensitive-data:/gu)).toHaveLength(1);
    // Drop the reads AND the summary: the note must go, even with an empty index.
    const gone = correlateAwsFlowSensitiveData(
      once.filter((e) => !e.id.startsWith("r") && !e.description.includes(BULK_READ_MARKER)),
    );
    expect(noteOf(gone)).toBeUndefined();
  });

  it("does not touch a flow the attribution pass left unattributed", () => {
    const out = chain([...manyReads(60), flow({ time: 0 })]);
    expect(noteOf(out)).toBeUndefined();
  });

  it("recomputes the same groups the shipped pass emitted — its own summary events are not read as reads", () => {
    const events = [launch(), ...manyReads(60), flow({ time: 0 })];
    const withSummaries = summarizeBulkReads(events);
    const summary = summaryOf(withSummaries);
    expect(readCloudRecord(summary)).toBeNull();
    const before = groupBulkReads(events).map((g) => `${g.credentialId}|${g.first}|${g.objectCount}`);
    const after = groupBulkReads(withSummaries).map((g) => `${g.credentialId}|${g.first}|${g.objectCount}`);
    expect(after).toEqual(before);
  });

  it("is registered as a derived note so correlation keeps it and dedup keying strips it", () => {
    expect(DERIVED_NOTE_NAMES).toContain("flow sensitive-data");
  });
});
