// #2545: an EC2 instance-role credential used away from the instance, read from real-shaped
// CloudTrail records through the real importer. One public address is a Medium note (a NAT gateway
// or the instance's own public IP explains it as well); the same instance credential seen from two
// or more public addresses is High, in the credential lineage summary. Nothing is read back out of
// a description, and a session NAME alone (caller-chosen on AssumeRole) never counts.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { instanceCredentialUseAway, METADATA_MARKER } from "../../src/analysis/cloudMetadataAccess.js";
import { mergeDelta, runTimelineChain, type WindowContext } from "../../src/analysis/stateMerge.js";
import { mergeIntoCase } from "../../src/analysis/caseMerge.js";
import { deltaSchema, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

const ACCT = "111122223333";
const INSTANCE = "i-0abc1234def567890";
const KEY = "ASIAEXAMPLEKEY000001";
const PUB = "203.0.113.10";
const PUB2 = "198.51.100.7";
const PRIV = "10.0.1.5";
let n = 0;

interface Opts {
  ip?: string;
  session?: string;
  delivery?: string | null;
  agent?: string;
  key?: string;
  name?: string;
  source?: string;
  extra?: Record<string, unknown>;
}

function rec(o: Opts = {}): Record<string, unknown> {
  const session = o.session ?? INSTANCE;
  const delivery = o.delivery === undefined ? "2.0" : o.delivery;
  n += 1;
  return {
    eventVersion: "1.08",
    eventTime: `2026-03-01T10:${String(n % 60).padStart(2, "0")}:00Z`,
    eventSource: o.source ?? "s3.amazonaws.com",
    eventName: o.name ?? "ListBuckets",
    awsRegion: "us-east-1",
    sourceIPAddress: o.ip ?? PUB,
    userAgent: o.agent ?? "aws-cli/2.15.0 Python/3.11 Linux/6.1",
    userIdentity: {
      type: "AssumedRole",
      principalId: `AROAEXAMPLEROLEID0001:${session}`,
      arn: `arn:aws:sts::${ACCT}:assumed-role/web-role/${session}`,
      accountId: ACCT,
      accessKeyId: o.key ?? KEY,
      sessionContext: {
        sessionIssuer: {
          type: "Role",
          principalId: "AROAEXAMPLEROLEID0001",
          arn: `arn:aws:iam::${ACCT}:role/web-role`,
          accountId: ACCT,
          userName: "web-role",
        },
        attributes: { creationDate: "2026-03-01T09:00:00Z", mfaAuthenticated: "false" },
        ...(delivery ? { ec2RoleDelivery: delivery } : {}),
      },
    },
    requestParameters: null,
    responseElements: null,
    requestID: `req-${n}`,
    eventID: `evt-${n}`,
    readOnly: true,
    eventType: "AwsApiCall",
    managementEvent: true,
    recipientAccountId: ACCT,
    ...o.extra,
  };
}

const parse = (recs: Record<string, unknown>[], aggregate = false) =>
  parseCloudTrail(JSON.stringify({ Records: recs }), { aggregate }).events;

/** The parsed rows as the merge receives them. */
function rows(recs: Record<string, unknown>[], aggregate = false): ForensicEvent[] {
  return parse(recs, aggregate).map((e, i) => ({
    ...e,
    id: `ev${i}`,
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
}

const uses = (es: ForensicEvent[]) => es.filter((e) => !e.description.startsWith("AWS credential lineage"));
const lineage = (recs: Record<string, unknown>[]) =>
  parse(recs).filter((e) => e.description.startsWith("AWS credential lineage"));
const noted = (e: ForensicEvent) => e.description.includes(METADATA_MARKER);

describe("one row: an instance credential from a public address (#2545)", () => {
  it("is a Medium note naming NAT and a public-IP instance, never High", () => {
    // Three identical calls: aggregated, they fold into fewer rows that must still carry the identity.
    const recs = [rec(), rec(), rec()];
    for (const aggregate of [false, true]) {
      const out = uses(instanceCredentialUseAway(rows(recs, aggregate)));
      expect(out.length).toBeGreaterThan(0);
      if (aggregate) expect(out.length).toBeLessThan(recs.length);
      for (const e of out) {
        expect(e.severity, `aggregate=${aggregate}`).toBe("Medium");
        expect(noted(e)).toBe(true);
        expect(e.description).toContain(PUB);
        expect(e.description).toContain("NAT gateway");
        expect(e.description).toContain("public IP address of its own");
        expect(e.description).not.toContain("taken off the host");
        // A note that says it does not show theft does not claim the theft techniques.
        expect(e.mitreTechniques ?? []).not.toContain("T1552.005");
      }
    }
  });

  it("is reached through the merge chain and survives it", () => {
    const out = runTimelineChain(rows([rec()]), [], "2026-03-02T00:00:00Z");
    const hit = out.find((e) => e.id === "ev0");
    expect(hit?.severity).toBe("Medium");
    expect(hit && noted(hit)).toBe(true);
  });

  it("says nothing for a private address, no address, a human session or a session merely NAMED i-…", () => {
    for (const r of [
      rec({ ip: PRIV }),
      rec({ ip: "ec2.amazonaws.com" }),
      rec({ session: "alice", delivery: null }),
      rec({ delivery: null }),
      rec({ session: "alice" }),
    ]) {
      const before = rows([r]);
      const after = instanceCredentialUseAway(before);
      for (const [i, e] of after.entries()) {
        expect(e.severity, e.description).toBe(before[i].severity);
        expect(noted(e), e.description).toBe(false);
      }
    }
  });

  it("is not raised by an instance-role ARN that only appears in a call's response", () => {
    const assume = rec({
      session: "alice",
      delivery: null,
      name: "AssumeRole",
      source: "sts.amazonaws.com",
      extra: {
        readOnly: false,
        requestParameters: { roleArn: `arn:aws:iam::${ACCT}:role/web-role`, roleSessionName: INSTANCE },
        responseElements: {
          credentials: { accessKeyId: "ASIAEXAMPLEKEY000777", expiration: "2026-03-01T11:00:00Z" },
          assumedRoleUser: {
            assumedRoleId: `AROAEXAMPLEROLEID0001:${INSTANCE}`,
            arn: `arn:aws:sts::${ACCT}:assumed-role/web-role/${INSTANCE}`,
          },
        },
      },
    });
    for (const e of uses(instanceCredentialUseAway(rows([assume])))) {
      expect(noted(e), e.description).toBe(false);
      expect(e.severity).not.toBe("High");
    }
  });
});

describe("the lineage: one instance credential from two or more public addresses (#2545)", () => {
  it("is High, with the instance-credential techniques and a plain clause", () => {
    const [row] = lineage([rec(), rec({ ip: PUB2 })]);
    expect(row.severity).toBe("High");
    expect(row.mitreTechniques).toEqual(expect.arrayContaining(["T1552.005", "T1078.004"]));
    expect(row.description).toContain("used from 2 different public addresses");
  });

  it("stays at today's Medium for one public and one private address", () => {
    const [row] = lineage([rec(), rec({ ip: PRIV })]);
    expect(row.severity).toBe("Medium");
    expect(row.description).not.toContain("different public addresses");
  });

  it("stays at today's Medium for one public address seen with two user agents", () => {
    const [row] = lineage([rec(), rec({ agent: "Boto3/1.34.0" })]);
    expect(row.severity).toBe("Medium");
  });

  it("stays at today's Medium for a non-instance session from two public addresses", () => {
    for (const o of [{ session: "ci-42", delivery: null }, { delivery: null }, { session: "ci-42" }]) {
      const [row] = lineage([rec(o), rec({ ...o, ip: PUB2 })]);
      expect(row.severity, JSON.stringify(o)).toBe("Medium");
      expect(row.mitreTechniques).not.toContain("T1552.005");
    }
  });
});

describe("the merge: incremental equals full for instance-credential rows (#2545)", () => {
  let root: string;
  let store: StateStore;
  let step = 0;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-inst2545-"));
    const cases = new CaseStore(root);
    for (const caseId of ["full", "inc"])
      await cases.createCase({ caseId, name: caseId, investigator: "i", aiProvider: null });
    store = new StateStore(cases);
    step = 0;
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  function delta(prefix: string, recs: Record<string, unknown>[]): AnalysisDelta {
    const forensicEvents = parse(recs).map((e, i) => ({
      id: `${prefix}${i}`,
      timestamp: e.timestamp,
      description: e.description,
      severity: e.severity,
      mitreTechniques: e.mitreTechniques ?? [],
      relatedFindingIds: [],
      asset: ACCT,
      sources: ["AWS CloudTrail"],
      canonical: e.canonical,
    }));
    return deltaSchema.parse({
      findings: [],
      iocs: [],
      mitreTechniques: [],
      forensicEvents,
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `import ${prefix}`,
      summary: "",
    });
  }

  /** One import into both cases, the equality check, and whether "inc" took the incremental path. */
  async function importBoth(d: AnalysisDelta): Promise<{ state: InvestigationState; fast: boolean }> {
    step += 1;
    const ctx: WindowContext = {
      windowSequence: -1,
      timestamp: `2026-10-30T10:${String(step).padStart(2, "0")}:00.000Z`,
      sourceScreenshots: [`file-${step}.json`],
    };
    await store.save(mergeDelta(await store.load("full"), d, ctx));
    const out = await mergeIntoCase(store, "inc", d, ctx, (s) => mergeDelta(s, d, ctx));
    const full = await store.load("full");
    const inc = await store.load("inc");
    expect({ ...inc, caseId: "x" }).toEqual({ ...full, caseId: "x" });
    return { state: full, fast: !out.complete };
  }

  it("marks a single-address use the same way on the incremental path", async () => {
    await importBoth(delta("seed", [rec({ session: "alice", delivery: null, ip: PRIV })]));
    const { state, fast } = await importBoth(delta("one", [rec(), rec({ ip: PRIV })]));
    expect(fast).toBe(true);
    const marked = state.forensicTimeline.filter(noted);
    expect(marked.length).toBeGreaterThan(0);
    for (const e of marked) expect(e.severity).toBe("Medium");
  });

  it("keeps the two-address lineage High, equal on both paths", async () => {
    await importBoth(delta("seed", [rec({ session: "alice", delivery: null, ip: PRIV })]));
    const { state } = await importBoth(delta("inst", [rec(), rec({ ip: PUB2 }), rec({ ip: PRIV })]));
    const spread = state.forensicTimeline.filter((e) => e.description.startsWith("AWS credential lineage"));
    expect(spread.map((e) => e.severity)).toContain("High");
  });
});
