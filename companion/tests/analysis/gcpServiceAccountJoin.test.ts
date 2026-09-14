// #1065 (second half of #931 item 12): every fact ONE export states about one service account,
// joined by unique id when present, else email — never a folder/org parent-scope claim, never a
// two-of-one-category upgrade, never a sharee/target match, order-independent admission.
import { describe, expect, it } from "vitest";
import { gcpServiceAccountJoins, GCP_SA_JOIN_MAX } from "../../src/analysis/gcpServiceAccountJoin.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";

type Row = Record<string, unknown>;
const SA = "svc@acme.iam.gserviceaccount.com";
const SA2 = "svc2@acme.iam.gserviceaccount.com";
const SA_UID = "104857600000000000001";
const T = "2026-05-02T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();

const gcp = (
  timestamp: string,
  method: string,
  service: string,
  over: Row = {},
  principalEmail = "alice@corp.example",
  resourceLabels: Row = {},
): Row => ({
  timestamp,
  logName: "projects/acme/logs/cloudaudit.googleapis.com%2Factivity",
  resource: { type: "service_account", labels: { project_id: "acme", ...resourceLabels } },
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    serviceName: service,
    methodName: method,
    authenticationInfo: { principalEmail },
    requestMetadata: { callerIp: "203.0.113.10" },
    status: {},
    ...over,
  },
});

const delta = (action: string, role: string, member: string) => ({ action, role, member });
const setPolicy = (
  time: string,
  resourceName: string,
  deltas: Row[],
  principalEmail = "alice@corp.example",
  status: Row = {},
) =>
  gcp(
    time,
    "google.iam.admin.v1.SetIAMPolicy",
    "iam.googleapis.com",
    { resourceName, serviceData: { policyDelta: { bindingDeltas: deltas } }, status },
    principalEmail,
  );

const genToken = (time: string, saEmail: string, saUid: string, principalEmail: string, status: Row = {}) =>
  gcp(
    time,
    "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken",
    "iamcredentials.googleapis.com",
    {
      resourceName: `projects/-/serviceAccounts/${saUid}`,
      request: { name: `projects/-/serviceAccounts/${saEmail}` },
      status,
    },
    principalEmail,
  );

const createKey = (time: string, saEmail: string, principalEmail = "alice@corp.example") =>
  gcp(
    time,
    "google.iam.admin.v1.CreateServiceAccountKey",
    "iam.googleapis.com",
    {
      resourceName: `projects/acme/serviceAccounts/${saEmail}`,
      request: { name: `projects/acme/serviceAccounts/${saEmail}` },
      response: { name: `projects/acme/serviceAccounts/${saEmail}/keys/abc123`, keyType: "USER_MANAGED" },
    },
    principalEmail,
  );

const insertVm = (time: string, saEmail: string, principalEmail = "alice@corp.example") =>
  gcp(
    time,
    "v1.compute.instances.insert",
    "compute.googleapis.com",
    {
      resourceName: "projects/acme/zones/z/instances/vm1",
      request: { serviceAccounts: [{ email: saEmail }] },
    },
    principalEmail,
  );

const callAs = (time: string, saEmail: string, method = "storage.objects.get", status: Row = {}) =>
  gcp(time, method, "storage.googleapis.com", { resourceName: "projects/acme/buckets/b/objects/o", status }, saEmail);

const named = (rows: Row[]) => gcpServiceAccountJoins(rows);
const blockFor = (rows: Row[], email: string) => {
  const r = named(rows);
  const row = r.find((x) => {
    const env = canonicalEventEnvelopeSchema.parse(x.canonical);
    return env.gcpServiceAccountJoin?.emails.includes(email);
  });
  return row ? canonicalEventEnvelopeSchema.parse(row.canonical).gcpServiceAccountJoin : undefined;
};

describe("GCP service account join: row existence", () => {
  it("no direct fact -> no row (a call by a human about an unrelated resource creates nothing)", () => {
    expect(named([gcp(at(0), "storage.objects.get", "storage.googleapis.com")])).toHaveLength(0);
  });

  it("a parent-scope binding alone never creates a row", () => {
    const rows = [setPolicy(at(0), "projects/acme", [delta("ADD", "roles/viewer", "user:bob@corp.example")])];
    expect(named(rows)).toHaveLength(0);
  });

  it("a call-only account (tier 1) still gets a row", () => {
    const b = blockFor([callAs(at(0), SA)], SA);
    expect(b).toBeDefined();
    expect(b?.admissionTier).toBe(1);
    expect(b?.callsAsPrincipal).toHaveLength(1);
  });
});

describe("GCP service account join: the three binding facts", () => {
  it("access-to-member: this SA granted access on another resource", () => {
    const rows = [setPolicy(at(0), "projects/acme/buckets/b", [delta("ADD", "roles/storage.admin", `serviceAccount:${SA}`)])];
    const b = blockFor(rows, SA);
    expect(b?.bindingsAsMember).toHaveLength(1);
    expect(b?.bindingsAsResource).toHaveLength(0);
  });

  it("authority-over-service-account: someone granted control OVER this SA", () => {
    const rows = [
      setPolicy(at(0), `projects/acme/serviceAccounts/${SA}`, [
        delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:carol@corp.example"),
      ]),
    ];
    const b = blockFor(rows, SA);
    expect(b?.bindingsAsResource).toHaveLength(1);
    expect(b?.bindingsAsMember).toHaveLength(0);
  });

  it("a project-level (parent-scope) delta on this SA's own project is counted, never attributed, only on an existing row", () => {
    const rows = [
      setPolicy(at(0), `projects/acme/serviceAccounts/${SA}`, [
        delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:carol@corp.example"),
      ]),
      setPolicy(at(10), "projects/acme", [delta("ADD", "roles/viewer", "user:dave@corp.example")]),
      setPolicy(at(20), "projects/acme", [delta("ADD", "roles/editor", "user:erin@corp.example")]),
    ];
    const b = blockFor(rows, SA);
    expect(b?.parentScopeCount).toBe(2);
    expect(b?.bindingsAsResource).toHaveLength(1);
  });

  it("a folder/org-level delta never appears on any SA row", () => {
    const rows = [
      setPolicy(at(0), `projects/acme/serviceAccounts/${SA}`, [
        delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:carol@corp.example"),
      ]),
      setPolicy(at(10), "folders/999", [delta("ADD", "roles/viewer", "user:dave@corp.example")]),
    ];
    const b = blockFor(rows, SA);
    expect(b?.parentScopeCount).toBe(0);
  });

  it("a deleted: member is shown verbatim, never resolved", () => {
    const rows = [
      setPolicy(at(0), `projects/acme/serviceAccounts/${SA}`, [
        delta("REMOVE", "roles/iam.serviceAccountTokenCreator", "deleted:user:old@corp.example?uid=123"),
      ]),
    ];
    // deleted: is not a service-account member, so this never joins as bindingsAsMember for any SA;
    // it still shows on the SA-as-resource row for the SA the binding concerns.
    const b = blockFor(rows, SA);
    expect(b?.bindingsAsResource[0].member).toBe("deleted:user:old@corp.example?uid=123");
  });
});

describe("GCP service account join: credentials, keys, attachments", () => {
  it("a credential mint and a key creation join by email", () => {
    const rows = [genToken(at(0), SA, SA_UID, "bob@corp.example"), createKey(at(10), SA)];
    const b = blockFor(rows, SA);
    expect(b?.credentials).toHaveLength(1);
    expect(b?.keys).toHaveLength(1);
  });

  it("a workload attachment joins by email and states the workload", () => {
    const rows = [insertVm(at(0), SA)];
    const b = blockFor(rows, SA);
    expect(b?.attachments).toHaveLength(1);
    expect(b?.attachments[0].workloadKind).toBe("gce-instance");
  });
});

describe("GCP service account join: grading", () => {
  it("the control-then-use pattern upgrades to at least High", () => {
    const rows = [
      setPolicy(at(0), `projects/acme/serviceAccounts/${SA}`, [
        delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:carol@corp.example"),
      ]),
      genToken(at(100), SA, SA_UID, "carol@corp.example"),
    ];
    const r = named(rows);
    const row = r.find((x) => canonicalEventEnvelopeSchema.parse(x.canonical).gcpServiceAccountJoin?.emails.includes(SA));
    expect(row?.severity).toBe("High");
    expect(row?.description).toContain("control-then-use");
  });

  it("two credential mints alone (no control grant) never upgrade", () => {
    const rows = [genToken(at(0), SA, SA_UID, "bob@corp.example"), genToken(at(100), SA, SA_UID, "bob@corp.example")];
    const b = blockFor(rows, SA);
    expect(b?.upgrade).toBeUndefined();
  });

  it("a denied control grant never upgrades, even with a later use", () => {
    const rows = [
      setPolicy(
        at(0),
        `projects/acme/serviceAccounts/${SA}`,
        [delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:carol@corp.example")],
        "carol@corp.example",
        { code: 7, message: "PERMISSION_DENIED" },
      ),
      genToken(at(100), SA, SA_UID, "carol@corp.example"),
    ];
    const b = blockFor(rows, SA);
    expect(b?.upgrade).toBeUndefined();
  });

  it("a denied use never upgrades", () => {
    const rows = [
      setPolicy(at(0), `projects/acme/serviceAccounts/${SA}`, [
        delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:carol@corp.example"),
      ]),
      genToken(at(100), SA, SA_UID, "carol@corp.example", { code: 7, message: "denied" }),
    ];
    const b = blockFor(rows, SA);
    expect(b?.upgrade).toBeUndefined();
  });

  it("a tie or an earlier use never upgrades (strictly later required)", () => {
    const rows = [
      setPolicy(at(50), `projects/acme/serviceAccounts/${SA}`, [
        delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:carol@corp.example"),
      ]),
      genToken(at(50), SA, SA_UID, "carol@corp.example"),
      genToken(at(10), SA, SA_UID, "carol@corp.example"),
    ];
    const b = blockFor(rows, SA);
    expect(b?.upgrade).toBeUndefined();
  });
});

describe("GCP service account join: alias folding", () => {
  it("an email-only credential record folds under a uniqueId learned from another record", () => {
    const rows = [
      gcp(at(0), "x", "y", {}, "alice@corp.example", { email_id: SA, unique_id: SA_UID }),
      genToken(at(10), SA, "", "bob@corp.example"), // no uniqueId in THIS record's resourceName
    ];
    const r = named(rows);
    // Both facts fold under the one uniqueId-keyed row.
    const withUid = r.filter((x) => {
      const env = canonicalEventEnvelopeSchema.parse(x.canonical);
      return env.gcpServiceAccountJoin?.identity === SA_UID;
    });
    expect(withUid).toHaveLength(1);
    expect(withUid[0].canonical && canonicalEventEnvelopeSchema.parse(withUid[0].canonical).gcpServiceAccountJoin?.credentials).toHaveLength(1);
  });

  it("two different uniqueIds for one email is a conflict: neither resolves, records key on the email", () => {
    const rows = [
      // Two alias-source records tie the SAME email to two DIFFERENT uniqueIds.
      gcp(at(0), "x", "y", {}, "alice@corp.example", { email_id: SA, unique_id: "111111111111111" }),
      gcp(at(1), "x", "y", {}, "alice@corp.example", { email_id: SA, unique_id: "222222222222222" }),
      // Two email-only credential records (no uniqueId of their own) for that SA.
      createKey(at(10), SA, "bob@corp.example"),
      createKey(at(20), SA, "bob@corp.example"),
    ];
    const r = named(rows);
    const forSa = r.filter((x) => {
      const env = canonicalEventEnvelopeSchema.parse(x.canonical);
      return env.gcpServiceAccountJoin?.emails.includes(SA);
    });
    // Neither uniqueId resolves the email; both key facts key on the plain email string -> one
    // row (the email itself is the identity), not split, not falsely merged under either uid.
    expect(forSa).toHaveLength(1);
    expect(canonicalEventEnvelopeSchema.parse(forSa[0].canonical).gcpServiceAccountJoin?.identity).toBe(lower(SA));
    expect(canonicalEventEnvelopeSchema.parse(forSa[0].canonical).gcpServiceAccountJoin?.keys).toHaveLength(2);
  });
});

function lower(s: string) {
  return s.toLowerCase();
}

describe("GCP service account join: order independence and bound", () => {
  it("two different record orders produce the identical kept row content", () => {
    const rows = [
      setPolicy(at(0), `projects/acme/serviceAccounts/${SA}`, [
        delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:carol@corp.example"),
      ]),
      genToken(at(100), SA, SA_UID, "carol@corp.example"),
      insertVm(at(5), SA2),
      createKey(at(6), SA2),
    ];
    const forward = named(rows);
    const reversed = named([...rows].reverse());
    // Locators are the physical record index, legitimately different when the input order
    // differs; what must be order-independent is WHICH accounts are admitted, their grade, tier
    // and fact counts — the #1064 lesson applied here from the start.
    const norm = (r: ReturnType<typeof named>) =>
      r
        .map((x) => {
          const env = canonicalEventEnvelopeSchema.parse(x.canonical);
          const j = env.gcpServiceAccountJoin;
          return {
            severity: x.severity,
            identity: j?.identity,
            tier: j?.admissionTier,
            upgraded: !!j?.upgrade,
            counts: {
              bindingsAsResource: j?.bindingsAsResource.length,
              credentials: j?.credentials.length,
              keys: j?.keys.length,
              attachments: j?.attachments.length,
            },
          };
        })
        .sort((a, b) => (a.identity ?? "").localeCompare(b.identity ?? ""));
    expect(norm(forward)).toEqual(norm(reversed));
  });

  it("more accounts than GCP_SA_JOIN_MAX produce an overflow row", () => {
    const rows: Row[] = [];
    for (let i = 0; i < GCP_SA_JOIN_MAX + 3; i++) {
      rows.push(createKey(at(i), `svc${i}@acme.iam.gserviceaccount.com`));
    }
    const r = named(rows);
    expect(r.length).toBe(GCP_SA_JOIN_MAX + 1);
    expect(r[r.length - 1].description).toContain("further account");
  });
});
