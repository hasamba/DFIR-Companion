// #931 item 12 (record half): a GCP Cloud Audit Log record read for what it states — the
// principal typed only by a documented service-account address, the delegation chain whole and
// in order, the key name as credential origin (never the key holder), typed projects, the IAM
// policy delta as Google wrote it, the service-account key lifecycle, and the four IAM
// Credentials facts. Nothing the record does not say; no effective permission ever.
import { describe, expect, it } from "vitest";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import {
  canonicalConformanceIssues,
  canonicalEventEnvelopeSchema,
} from "../../src/analysis/canonicalEvent.js";

const SA = "svc@acme.iam.gserviceaccount.com";
const SA_RES = `projects/acme/serviceAccounts/${SA}`;
const USER = "alice@corp.example";
type Row = Record<string, unknown>;
const gcp = (method: string, over: Row = {}, top: Row = {}): Row => ({
  logName: "projects/acme/logs/cloudaudit.googleapis.com%2Factivity",
  timestamp: "2023-07-01T10:00:00.123456789Z",
  resource: {
    type: "service_account",
    labels: { project_id: "acme", email_id: SA, unique_id: "104857600000000000001" },
  },
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    serviceName: "iam.googleapis.com",
    methodName: method,
    authenticationInfo: { principalEmail: USER },
    requestMetadata: { callerIp: "203.0.113.11", callerSuppliedUserAgent: "google-cloud-sdk gcloud/450.0.0" },
    resourceName: SA_RES,
    status: {},
    ...over,
  },
  ...top,
});
const rows = (records: Row[], opts: Row = {}) =>
  parseCloudActivity(JSON.stringify(records), { aggregate: false, ...opts }).events;
const one = (method: string, over: Row = {}, top: Row = {}) => rows([gcp(method, over, top)])[0];
const delta = (action: string, role: string, member: string, condition?: Row) => ({
  action,
  role,
  member,
  ...(condition ? { condition } : {}),
});
const setPolicy = (deltas: Row[], over: Row = {}) =>
  gcp("google.iam.admin.v1.SetIAMPolicy", {
    serviceData: {
      "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
      policyDelta: { bindingDeltas: deltas },
    },
    ...over,
  });
const envelopeOf = (e: { canonical?: unknown }) => canonicalEventEnvelopeSchema.parse(e.canonical);

describe("GCP identity — who acted, as the record states", () => {
  it("a documented service-account address is typed with its home project; a user is 'user or unknown'; a service agent has no derivable home project", () => {
    const sa = one("google.iam.admin.v1.GetServiceAccount", { authenticationInfo: { principalEmail: SA } });
    expect(sa.description).toContain(`by ${SA}`);
    expect(sa.description).toContain("service account (home project acme, an id)");
    const env = envelopeOf(sa);
    expect(env.gcp?.principal).toMatchObject({
      email: SA,
      kind: "service-account",
      homeProject: { kind: "id", value: "acme" },
    });
    expect(env.actor).toEqual({ kind: "cloud_principal", name: SA });
    expect(canonicalConformanceIssues(env)).toEqual([]);
    const compute = one("x", {
      authenticationInfo: { principalEmail: "123456789012-compute@developer.gserviceaccount.com" },
    });
    expect(compute.description).toContain("service account (home project 123456789012, a number)");
    const appspot = one("x", { authenticationInfo: { principalEmail: "acme@appspot.gserviceaccount.com" } });
    expect(appspot.description).toContain("service account (home project acme, an id)");
    const agent = one("x", {
      authenticationInfo: {
        principalEmail: "service-123456789012@gcp-sa-cloudbuild.iam.gserviceaccount.com",
      },
    });
    expect(agent.description).toContain(
      "service agent (Google-managed; home project not derivable from the address)",
    );
    expect(envelopeOf(agent).gcp?.principal.kind).toBe("service-agent");
    const odd = one("x", {
      authenticationInfo: { principalEmail: "Weird.Name@some-other.gserviceaccount.com" },
    });
    expect(odd.description).toContain("service account (home project not derivable from the address)");
    expect(odd.description).not.toContain("service agent");
    const user = one("x");
    expect(user.description).toContain(`by ${USER}`);
    expect(envelopeOf(user).gcp?.principal.kind).toBe("user-or-unknown");
    expect(envelopeOf(user).actor).toEqual({ kind: "account", name: USER });
    expect(user.description).not.toContain("group");
  });

  it("principalSubject is kept verbatim and typed only by its documented prefix; opaque subjects are said as such", () => {
    const subject =
      "principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/subject/repo:org/app";
    const wif = one("x", { authenticationInfo: { principalSubject: subject } });
    expect(wif.description).toContain(`subject ${subject} (a federated principal)`);
    expect(envelopeOf(wif).gcp?.principal.subject).toEqual({ value: subject, kind: "principal" });
    const set = one("x", {
      authenticationInfo: {
        principalSubject:
          "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/*",
      },
    });
    expect(envelopeOf(set).gcp?.principal.subject?.kind).toBe("principal-set");
    const opaque = one("x", { authenticationInfo: { principalEmail: USER, principalSubject: "abc123" } });
    expect(opaque.description).toContain("subject abc123 (opaque subject)");
  });

  it("the key name is a credential origin — never the key holder; the delegation chain is whole, ordered and typed — never 'impersonated by'", () => {
    const keyed = one("x", {
      authenticationInfo: {
        principalEmail: SA,
        serviceAccountKeyName: `//iam.googleapis.com/${SA_RES}/keys/0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b`,
      },
    });
    expect(keyed.description).toContain(
      "authenticated with credentials derived from key …/keys/0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b; this record does not identify the key holder",
    );
    expect(keyed.description).not.toContain("signed with");
    expect(envelopeOf(keyed).gcp?.principal.keyName).toBe(
      `//iam.googleapis.com/${SA_RES}/keys/0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b`,
    );
    const chained = one("x", {
      authenticationInfo: {
        principalEmail: SA,
        serviceAccountDelegationInfo: [
          { firstPartyPrincipal: { principalEmail: USER } },
          { firstPartyPrincipal: { principalEmail: "mid@acme.iam.gserviceaccount.com" } },
          {
            principalSubject:
              "principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/subject/x",
          },
          { thirdPartyPrincipal: { thirdPartyClaims: { iss: "https://idp.example" } } },
        ],
      },
    });
    expect(chained.description).toContain(
      `delegation authority recorded as: ${USER} → mid@acme.iam.gserviceaccount.com → principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/subject/x → (third-party principal)`,
    );
    expect(chained.description).not.toMatch(/impersonat/);
    const env = envelopeOf(chained);
    expect(env.gcp?.delegation.map((d) => d.kind)).toEqual([
      "first-party",
      "first-party",
      "subject",
      "third-party",
    ]);
    expect(env.subject).toEqual({ kind: "account", name: USER });
    const none = one("x", { authenticationInfo: { principalEmail: SA } });
    expect(none.description).toContain("no delegation chain in this record");
  });

  it("projects are typed with their namespace; 'differ' is said only for two ids or two numbers; projects/- and a folder log are never compared", () => {
    const differ = one("x", { resourceName: "projects/other/buckets/b" });
    expect(differ.description).toContain(
      "log project acme (an id); resource project other (an id) — the log's project and the resource's project differ",
    );
    expect(differ.description).not.toContain("cross-project use");
    expect(envelopeOf(differ).gcp?.projects).toMatchObject({
      log: { namespace: "projects", kind: "id", value: "acme" },
      resource: { namespace: "projects", kind: "id", value: "other" },
      differ: true,
    });
    const same = one("x");
    expect(same.description).not.toContain("differ");
    const numberVsId = one("x", { resourceName: "projects/123456789012/buckets/b" });
    expect(numberVsId.description).toContain("resource project 123456789012 (a number)");
    expect(numberVsId.description).not.toContain("differ");
    const wildcard = one("x", { resourceName: `projects/-/serviceAccounts/${SA}` });
    expect(wildcard.description).not.toContain("resource project");
    const folder = one("x", {}, { logName: "folders/987/logs/cloudaudit.googleapis.com%2Factivity" });
    expect(folder.description).toContain("log folder 987");
    expect(folder.description).not.toContain("differ");
    const org = one("x", { resourceName: "//cloudresourcemanager.googleapis.com/projects/other" });
    expect(org.description).toContain("resource project other (an id)");
  });
});

describe("GCP IAM policy delta — the change as Google wrote it", () => {
  it("each binding delta is one row; authority over the service account granted to a member reads the role's documented permissions, nominally, and grades High", () => {
    const r = rows([
      setPolicy([
        delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:bob@corp.example"),
        delta("ADD", "roles/iam.serviceAccountUser", "user:carol@corp.example"),
      ]),
    ]);
    expect(r).toHaveLength(2);
    const [creator, user] = r;
    expect(creator.severity).toBe("High");
    expect(creator.mitreTechniques).toEqual(expect.arrayContaining(["T1098.003", "T1550.001"]));
    expect(creator.description).toContain(
      `authority over service account ${SA} granted to user:bob@corp.example`,
    );
    expect(creator.description).toContain(
      "added a binding for roles/iam.serviceAccountTokenCreator, whose documented permissions include: generating access tokens and ID tokens for the service account, signing blobs and JWTs",
    );
    expect(creator.description).toContain(
      "nominal; conditions, deny policies, principal access boundaries and inheritance are not evaluated by this record",
    );
    expect(creator.description).not.toMatch(/\bgrants capability|effective|can now impersonate/);
    expect(user.severity).toBe("Medium");
    expect(user.description).toContain(
      "attaching the service account to a workload (actAs) — not the permission to mint credentials",
    );
    const env = envelopeOf(creator);
    expect(env.event).toEqual({
      category: "cloud",
      type: "iam-binding",
      action: "google.iam.admin.v1.SetIAMPolicy",
      outcome: "success",
    });
    expect(env.gcp?.binding).toMatchObject({
      action: "ADD",
      role: "roles/iam.serviceAccountTokenCreator",
      member: "user:bob@corp.example",
      memberKind: "user",
      resource: SA_RES,
      resourceKind: "service-account",
      direction: "authority-over-service-account",
      nominal: true,
    });
    expect(env.object).toEqual({ kind: "cloud_principal", name: SA });
    expect(canonicalConformanceIssues(env)).toEqual([]);
    expect(creator.aggKey).not.toBe(user.aggKey);
  });

  it("a binding on the project is parent-scope; the service account as member is access granted to it; removal is Low; a custom or unclassified role is said so", () => {
    const parent = rows([
      setPolicy([delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:bob@corp.example")], {
        serviceName: "cloudresourcemanager.googleapis.com",
        resourceName: "projects/acme",
      }),
    ])[0];
    expect(parent.severity).toBe("High");
    expect(parent.description).toContain(
      "on project acme — nominally applies to the service accounts under it; inheritance not evaluated",
    );
    expect(envelopeOf(parent).gcp?.binding?.direction).toBe("parent-scope");
    const member = rows([
      setPolicy([delta("ADD", "roles/storage.objectViewer", `serviceAccount:${SA}`)], {
        serviceName: "cloudresourcemanager.googleapis.com",
        resourceName: "projects/acme",
      }),
    ])[0];
    expect(member.severity).toBe("Medium");
    expect(member.description).toContain(
      `access granted to serviceAccount:${SA} on projects/acme — added a binding for roles/storage.objectViewer (role as recorded; not classified here)`,
    );
    expect(envelopeOf(member).gcp?.binding?.direction).toBe("access-to-member");
    const removed = rows([
      setPolicy([delta("REMOVE", "roles/iam.serviceAccountTokenCreator", "user:bob@corp.example")]),
    ])[0];
    expect(removed.severity).toBe("Low");
    expect(removed.description).toContain("removed a binding for roles/iam.serviceAccountTokenCreator");
    const custom = rows([
      setPolicy([delta("ADD", "projects/acme/roles/customThing", "user:bob@corp.example")]),
    ])[0];
    expect(custom.severity).toBe("Medium");
    expect(custom.description).toContain(
      "custom role projects/acme/roles/customThing; its permissions are not in this record",
    );
  });

  it("the role table: Owner / Editor include key creation and actAs (High); Security Admin / Project IAM Admin change allow policies (High); OpenID token creator High; workload identity user Medium; security reviewer Low reconnaissance", () => {
    const grade = (role: string) =>
      rows([
        setPolicy([delta("ADD", role, "user:bob@corp.example")], {
          serviceName: "cloudresourcemanager.googleapis.com",
          resourceName: "projects/acme",
        }),
      ])[0];
    const owner = grade("roles/owner");
    expect(owner.severity).toBe("High");
    expect(owner.description).toContain("service-account key creation and actAs, and project IAM policy");
    const editor = grade("roles/editor");
    expect(editor.severity).toBe("High");
    expect(editor.description).toContain("service-account key creation and actAs");
    expect(grade("roles/iam.securityAdmin").description).toContain(
      "changing allow policies at its scope — policy writing, not impersonation",
    );
    expect(grade("roles/iam.securityAdmin").severity).toBe("High");
    expect(grade("roles/resourcemanager.projectIamAdmin").severity).toBe("High");
    expect(grade("roles/iam.serviceAccountOpenIdTokenCreator").severity).toBe("High");
    expect(grade("roles/iam.serviceAccountKeyAdmin").description).toContain(
      "creating and deleting service-account keys",
    );
    expect(grade("roles/iam.workloadIdentityUser").severity).toBe("Medium");
    expect(grade("roles/iam.workloadIdentityUser").description).toContain(
      "access-token and ID-token generation for federated identities",
    );
    const reviewer = grade("roles/iam.securityReviewer");
    expect(reviewer.severity).toBe("Low");
    expect(reviewer.description).toContain("read-only reconnaissance of IAM policies and keys");
  });

  it("a public member is High only on a classified dangerous role; a condition is shown, never evaluated; deleted: members are kept verbatim", () => {
    const publicCreator = rows([
      setPolicy([delta("ADD", "roles/iam.serviceAccountTokenCreator", "allUsers")]),
    ])[0];
    expect(publicCreator.severity).toBe("High");
    expect(publicCreator.description).toContain("granted to allUsers (public member)");
    const publicUnknown = rows([
      setPolicy([delta("ADD", "roles/viewer", "allAuthenticatedUsers")], {
        serviceName: "cloudresourcemanager.googleapis.com",
        resourceName: "projects/acme",
      }),
    ])[0];
    expect(publicUnknown.severity).toBe("Medium");
    expect(publicUnknown.description).toContain("public member on an unclassified role");
    const conditional = rows([
      setPolicy([
        delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:bob@corp.example", {
          title: "until",
          expression: 'request.time < timestamp("2030-01-01T00:00:00Z")',
        }),
      ]),
    ])[0];
    expect(conditional.description).toContain(
      'condition "until": request.time < timestamp("2030-01-01T00:00:00Z") (shown, not evaluated)',
    );
    expect(conditional.severity).toBe("High");
    const deleted = rows([
      setPolicy([
        delta(
          "REMOVE",
          "roles/iam.serviceAccountUser",
          "deleted:user:bob@corp.example?uid=123456789012345678901",
        ),
      ]),
    ])[0];
    expect(deleted.description).toContain("deleted:user:bob@corp.example?uid=123456789012345678901");
    expect(envelopeOf(deleted).gcp?.binding?.memberKind).toBe("deleted");
  });

  it("the delta is read from serviceData or metadata; identical copies fold; differing copies are said; no delta reads 'policy set; the delta is not in this record'", () => {
    const meta = rows([
      gcp("google.iam.admin.v1.SetIAMPolicy", {
        metadata: {
          policyDelta: {
            bindingDeltas: [delta("ADD", "roles/iam.serviceAccountUser", "user:bob@corp.example")],
          },
        },
      }),
    ]);
    expect(meta).toHaveLength(1);
    expect(meta[0].description).toContain("added a binding for roles/iam.serviceAccountUser");
    const both = rows([
      gcp("google.iam.admin.v1.SetIAMPolicy", {
        serviceData: {
          policyDelta: {
            bindingDeltas: [delta("ADD", "roles/iam.serviceAccountUser", "user:bob@corp.example")],
          },
        },
        metadata: {
          policyDelta: {
            bindingDeltas: [delta("ADD", "roles/iam.serviceAccountUser", "user:bob@corp.example")],
          },
        },
      }),
    ]);
    expect(both).toHaveLength(1);
    const differ = rows([
      gcp("google.iam.admin.v1.SetIAMPolicy", {
        serviceData: {
          policyDelta: {
            bindingDeltas: [delta("ADD", "roles/iam.serviceAccountUser", "user:bob@corp.example")],
          },
        },
        metadata: {
          policyDelta: {
            bindingDeltas: [delta("ADD", "roles/iam.serviceAccountTokenCreator", "user:bob@corp.example")],
          },
        },
      }),
    ]);
    expect(differ).toHaveLength(2);
    expect(differ[0].description).toContain("the two delta copies in this record differ");
    const none = rows([
      gcp("google.iam.admin.v1.SetIAMPolicy", {
        response: { bindings: [{ role: "roles/owner", members: ["user:bob@corp.example"] }] },
      }),
    ]);
    expect(none).toHaveLength(1);
    expect(none[0].severity).toBe("Medium");
    expect(none[0].description).toContain("; the delta is not in this record");
    expect(none[0].description).not.toContain("roles/owner");
  });

  it("storage setIamPermissions keeps the data-exposure reading beside the delta; 17 deltas → 16 rows and the count; a denied SetIamPolicy is an attempt", () => {
    const storage = rows([
      setPolicy([delta("ADD", "roles/storage.objectViewer", "allUsers")], {
        serviceName: "storage.googleapis.com",
        methodName: "storage.setIamPermissions",
        resourceName: "projects/_/buckets/b",
      }),
    ])[0];
    expect(storage.severity).toBe("High");
    expect(storage.mitreTechniques).toContain("T1530");
    expect(storage.description).toContain("on bucket b");
    const many = rows([
      setPolicy(
        Array.from({ length: 17 }, (_, i) => delta("ADD", "roles/viewer", `user:u${i}@corp.example`)),
        { serviceName: "cloudresourcemanager.googleapis.com", resourceName: "projects/acme" },
      ),
    ]);
    expect(many).toHaveLength(16);
    expect(many[15].description).toContain("+1 further binding delta in this record not individually listed");
    const denied = rows([
      setPolicy([delta("ADD", "roles/owner", "user:bob@corp.example")], {
        status: { code: 7, message: "PERMISSION_DENIED" },
      }),
    ])[0];
    expect(denied.severity).toBe("Medium");
    expect(denied.description).toContain("attempted, denied (7");
    expect(denied.description).not.toContain("added a binding");
    expect(denied.description).toContain("requested a binding for roles/owner");
  });
});

describe("GCP IAM Credentials and service-account keys", () => {
  const creds = (method: string, request: Row = {}, over: Row = {}) =>
    gcp(method, {
      serviceName: "iamcredentials.googleapis.com",
      resourceName: "projects/-/serviceAccounts/104857600000000000001",
      request: {
        "@type": "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest",
        name: `projects/-/serviceAccounts/${SA}`,
        ...request,
      },
      ...over,
    });

  it("GenerateAccessToken / GenerateIdToken establish a token (High, T1550.001); SignBlob / SignJwt establish only a signature; all are DATA_ACCESS records", () => {
    const token = rows([
      creds("GenerateAccessToken", {
        scope: ["https://www.googleapis.com/auth/cloud-platform"],
        lifetime: "3600s",
        delegates: ["projects/-/serviceAccounts/mid@acme.iam.gserviceaccount.com"],
      }),
    ])[0];
    expect(token.severity).toBe("High");
    expect(token.mitreTechniques).toContain("T1550.001");
    expect(token.description).toContain(
      `access token generated for service account ${SA} (unique id 104857600000000000001)`,
    );
    expect(token.description).toContain(
      "lifetime 3600s; scopes https://www.googleapis.com/auth/cloud-platform; delegates projects/-/serviceAccounts/mid@acme.iam.gserviceaccount.com",
    );
    expect(token.description).toContain(
      "a DATA_ACCESS record — present only where Data Access audit logging is enabled for iamcredentials",
    );
    const env = envelopeOf(token);
    expect(env.event.type).toBe("credential");
    expect(env.gcp?.credential).toMatchObject({
      fact: "access-token-generated",
      serviceAccount: SA,
      uniqueId: "104857600000000000001",
      scopes: ["https://www.googleapis.com/auth/cloud-platform"],
      delegates: ["projects/-/serviceAccounts/mid@acme.iam.gserviceaccount.com"],
      lifetime: "3600s",
    });
    expect(env.object).toEqual({ kind: "cloud_principal", id: "104857600000000000001", name: SA });
    expect(canonicalConformanceIssues(env)).toEqual([]);
    expect(rows([creds("GenerateIdToken", { audience: "https://app.example" })])[0].description).toContain(
      `ID token generated for service account ${SA}`,
    );
    const blob = rows([creds("SignBlob")])[0];
    expect(blob.severity).toBe("Medium");
    expect(blob.mitreTechniques).not.toContain("T1550.001");
    expect(blob.description).toContain(`blob signed by service account ${SA}`);
    expect(blob.description).toContain("no token established by this record");
    expect(rows([creds("SignJwt")])[0].description).toContain("JWT signed by service account");
  });

  it("a numeric resourceName is the durable identity, never an email or a project; the email comes from request.name or resource.labels; a denied call is an attempt", () => {
    const noName = rows([creds("GenerateAccessToken", {}, { request: { "@type": "x" } })])[0];
    expect(noName.description).toContain(
      `access token generated for service account ${SA} (unique id 104857600000000000001)`,
    );
    const bare = rows([
      {
        ...creds("GenerateAccessToken", {}, { request: { "@type": "x" } }),
        resource: { type: "service_account" },
      },
    ])[0];
    expect(bare.description).toContain(
      "access token generated for service account (unique id 104857600000000000001; email not in this record)",
    );
    expect(bare.description).not.toContain("resource project 104857600000000000001");
    const denied = rows([
      creds("GenerateAccessToken", {}, { status: { code: 7, message: "PERMISSION_DENIED" } }),
    ])[0];
    expect(denied.severity).toBe("Medium");
    expect(denied.description).toContain("attempted, denied (7");
    expect(denied.description).toContain("access token requested for service account");
    expect(denied.description).not.toContain("generated");
  });

  it("key lifecycle: a created key names the key and says the material is not in the record (High); delete / disable Low; upload High", () => {
    const created = one("google.iam.admin.v1.CreateServiceAccountKey", {
      request: { name: SA_RES, privateKeyType: "TYPE_GOOGLE_CREDENTIALS_FILE" },
      response: {
        name: `${SA_RES}/keys/0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b`,
        keyType: "USER_MANAGED",
        keyOrigin: "GOOGLE_PROVIDED",
      },
    });
    expect(created.severity).toBe("High");
    expect(created.mitreTechniques).toContain("T1098.001");
    expect(created.description).toContain(
      `created key …/keys/0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b for service account ${SA} (USER_MANAGED, GOOGLE_PROVIDED); the key material is not in the record`,
    );
    expect(envelopeOf(created).gcp?.key).toMatchObject({
      action: "created",
      name: `${SA_RES}/keys/0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b`,
      serviceAccount: SA,
    });
    expect(envelopeOf(created).event.type).toBe("service-account-key");
    const deleted = one("google.iam.admin.v1.DeleteServiceAccountKey", {
      resourceName: `${SA_RES}/keys/0a1b`,
      request: { name: `${SA_RES}/keys/0a1b` },
    });
    expect(deleted.severity).toBe("Low");
    expect(deleted.description).toContain("deleted key …/keys/0a1b");
    expect(
      one("google.iam.admin.v1.DisableServiceAccountKey", { resourceName: `${SA_RES}/keys/0a1b` }).severity,
    ).toBe("Low");
    const uploaded = one("google.iam.admin.v1.UploadServiceAccountKey", {
      request: { name: SA_RES },
      response: { name: `${SA_RES}/keys/ff` },
    });
    expect(uploaded.severity).toBe("High");
    expect(uploaded.description).toContain("uploaded key …/keys/ff");
  });
});

describe("GCP identity — neutralisation, bounds, the unchanged rows", () => {
  it("every displayed field is neutralised and the row stays within 600 characters", () => {
    const evil = "user:bob] [fake: owner\r\n=CMD()|<b>‮@corp.example";
    const e = rows([
      setPolicy([delta("ADD", "roles/iam] [fake", evil, { title: "t] [x", expression: "x] [y|<i>" })], {
        authenticationInfo: {
          principalEmail: "a] [b@corp.example",
          serviceAccountKeyName: "//iam.googleapis.com/projects/p/serviceAccounts/s/keys/k] [z",
          serviceAccountDelegationInfo: [{ firstPartyPrincipal: { principalEmail: "d] [e@corp.example" } }],
          principalSubject: "sub] [ject",
        },
        requestMetadata: { callerIp: "203.0.113.11", callerSuppliedUserAgent: "ua] [x​" },
        resourceName: "projects/acme] [x/serviceAccounts/s] [t",
        status: { code: 7, message: "denied] [ok" },
      }),
    ])[0];
    for (const bad of ["] [", "\r", "\n", "‮", "​"]) expect(e.description).not.toContain(bad);
    expect(e.description.length).toBeLessThanOrEqual(600);
    const long = rows([
      setPolicy([delta("ADD", "roles/owner", `user:${"b".repeat(400)}@corp.example`)], {
        resourceName: `projects/${"p".repeat(300)}`,
      }),
    ])[0];
    expect(long.description.length).toBeLessThanOrEqual(600);
    expect(long.description).toContain("added a binding for roles/owner");
  });

  it("a record with none of the decoded shapes reads as before, with the identity facts appended; the existing grades stand", () => {
    const e = one("storage.objects.get", {
      serviceName: "storage.googleapis.com",
      resourceName: "projects/_/buckets/b/objects/o",
    });
    expect(e.description).toContain(
      "GCP storage.objects.get (storage) by alice@corp.example from 203.0.113.11 on objects/o",
    );
    expect(e.severity).toBe("Info");
    expect(envelopeOf(e).event.type).toBe("api-call");
    const key = one("google.iam.admin.v1.CreateServiceAccountKey");
    expect(key.severity).toBe("High");
    expect(key.description).toContain("by alice@corp.example from 203.0.113.11");
  });
});
