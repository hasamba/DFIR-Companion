// GCP IAM records read for what they state (#931 item 12, record half): a SetIamPolicy's
// binding deltas as Google wrote them (serviceData or metadata — never a response snapshot),
// each delta one row with the role's DOCUMENTED permissions as nominal words; the four IAM
// Credentials facts (a token generated, or only a signature); the service-account key
// lifecycle. A denied call is an attempt. No effective permission is ever emitted.

import type { Severity } from "./stateTypes.js";
import type { GcpBinding, GcpCredential, GcpKey } from "./canonicalGcp.js";
import { field, lower, seg, show, showId, strings } from "./gcpIdentity.js";
import { getCI, isObject, str } from "./siemImport.js";
import { decodeGcpAuditConfigDelta, decodeGcpLogging } from "./loggingChangeCloud.js";
import type { LoggingReading } from "./loggingChange.js";
import type { LoggingChangeBlock } from "./canonicalLogging.js";

type Row = Record<string, unknown>;

export const DELTAS_PER_RECORD_MAX = 16;
const NOMINAL =
  "nominal; conditions, deny policies, principal access boundaries and inheritance are not evaluated by this record";
const DATA_ACCESS_NOTE =
  "a DATA_ACCESS record — present only where Data Access audit logging is enabled for iamcredentials";
const UNIQUE_ID = /^\d{15,25}$/;
const SA_ADDRESS = /^[^@\s]+@[^@\s]+\.gserviceaccount\.com$/i;

/** Predefined roles with the documented permissions the item separates; everything else is custom or unclassified. */
interface RoleDef {
  documented: string;
  severity: Severity;
  mitre: string[];
}
export const GCP_ROLES: Readonly<Record<string, RoleDef>> = {
  "roles/iam.serviceaccounttokencreator": {
    documented: "generating access tokens and ID tokens for the service account, signing blobs and JWTs",
    severity: "High",
    mitre: ["T1098.003", "T1550.001"],
  },
  "roles/iam.serviceaccountopenidtokencreator": {
    documented: "generating OpenID Connect ID tokens for the service account",
    severity: "High",
    mitre: ["T1098.003", "T1550.001"],
  },
  "roles/iam.serviceaccountuser": {
    documented:
      "attaching the service account to a workload (actAs) — not the permission to mint credentials",
    severity: "Medium",
    mitre: ["T1098.003"],
  },
  "roles/iam.serviceaccountkeyadmin": {
    documented: "creating and deleting service-account keys",
    severity: "High",
    mitre: ["T1098.001"],
  },
  "roles/iam.serviceaccountadmin": {
    documented: "creating, deleting and managing service accounts and their allow policies",
    severity: "High",
    mitre: ["T1098.003"],
  },
  "roles/iam.workloadidentityuser": {
    documented: "access-token and ID-token generation for federated identities bound to the service account",
    severity: "Medium",
    mitre: ["T1098.003"],
  },
  "roles/owner": {
    documented: "service-account key creation and actAs, and project IAM policy",
    severity: "High",
    mitre: ["T1098.003"],
  },
  "roles/editor": {
    documented: "service-account key creation and actAs",
    severity: "High",
    mitre: ["T1098.003"],
  },
  "roles/iam.securityadmin": {
    documented: "changing allow policies at its scope — policy writing, not impersonation",
    severity: "High",
    mitre: ["T1098.003"],
  },
  "roles/resourcemanager.projectiamadmin": {
    documented: "changing allow policies at its scope — policy writing, not impersonation",
    severity: "High",
    mitre: ["T1098.003"],
  },
  "roles/iam.securityreviewer": {
    documented: "read-only reconnaissance of IAM policies and keys",
    severity: "Low",
    mitre: ["T1087.004"],
  },
};

export interface GcpActionReading {
  kind: "binding" | "credential" | "key" | "logging";
  severity: Severity;
  mitre: string[];
  posture: string;
  object: string;
  qualifiers: string[];
  keySegment: string;
  /** The service account the row is about, for the envelope object. */
  serviceAccount?: { email?: string; uniqueId?: string };
  /** The reading's grade replaces the importer's table grade (a binding delta); otherwise it only raises. */
  replacesTableGrade?: boolean;
  binding?: GcpBinding;
  credential?: GcpCredential;
  key?: GcpKey;
  loggingChange?: LoggingChangeBlock;
}

const asAction = (r: LoggingReading): GcpActionReading => ({
  kind: "logging",
  severity: r.severity,
  mitre: r.mitre,
  posture: r.posture,
  object: r.detail,
  qualifiers: r.qualifiers,
  keySegment: r.keySegment,
  replacesTableGrade: true,
  loggingChange: r.block,
});

/** The audit-config deltas of a SetIamPolicy record from both documented locations, identical copies folded; a differing copy is kept and flagged. */
function auditConfigDeltas(pp: Row): { deltas: Row[]; copiesDiffer: boolean } {
  const read = (v: unknown): Row[] => {
    const policyDelta = isObject(v) ? getCI(v, "policyDelta") : undefined;
    const deltas = isObject(policyDelta) ? getCI(policyDelta, "auditConfigDeltas") : undefined;
    return Array.isArray(deltas) ? deltas.filter(isObject) : [];
  };
  const key = (d: Row) =>
    ["action", "service", "logType", "exemptedMember"].map((k) => field(d, k)).join("|");
  const legacy = read(getCI(pp, "serviceData"));
  const current = read(getCI(pp, "metadata"));
  if (!legacy.length || !current.length)
    return { deltas: legacy.length ? legacy : current, copiesDiffer: false };
  const seen = new Map(legacy.map((d) => [key(d), d]));
  let copiesDiffer = legacy.length !== current.length;
  for (const d of current) {
    if (seen.has(key(d))) continue;
    copiesDiffer = true;
    seen.set(key(d), d);
  }
  return { deltas: [...seen.values()], copiesDiffer };
}

const denied = (pp: Row): { denied: boolean; code: string; message: string } => {
  const status = getCI(pp, "status");
  const code = isObject(status) ? str(getCI(status, "code")).trim() : "";
  return { denied: !!code && code !== "0", code, message: field(pp, "status", "message") };
};
const deniedWords = (d: ReturnType<typeof denied>): string =>
  `attempted, denied (${show(d.code, 10)}${d.message ? `: ${show(d.message, 60)}` : ""})`;
const saOfName = (name: string): string => {
  const m = /serviceAccounts\/([^/]+)/.exec(name);
  return m ? m[1] : "";
};

// ───────────────────────────── the policy delta ─────────────────────────────

type MemberKind = GcpBinding["memberKind"];
function memberKindOf(member: string): MemberKind {
  const m = member.trim();
  if (m === "allUsers" || m === "allAuthenticatedUsers") return "public";
  if (m.startsWith("deleted:")) return "deleted";
  if (m.startsWith("user:")) return "user";
  if (m.startsWith("serviceAccount:")) return "service-account";
  if (m.startsWith("group:")) return "group";
  if (m.startsWith("domain:")) return "domain";
  if (m.startsWith("principal:")) return "principal";
  if (m.startsWith("principalSet:")) return "principal-set";
  return "other";
}
type ResourceKind = GcpBinding["resourceKind"];
function resourceKindOf(resource: string, service: string): ResourceKind {
  const r = resource.replace(/^\/\/[^/]+\//, "");
  if (/\/serviceAccounts\/[^/]+$/.test(r)) return "service-account";
  if (/buckets\//.test(r) || /storage/i.test(service)) return "bucket";
  if (/^projects\/[^/]+$/.test(r)) return "project";
  if (/^folders\/[^/]+$/.test(r)) return "folder";
  if (/^organizations\/[^/]+$/.test(r)) return "organization";
  return "other";
}
const resourceWords = (resource: string, kind: ResourceKind): string => {
  const r = resource.replace(/^\/\/[^/]+\//, "");
  if (kind === "service-account") return `service account ${show(saOfName(r), 80)}`;
  if (kind === "bucket") return `bucket ${show(r.replace(/^projects\/[^/]+\/buckets\//, ""), 80)}`;
  if (kind === "project") return `project ${show(r.replace(/^projects\//, ""), 40)}`;
  return show(r, 100);
};

interface Delta {
  action: string;
  role: string;
  member: string;
  condition?: { title?: string; expression?: string };
}
function readDeltas(v: unknown): Delta[] {
  const policyDelta = isObject(v) ? getCI(v, "policyDelta") : undefined;
  const deltas = isObject(policyDelta) ? getCI(policyDelta, "bindingDeltas") : undefined;
  if (!Array.isArray(deltas)) return [];
  return deltas.filter(isObject).map((d) => {
    const cond = isObject(getCI(d, "condition")) ? (getCI(d, "condition") as Row) : null;
    return {
      action: field(d, "action"),
      role: field(d, "role"),
      member: field(d, "member"),
      ...(cond
        ? {
            condition: {
              ...(field(cond, "title") ? { title: field(cond, "title") } : {}),
              ...(field(cond, "expression") ? { expression: field(cond, "expression") } : {}),
            },
          }
        : {}),
    };
  });
}
const deltaKey = (d: Delta): string =>
  [d.action, d.role, d.member, d.condition?.title ?? "", d.condition?.expression ?? ""].map(seg).join("|");

/** The deltas of a SetIamPolicy record from either documented location; identical copies fold, differing copies are both kept and said. */
export function policyDeltas(pp: Row): { deltas: Delta[]; copiesDiffer: boolean } {
  const legacy = readDeltas(getCI(pp, "serviceData"));
  const current = readDeltas(getCI(pp, "metadata"));
  if (!legacy.length || !current.length)
    return { deltas: legacy.length ? legacy : current, copiesDiffer: false };
  const seen = new Map(legacy.map((d) => [deltaKey(d), d]));
  let differ = false;
  for (const d of current) {
    if (seen.has(deltaKey(d))) continue;
    differ = true;
    seen.set(deltaKey(d), d);
  }
  if (legacy.length !== current.length) differ = true;
  return { deltas: [...seen.values()], copiesDiffer: differ };
}

const isSetIamPolicy = (method: string): boolean => /setiam(policy|permissions)$/i.test(method);

function bindingReading(
  pp: Row,
  service: string,
  d: Delta,
  extra: { copiesDiffer: boolean; further: number; storage: boolean },
): GcpActionReading {
  const den = denied(pp);
  const resource = field(pp, "resourceName");
  const resourceKind = resourceKindOf(resource, service);
  const memberKind = memberKindOf(d.member);
  const add = lower(d.action) === "add";
  const roleLower = lower(d.role);
  const def = GCP_ROLES[roleLower];
  const custom = /^(projects|organizations)\/[^/]+\/roles\//i.test(d.role);
  const roleClass: GcpBinding["roleClass"] = def ? "classified" : custom ? "custom" : "unclassified";
  const memberIsSa = memberKind === "service-account";
  const direction: GcpBinding["direction"] =
    resourceKind === "service-account"
      ? "authority-over-service-account"
      : memberIsSa
        ? "access-to-member"
        : resourceKind === "project" || resourceKind === "folder" || resourceKind === "organization"
          ? "parent-scope"
          : "other-resource";
  const verb = den.denied ? `requested a binding for` : add ? `added a binding for` : `removed a binding for`;
  const roleWords = def
    ? `${verb} ${show(d.role, 80)}, whose documented permissions include: ${def.documented} (${NOMINAL})`
    : custom
      ? `${verb} custom role ${show(d.role, 120)}; its permissions are not in this record`
      : `${verb} ${show(d.role, 80)} (role as recorded; not classified here)`;
  const memberWords = `${show(d.member, 120)}${memberKind === "public" ? " (public member)" : ""}`;
  const head =
    direction === "authority-over-service-account"
      ? `authority over ${resourceWords(resource, resourceKind)} granted to ${memberWords}`
      : direction === "access-to-member"
        ? `access granted to ${memberWords} on ${show(resource.replace(/^\/\/[^/]+\//, ""), 100)}`
        : direction === "parent-scope"
          ? `to ${memberWords} on ${resourceWords(resource, resourceKind)} — nominally applies to the service accounts under it; inheritance not evaluated`
          : `to ${memberWords} on ${resourceWords(resource, resourceKind)}`;
  let severity: Severity = !add ? "Low" : def ? def.severity : "Medium";
  const mitre = add && def ? [...def.mitre] : [];
  if (add && memberKind === "public" && !def) severity = "Medium";
  // A public member on a storage bucket is data exposure whatever the role — the importer's own reading.
  if (extra.storage && add) {
    mitre.push("T1530");
    if (memberKind === "public") severity = "High";
  }
  if (den.denied) severity = "Medium";
  const qualifiers = [
    ...(memberKind === "public" && !def && add ? ["public member on an unclassified role"] : []),
    ...(d.condition
      ? [
          `condition${d.condition.title ? ` "${show(d.condition.title, 40)}"` : ""}${d.condition.expression ? `: ${show(d.condition.expression, 120)}` : ""} (shown, not evaluated)`,
        ]
      : []),
    ...(extra.copiesDiffer ? ["the two delta copies in this record differ"] : []),
    ...(extra.further
      ? [
          `+${extra.further} further binding delta${extra.further === 1 ? "" : "s"} in this record not individually listed`,
        ]
      : []),
    ...(den.denied ? [deniedWords(den)] : []),
  ];
  const sa = resourceKind === "service-account" ? saOfName(resource) : "";
  const block: GcpBinding = {
    action: d.action,
    role: d.role,
    member: d.member,
    memberKind,
    resource,
    resourceKind,
    direction,
    ...(def ? { documented: def.documented } : {}),
    roleClass,
    ...(d.condition ? { condition: d.condition } : {}),
    nominal: true,
    copiesDiffer: extra.copiesDiffer,
    furtherDeltas: extra.further,
    denied: den.denied,
  };
  return {
    kind: "binding",
    severity,
    mitre,
    posture: head,
    object: roleWords,
    qualifiers,
    keySegment: `|binding|${[d.action, d.role, d.member, resource, d.condition?.expression ?? ""].map(seg).join("|")}`,
    ...(sa
      ? {
          serviceAccount: {
            ...(SA_ADDRESS.test(sa) ? { email: sa } : {}),
            ...(UNIQUE_ID.test(sa) ? { uniqueId: sa } : {}),
          },
        }
      : {}),
    binding: block,
    // A delta says more than the table: its grade replaces the blanket SetIamPolicy grade.
    replacesTableGrade: true,
  };
}

/** No delta in the record: the policy was set, and that is all the record says. */
function policyWithoutDelta(pp: Row, service: string): GcpActionReading {
  const den = denied(pp);
  const resource = field(pp, "resourceName");
  const resourceKind = resourceKindOf(resource, service);
  const storage = /storage/i.test(service);
  return {
    kind: "binding",
    // Without the delta the record says only that a policy was set — Medium; a storage policy
    // keeps the importer's exposure reading.
    severity: den.denied ? "Medium" : storage ? "High" : "Medium",
    mitre: storage ? ["T1530"] : ["T1098.003"],
    replacesTableGrade: true,
    posture: `policy set on ${resourceWords(resource, resourceKind)}; the delta is not in this record`,
    object: "",
    qualifiers: den.denied ? [deniedWords(den)] : [],
    keySegment: `|policy-set|${seg(resource)}`,
    binding: {
      action: "UNKNOWN",
      role: "",
      member: "",
      memberKind: "other",
      resource,
      resourceKind,
      direction: resourceKind === "service-account" ? "authority-over-service-account" : "other-resource",
      roleClass: "unclassified",
      nominal: true,
      copiesDiffer: false,
      furtherDeltas: 0,
      denied: den.denied,
    },
  };
}

// ───────────────────────────── credentials and keys ─────────────────────────────

const CREDENTIAL_FACTS: Record<string, GcpCredential["fact"]> = {
  generateaccesstoken: "access-token-generated",
  generateidtoken: "id-token-generated",
  signblob: "blob-signed",
  signjwt: "jwt-signed",
};
const FACT_WORDS: Record<GcpCredential["fact"], [done: string, requested: string]> = {
  "access-token-generated": ["access token generated for", "access token requested for"],
  "id-token-generated": ["ID token generated for", "ID token requested for"],
  "blob-signed": ["blob signed by", "blob signing requested from"],
  "jwt-signed": ["JWT signed by", "JWT signing requested from"],
};

function credentialReading(pp: Row, rec: Row, method: string): GcpActionReading | null {
  const fact = CREDENTIAL_FACTS[lower(method).replace(/^.*\./, "")];
  if (!fact) return null;
  const den = denied(pp);
  const request = isObject(getCI(pp, "request")) ? (getCI(pp, "request") as Row) : {};
  const fromName = saOfName(field(request, "name"));
  const fromResource = saOfName(field(pp, "resourceName"));
  const labelEmail = field(rec, "resource", "labels", "email_id");
  const labelId = field(rec, "resource", "labels", "unique_id");
  const email = [fromName, fromResource, labelEmail].find((v) => SA_ADDRESS.test(v)) ?? "";
  const uniqueId = [fromResource, fromName, labelId].find((v) => UNIQUE_ID.test(v)) ?? "";
  const scopes = strings(getCI(request, "scope"));
  const delegates = strings(getCI(request, "delegates"));
  const lifetime = field(request, "lifetime");
  const audience = field(request, "audience");
  const token = fact === "access-token-generated" || fact === "id-token-generated";
  const who = email
    ? `service account ${show(email, 80)}${uniqueId ? ` (unique id ${showId(uniqueId, 30)})` : ""}`
    : `service account (${uniqueId ? `unique id ${showId(uniqueId, 30)}; ` : ""}email not in this record)`;
  const facts = [
    ...(lifetime ? [`lifetime ${show(lifetime, 20)}`] : []),
    ...(audience ? [`audience ${show(audience, 80)}`] : []),
    ...(scopes.length ? [`scopes ${scopes.map((s) => show(s, 80)).join(", ")}`] : []),
    ...(delegates.length ? [`delegates ${delegates.map((s) => show(s, 100)).join(", ")}`] : []),
  ];
  return {
    kind: "credential",
    severity: den.denied ? "Medium" : token ? "High" : "Medium",
    mitre: token && !den.denied ? ["T1550.001"] : [],
    posture: `${FACT_WORDS[fact][den.denied ? 1 : 0]} ${who}`,
    object: facts.join("; "),
    qualifiers: [
      ...(token ? [] : ["no token established by this record"]),
      DATA_ACCESS_NOTE,
      ...(den.denied ? [deniedWords(den)] : []),
    ],
    keySegment: `|credential|${[fact, email, uniqueId].map(seg).join("|")}`,
    serviceAccount: { ...(email ? { email } : {}), ...(uniqueId ? { uniqueId } : {}) },
    credential: {
      fact,
      ...(email ? { serviceAccount: email } : {}),
      ...(uniqueId ? { uniqueId } : {}),
      scopes,
      delegates,
      ...(lifetime ? { lifetime } : {}),
      ...(audience ? { audience } : {}),
      denied: den.denied,
    },
  };
}

const KEY_ACTIONS: Record<string, GcpKey["action"]> = {
  createserviceaccountkey: "created",
  uploadserviceaccountkey: "uploaded",
  deleteserviceaccountkey: "deleted",
  disableserviceaccountkey: "disabled",
  enableserviceaccountkey: "enabled",
};

function keyReading(pp: Row, method: string): GcpActionReading | null {
  const action = KEY_ACTIONS[lower(method).replace(/^.*\./, "")];
  if (!action) return null;
  const den = denied(pp);
  const request = isObject(getCI(pp, "request")) ? (getCI(pp, "request") as Row) : {};
  const response = isObject(getCI(pp, "response")) ? (getCI(pp, "response") as Row) : {};
  const name =
    [field(response, "name"), field(request, "name"), field(pp, "resourceName")].find((v) =>
      /\/keys\/[^/]+$/.test(v),
    ) ?? "";
  const sa = saOfName(name) || saOfName(field(request, "name")) || saOfName(field(pp, "resourceName"));
  const keyType = field(response, "keyType");
  const keyOrigin = field(response, "keyOrigin");
  const keyId = name ? name.slice(name.lastIndexOf("/") + 1) : "";
  const created = action === "created" || action === "uploaded";
  return {
    kind: "key",
    severity: den.denied ? "Medium" : created ? "High" : "Low",
    mitre: created && !den.denied ? ["T1098.001"] : [],
    posture: `${den.denied ? `key ${action === "created" ? "creation" : action === "uploaded" ? "upload" : action} requested` : `${action} key`}${keyId ? ` …/keys/${showId(keyId, 60)}` : " (key name not in this record)"}${sa ? ` for service account ${show(sa, 80)}` : ""}${
      keyType || keyOrigin
        ? ` (${[keyType, keyOrigin]
            .filter(Boolean)
            .map((v) => show(v, 30))
            .join(", ")})`
        : ""
    }${created ? "; the key material is not in the record" : ""}`,
    object: "",
    qualifiers: den.denied ? [deniedWords(den)] : [],
    keySegment: `|key|${[action, name].map(seg).join("|")}`,
    serviceAccount: {
      ...(SA_ADDRESS.test(sa) ? { email: sa } : {}),
      ...(UNIQUE_ID.test(sa) ? { uniqueId: sa } : {}),
    },
    key: {
      action,
      ...(name ? { name } : {}),
      ...(sa ? { serviceAccount: sa } : {}),
      ...(keyType ? { keyType } : {}),
      ...(keyOrigin ? { keyOrigin } : {}),
      denied: den.denied,
    },
  };
}

/** The action readings of one GCP record: one per binding delta, or one credential / key fact, or none. */
export function decodeGcpAction(pp: Row, rec: Row, method: string, service: string): GcpActionReading[] {
  const den = denied(pp);
  if (isSetIamPolicy(method)) {
    const { deltas, copiesDiffer } = policyDeltas(pp);
    // The audit-config deltas ride beside the binding deltas (#931 item 14): each is its own row.
    const auditRead = auditConfigDeltas(pp);
    const audit = auditRead.deltas.slice(0, DELTAS_PER_RECORD_MAX).map((d) => {
      const r = asAction(decodeGcpAuditConfigDelta(d, den.denied));
      return auditRead.copiesDiffer
        ? { ...r, qualifiers: [...r.qualifiers, "the two delta copies in this record differ"] }
        : r;
    });
    if (!deltas.length) return audit.length ? audit : [policyWithoutDelta(pp, service)];
    const shown = deltas.slice(0, DELTAS_PER_RECORD_MAX);
    const storage = /storage/i.test(service);
    return [
      ...shown.map((d, i) =>
        bindingReading(pp, service, d, {
          copiesDiffer,
          further: i === shown.length - 1 ? deltas.length - shown.length : 0,
          storage,
        }),
      ),
      ...audit,
    ];
  }
  const logging = decodeGcpLogging(service, method, getCI(pp, "request"), den.denied);
  if (logging) return [asAction(logging)];
  const credential = /iamcredentials/i.test(service) ? credentialReading(pp, rec, method) : null;
  if (credential) return [credential];
  const key = keyReading(pp, method);
  return key ? [key] : [];
}
