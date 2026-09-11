import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import {
  capabilityOf,
  classSeverity,
  KNOWN_APIS,
  LOW_PRIVILEGE_SCOPES,
  roleTier,
  type CapabilityClass,
  type RoleTier,
} from "./entraCapabilities.js";
import {
  isGuid,
  parseConsentPermissions,
  parseKeyDescriptions,
  type EntraAuditRecord,
  type EntraProp,
  type EntraTarget,
  type KeyDescription,
} from "./entraAuditRecord.js";

// Entra application changes, read from the one audit record each arrives in (#931 item 1).
//
// A record establishes: which credential was ADDED (the old and new lists are both in it — the one
// delta a single record does hold), which permission was granted and on which API (identified only
// by the API's immutable application id), whether the consent was an admin's or a user's and for
// everyone or one person, which directory role went to whom. It does not establish that anything
// was USED — that is the sign-in row's, and the chain is #973's. One record can carry several
// atomic changes (three scopes, two credentials); each is its own row with its own whole key, so
// none of them overwrites another in aggregation.

export type ChangeKind =
  | "credential-added"
  | "credential-removed"
  | "app-permission-granted"
  | "app-permission-removed"
  | "delegated-permission-granted"
  | "delegated-permission-removed"
  | "role-assigned"
  | "role-removed"
  | "owner-added"
  | "owner-removed";

export interface EntraAppChange {
  kind: ChangeKind;
  posture: string;
  /** The object slot — the API, the subject, the consent words; "" when the posture carries it. */
  object: string;
  attempted: boolean;
  subject: { id: string; name: string; appId: string; type: string };
  resource: { id: string; name: string; appId: string; api: string };
  capability: { value: string; class: CapabilityClass | ""; allows: string; delegated: boolean } | null;
  consent: { admin: boolean | null; allUsers: boolean | null; principalId: string; entryId: string } | null;
  credential: KeyDescription | null;
  role: {
    name: string;
    templateId: string;
    objectId: string;
    tier: RoleTier;
    eligible: boolean;
    activation: boolean;
    memberType: string;
    memberId: string;
    memberName: string;
  } | null;
  selfGrant: boolean;
  severity: Severity;
  mitre: string[];
  /** The capability's allowed action, for the description. */
  words: string;
  qualifiers: string[];
  /** Posture, capability, consent, qualifiers — everything but the importer's head and tail. */
  summary: string;
  /** The WHOLE aggregation key — the importer bounds it (`boundedAggKey`). */
  aggKey: string;
}

/**
 * Tenant-scoped resolution of a service principal's OBJECT id to its immutable app id, learned from
 * other records of the same export that state both (an app-role assignment names the resource's
 * object id and its ServicePrincipalNames). Returns "" when unknown.
 */
export type Resolver = (objectId: string) => string;

const NOT_OBSERVED = "assigned, not yet observed in use";
const DELEGATED_NOTE = "delegated — bounded by the consenting user's own access";
const UNIDENTIFIED = "API not identified in this record";
const NAME_MAX = 60;
const ID_SHORT = 8;
const digest = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 16);
const short = (id: string): string => (id.length > ID_SHORT ? `${id.slice(0, ID_SHORT)}…` : id);
const bool = (v: unknown): boolean | null =>
  typeof v === "boolean"
    ? v
    : typeof v === "string"
      ? /^true$/i.test(v)
        ? true
        : /^false$/i.test(v)
          ? false
          : null
      : null;
const text = (v: unknown): string => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");
const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : typeof v === "string" ? [v] : [];

const propOf = (r: EntraAuditRecord, name: string): EntraProp | undefined =>
  r.props.find((p) => p.name.toLowerCase() === name.toLowerCase());
const propText = (r: EntraAuditRecord, name: string): string => text(propOf(r, name)?.newValue).trim();
const targetOf = (r: EntraAuditRecord, ...types: string[]): EntraTarget | undefined =>
  r.targets.find((t) => types.some((x) => x.toLowerCase() === t.type.toLowerCase()));
const label = (t: { name: string; upn: string; id: string } | undefined): string =>
  (t?.upn || t?.name || short(t?.id ?? "")).slice(0, NAME_MAX);

// The API behind a resource, from its immutable app id in `TargetId.ServicePrincipalNames` (or a
// `ServicePrincipalNames`/`AppId` property); a display name is a label and never an identity.
function apiOf(
  r: EntraAuditRecord,
  resourceObjectId = "",
  resolve?: Resolver,
): { appId: string; api: string } {
  const names = [
    resourceObjectId && resolve ? resolve(resourceObjectId) : "",
    ...strings(propOf(r, "TargetId.ServicePrincipalNames")?.newValue),
    ...strings(propOf(r, "ServicePrincipalNames")?.newValue),
    propText(r, "Resource.AppId"),
  ];
  for (const n of names) {
    const id = n.trim().toLowerCase();
    if (isGuid(id) && KNOWN_APIS[id]) return { appId: id, api: KNOWN_APIS[id] };
  }
  return { appId: "", api: "" };
}

const worst = (a: Severity, b: Severity): Severity => {
  const rank: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
  return rank[b] > rank[a] ? b : a;
};

interface Base {
  r: EntraAuditRecord;
  kind: ChangeKind;
  verb: string; // present tense
  infinitive: string;
  subject: EntraAppChange["subject"];
  resource: EntraAppChange["resource"];
  atomic: string; // the atomic identity for the key
  severity: Severity;
  mitre: string[];
  qualifiers: string[];
  detail: string; // after the verb, in the posture
  object?: string; // the object slot: the API, the subject, the consent words
  words: string;
  capability?: EntraAppChange["capability"];
  consent?: EntraAppChange["consent"];
  credential?: KeyDescription | null;
  role?: EntraAppChange["role"];
  selfGrant?: boolean;
}

function build(b: Base): EntraAppChange {
  // Anything but a success is an attempt: a timeout or an absent result does not establish the change.
  const attempted = b.r.outcome !== "success";
  const removal = b.kind.endsWith("-removed");
  const self = b.selfGrant ?? false;
  const posture = `${self && !attempted ? "self-grant: " : ""}${attempted ? `attempted to ${b.infinitive}` : b.verb}${b.detail ? ` ${b.detail}` : ""}`;
  const severity: Severity = attempted
    ? "Medium"
    : removal
      ? "Low"
      : self
        ? worst(b.severity, "High")
        : b.severity;
  const qualifiers = attempted
    ? [...b.qualifiers.filter((q) => q !== NOT_OBSERVED), "requested, not granted"]
    : b.qualifiers;
  const summary = [
    `${posture}${b.object ? ` ${b.object}` : ""}`,
    b.words ? `— ${b.words}` : "",
    attempted ? "(requested)" : "",
    ...qualifiers.map((q) => `[${q}]`),
  ]
    .filter(Boolean)
    .join(" ");
  return {
    kind: b.kind,
    posture,
    object: b.object ?? "",
    attempted,
    subject: b.subject,
    resource: b.resource,
    capability: b.capability ?? null,
    consent: b.consent ?? null,
    credential: b.credential ?? null,
    role: b.role ?? null,
    selfGrant: self,
    severity,
    mitre: attempted || removal ? [] : b.mitre,
    words: b.words,
    qualifiers,
    summary,
    aggKey:
      `entra-app|${b.r.tenant}|${b.r.operation}|${b.r.outcome}|${b.subject.id || b.subject.name}|${b.resource.id || "-"}|${b.atomic}`.toLowerCase(),
  };
}

const spSubject = (r: EntraAuditRecord): EntraAppChange["subject"] => {
  const t = targetOf(r, "ServicePrincipal", "Application");
  return { id: t?.id ?? "", name: label(t), appId: "", type: t?.type ?? "" };
};
const clientSubject = (r: EntraAuditRecord): EntraAppChange["subject"] => {
  const id = propText(r, "ServicePrincipal.ObjectID");
  if (id) {
    return {
      id,
      name: (propText(r, "ServicePrincipal.DisplayName") || short(id)).slice(0, NAME_MAX),
      appId: propText(r, "ServicePrincipal.AppId"),
      type: "ServicePrincipal",
    };
  }
  return spSubject(r);
};
const isSelf = (r: EntraAuditRecord, subject: EntraAppChange["subject"]): boolean =>
  r.initiator.kind === "app" &&
  ((!!r.initiator.id && r.initiator.id.toLowerCase() === subject.id.toLowerCase()) ||
    (!!r.initiator.appId &&
      !!subject.appId &&
      r.initiator.appId.toLowerCase() === subject.appId.toLowerCase()));

// ───────────────────────────── credentials ─────────────────────────────

function credentialChanges(r: EntraAuditRecord, removal: boolean): EntraAppChange[] {
  const p = propOf(r, "KeyDescription");
  const subject = spSubject(r);
  const kind: ChangeKind = removal ? "credential-removed" : "credential-added";
  const base = {
    r,
    kind,
    subject,
    resource: { id: "", name: "", appId: "", api: "" },
    mitre: ["T1098.001"],
    qualifiers: [],
    words: "",
  };
  if (!p) return [];
  const newList = parseKeyDescriptions(p.newValue);
  const oldList = parseKeyDescriptions(p.oldValue);
  const readable =
    !p.unreadable && (newList.length || oldList.length || (Array.isArray(p.newValue) && !p.newValue.length));
  if (!readable) {
    return [
      build({
        ...base,
        verb: "credential list changed (unreadable)",
        infinitive: "change the credential list (unreadable)",
        object: `for ${subject.name || short(subject.id)}`,
        atomic: `raw:${p.rawDigest}`,
        severity: "High",
        detail: "",
      }),
    ];
  }
  const from = removal ? oldList : newList;
  const against = new Set((removal ? newList : oldList).map((k) => k.keyId.toLowerCase()));
  return from
    .filter((k) => !against.has(k.keyId.toLowerCase()))
    .map((k) =>
      build({
        ...base,
        verb: `${removal ? "removes" : "adds"} ${k.keyType || "unknown-type"} credential ${k.keyId.slice(0, 36)}`,
        infinitive: `${removal ? "remove" : "add"} ${k.keyType || "unknown-type"} credential ${k.keyId.slice(0, 36)}`,
        detail: `"${k.displayName.slice(0, 40)}" (${newList.length} now)`,
        object: `for ${subject.name || short(subject.id)}`,
        atomic: `cred:${k.keyId}`,
        severity: "High",
        credential: k,
      }),
    );
}

// ───────────────────────────── permissions ─────────────────────────────

function permissionChange(
  r: EntraAuditRecord,
  opts: {
    kind: ChangeKind;
    value: string;
    delegated: boolean;
    subject: EntraAppChange["subject"];
    resource: EntraAppChange["resource"];
    consent: EntraAppChange["consent"];
    atomic: string;
  },
): EntraAppChange {
  const cap = opts.resource.appId ? capabilityOf(opts.resource.appId, opts.value) : null;
  const cls = cap?.class ?? "";
  const removal = opts.kind.endsWith("-removed");
  const noun = opts.delegated ? "delegated permission" : "application permission";
  const where = opts.resource.api
    ? `on ${opts.resource.api}`
    : `on API ${opts.resource.name || short(opts.resource.id) || "unknown"}`;
  const forSubject = ` for ${opts.subject.name || short(opts.subject.id)}`;
  const consentWords = [
    opts.consent?.admin === true ? "admin consent" : opts.consent?.admin === false ? "user consent" : "",
    opts.consent?.allUsers === true
      ? "for all users"
      : opts.consent?.allUsers === false
        ? `for one user${opts.consent.principalId ? ` ${short(opts.consent.principalId)}` : ""}`
        : "",
  ].filter(Boolean);
  // GRADE — set by the decoder: an application permission by its class on an identified API,
  // Medium on an unidentified one whatever the spelling; a delegated scope by the consent's reach
  // and the scope's class, Low for the ordinary one-user scopes.
  let severity: Severity;
  const valueLower = opts.value.toLowerCase();
  const dataOrIdentity = cls === "data read" || cls === "data write/send" || cls === "identity takeover";
  if (!opts.delegated) severity = cls ? classSeverity(cls) : "Medium";
  else if (opts.consent?.allUsers) severity = dataOrIdentity ? "High" : "Medium";
  else if (LOW_PRIVILEGE_SCOPES.has(valueLower)) severity = "Low";
  else severity = cls === "data write/send" || cls === "identity takeover" ? "High" : "Medium";
  const mitre =
    cls === "data read" || cls === "data write/send" ? ["T1528"] : opts.delegated ? ["T1528"] : ["T1098.003"];
  const qualifiers = [
    ...(opts.resource.api ? [] : [UNIDENTIFIED]),
    ...(opts.delegated ? [DELEGATED_NOTE] : []),
    ...(removal ? [] : [NOT_OBSERVED]),
  ];
  return build({
    r,
    kind: opts.kind,
    verb: `${removal ? "revokes" : "grants"} ${noun} ${opts.value}`,
    infinitive: `${removal ? "revoke" : "grant"} ${noun} ${opts.value}`,
    detail: "",
    object: `${where}${forSubject}${consentWords.length ? ` (${consentWords.join(", ")})` : ""}`,
    subject: opts.subject,
    resource: opts.resource,
    atomic: opts.atomic,
    severity,
    mitre,
    qualifiers,
    words: cap?.allows ?? "",
    capability: { value: opts.value, class: cls, allows: cap?.allows ?? "", delegated: opts.delegated },
    consent: opts.consent,
    selfGrant: isSelf(r, opts.subject),
  });
}

function appRoleChanges(r: EntraAuditRecord, removal: boolean, resolve?: Resolver): EntraAppChange[] {
  const value = propText(r, "AppRole.Value");
  if (!value) return [];
  const subject = clientSubject(r);
  const t = r.targets[0];
  const { appId, api } = apiOf(r, t?.id ?? "", resolve);
  const resource = { id: t?.id ?? "", name: (t?.name ?? "").slice(0, NAME_MAX), appId, api };
  return [
    permissionChange(r, {
      kind: removal ? "app-permission-removed" : "app-permission-granted",
      value,
      delegated: false,
      subject,
      resource,
      consent: null,
      atomic: `approle:${value}:${propText(r, "AppRole.Id")}`,
    }),
  ];
}

function delegatedGrantChanges(r: EntraAuditRecord, removal: boolean, resolve?: Resolver): EntraAppChange[] {
  const scopes = propText(r, "DelegatedPermissionGrant.Scope").split(/\s+/).filter(Boolean);
  if (!scopes.length) return [];
  const subject = clientSubject(r);
  const t = r.targets.find((x) => x.id.toLowerCase() !== subject.id.toLowerCase()) ?? r.targets[0];
  const resourceId = propText(r, "DelegatedPermissionGrant.ResourceId") || t?.id || "";
  const { appId, api } = apiOf(r, resourceId, resolve);
  const resource = {
    id: resourceId,
    name: (t?.name ?? "").slice(0, NAME_MAX),
    appId,
    api,
  };
  const consentType = propText(r, "DelegatedPermissionGrant.ConsentType");
  const principalId = propText(r, "DelegatedPermissionGrant.PrincipalId") || targetOf(r, "User")?.id || "";
  const consent = {
    admin: bool(propOf(r, "ConsentContext.IsAdminConsent")?.newValue),
    allUsers: /^allprincipals$/i.test(consentType) ? true : /^principal$/i.test(consentType) ? false : null,
    principalId,
    entryId: propText(r, "DelegatedPermissionGrant.Id"),
  };
  const grantId =
    consent.entryId ||
    (consent.allUsers === false && !principalId
      ? `raw:${propOf(r, "DelegatedPermissionGrant.Scope")?.rawDigest}`
      : "");
  return scopes.map((scope) =>
    permissionChange(r, {
      kind: removal ? "delegated-permission-removed" : "delegated-permission-granted",
      value: scope,
      delegated: true,
      subject,
      resource,
      consent,
      atomic: `scope:${scope}:${consentType}:${principalId}:${grantId}`,
    }),
  );
}

function consentChanges(r: EntraAuditRecord, resolve?: Resolver): EntraAppChange[] {
  const p = propOf(r, "ConsentAction.Permissions");
  const entries = parseConsentPermissions(p?.newValue);
  if (!entries.length) return [];
  const subject = spSubject(r);
  const admin = bool(propOf(r, "ConsentContext.IsAdminConsent")?.newValue);
  const appOnly = bool(propOf(r, "ConsentContext.IsAppOnly")?.newValue) === true;
  const behalfOfAll = bool(propOf(r, "ConsentContext.OnBehalfOfAll")?.newValue);
  return entries.flatMap((e) => {
    const { appId, api } = apiOf(r, e.resourceId, resolve);
    const allUsers = /^allprincipals$/i.test(e.consentType)
      ? true
      : /^principal$/i.test(e.consentType)
        ? false
        : behalfOfAll;
    const consent = { admin, allUsers, principalId: e.principalId, entryId: e.id };
    const grantId = e.id || (allUsers === false && !e.principalId ? `raw:${p?.rawDigest}` : "");
    const resource = { id: e.resourceId, name: "", appId, api };
    return e.scopes.map((scope) =>
      permissionChange(r, {
        kind: appOnly ? "app-permission-granted" : "delegated-permission-granted",
        value: scope,
        delegated: !appOnly,
        subject,
        resource,
        consent,
        atomic: `scope:${scope}:${e.consentType}:${e.principalId}:${grantId}`,
      }),
    );
  });
}

// ───────────────────────────── roles and owners ─────────────────────────────

function roleChanges(r: EntraAuditRecord, removal: boolean): EntraAppChange[] {
  const name = propText(r, "Role.DisplayName");
  const templateId = propText(r, "Role.TemplateId");
  const objectId = propText(r, "Role.ObjectID") || propText(r, "Role.ObjectId");
  if (!name && !templateId && !objectId) return [];
  const member = targetOf(r, "User", "ServicePrincipal", "Group", "Application") ?? r.targets[0];
  const known = templateId ? roleTier(templateId) : null;
  const tier: RoleTier = known?.tier ?? "other";
  const roleName = (name || known?.name || short(objectId)).slice(0, NAME_MAX);
  const op = r.operation.toLowerCase();
  const eligible = /eligible/.test(op);
  const activation = /activation/.test(op);
  const memberType = member?.type || "principal";
  const memberWord = /serviceprincipal/i.test(memberType)
    ? "service principal"
    : /application/i.test(memberType)
      ? "application"
      : /group/i.test(memberType)
        ? "group"
        : "user";
  const subject = { id: member?.id ?? "", name: label(member), appId: "", type: memberType };
  const roleAtomic =
    objectId ||
    templateId ||
    `raw:${digest(
      r.props
        .filter((p) => /^role\./i.test(p.name))
        .map((p) => `${p.name}=${text(p.newValue)}`)
        .join("|"),
    )}`;
  const severity: Severity = tier === "tier-0" ? "High" : tier === "admin" ? "Medium" : "Medium";
  const verbBase = removal
    ? "removes directory role"
    : eligible
      ? "assigns eligible directory role"
      : activation
        ? "activates directory role"
        : "assigns directory role";
  const infinitive = removal
    ? "remove directory role"
    : eligible
      ? "assign eligible directory role"
      : activation
        ? "activate directory role"
        : "assign directory role";
  return [
    build({
      r,
      kind: removal ? "role-removed" : "role-assigned",
      verb: `${verbBase} ${roleName}`,
      infinitive: `${infinitive} ${roleName}`,
      detail: `${removal ? "from" : "to"} ${memberWord} ${subject.name}${activation ? " (PIM activation)" : ""}`,
      subject,
      resource: { id: "", name: "", appId: "", api: "" },
      atomic: `role:${roleAtomic}`,
      severity,
      mitre: ["T1098.003"],
      qualifiers: removal ? [] : [NOT_OBSERVED],
      words:
        tier === "tier-0" ? "can take over the tenant" : tier === "admin" ? "administers one service" : "",
      role: {
        name: roleName,
        templateId,
        objectId,
        tier,
        eligible,
        activation,
        memberType,
        memberId: subject.id,
        memberName: subject.name,
      },
      selfGrant: isSelf(r, subject),
    }),
  ];
}

function ownerChanges(r: EntraAuditRecord, removal: boolean): EntraAppChange[] {
  const owner = targetOf(r, "User");
  const app = targetOf(r, "ServicePrincipal", "Application");
  if (!owner || !app) return [];
  const subject = { id: app.id, name: label(app), appId: "", type: app.type };
  const appWord = /application/i.test(app.type) ? "application" : "service principal";
  return [
    build({
      r,
      kind: removal ? "owner-removed" : "owner-added",
      verb: `${removal ? "removes" : "adds"} owner ${label(owner)}`,
      infinitive: `${removal ? "remove" : "add"} owner ${label(owner)}`,
      detail: `${removal ? "from" : "to"} ${appWord} ${subject.name}`,
      subject,
      resource: { id: "", name: "", appId: "", api: "" },
      atomic: `owner:${owner.id || owner.upn}`,
      severity: "Medium",
      mitre: ["T1098.001"],
      qualifiers: [],
      words: "",
    }),
  ];
}

/** Every atomic change one Entra audit record establishes; empty when its operation is not decoded. */
export function decodeEntraAppChanges(r: EntraAuditRecord, resolve?: Resolver): EntraAppChange[] {
  const op = r.operation.toLowerCase();
  if (
    /^(add|update) (service principal credentials|application - certificates and secrets management|application certificates and secrets management)$/.test(
      op,
    )
  )
    return credentialChanges(r, false);
  if (
    /^remove (service principal credentials|application - certificates and secrets management|application certificates and secrets management)$/.test(
      op,
    )
  )
    return credentialChanges(r, true);
  if (op === "add app role assignment to service principal") return appRoleChanges(r, false, resolve);
  if (op === "remove app role assignment from service principal") return appRoleChanges(r, true, resolve);
  if (op === "add delegated permission grant") return delegatedGrantChanges(r, false, resolve);
  if (op === "remove delegated permission grant") return delegatedGrantChanges(r, true, resolve);
  if (op === "consent to application") return consentChanges(r, resolve);
  if (/^add (eligible )?member to role/.test(op)) return roleChanges(r, false);
  if (/^remove (eligible )?member from role/.test(op)) return roleChanges(r, true);
  if (/^add owner to (application|service principal)$/.test(op)) return ownerChanges(r, false);
  if (/^remove owner from (application|service principal)$/.test(op)) return ownerChanges(r, true);
  return [];
}
