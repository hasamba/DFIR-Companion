// GCP Cloud Audit Log identity (#931 item 12, record half): who acted as the record states it —
// the principal typed only by a documented service-account address (a user, a group and an
// opaque subject are never guessed at), the subject verbatim, the key the credentials derived
// from (never the key holder), the delegation chain whole and in order (never "impersonated
// by"), and the log's and the resource's projects typed by namespace and kind (an id and a
// number are never compared). Shared by every GCP row the importer emits.

import type { GcpDelegation, GcpPrincipal, GcpProjectRef } from "./canonicalGcp.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { getCI, getPath, isObject, str } from "./siemImport.js";

type Row = Record<string, unknown>;

export const FIELD_MAX = 200;
const DELEGATION_MAX = 8;
const FORMAT_CHARS = /[\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;

/** Neutralised for display: brackets, controls, format and bidi characters gone, bounded. */
export const show = (v: string, max = FIELD_MAX): string => {
  const shown = breakHashRuns(showToken(v.replace(FORMAT_CHARS, "")));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
/** An identifier shown whole (a key id, a unique id): neutralised and bounded, hex runs kept. */
export const showId = (v: string, max = FIELD_MAX): string => {
  const shown = showToken(v.replace(FORMAT_CHARS, ""));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
export const lower = (s: string): string => s.trim().toLowerCase();
export const seg = (v: string): string => `${v.length}:${v}`;
export const field = (o: unknown, ...keys: string[]): string => {
  let cur: unknown = o;
  for (const k of keys) cur = isObject(cur) ? getCI(cur, k) : undefined;
  return str(cur).trim();
};
export const strings = (v: unknown, max = 8): string[] =>
  (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v])
    .map((x) => str(x).trim())
    .filter(Boolean)
    .slice(0, max);

// ───────────────────────────── the principal ─────────────────────────────

const PROJECT_ID = /^[a-z][a-z0-9-]{2,28}[a-z0-9]$/;
const PROJECT_NUMBER = /^\d{6,}$/;
/** A documented user-managed service-account address: `name@<project-id>.iam.gserviceaccount.com`. */
const USER_MANAGED_SA = /^[a-z0-9-]+@([a-z][a-z0-9-]{2,28}[a-z0-9])\.iam\.gserviceaccount\.com$/;
/** The Compute Engine default: `<project-number>-compute@developer.gserviceaccount.com`. */
const COMPUTE_DEFAULT_SA = /^(\d{6,})-compute@developer\.gserviceaccount\.com$/;
/** The App Engine default: `<project-id>@appspot.gserviceaccount.com`. */
const APPSPOT_SA = /^([a-z][a-z0-9-]{2,28}[a-z0-9])@appspot\.gserviceaccount\.com$/;
/** Google-managed service agents — the address does not carry a home project. */
const SERVICE_AGENT =
  /^(service-\d+@[a-z0-9-]+\.iam\.gserviceaccount\.com|\d+@cloudservices\.gserviceaccount\.com|[^@]+@gcp-sa-[a-z0-9-]+\.iam\.gserviceaccount\.com)$/;

export function principalOf(email: string): { kind: GcpPrincipal["kind"]; homeProject?: GcpProjectRef } {
  const e = lower(email);
  if (!e) return { kind: "none" };
  const userManaged = USER_MANAGED_SA.exec(e);
  if (userManaged && !/^service-\d+@/.test(e))
    return {
      kind: "service-account",
      homeProject: { namespace: "projects", kind: "id", value: userManaged[1] },
    };
  const compute = COMPUTE_DEFAULT_SA.exec(e);
  if (compute)
    return {
      kind: "service-account",
      homeProject: { namespace: "projects", kind: "number", value: compute[1] },
    };
  const appspot = APPSPOT_SA.exec(e);
  if (appspot)
    return { kind: "service-account", homeProject: { namespace: "projects", kind: "id", value: appspot[1] } };
  if (SERVICE_AGENT.test(e)) return { kind: "service-agent" };
  // A gserviceaccount.com address of a shape the table does not name is a service account whose
  // home project the address does not establish — never called a service agent.
  if (/gserviceaccount\.com$/.test(e)) return { kind: "service-account" };
  return { kind: "user-or-unknown" };
}

function subjectOf(subject: string): GcpPrincipal["subject"] | undefined {
  if (!subject) return undefined;
  const kind: NonNullable<GcpPrincipal["subject"]>["kind"] = subject.startsWith("principal://")
    ? "principal"
    : subject.startsWith("principalSet://")
      ? "principal-set"
      : subject.startsWith("serviceAccount:")
        ? "service-account"
        : subject.startsWith("user:")
          ? "user"
          : "opaque";
  return { value: subject, kind };
}

export function readPrincipal(pp: Row): GcpPrincipal {
  const email = field(pp, "authenticationInfo", "principalEmail");
  const subject = field(pp, "authenticationInfo", "principalSubject");
  const keyName = field(pp, "authenticationInfo", "serviceAccountKeyName");
  const userAgent = field(pp, "requestMetadata", "callerSuppliedUserAgent");
  const typed = principalOf(email);
  return {
    ...(email ? { email } : {}),
    kind: typed.kind,
    ...(typed.homeProject ? { homeProject: typed.homeProject } : {}),
    ...(subject ? { subject: subjectOf(subject) } : {}),
    ...(keyName ? { keyName } : {}),
    ...(userAgent ? { userAgent } : {}),
  };
}

export function readDelegation(pp: Row): GcpDelegation[] {
  const raw = getPath(pp, "authenticationInfo.serviceAccountDelegationInfo");
  if (!Array.isArray(raw)) return [];
  return raw
    .filter(isObject)
    .slice(0, DELEGATION_MAX)
    .map((entry): GcpDelegation => {
      const first = field(entry, "firstPartyPrincipal", "principalEmail");
      if (first) return { kind: "first-party", value: first };
      const subject = field(entry, "principalSubject");
      if (subject) return { kind: "subject", value: subject };
      return { kind: "third-party" };
    });
}

// ───────────────────────────── projects ─────────────────────────────

const NAMESPACES = new Set(["projects", "folders", "organizations", "billingAccounts"]);

/** `<namespace>/<id-or-number>` at the head of a resource or log name, with any `//service/` authority prefix skipped. */
export function projectRefOf(name: string): GcpProjectRef | undefined {
  const path = name.replace(/^\/\/[^/]+\//, "");
  const m = /^([a-zA-Z]+)\/([^/]+)/.exec(path);
  if (!m || !NAMESPACES.has(m[1])) return undefined;
  const value = m[2];
  if (value === "-" || value === "_") return undefined;
  if (PROJECT_NUMBER.test(value)) return { namespace: m[1], kind: "number", value };
  if (m[1] !== "projects" || PROJECT_ID.test(value)) return { namespace: m[1], kind: "id", value };
  return undefined;
}

export function readProjects(
  rec: Row,
  pp: Row,
): { log?: GcpProjectRef; resource?: GcpProjectRef; differ: boolean } {
  const log =
    projectRefOf(str(getCI(rec, "logName")).trim()) ??
    projectRefOf(`projects/${field(rec, "resource", "labels", "project_id")}`);
  const resource = projectRefOf(field(pp, "resourceName"));
  const differ =
    !!log &&
    !!resource &&
    log.namespace === "projects" &&
    resource.namespace === "projects" &&
    log.kind === resource.kind &&
    log.value !== resource.value;
  return { ...(log ? { log } : {}), ...(resource ? { resource } : {}), differ };
}

// ───────────────────────────── words ─────────────────────────────

const refWords = (r: GcpProjectRef): string =>
  `${r.namespace === "projects" ? "project" : r.namespace.replace(/s$/, "")} ${show(r.value, 40)}${r.namespace === "projects" ? ` (${r.kind === "id" ? "an id" : "a number"})` : ""}`;

/** The identity facts every GCP row appends, in fixed order — each bounded. */
export function identityWords(
  p: GcpPrincipal,
  delegation: readonly GcpDelegation[],
  projects: ReturnType<typeof readProjects>,
): string[] {
  const out: string[] = [];
  if (p.kind === "service-account")
    out.push(
      `service account (${p.homeProject ? `home project ${show(p.homeProject.value, 40)}, ${p.homeProject.kind === "id" ? "an id" : "a number"}` : "home project not derivable from the address"})`,
    );
  else if (p.kind === "service-agent")
    out.push("service agent (Google-managed; home project not derivable from the address)");
  if (p.subject)
    out.push(
      `subject ${show(p.subject.value, 160)} (${p.subject.kind === "principal" ? "a federated principal" : p.subject.kind === "principal-set" ? "a federated principal set" : p.subject.kind === "opaque" ? "opaque subject" : p.subject.kind})`,
    );
  if (p.keyName)
    out.push(
      `authenticated with credentials derived from key …/keys/${showId(p.keyName.slice(p.keyName.lastIndexOf("/") + 1), 60)}; this record does not identify the key holder`,
    );
  if (delegation.length)
    out.push(
      `delegation authority recorded as: ${delegation.map((d) => (d.kind === "third-party" ? "(third-party principal)" : show(d.value ?? "", 120))).join(" → ")}`,
    );
  else if (p.kind === "service-account" || p.kind === "service-agent")
    out.push("no delegation chain in this record");
  const log = projects.log ? `log ${refWords(projects.log)}` : "";
  const res = projects.resource ? `resource ${refWords(projects.resource)}` : "";
  if (projects.differ) out.push(`${log}; ${res} — the log's project and the resource's project differ`);
  else if (
    res &&
    projects.resource?.namespace === "projects" &&
    (!projects.log || projects.log.kind !== projects.resource.kind)
  )
    out.push(res);
  else if (log && projects.log?.namespace !== "projects") out.push(log);
  return out;
}
