// The Entra application privilege path — credential added → privileged capability granted →
// successful sign-in with the matched credential → an action consistent with the grant — built
// inside one export, over the records the importer read, before aggregation and caps
// (#931 item 1, second half — #973).
//
// A sign-in row is Info or Low and leaves the forensic timeline at the import seam, so a merge-
// time pass would see it only by accident of import order; the chain is therefore built here,
// where every record of the export is in hand, and emitted as one summary row per application
// that survives the cut. Cross-export chains stay open on #973.
//
// What the finding establishes: that these records, joined only through the application's
// immutable app id (an object id links to it only through a record of the same export that
// states both — a sign-in, a consent property), happened in this order, inside a window, with
// this credential key matched exactly, and that an action's operation is CONSISTENT with a
// permission granted before it. It does not establish that the credential "enabled" anything,
// that the action used the new grant (the authorization a token carried is not in the record),
// that a failed sign-in was a use, that an eligible role was active, or that a delegated scope
// served an app-credential sign-in. Absence is said against the export's own record counts.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { EntraPathBlock, EntraPathStep } from "./canonicalEntra.js";
import { decodeEntraAppChanges, type EntraAppChange, type Resolver } from "./entraAppChange.js";
import { isGuid, readEntraAuditRecord, type EntraAuditRecord } from "./entraAuditRecord.js";
import type { CapabilityClass, RoleTier } from "./entraCapabilities.js";
import { isServicePrincipalSignIn, readSpSignIn, type SpSignIn } from "./entraAuditImport.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { normalizeTime, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

/** An episode opens at a credential-added step and closes this many days later. */
export const PRIVILEGE_PATH_WINDOW_DAYS = 30;
/** Findings emitted per import, by grade, completeness, recency, then app id; the rest counted. */
export const PRIVILEGE_PATHS_MAX = 256;
const STEPS_NAMED_MAX = 8;
const NAME_MAX = 60;
const DESCRIPTION_MAX = 900;
const WINDOW_MS = PRIVILEGE_PATH_WINDOW_DAYS * 86_400_000;

/** The capability classes that control the tenant — a grant of one is the privileged step. */
export const PRIVILEGED_CLASSES: ReadonlySet<CapabilityClass> = new Set<CapabilityClass>([
  "app-role grant management",
  "delegated-grant management",
  "credential management",
  "directory RBAC",
  "identity takeover",
]);
const PRIVILEGED_TIERS: ReadonlySet<RoleTier> = new Set<RoleTier>(["tier-0", "admin"]);

/**
 * The Microsoft Graph application permissions that SUFFICE for an operation, as sets — an
 * operation with several sufficient permissions lists them all; one this table does not name is
 * unmapped. A directory role of tier-0 also suffices for any directory operation.
 */
export const OPERATION_PERMISSIONS: ReadonlyMap<string, readonly string[]> = new Map([
  ["add member to role", ["RoleManagement.ReadWrite.Directory"]],
  ["add eligible member to role", ["RoleManagement.ReadWrite.Directory"]],
  ["add app role assignment to service principal", ["AppRoleAssignment.ReadWrite.All"]],
  ["add delegated permission grant", ["DelegatedPermissionGrant.ReadWrite.All"]],
  ["add service principal credentials", ["Application.ReadWrite.All", "Application.ReadWrite.OwnedBy"]],
  [
    "update application - certificates and secrets management",
    ["Application.ReadWrite.All", "Application.ReadWrite.OwnedBy"],
  ],
  ["add owner to application", ["Application.ReadWrite.All", "Application.ReadWrite.OwnedBy"]],
  ["add owner to service principal", ["Application.ReadWrite.All", "Application.ReadWrite.OwnedBy"]],
  ["add user", ["User.ReadWrite.All"]],
  ["update user", ["User.ReadWrite.All"]],
  ["reset user password", ["User.ReadWrite.All", "User-PasswordProfile.ReadWrite.All"]],
  ["change user password", ["User.ReadWrite.All", "User-PasswordProfile.ReadWrite.All"]],
]);

// ───────────────────────────── readings ─────────────────────────────

const show = (v: string, max = NAME_MAX): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
const shortId = (id: string): string => (id.length > 8 ? `${id.slice(0, 8)}…` : id);
const ms = (iso: string): number | null => {
  const t = Date.parse(normalizeTime(iso));
  return Number.isFinite(t) ? t : null;
};
const lower = (s: string): string => s.trim().toLowerCase();

interface Step {
  kind:
    | "credential"
    | "credential-removed"
    | "grant"
    | "grant-removed"
    | "role"
    | "role-removed"
    | "sign-in"
    | "action"
    | "excluded";
  time: number | null;
  observed: string;
  locator: string;
  initiator: string;
  initiatorIsApp: boolean;
  words: string;
  /** credential steps */
  keyId?: string;
  /** grant / role steps */
  permission?: string;
  privileged?: boolean;
  /** sign-in steps */
  matched?: boolean;
  success?: boolean;
  /** action steps */
  operation?: string;
}

interface Chain {
  tenant: string;
  appId: string;
  name: string;
  steps: Step[];
  /** Records that named this application by an id no record of the export links to an app id. */
  unlinked: number;
}

// ───────────────────────────── identity ─────────────────────────────

/**
 * (tenant, object id) → app id, learned only from records that STATE both: a sign-in
 * (servicePrincipalId + appId), a consent property (ServicePrincipal.ObjectID + .AppId), an
 * `AppId` property on a record whose target is the application. A conflict unlearns the id.
 */
export function learnSubjectResolver(records: readonly Row[]): Resolver {
  const map = new Map<string, string>();
  const conflicts = new Set<string>();
  const learn = (tenant: string, objectId: string, appId: string) => {
    if (!isGuid(objectId) || !appId.trim()) return;
    const k = `${lower(tenant)}|${lower(objectId)}`;
    const prev = map.get(k);
    if (prev && prev !== lower(appId)) conflicts.add(k);
    else map.set(k, lower(appId));
  };
  for (const rec of records) {
    if (isServicePrincipalSignIn(rec)) {
      const s = readSpSignIn(rec);
      learn(s.tenant, s.spId, s.appId);
      continue;
    }
    const audit = readEntraAuditRecord(rec);
    if (!audit) continue;
    const prop = (name: string) => audit.props.find((p) => p.name.toLowerCase() === name.toLowerCase());
    const objectId = prop("ServicePrincipal.ObjectID");
    const propAppId = prop("ServicePrincipal.AppId") ?? prop("Application.AppId") ?? prop("AppId");
    if (objectId && propAppId)
      learn(audit.tenant, String(objectId.newValue ?? ""), String(propAppId.newValue ?? ""));
    else if (propAppId) {
      const target = audit.targets.find((t) => /serviceprincipal|application/i.test(t.type));
      if (target?.id) learn(audit.tenant, target.id, String(propAppId.newValue ?? ""));
    }
  }
  return (objectId, tenant) => {
    const k = `${lower(tenant)}|${lower(objectId)}`;
    return conflicts.has(k) ? "" : (map.get(k) ?? "");
  };
}

// ───────────────────────────── steps ─────────────────────────────

const initiatorWords = (r: EntraAuditRecord): { words: string; isApp: boolean } => {
  const who = r.initiator.upn || r.initiator.name || r.initiator.id || r.initiator.appId;
  const isApp = r.initiator.kind === "app";
  return {
    words: `${show(who || "initiator not in the record")}${isApp ? " (an application, not a user)" : ""}`,
    isApp,
  };
};

function changeStep(r: EntraAuditRecord, c: EntraAppChange, index: number): Step | null {
  const { words: by, isApp } = initiatorWords(r);
  const base = {
    time: ms(r.time),
    observed: r.time,
    locator: `record:${index}`,
    initiator: by,
    initiatorIsApp: isApp,
  };
  if (c.attempted)
    return {
      ...base,
      kind: "excluded",
      words: `attempted ${c.kind.replace(/-/g, " ")} — failed, not a step`,
    };
  if (c.kind === "credential-added" && c.credential)
    return {
      ...base,
      kind: "credential",
      keyId: lower(c.credential.keyId),
      words: `credential added by ${by}: ${show(c.credential.keyType || "credential", 20)} ${shortId(c.credential.keyId)}${c.credential.displayName ? ` "${show(c.credential.displayName, 30)}"` : ""}`,
    };
  if (c.kind === "credential-removed" && c.credential)
    return {
      ...base,
      kind: "credential-removed",
      keyId: lower(c.credential.keyId),
      words: `credential ${shortId(c.credential.keyId)} removed by ${by}`,
    };
  if (c.kind === "delegated-permission-granted" && c.capability)
    return {
      ...base,
      kind: "excluded",
      words: `delegated permission ${show(c.capability.value, 60)} granted — needs a signed-in user; not part of this path`,
    };
  if (c.kind === "app-permission-granted" && c.capability) {
    const privileged = c.capability.class !== "" && PRIVILEGED_CLASSES.has(c.capability.class);
    return {
      ...base,
      kind: "grant",
      permission: lower(c.capability.value),
      privileged,
      words: `${privileged ? "privileged capability" : "capability"} granted by ${by}: application permission ${show(c.capability.value, 60)}${c.resource.api ? ` on ${show(c.resource.api, 40)}` : ""}${c.capability.class ? ` (${c.capability.class})` : " (class not identified)"}${c.consent?.admin ? ", admin consent" : ""}`,
    };
  }
  if (c.kind === "app-permission-removed" && c.capability)
    return {
      ...base,
      kind: "grant-removed",
      permission: lower(c.capability.value),
      words: `permission ${show(c.capability.value, 60)} removed by ${by}`,
    };
  if (c.kind === "role-assigned" && c.role) {
    if (c.role.eligible && !c.role.activation)
      return {
        ...base,
        kind: "excluded",
        words: `directory role ${show(c.role.name)} assigned as eligible — not activated; not a grant step`,
      };
    const privileged = PRIVILEGED_TIERS.has(c.role.tier);
    return {
      ...base,
      kind: "role",
      permission: `role:${lower(c.role.templateId || c.role.name)}`,
      privileged,
      words: `${privileged ? "privileged directory role" : "directory role"} assigned by ${by}: ${show(c.role.name)}${c.role.tier === "tier-0" ? " (can take over the tenant)" : ""}`,
    };
  }
  if (c.kind === "role-removed" && c.role)
    return {
      ...base,
      kind: "role-removed",
      permission: `role:${lower(c.role.templateId || c.role.name)}`,
      words: `directory role ${show(c.role.name)} removed by ${by}`,
    };
  return null;
}

function signInStep(s: SpSignIn, index: number, keys: ReadonlySet<string>): Step {
  const matched = !!s.credKey && keys.has(lower(s.credKey));
  const success = s.outcome === "success";
  const cred = s.credType
    ? `${show(s.credType, 20)}${s.credKey ? ` ${shortId(s.credKey)}` : ""}`
    : "credential not in the record";
  const words = success
    ? matched
      ? `signed in${s.resourceName ? ` → ${show(s.resourceName, 40)}` : ""} with the new credential (${cred})`
      : `signed in${s.resourceName ? ` → ${show(s.resourceName, 40)}` : ""} with an unmatched credential (${cred})`
    : matched
      ? `attempted sign-in with the new credential (${cred}) — ${s.rejected ? `rejected: ${s.rejected}` : s.outcome === "failure" ? `failed (AADSTS${s.code})` : "outcome unknown"}; not a use`
      : `sign-in attempt${s.rejected ? ` rejected: ${s.rejected}` : ""} — not counted`;
  return {
    kind: "sign-in",
    time: ms(s.observed),
    observed: s.observed,
    locator: `record:${index}`,
    initiator: "",
    initiatorIsApp: true,
    matched,
    success,
    words,
  };
}

function actionStep(r: EntraAuditRecord, index: number, granted: ReadonlySet<string>, tier0: boolean): Step {
  const sufficient = OPERATION_PERMISSIONS.get(lower(r.operation));
  const consistent = sufficient?.find((p) => granted.has(lower(p)));
  const words = !sufficient
    ? `acted: ${show(r.operation, 60)} — the action's required permission was not mapped`
    : tier0
      ? `acted: ${show(r.operation, 60)} — consistent with the tier-0 directory role granted; the authorization the token carried is not in the record`
      : consistent
        ? `acted: ${show(r.operation, 60)} — consistent with the granted ${consistent}; the authorization the token carried is not in the record`
        : `acted: ${show(r.operation, 60)} — needs ${sufficient.join(" or ")}, not among the granted`;
  return {
    kind: "action",
    time: ms(r.time),
    observed: r.time,
    locator: `record:${index}`,
    initiator: "",
    initiatorIsApp: true,
    operation: r.operation,
    matched: !!(sufficient && (consistent || tier0)),
    words,
  };
}

// ───────────────────────────── episodes ─────────────────────────────

interface Episode {
  credential: Step;
  grants: Step[];
  signIns: Step[];
  actions: Step[];
  outside: Step[];
  removed: Step[];
  grade: Severity | null;
  stages: number;
}

function episodesOf(chain: Chain): Episode[] {
  const sorted = [...chain.steps].sort(
    (a, b) => (a.time ?? Infinity) - (b.time ?? Infinity) || a.locator.localeCompare(b.locator),
  );
  const out: Episode[] = [];
  for (const cred of sorted.filter((s) => s.kind === "credential" && s.time !== null)) {
    const open = cred.time!;
    const close = open + WINDOW_MS;
    const inWindow = (s: Step) => s.time !== null && s.time >= open && s.time <= close;
    const later = sorted.filter((s) => s !== cred && s.time !== null && s.time >= open);
    const outside = later.filter((s) => !inWindow(s) && s.kind !== "excluded");
    const within = later.filter(inWindow);
    // Effective intervals: a grant or role revoked, or the credential removed, before a later step
    // ends it — the later step then does not count.
    const removedAt = (kind: Step["kind"], key: string | undefined): number | null => {
      const r = within.find((s) => s.kind === kind && (s.keyId ?? s.permission) === key);
      return r?.time ?? null;
    };
    const credEnd = removedAt("credential-removed", cred.keyId);
    // Every grant is a stage; only a PRIVILEGED one can carry the path to High.
    const grants = within.filter((s) => s.kind === "grant" || s.kind === "role");
    const privileged = grants.some((g) => g.privileged);
    const live = (s: Step, end: number | null) => end === null || (s.time !== null && s.time < end);
    const grantEnds = new Map(
      grants.map((g) => [g, removedAt(g.kind === "grant" ? "grant-removed" : "role-removed", g.permission)]),
    );
    const granted = new Set(grants.map((g) => g.permission!));
    const tier0 = grants.some((g) => g.kind === "role" && g.words.includes("can take over the tenant"));
    const signIns = within.filter((s) => s.kind === "sign-in" && s.matched && s.success && live(s, credEnd));
    const actions = within
      .filter(
        (s) =>
          s.kind === "action" &&
          s.time !== null &&
          grants.some((g) => g.time !== null && s.time! >= g.time && live(s, grantEnds.get(g) ?? null)),
      )
      .map((s) => ({ ...s, ...(s.operation ? refreshAction(s, granted, tier0) : {}) }));
    const removed = within.filter(
      (s) => s.kind === "credential-removed" || s.kind === "grant-removed" || s.kind === "role-removed",
    );
    const stages =
      1 + (grants.length ? 1 : 0) + (signIns.length ? 1 : 0) + (actions.some((a) => a.matched) ? 1 : 0);
    const grade: Severity | null =
      stages >= 4 && privileged ? "High" : stages >= 3 ? "Medium" : stages === 2 ? "Low" : null;
    out.push({ credential: cred, grants, signIns, actions, outside, removed, grade, stages });
  }
  return out;
}

/** An action's words against the grants of THIS episode (the same operation can be consistent in one episode and not another). */
function refreshAction(
  s: Step,
  granted: ReadonlySet<string>,
  tier0: boolean,
): Pick<Step, "words" | "matched"> {
  const sufficient = OPERATION_PERMISSIONS.get(lower(s.operation ?? ""));
  const consistent = sufficient?.find((p) => granted.has(lower(p)));
  const op = show(s.operation ?? "", 60);
  if (!sufficient)
    return { words: `acted: ${op} — the action's required permission was not mapped`, matched: false };
  if (tier0)
    return {
      words: `acted: ${op} — consistent with the tier-0 directory role granted; the authorization the token carried is not in the record`,
      matched: true,
    };
  if (consistent)
    return {
      words: `acted: ${op} — consistent with the granted ${consistent}; the authorization the token carried is not in the record`,
      matched: true,
    };
  return { words: `acted: ${op} — needs ${sufficient.join(" or ")}, not among the granted`, matched: false };
}

const RANK: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

// ───────────────────────────── the pass ─────────────────────────────

export interface ExportCoverage {
  tenant: string;
  signIns: { records: number; first: string; last: string } | null;
  audits: { records: number; first: string; last: string } | null;
}

/** One summary row per application whose export records form a path; the rows say what they rest on. */
export function entraPrivilegePaths(records: readonly Row[], resolve: Resolver): MappedEvent[] {
  const subjectOf = learnSubjectResolver(records);
  const chains = new Map<string, Chain>();
  const coverage = new Map<string, ExportCoverage>();
  const cover = (tenant: string, kind: "signIns" | "audits", time: string) => {
    const c =
      coverage.get(lower(tenant)) ??
      coverage.set(lower(tenant), { tenant, signIns: null, audits: null }).get(lower(tenant))!;
    const t = normalizeTime(time);
    const cur = c[kind] ?? { records: 0, first: t, last: t };
    c[kind] = {
      records: cur.records + 1,
      first: t && (!cur.first || t < cur.first) ? t : cur.first,
      last: t && (!cur.last || t > cur.last) ? t : cur.last,
    };
  };
  const chainOf = (tenant: string, appId: string, name: string): Chain => {
    const k = `${lower(tenant)}|${lower(appId)}`;
    const c =
      chains.get(k) ?? chains.set(k, { tenant, appId: lower(appId), name, steps: [], unlinked: 0 }).get(k)!;
    if (!c.name && name) c.name = name;
    return c;
  };
  const appOf = (tenant: string, objectId: string, appId: string): string =>
    appId.trim() ? lower(appId) : isGuid(objectId) ? subjectOf(objectId, tenant) : "";

  // First pass: every change, by the application it is ABOUT; every sign-in; every app-initiated action.
  const signIns: { s: SpSignIn; index: number }[] = [];
  const actions: { r: EntraAuditRecord; index: number; appId: string }[] = [];
  let unlinked = 0;
  records.forEach((rec, index) => {
    if (isServicePrincipalSignIn(rec)) {
      const s = readSpSignIn(rec);
      cover(s.tenant, "signIns", s.observed);
      signIns.push({ s, index });
      return;
    }
    const r = readEntraAuditRecord(rec);
    if (!r) return;
    cover(r.tenant, "audits", r.time);
    for (const c of decodeEntraAppChanges(r, resolve)) {
      // A change ABOUT an application: its subject is a service principal or an application. A
      // role given to a user by an application is that application's action (below), not a change to it.
      if (!/serviceprincipal|application/i.test(c.subject.type)) continue;
      const appId = appOf(r.tenant, c.subject.id, c.subject.appId);
      if (!appId) {
        unlinked += 1;
        continue;
      }
      const step = changeStep(r, c, index);
      if (step) chainOf(r.tenant, appId, c.subject.name).steps.push(step);
    }
    if (r.initiator.kind === "app") {
      const appId = appOf(r.tenant, r.initiator.id, r.initiator.appId);
      if (appId) actions.push({ r, index, appId });
    }
  });
  for (const { s, index } of signIns) {
    const appId = appOf(s.tenant, s.spId, s.appId);
    if (!appId) continue;
    const c = chains.get(`${lower(s.tenant)}|${appId}`);
    if (!c) continue;
    c.steps.push(
      signInStep(
        s,
        index,
        new Set(c.steps.filter((x) => x.kind === "credential" && x.keyId).map((x) => x.keyId!)),
      ),
    );
  }
  for (const { r, index, appId } of actions) {
    const c = chains.get(`${lower(r.tenant)}|${appId}`);
    if (!c) continue;
    c.steps.push(actionStep(r, index, new Set(), false));
  }

  // Episodes, the best per application, ranked, bounded.
  const findings = [...chains.values()]
    .map((chain) => {
      const episodes = episodesOf(chain).filter((e) => e.grade !== null);
      if (!episodes.length) return null;
      episodes.sort(
        (a, b) =>
          RANK[b.grade!] - RANK[a.grade!] ||
          b.stages - a.stages ||
          (b.credential.time ?? 0) - (a.credential.time ?? 0),
      );
      return { chain, best: episodes[0], others: episodes.slice(1) };
    })
    .filter((f): f is NonNullable<typeof f> => f !== null)
    .sort(
      (a, b) =>
        RANK[b.best.grade!] - RANK[a.best.grade!] ||
        b.best.stages - a.best.stages ||
        (b.best.credential.time ?? 0) - (a.best.credential.time ?? 0) ||
        a.chain.appId.localeCompare(b.chain.appId),
    );
  const rows = findings
    .slice(0, PRIVILEGE_PATHS_MAX)
    .map((f) => summaryRow(f.chain, f.best, f.others, coverage.get(lower(f.chain.tenant))));
  if (findings.length > PRIVILEGE_PATHS_MAX) rows.push(omittedRow(findings.length - PRIVILEGE_PATHS_MAX));
  return rows.map((row) =>
    unlinked
      ? {
          ...row,
          description: row.description
            .replace(
              /\]$/,
              `; ${unlinked} change${unlinked === 1 ? "" : "s"} named an application by an id no record of this export links to an app id — not joined]`,
            )
            .slice(0, DESCRIPTION_MAX),
        }
      : row,
  );
}

function summaryRow(
  chain: Chain,
  e: Episode,
  others: Episode[],
  coverage: ExportCoverage | undefined,
): MappedEvent {
  const iso = (t: number | null) => (t === null ? "time not readable" : new Date(t).toISOString());
  const stepWords = (s: Step) => `${iso(s.time)} ${s.words}`;
  const named = (steps: Step[], label: string): string[] => {
    const shown = steps.slice(0, STEPS_NAMED_MAX).map(stepWords);
    const more = steps.length > STEPS_NAMED_MAX ? [`+${steps.length - STEPS_NAMED_MAX} more ${label}`] : [];
    return [...shown, ...more];
  };
  const absence = (kind: "signIns" | "audits", what: string): string => {
    const c = coverage?.[kind];
    return c
      ? `no ${what} by this application among the ${c.records} ${kind === "signIns" ? "sign-in" : "directory-audit"} records of this export (${c.first.slice(0, 10)} → ${c.last.slice(0, 10)})`
      : `${kind === "signIns" ? "sign-in" : "directory-audit"} log not in this export`;
  };
  const parts = [
    stepWords(e.credential),
    ...(e.grants.length ? named(e.grants, "grants") : ["no capability granted inside the window"]),
    ...(e.grants.length && !e.grants.some((g) => g.privileged)
      ? ["no privileged capability granted inside the window"]
      : []),
    ...(e.signIns.length
      ? named(e.signIns, "sign-ins")
      : [absence("signIns", "successful sign-in with the new credential")]),
    ...(e.actions.length ? named(e.actions, "actions") : [absence("audits", "directory change")]),
    ...(e.removed.length ? named(e.removed, "removals") : []),
    ...(e.outside.length
      ? [`outside the ${PRIVILEGE_PATH_WINDOW_DAYS}-day window: ${named(e.outside, "steps").join("; ")}`]
      : []),
    ...(others.length
      ? [
          `${others.length} other episode${others.length === 1 ? "" : "s"}: ${others.map((o) => o.grade).join(", ")}`,
        ]
      : []),
    e.stages >= 4
      ? e.grade === "High"
        ? "all four stages in order"
        : "all four stages in order; the capability granted is not a tenant-control one"
      : e.stages === 3
        ? "three of four stages"
        : "two of four stages",
  ];
  const head = `Entra privilege path: ${show(chain.name || "(unnamed application)")} (app id ${chain.appId})`;
  const body = `${head} [${parts.join("; ")}]`;
  const description = body.length > DESCRIPTION_MAX ? `${body.slice(0, DESCRIPTION_MAX - 2)}…]` : body;
  const identity = createHash("sha256")
    .update(`${chain.tenant.length}:${chain.tenant}|${chain.appId.length}:${chain.appId}`)
    .digest("hex")
    .slice(0, 32);
  const steps: EntraPathStep[] = [e.credential, ...e.grants, ...e.signIns, ...e.actions]
    .slice(0, 4 * STEPS_NAMED_MAX)
    .map((s) => ({
      stage:
        s.kind === "credential"
          ? "credential"
          : s.kind === "grant" || s.kind === "role"
            ? "grant"
            : s.kind === "sign-in"
              ? "sign-in"
              : "action",
      time: s.observed,
      locator: s.locator,
      ...(s.keyId ? { keyId: s.keyId } : {}),
      ...(s.permission ? { permission: s.permission } : {}),
      ...(s.matched !== undefined ? { matched: s.matched } : {}),
      ...(s.initiatorIsApp ? { initiatorIsApp: true } : {}),
    }));
  const block: EntraPathBlock = {
    appId: chain.appId,
    ...(chain.tenant ? { tenant: chain.tenant } : {}),
    windowDays: PRIVILEGE_PATH_WINDOW_DAYS,
    stages: e.stages,
    steps,
    outsideWindow: e.outside.length,
    otherEpisodes: others.length,
    coverage: {
      ...(coverage?.signIns ? { signIns: coverage.signIns } : {}),
      ...(coverage?.audits ? { audits: coverage.audits } : {}),
    },
    basis: "records of this export only; joined through the application id; consistency, not authorization",
  };
  const mitre = [
    ...(e.stages >= 1 ? ["T1098.001"] : []),
    ...(e.grants.some((g) => g.kind === "role") ? ["T1098.003"] : []),
  ];
  const observed = e.credential.observed;
  return {
    timestamp: normalizeTime(observed),
    description,
    severity: e.grade!,
    mitre,
    aggKey: boundedAggKey(`entra-privilege-path|${identity}`),
    sources: ["Entra ID"],
    canonical: createCanonicalEvent({
      event: {
        category: "cloud",
        type: "privilege-path",
        action: "application",
        outcome: e.stages >= 4 ? "complete" : "partial",
      },
      actor: { kind: "cloud_principal", id: chain.appId, ...(chain.name ? { name: chain.name } : {}) },
      cloud: {
        provider: "entra",
        ...(chain.tenant ? { tenant: chain.tenant } : {}),
        principalId: chain.appId,
        principalType: "application",
      },
      entra: block,
      time: { observed, normalized: normalizeTime(observed) },
      evidence: {
        rawRecords: [...new Set(steps.map((s) => s.locator))]
          .slice(0, STEPS_NAMED_MAX)
          .map((locator) => ({ source: "entra-export", locator })),
      },
      producer: { importer: "m365-audit", parserVersion: "1", mappingVersion: "entra-privilege-path-v1" },
    }),
  };
}

function omittedRow(count: number): MappedEvent {
  const description = `Entra privilege path: ${count} further application${count === 1 ? "" : "s"} with a path in this export beyond the ${PRIVILEGE_PATHS_MAX} reported — not shown`;
  return {
    timestamp: "",
    description,
    severity: "Low",
    mitre: [],
    aggKey: boundedAggKey(`entra-privilege-path|omitted|${count}`),
    sources: ["Entra ID"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "privilege-path", action: "omitted" },
      cloud: { provider: "entra" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "entra-export", locator: "omitted" }] },
      producer: { importer: "m365-audit", parserVersion: "1", mappingVersion: "entra-privilege-path-v1" },
    }),
  };
}
