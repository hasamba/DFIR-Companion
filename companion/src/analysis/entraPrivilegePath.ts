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
 * The Microsoft Graph application permissions that SUFFICE for an operation: alternatives, each a
 * conjunction (Graph's own contracts — an owner write needs Directory.Read.All beside the
 * application permission). An operation this table does not name is unmapped; a tier-0 directory
 * role suffices for any directory operation.
 */
export const OPERATION_PERMISSIONS: ReadonlyMap<string, readonly (readonly string[])[]> = new Map([
  ["add member to role", [["RoleManagement.ReadWrite.Directory"]]],
  ["add eligible member to role", [["RoleManagement.ReadWrite.Directory"]]],
  ["add app role assignment to service principal", [["AppRoleAssignment.ReadWrite.All"]]],
  ["add delegated permission grant", [["DelegatedPermissionGrant.ReadWrite.All"]]],
  ["add service principal credentials", [["Application.ReadWrite.All"], ["Application.ReadWrite.OwnedBy"]]],
  [
    "update application - certificates and secrets management",
    [["Application.ReadWrite.All"], ["Application.ReadWrite.OwnedBy"]],
  ],
  [
    "add owner to application",
    [
      ["Application.ReadWrite.All", "Directory.Read.All"],
      ["Application.ReadWrite.OwnedBy", "Directory.Read.All"],
    ],
  ],
  [
    "add owner to service principal",
    [
      ["Application.ReadWrite.All", "Directory.Read.All"],
      ["Application.ReadWrite.OwnedBy", "Directory.Read.All"],
    ],
  ],
  ["add user", [["User.ReadWrite.All"]]],
  ["update user", [["User.ReadWrite.All"]]],
  ["reset user password", [["User.ReadWrite.All"], ["User-PasswordProfile.ReadWrite.All"]]],
  ["change user password", [["User.ReadWrite.All"], ["User-PasswordProfile.ReadWrite.All"]]],
]);
/** Steps read per application; the rest are counted. */
export const STEPS_PER_APP_MAX = 1024;
/** Credential episodes evaluated per application; the rest are counted. */
const EPISODES_PER_APP_MAX = 32;

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
  /** sign-in steps: the key the record carries (a thumbprint is not one) and the outcome */
  signInKey?: string;
  thumbprintOnly?: boolean;
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
  /** Steps past STEPS_PER_APP_MAX — counted, never read. */
  beyond: number;
}

// ───────────────────────────── identity ─────────────────────────────

/**
 * (tenant, object id) → app id, learned only from records that STATE both: a sign-in
 * (servicePrincipalId + appId), a consent property (ServicePrincipal.ObjectID + .AppId), an
 * `AppId` property on a record whose target is the application. A conflict unlearns the id.
 */
export function learnSubjectResolver(records: readonly Row[], exportTenant: string): Resolver {
  const map = new Map<string, string>();
  const conflicts = new Set<string>();
  const learn = (tenant: string, objectId: string, appId: string) => {
    if (!isGuid(objectId) || !isGuid(appId)) return;
    const k = `${lower(tenant || exportTenant)}|${lower(objectId)}`;
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
    // Only properties of ONE target tuple teach a mapping: the object id and the app id must sit
    // on the same target index, or the app id on a target that IS the application.
    const byTarget = new Map<number, { objectId?: string; appId?: string }>();
    for (const p of audit.props) {
      const slot = byTarget.get(p.targetIndex) ?? byTarget.set(p.targetIndex, {}).get(p.targetIndex)!;
      const name = p.name.toLowerCase();
      if (name === "serviceprincipal.objectid") slot.objectId = String(p.newValue ?? "");
      if (name === "serviceprincipal.appid" || name === "application.appid" || name === "appid")
        slot.appId = String(p.newValue ?? "");
    }
    for (const [index, slot] of byTarget) {
      if (!slot.appId) continue;
      if (slot.objectId) learn(audit.tenant, slot.objectId, slot.appId);
      else {
        const target = audit.targets[index];
        if (target && /serviceprincipal|application/i.test(target.type) && target.id)
          learn(audit.tenant, target.id, slot.appId);
      }
    }
  }
  return (objectId, tenant) => {
    const k = `${lower(tenant || exportTenant)}|${lower(objectId)}`;
    return conflicts.has(k) ? "" : (map.get(k) ?? "");
  };
}

/**
 * The one tenant an export's sign-in records name, for the Graph directory-audit records that
 * name none (Graph directoryAudits carry no tenant field) — "" when the sign-ins name none or
 * several, in which case a tenantless audit record joins nothing outside its own tenantless set.
 */
export function exportTenantOf(records: readonly Row[]): string {
  const tenants = new Set(
    records
      .filter(isServicePrincipalSignIn)
      .map((rec) => lower(readSpSignIn(rec).tenant))
      .filter(Boolean),
  );
  return tenants.size === 1 ? [...tenants][0] : "";
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

function signInStep(s: SpSignIn, index: number): Step {
  const success = s.outcome === "success";
  const cred = s.credType
    ? `${show(s.credType, 20)}${s.credKeyId ? ` ${shortId(s.credKeyId)}` : s.credThumbprint ? ` thumbprint ${shortId(s.credThumbprint)}` : ""}`
    : "credential not in the record";
  return {
    kind: "sign-in",
    time: ms(s.observed),
    observed: s.observed,
    locator: `record:${index}`,
    initiator: "",
    initiatorIsApp: true,
    ...(s.credKeyId ? { signInKey: lower(s.credKeyId) } : {}),
    ...(!s.credKeyId && s.credThumbprint ? { thumbprintOnly: true } : {}),
    success,
    // The words are finished per episode (the key it is matched against is the episode's).
    words: `${success ? "signed in" : "sign-in attempt"}${s.resourceName ? ` → ${show(s.resourceName, 40)}` : ""} (${cred})${
      success
        ? ""
        : s.rejected
          ? ` — rejected: ${s.rejected}`
          : s.outcome === "failure"
            ? ` — failed (AADSTS${s.code})`
            : " — outcome unknown"
    }`,
  };
}

function actionStep(r: EntraAuditRecord, index: number): Step {
  return {
    kind: r.outcome === "success" ? "action" : "excluded",
    time: ms(r.time),
    observed: r.time,
    locator: `record:${index}`,
    initiator: "",
    initiatorIsApp: true,
    operation: r.operation,
    words:
      r.outcome === "success"
        ? `acted: ${show(r.operation, 60)}`
        : `attempted: ${show(r.operation, 60)} — ${r.outcome}; not a step`,
  };
}

/** An action's words against the permissions LIVE at its time: consistent, not among them, or unmapped. */
function actionWords(
  op: string,
  live: ReadonlySet<string>,
  tier0: boolean,
): { words: string; matched: boolean } {
  const alternatives = OPERATION_PERMISSIONS.get(lower(op));
  const shown = show(op, 60);
  if (!alternatives)
    return { words: `acted: ${shown} — the action's required permission was not mapped`, matched: false };
  if (tier0)
    return {
      words: `acted: ${shown} — consistent with the tier-0 directory role granted; the authorization the token carried is not in the record`,
      matched: true,
    };
  const met = alternatives.find((conj) => conj.every((p) => live.has(lower(p))));
  if (met)
    return {
      words: `acted: ${shown} — consistent with the granted ${met.join(" + ")}; the authorization the token carried is not in the record`,
      matched: true,
    };
  return {
    words: `acted: ${shown} — needs ${alternatives.map((c) => c.join(" + ")).join(" or ")}, not among the permissions live at that time`,
    matched: false,
  };
}

// ───────────────────────────── episodes ─────────────────────────────

interface Episode {
  credential: Step;
  /** Every grant inside the window; `grant` is the first — the one the order is judged against. */
  grants: Step[];
  grant?: Step;
  signIns: Step[];
  signIn?: Step;
  actions: Step[];
  action?: Step;
  outside: Step[];
  removed: Step[];
  grade: Severity | null;
  stages: number;
  privileged: boolean;
}

function episodesOf(chain: Chain): { episodes: Episode[]; episodesBeyond: number } {
  const sorted = [...chain.steps].sort(
    (a, b) => (a.time ?? Infinity) - (b.time ?? Infinity) || a.locator.localeCompare(b.locator),
  );
  const credentials = sorted.filter((s) => s.kind === "credential" && s.time !== null);
  const out: Episode[] = [];
  for (const cred of credentials.slice(0, EPISODES_PER_APP_MAX)) {
    const open = cred.time!;
    const close = open + WINDOW_MS;
    // Strictly after the credential: an equal timestamp establishes no order.
    const later = sorted.filter((s) => s !== cred && s.time !== null && s.time > open);
    const outside = later.filter((s) => s.time! > close && s.kind !== "excluded");
    const within = later.filter((s) => s.time! <= close);
    // Effective intervals per exact grant / role / credential: ended by the FIRST removal of the
    // same key after it; a re-grant after a removal is its own interval.
    const endOf = (start: Step, kind: Step["kind"], key: string | undefined): number | null =>
      within.find((s) => s.kind === kind && s.time! > start.time! && (s.keyId ?? s.permission) === key)
        ?.time ?? null;
    const credEnd = endOf(cred, "credential-removed", cred.keyId);
    const grants = within.filter((s) => s.kind === "grant" || s.kind === "role");
    const grantEnd = new Map(
      grants.map((g) => [g, endOf(g, g.kind === "grant" ? "grant-removed" : "role-removed", g.permission)]),
    );
    const liveAt = (t: number): { permissions: Set<string>; tier0: boolean } => {
      const live = grants.filter(
        (g) => g.time! <= t && ((grantEnd.get(g) ?? null) === null || t < grantEnd.get(g)!),
      );
      return {
        permissions: new Set(live.map((g) => g.permission!)),
        tier0: live.some((g) => g.kind === "role" && g.words.includes("can take over the tenant")),
      };
    };
    // The ordered subsequence: the first grant after the credential; the first SUCCESSFUL sign-in
    // with THIS credential's key after that grant (after the credential when there is no grant),
    // while the credential is live; the first successful action after that sign-in (after the
    // grant when there is no sign-in) consistent with a permission live at its time.
    // The first privileged grant when there is one, else the first grant.
    const grant = grants.find((g) => g.privileged) ?? grants[0];
    const signInsRaw = within
      .filter((s) => s.kind === "sign-in")
      .map((s) => ({
        ...s,
        matched: !!s.signInKey && s.signInKey === cred.keyId,
        words: s.thumbprintOnly
          ? `${s.words} — identified by thumbprint only, not matched to a key id`
          : s.signInKey && s.signInKey === cred.keyId
            ? s.success
              ? `${s.words} — with the new credential`
              : `${s.words} — with the new credential; not a use`
            : `${s.words} — with an unmatched credential`,
      }));
    const afterGrant = grant ? grant.time! : open;
    const inOrder = (s: Step): boolean => s.time! > afterGrant && (credEnd === null || s.time! < credEnd);
    const chosen = signInsRaw.find((s) => s.matched && s.success && inOrder(s));
    // A matched sign-in that is not the stage says why: before the grant, or after the removal.
    const signIns = signInsRaw.map((s) =>
      s.matched && s.success && s !== chosen
        ? {
            ...s,
            words: `${s.words}${s.time! <= afterGrant ? ", before the grant" : credEnd !== null && s.time! >= credEnd ? ", after the credential was removed" : ""}`,
          }
        : s,
    );
    const signIn = chosen ? signIns[signInsRaw.indexOf(chosen)] : undefined;
    const afterSignIn = signIn ? signIn.time! : afterGrant;
    const actions = within
      .filter((s) => s.kind === "action" && s.time! > afterSignIn)
      .map((s) => {
        const { permissions, tier0 } = liveAt(s.time!);
        return { ...s, ...actionWords(s.operation ?? "", permissions, tier0) };
      });
    const action = actions.find((a) => a.matched);
    const removed = within.filter(
      (s) => s.kind === "credential-removed" || s.kind === "grant-removed" || s.kind === "role-removed",
    );
    const privileged = !!grant?.privileged;
    const stages = 1 + (grant ? 1 : 0) + (signIn ? 1 : 0) + (action ? 1 : 0);
    const grade: Severity | null =
      stages >= 4 && privileged ? "High" : stages >= 3 ? "Medium" : stages === 2 ? "Low" : null;
    out.push({
      credential: cred,
      grants,
      grant,
      signIns,
      signIn,
      actions,
      action,
      outside,
      removed,
      grade,
      stages,
      privileged,
    });
  }
  return { episodes: out, episodesBeyond: Math.max(0, credentials.length - EPISODES_PER_APP_MAX) };
}

const RANK: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

// ───────────────────────────── the pass ─────────────────────────────

export interface ExportCoverage {
  tenant: string;
  signIns: { records: number; first: string; last: string } | null;
  audits: { records: number; first: string; last: string } | null;
  /** For the tenantless set only: how many tenants the export's sign-ins name (0 when they are joined). */
  signInTenantsUnjoined: number;
}

/** One summary row per application whose export records form a path; the rows say what they rest on. */
export function entraPrivilegePaths(records: readonly Row[], resolve: Resolver): MappedEvent[] {
  const exportTenant = exportTenantOf(records);
  const subjectOf = learnSubjectResolver(records, exportTenant);
  const chains = new Map<string, Chain>();
  const coverage = new Map<string, ExportCoverage>();
  const tenantOf = (t: string): string => lower(t) || exportTenant;
  const cover = (tenant: string, kind: "signIns" | "audits", time: string) => {
    const k = tenantOf(tenant);
    const c =
      coverage.get(k) ??
      coverage.set(k, { tenant: k, signIns: null, audits: null, signInTenantsUnjoined: 0 }).get(k)!;
    const t = normalizeTime(time);
    const cur = c[kind] ?? { records: 0, first: t, last: t };
    c[kind] = {
      records: cur.records + 1,
      first: t && (!cur.first || t < cur.first) ? t : cur.first,
      last: t && (!cur.last || t > cur.last) ? t : cur.last,
    };
  };
  const chainOf = (tenant: string, appId: string, name: string): Chain => {
    const k = `${tenantOf(tenant)}|${lower(appId)}`;
    const c =
      chains.get(k) ??
      chains.set(k, { tenant: tenantOf(tenant), appId: lower(appId), name, steps: [], beyond: 0 }).get(k)!;
    if (!c.name && name) c.name = name;
    return c;
  };
  const push = (c: Chain, step: Step) => {
    if (c.steps.length < STEPS_PER_APP_MAX) c.steps.push(step);
    else c.beyond += 1;
  };
  // An app id the record states (a GUID), else the object id resolved through a record that states both.
  const appOf = (tenant: string, objectId: string, appId: string): string =>
    isGuid(appId) ? lower(appId) : isGuid(objectId) ? subjectOf(objectId, tenant) : "";

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
      if (step) push(chainOf(r.tenant, appId, c.subject.name), step);
    }
    if (r.initiator.kind === "app") {
      const appId = appOf(r.tenant, r.initiator.id, r.initiator.appId);
      if (appId) actions.push({ r, index, appId });
    }
  });
  if (!exportTenant) {
    const tenantless = coverage.get("");
    if (tenantless) tenantless.signInTenantsUnjoined = new Set(signIns.map((x) => lower(x.s.tenant))).size;
  }
  for (const { s, index } of signIns) {
    const appId = appOf(s.tenant, s.spId, s.appId);
    const c = appId ? chains.get(`${tenantOf(s.tenant)}|${appId}`) : undefined;
    if (c) push(c, signInStep(s, index));
  }
  for (const { r, index, appId } of actions) {
    const c = chains.get(`${tenantOf(r.tenant)}|${appId}`);
    if (c) push(c, actionStep(r, index));
  }

  // Episodes, the best per application, ranked, bounded.
  const findings = [...chains.values()]
    .map((chain) => {
      const { episodes, episodesBeyond } = episodesOf(chain);
      const graded = episodes.filter((e) => e.grade !== null);
      if (!graded.length) return null;
      graded.sort(
        (a, b) =>
          RANK[b.grade!] - RANK[a.grade!] ||
          b.stages - a.stages ||
          (b.credential.time ?? 0) - (a.credential.time ?? 0),
      );
      return { chain, best: graded[0], others: graded.slice(1), beyond: chain.beyond + episodesBeyond };
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
    .map((f) => summaryRow(f.chain, f.best, f.others, f.beyond, coverage.get(f.chain.tenant)));
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
  beyond: number,
  coverage: ExportCoverage | undefined,
): MappedEvent {
  const iso = (t: number | null) => (t === null ? "time not readable" : new Date(t).toISOString());
  const stepWords = (s: Step) => `${iso(s.time)} ${s.words}`;
  const named = (steps: Step[], label: string): string[] => {
    const shown = steps.slice(0, STEPS_NAMED_MAX).map(stepWords);
    const more = steps.length > STEPS_NAMED_MAX ? [`+${steps.length - STEPS_NAMED_MAX} more ${label}`] : [];
    return [...shown, ...more];
  };
  // Absence is scoped to the episode's window and backed by the export's own counts; a matching
  // record OUTSIDE the window is listed beside it, never contradicted.
  const absence = (kind: "signIns" | "audits", what: string): string => {
    const c = coverage?.[kind];
    if (c)
      return `no ${what} inside the window among the ${c.records} ${kind === "signIns" ? "sign-in" : "directory-audit"} records of this export (${c.first.slice(0, 10)} → ${c.last.slice(0, 10)})`;
    if (kind === "signIns" && coverage?.signInTenantsUnjoined)
      return `the sign-in records of this export name ${coverage.signInTenantsUnjoined} tenants and the directory-audit records name none — not joined`;
    return `${kind === "signIns" ? "sign-in" : "directory-audit"} log not in this export`;
  };
  const unmatchedSignIns = e.signIns.filter((s) => s !== e.signIn);
  const otherActions = e.actions.filter((a) => a !== e.action);
  const parts = [
    stepWords(e.credential),
    ...(e.grants.length ? named(e.grants, "grants") : ["no capability granted inside the window"]),
    ...(e.grants.length && !e.privileged ? ["no privileged capability granted inside the window"] : []),
    ...(e.signIn
      ? [stepWords(e.signIn)]
      : [absence("signIns", "successful sign-in with the new credential")]),
    ...(unmatchedSignIns.length ? named(unmatchedSignIns, "other sign-ins") : []),
    ...(e.action
      ? [stepWords(e.action)]
      : [absence("audits", "consistent directory change by this application")]),
    ...(otherActions.length ? named(otherActions, "other actions") : []),
    ...(e.removed.length ? named(e.removed, "removals") : []),
    ...(e.outside.length
      ? [`outside the ${PRIVILEGE_PATH_WINDOW_DAYS}-day window: ${named(e.outside, "steps").join("; ")}`]
      : []),
    ...(others.length
      ? [
          `${others.length} other episode${others.length === 1 ? "" : "s"}: ${others.map((o) => o.grade).join(", ")}`,
        ]
      : []),
    ...(beyond ? [`${beyond} step${beyond === 1 ? "" : "s"} beyond the bound, not evaluated`] : []),
    e.stages >= 4
      ? e.grade === "High"
        ? "all four stages in order"
        : "all four stages in order; no privileged capability granted"
      : e.stages === 3
        ? "three of four stages"
        : "two of four stages",
  ];
  const head = `Entra privilege path: ${show(chain.name || "(unnamed application)")} (app id ${chain.appId})`;
  // The counts and the stage sentence are packed first; the step words are cut to what remains.
  const tailFrom = parts.length - (1 + (beyond ? 1 : 0) + (others.length ? 1 : 0));
  const tail = parts.slice(tailFrom).join("; ");
  const room = DESCRIPTION_MAX - head.length - tail.length - 6;
  const lead = parts.slice(0, tailFrom).join("; ");
  const description = `${head} [${lead.length > room ? `${lead.slice(0, Math.max(0, room - 1))}…` : lead}; ${tail}]`;
  const identity = createHash("sha256")
    .update(`${chain.tenant.length}:${chain.tenant}|${chain.appId.length}:${chain.appId}`)
    .digest("hex")
    .slice(0, 32);
  const steps: EntraPathStep[] = [
    e.credential,
    ...e.grants,
    ...(e.signIn ? [e.signIn] : []),
    ...(e.action ? [e.action] : []),
  ]
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
