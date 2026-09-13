// Google Workspace OAuth lifecycle (#931 item 10, chain half — #983): who authorized a client,
// what it called after each authorization and before a revocation, when it was revoked, whether
// calls continued — built over the records of ONE Reports API export inside the importer (the
// `activity` rows are Info and leave the forensic timeline at import).
//
// What one row rests on, and what it never says:
//   - identity: the tenant (`id.customerId`), the client id (`client_id`, never `app_name`) and the
//     user's profile id (never an email alone, never Google's placeholder id); a record missing
//     any of them joins nothing and is counted;
//   - activity is placed in TIME against the same user's authorizations and revocations — no
//     record ties a call to a particular grant or its scopes, so nothing says "under the grant";
//   - a `request` never opens a lifecycle; a `deny` is a refusal; a missing revocation is "no
//     revocation record in this export" — the current grant state is not established;
//   - calls and bytes are summed over EVERY activity record (a big integer); only the narration
//     is bounded; admin app-control rows are joined by OAUTH2_APP_ID for WEB_APPLICATION only;
//   - coverage is the export's own record count and range; retention is stated, completeness is
//     never claimed.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { GwsGrant, GwsLifecycleBlock } from "./canonicalGwsLifecycle.js";
import { decodeGwsToken, readGwsParams, scopeTier, type GwsParam, type ScopeTier } from "./gwsOAuth.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { getCI, getPath, isObject, normalizeTime, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

export const GWS_LIFECYCLES_MAX = 256;
export const USERS_NAMED_MAX = 16;
export const METHODS_TRACKED_MAX = 64;
const METHODS_NAMED_MAX = 8;
const SCOPES_NAMED_MAX = 8;
const AUTHORIZATIONS_NAMED_MAX = 4;
const ADMIN_CONTROLS_MAX = 16;
const LOGIN_WINDOW_MS = 10 * 60_000;
const NAME_MAX = 80;
const DESCRIPTION_MAX = 1400;
/** Google's documented placeholder profile id for an actor with no profile. */
const PLACEHOLDER_PROFILE = "105250506097979753968";
const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const TIER_RANK: Record<ScopeTier | "unknown", number> = { High: 3, Medium: 2, Low: 1, unknown: 0 };
const RETENTION_NOTE =
  "the Reports API retains token events for 6 months; the export's completeness for the period is not established by this evidence";
const ADMIN_CONTROL_EVENTS = new Set([
  "ADD_TO_TRUSTED_OAUTH2_APPS",
  "REMOVE_FROM_TRUSTED_OAUTH2_APPS",
  "ADD_TO_BLOCKED_OAUTH2_APPS",
  "REMOVE_FROM_BLOCKED_OAUTH2_APPS",
]);

const show = (v: string, max = NAME_MAX): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
const lower = (s: string): string => s.trim().toLowerCase();
const text = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v)).trim();
const ms = (iso: string): number | null => {
  const t = Date.parse(normalizeTime(iso));
  return Number.isFinite(t) ? t : null;
};
const iso = (t: number): string => new Date(t).toISOString();
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const param = (params: readonly GwsParam[], name: string): string =>
  (params.find((p) => p.name.toLowerCase() === name.toLowerCase())?.value ?? "").trim();
const bigDigits = (s: string): bigint => (/^\d+$/.test(s) ? BigInt(s) : 0n);

// ───────────────────────────── accumulators (bounded) ─────────────────────────────

interface Cited {
  time: number;
  locator: string;
}
interface Authorization extends Cited {
  tier: ScopeTier;
  scopes: string[];
}
interface Grant {
  profileId: string;
  email: string;
  authorizations: Authorization[];
  activity: Cited[];
  calls: number;
  bytes: bigint;
  methods: Map<string, number>;
  callsBeyondTrackedMethods: number;
  first: Cited | null;
  last: Cited | null;
  revocations: Cited[];
  logins: Cited[];
  driveEvents: Cited[];
}
interface Client {
  tenant: string;
  clientId: string;
  name: string;
  grants: Map<string, Grant>;
  requests: number;
  denials: number;
  adminControls: { event: string; time: number; locator: string }[];
  top: Severity;
}

/** Activity rows kept per grant for the time placement; totals count every one. */
const ACTIVITY_KEPT_MAX = 4096;

function grantFor(c: Client, profileId: string, email: string): Grant {
  const g =
    c.grants.get(profileId) ??
    c.grants
      .set(profileId, {
        profileId,
        email,
        authorizations: [],
        activity: [],
        calls: 0,
        bytes: 0n,
        methods: new Map(),
        callsBeyondTrackedMethods: 0,
        first: null,
        last: null,
        revocations: [],
        logins: [],
        driveEvents: [],
      })
      .get(profileId)!;
  if (!g.email && email) g.email = email;
  return g;
}

function clientFor(clients: Map<string, Client>, tenant: string, clientId: string, name: string): Client {
  const k = `${lower(tenant)}|${clientId}`;
  const c =
    clients.get(k) ??
    clients
      .set(k, {
        tenant,
        clientId,
        name,
        grants: new Map(),
        requests: 0,
        denials: 0,
        adminControls: [],
        top: "Info",
      })
      .get(k)!;
  if (!c.name && name) c.name = name;
  return c;
}

// ───────────────────────────── the users ─────────────────────────────

/** A user is a validated, non-placeholder profile id; an email resolves through a record that states both. */
function learnUsers(records: readonly Row[]): (rec: Row) => { profileId: string; email: string } | null {
  const byEmail = new Map<string, string>();
  const conflicts = new Set<string>();
  for (const rec of records) {
    const email = lower(text(getPath(rec, "actor.email")));
    const pid = text(getPath(rec, "actor.profileId"));
    if (!email || !/^\d{6,}$/.test(pid) || pid === PLACEHOLDER_PROFILE) continue;
    const prev = byEmail.get(email);
    if (prev && prev !== pid) conflicts.add(email);
    else byEmail.set(email, pid);
  }
  return (rec) => {
    const email = text(getPath(rec, "actor.email"));
    const pid = text(getPath(rec, "actor.profileId"));
    if (/^\d{6,}$/.test(pid) && pid !== PLACEHOLDER_PROFILE) return { profileId: pid, email };
    const learned = email && !conflicts.has(lower(email)) ? (byEmail.get(lower(email)) ?? "") : "";
    return learned ? { profileId: learned, email } : null;
  };
}

// ───────────────────────────── the pass ─────────────────────────────

interface Scanned {
  rec: Row;
  event: Row;
  locator: string;
  time: number;
  app: string;
  name: string;
  params: GwsParam[];
}

function scan(records: readonly Row[]): Scanned[] {
  const out: Scanned[] = [];
  records.forEach((rec, recordIndex) => {
    if (!isObject(rec)) return;
    const time = ms(text(getPath(rec, "id.time")));
    const app = lower(text(getPath(rec, "id.applicationName")));
    if (time === null || !app) return;
    const events = getCI(rec, "events");
    (Array.isArray(events) ? events : []).forEach((e, eventIndex) => {
      if (!isObject(e)) return;
      out.push({
        rec,
        event: e,
        locator: `record:${recordIndex}/event:${eventIndex}`,
        time,
        app,
        name: text(getCI(e, "name")),
        params: readGwsParams(e),
      });
    });
  });
  return out;
}

/** One summary row per (tenant, client id) whose export records form a lifecycle; the rows say what they rest on. */
export function gwsOAuthLifecycles(records: readonly Row[]): MappedEvent[] {
  const clients = new Map<string, Client>();
  const coverage = { records: 0, first: "", last: "" };
  let incomplete = 0;
  const userOf = learnUsers(records);
  const scanned = scan(records);
  // Pass 1: the token rows.
  for (const s of scanned) {
    if (s.app !== "token") continue;
    coverage.records += 1;
    const t = normalizeTime(text(getPath(s.rec, "id.time")));
    if (!coverage.first || t < coverage.first) coverage.first = t;
    if (!coverage.last || t > coverage.last) coverage.last = t;
    const reading = decodeGwsToken(s.name, s.params);
    if (!reading) continue;
    const tenant = text(getPath(s.rec, "id.customerId"));
    const user = userOf(s.rec);
    if (!tenant || !reading.client.id || !user) {
      incomplete += 1;
      continue;
    }
    const c = clientFor(clients, tenant, reading.client.id, reading.client.name);
    if (RANK[reading.severity] > RANK[c.top]) c.top = reading.severity;
    if (reading.kind === "request") {
      c.requests += 1;
      continue;
    }
    if (reading.kind === "deny") {
      c.denials += 1;
      continue;
    }
    const g = grantFor(c, user.profileId, user.email);
    const cited: Cited = { time: s.time, locator: s.locator };
    if (reading.kind === "authorize") {
      const tier = reading.scopes.length
        ? reading.scopes
            .map(scopeTier)
            .reduce((m, x) => (TIER_RANK[x] > TIER_RANK[m] ? x : m), "Low" as ScopeTier)
        : "High";
      g.authorizations.push({ ...cited, tier, scopes: reading.scopes });
    } else if (reading.kind === "revoke") g.revocations.push(cited);
    else {
      g.calls += 1;
      g.bytes += bigDigits(reading.bytes ?? "");
      if (!g.first || s.time < g.first.time) g.first = cited;
      if (!g.last || s.time > g.last.time) g.last = cited;
      const method = reading.api.method || reading.api.name || "(method not in the record)";
      const n = g.methods.get(method);
      if (n !== undefined) g.methods.set(method, n + 1);
      else if (g.methods.size < METHODS_TRACKED_MAX) g.methods.set(method, 1);
      else g.callsBeyondTrackedMethods += 1;
      if (g.activity.length < ACTIVITY_KEPT_MAX) g.activity.push(cited);
    }
  }
  // Pass 2: the rows beside — admin app control by OAUTH2_APP_ID (web applications only), logins
  // and Drive rows of the users the lifecycles name.
  const byProfile = new Map<string, Grant[]>();
  for (const c of clients.values())
    for (const g of c.grants.values())
      (byProfile.get(g.profileId) ?? byProfile.set(g.profileId, []).get(g.profileId)!).push(g);
  for (const s of scanned) {
    if (s.app === "admin" && ADMIN_CONTROL_EVENTS.has(s.name.toUpperCase())) {
      const appId = param(s.params, "OAUTH2_APP_ID");
      const appType = param(s.params, "OAUTH2_APP_TYPE").toUpperCase();
      const tenant = text(getPath(s.rec, "id.customerId"));
      if (!appId || appType !== "WEB_APPLICATION" || !tenant) continue;
      const c = clients.get(`${lower(tenant)}|${appId}`);
      if (c && c.adminControls.length < ADMIN_CONTROLS_MAX)
        c.adminControls.push({ event: s.name.toUpperCase(), time: s.time, locator: s.locator });
      continue;
    }
    if (s.app !== "login" && s.app !== "drive") continue;
    const user = userOf(s.rec);
    if (!user) continue;
    for (const g of byProfile.get(user.profileId) ?? []) {
      if (s.app === "login") {
        if (
          g.authorizations.some((a) => Math.abs(a.time - s.time) <= LOGIN_WINDOW_MS) &&
          g.logins.length < ACTIVITY_KEPT_MAX
        )
          g.logins.push({ time: s.time, locator: s.locator });
      } else if (inWindow(g, s.time) && g.driveEvents.length < ACTIVITY_KEPT_MAX)
        g.driveEvents.push({ time: s.time, locator: s.locator });
    }
  }
  const findings = [...clients.values()]
    .filter(
      (c) =>
        [...c.grants.values()].some((g) => g.authorizations.length || g.calls) || c.requests || c.denials,
    )
    .map((c) => ({ c, tier: coveredTier(c), grade: gradeOf(c) }))
    .sort(
      (a, b) =>
        RANK[b.grade] - RANK[a.grade] ||
        TIER_RANK[b.tier] - TIER_RANK[a.tier] ||
        b.c.grants.size - a.c.grants.size ||
        a.c.clientId.localeCompare(b.c.clientId),
    );
  const rows = findings
    .slice(0, GWS_LIFECYCLES_MAX)
    .map((f) => summaryRow(f.c, f.tier, f.grade, incomplete, coverage));
  if (findings.length > GWS_LIFECYCLES_MAX)
    rows.push(omittedRow(findings.length - GWS_LIFECYCLES_MAX, findings[GWS_LIFECYCLES_MAX].grade));
  return rows;
}

/** Between an authorization and the first later revocation of this user (or the end of the export). */
function inWindow(g: Grant, t: number): boolean {
  const auths = g.authorizations.map((a) => a.time).sort((a, b) => a - b);
  const revs = g.revocations.map((r) => r.time).sort((a, b) => a - b);
  for (const a of auths) {
    if (t <= a) continue;
    const end = revs.find((r) => r > a);
    if (end === undefined || t < end) return true;
  }
  return false;
}

function coveredTier(c: Client): ScopeTier | "unknown" {
  let tier: ScopeTier | "unknown" = "unknown";
  for (const g of c.grants.values())
    for (const a of g.authorizations) if (TIER_RANK[a.tier] > TIER_RANK[tier]) tier = a.tier;
  return tier;
}

/** The highest authorization the row covers; activity with no authorization in the export is Medium; requests / denials alone Low. Never below the top token row. */
function gradeOf(c: Client): Severity {
  const tier = coveredTier(c);
  const hasActivity = [...c.grants.values()].some((g) => g.calls > 0);
  const floor: Severity = tier !== "unknown" ? tier : hasActivity ? "Medium" : "Low";
  return RANK[c.top] > RANK[floor] ? c.top : floor;
}

// ───────────────────────────── the row ─────────────────────────────

/**
 * The placement of a grant's activity in time: before any authorization in the export; after an
 * authorization and before a revocation (`between`, of which `reauthorized` follow a revocation
 * AND a later authorization); after a revocation with no later authorization before it (`after`).
 */
function placement(g: Grant): { before: number; between: number; after: number; reauthorized: number } {
  const auths = g.authorizations.map((a) => a.time).sort((a, b) => a - b);
  const revs = g.revocations.map((r) => r.time).sort((a, b) => a - b);
  let before = 0;
  let between = 0;
  let after = 0;
  let reauthorized = 0;
  for (const a of g.activity) {
    const lastAuth = [...auths].reverse().find((x) => x < a.time);
    const lastRev = [...revs].reverse().find((x) => x < a.time);
    if (lastAuth === undefined) before += 1;
    else if (lastRev !== undefined && lastRev > lastAuth) after += 1;
    else {
      between += 1;
      // A call after a revocation that a LATER authorization precedes: re-authorized, not orphaned.
      if (lastRev !== undefined) reauthorized += 1;
    }
  }
  return { before, between, after, reauthorized };
}

function grantWords(g: Grant): string {
  const auths = [...g.authorizations].sort((a, b) => a.time - b.time);
  const revs = [...g.revocations].sort((a, b) => a.time - b.time);
  const who = show(g.email || `profile ${g.profileId}`, 60);
  const p = placement(g);
  const authWords = auths.slice(0, AUTHORIZATIONS_NAMED_MAX).map((a, i) => {
    const wider = i > 0 && a.scopes.some((s) => !auths[i - 1].scopes.includes(s));
    const scopes = a.scopes.length
      ? `${a.scopes
          .slice(0, SCOPES_NAMED_MAX)
          .map((s) => show(s.replace(/^https:\/\/www\.googleapis\.com\/auth\//, ""), 40))
          .join(
            ", ",
          )}${a.scopes.length > SCOPES_NAMED_MAX ? ` +${a.scopes.length - SCOPES_NAMED_MAX} more` : ""}`
      : "scopes not in this record";
    return `${i === 0 ? "authorized" : wider ? "re-authorized with wider scopes" : "re-authorized"} ${iso(a.time)} (${a.tier}: ${scopes}) — ${a.locator}`;
  });
  const methods = [...g.methods.entries()].sort((a, b) => b[1] - a[1]);
  const activityWords =
    g.calls > 0
      ? `activity: ${plural(g.calls, "call")}, ${g.bytes.toLocaleString("en-US")} bytes returned, ${plural(g.methods.size + (g.callsBeyondTrackedMethods ? 1 : 0), "method")} (${methods
          .slice(0, METHODS_NAMED_MAX)
          .map(([m, n]) => `${show(m, 50)} ×${n}`)
          .join(
            ", ",
          )}${methods.length > METHODS_NAMED_MAX ? ", …" : ""}${g.callsBeyondTrackedMethods ? `; ${g.callsBeyondTrackedMethods} calls to methods beyond the tracked ${METHODS_TRACKED_MAX}` : ""}) ${iso(g.first!.time)} → ${iso(g.last!.time)}${
          p.between ? `; ${p.between} after an authorization and before a revocation` : ""
        }${p.before ? `; ${p.before} before any authorization in this export — the grant predates the export or was not exported` : ""}${
          p.reauthorized ? `; ${p.reauthorized} after a revocation that a later authorization precedes` : ""
        }${
          p.after
            ? `; after a revocation with no re-authorization in the export before them: ${p.after} — delayed delivery of earlier calls or a live token; not established`
            : ""
        }${g.activity.length < g.calls ? `; placement read on the first ${g.activity.length} of ${g.calls} calls` : ""}`
      : "no activity record in this export";
  const revWords = revs.length
    ? `revoked ${revs
        .slice(0, 3)
        .map((r) => `${iso(r.time)} (${r.locator})`)
        .join(", ")}${revs.length > 3 ? ` +${revs.length - 3} more` : ""}`
    : "no revocation record in this export; the current grant state is not established";
  const beside = [
    ...(g.logins.length
      ? [
          `${plural(g.logins.length, "login row")} within 10 min of an authorization — contemporaneous, not established as the same session`,
        ]
      : []),
    ...(g.driveEvents.length
      ? [
          `${plural(g.driveEvents.length, "Drive event")} by this user between an authorization and a revocation — not attributed to the app`,
        ]
      : []),
  ];
  return `${who}: ${[...authWords, ...(auths.length > AUTHORIZATIONS_NAMED_MAX ? [`+${auths.length - AUTHORIZATIONS_NAMED_MAX} more authorizations`] : []), activityWords, revWords, ...beside].join("; ")}`;
}

function summaryRow(
  c: Client,
  tier: ScopeTier | "unknown",
  grade: Severity,
  incomplete: number,
  coverage: { records: number; first: string; last: string },
): MappedEvent {
  const grants = [...c.grants.values()].sort(
    (a, b) =>
      TIER_RANK[
        a.authorizations.reduce<ScopeTier | "unknown">(
          (m, x) => (TIER_RANK[x.tier] > TIER_RANK[m] ? x.tier : m),
          "unknown",
        )
      ] -
        TIER_RANK[
          b.authorizations.reduce<ScopeTier | "unknown">(
            (m, x) => (TIER_RANK[x.tier] > TIER_RANK[m] ? x.tier : m),
            "unknown",
          )
        ] || a.profileId.localeCompare(b.profileId),
  );
  grants.reverse();
  const authorized = grants.filter((g) => g.authorizations.length).length;
  const parts = [
    ...grants.slice(0, USERS_NAMED_MAX).map(grantWords),
    ...(c.requests
      ? [`${plural(c.requests, "access request")} — requested, not granted by those records`]
      : []),
    ...(c.denials ? [`${plural(c.denials, "denial")}`] : []),
    ...c.adminControls
      .slice(0, ADMIN_CONTROLS_MAX)
      .map((a) => `admin app control: ${a.event} ${iso(a.time)} (${a.locator})`),
  ];
  const tail = [
    ...(grants.length > USERS_NAMED_MAX ? [`+${plural(grants.length - USERS_NAMED_MAX, "more user")}`] : []),
    `${plural(authorized, "user")} authorized this client in the ${plural(coverage.records, "token record")} of this export (${coverage.first.slice(0, 10)} → ${coverage.last.slice(0, 10)})`,
    ...(incomplete
      ? [`${plural(incomplete, "token record")} without a tenant, client id or user — not joined`]
      : []),
    RETENTION_NOTE,
    tier === "unknown"
      ? "no authorization in this export; the scopes are not known"
      : `highest authorization covered: ${tier}`,
  ].join("; ");
  const head = `Google Workspace OAuth lifecycle: ${show(c.name || "(unnamed application)", 60)} (client ${show(c.clientId, 100)})`;
  const room = DESCRIPTION_MAX - head.length - tail.length - 6;
  const lead = parts.join("; ");
  const description = `${head} [${lead.length > room ? `${lead.slice(0, Math.max(0, room - 1))}…` : lead}; ${tail}]`;
  const identity = createHash("sha256")
    .update(`${c.tenant.length}:${c.tenant}|${c.clientId.length}:${c.clientId}`)
    .digest("hex")
    .slice(0, 32);
  const blockGrants: GwsGrant[] = grants.slice(0, USERS_NAMED_MAX).map((g) => {
    const p = placement(g);
    return {
      profileId: g.profileId,
      ...(g.email ? { email: g.email } : {}),
      authorizations: g.authorizations.slice(0, AUTHORIZATIONS_NAMED_MAX).map((a) => ({
        time: iso(a.time),
        locator: a.locator,
        tier: a.tier,
        scopes: a.scopes.slice(0, SCOPES_NAMED_MAX),
        scopesBeyond: Math.max(0, a.scopes.length - SCOPES_NAMED_MAX),
      })),
      authorizationsBeyond: Math.max(0, g.authorizations.length - AUTHORIZATIONS_NAMED_MAX),
      activity: {
        calls: g.calls,
        bytes: g.bytes.toString(),
        methods: [...g.methods.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, METHODS_NAMED_MAX)
          .map(([method, calls]) => ({ method, calls })),
        callsBeyondTrackedMethods: g.callsBeyondTrackedMethods,
        ...(g.first ? { first: { time: iso(g.first.time), locator: g.first.locator } } : {}),
        ...(g.last ? { last: { time: iso(g.last.time), locator: g.last.locator } } : {}),
      },
      beforeAuthorization: p.before,
      revocations: g.revocations.slice(0, 8).map((r) => ({ time: iso(r.time), locator: r.locator })),
      afterRevocation: { calls: p.after, reauthorized: p.reauthorized },
      contemporaneousLogins: g.logins.length,
      driveEventsInWindow: g.driveEvents.length,
    };
  });
  const block: GwsLifecycleBlock = {
    clientId: c.clientId,
    tenant: c.tenant,
    coveredTier: tier,
    grants: blockGrants,
    usersBeyond: Math.max(0, grants.length - USERS_NAMED_MAX),
    requests: c.requests,
    denials: c.denials,
    adminControls: c.adminControls.map((a) => ({ event: a.event, time: iso(a.time), locator: a.locator })),
    incomplete,
    coverage,
    basis:
      "records of this export only; joined through the tenant, the client id and the user's profile id; activity placed in time, never tied to a grant or its scopes",
  };
  const cited = [
    ...new Set(
      grants.flatMap((g) => [
        ...g.authorizations.map((a) => a.locator),
        ...g.revocations.map((r) => r.locator),
        ...(g.first ? [g.first.locator] : []),
        ...(g.last ? [g.last.locator] : []),
      ]),
    ),
  ].slice(0, 256);
  const firstTime = Math.min(
    ...grants.flatMap((g) => [...g.authorizations.map((a) => a.time), ...(g.first ? [g.first.time] : [])]),
    Infinity,
  );
  const observed = Number.isFinite(firstTime) ? iso(firstTime) : coverage.first;
  return {
    timestamp: normalizeTime(observed),
    description,
    severity: grade,
    mitre: tier === "High" ? ["T1528"] : [],
    aggKey: boundedAggKey(`gws-oauth-lifecycle|${identity}`),
    sources: ["Google Workspace"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "oauth-lifecycle", action: "lifecycle", outcome: "success" },
      actor: { kind: "cloud_principal", id: c.clientId, name: c.name || c.clientId },
      cloud: { provider: "google-workspace", tenant: c.tenant, principalId: c.clientId },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: {
        rawRecords: (cited.length ? cited : ["none"]).map((l) => ({
          source: "google-workspace-reports",
          locator: l,
        })),
      },
      producer: {
        importer: "google-workspace",
        parserVersion: "1",
        mappingVersion: "gws-oauth-lifecycle-v1",
        ruleVersions: ["gws-lifecycle-v1"],
      },
      gwsLifecycle: block,
    }),
  };
}

function omittedRow(count: number, severity: Severity): MappedEvent {
  const description = `Google Workspace OAuth lifecycle: ${count} further client${count === 1 ? "" : "s"} with a lifecycle in this export beyond the ${GWS_LIFECYCLES_MAX} reported — not shown`;
  return {
    timestamp: "",
    description,
    severity,
    mitre: [],
    aggKey: boundedAggKey(`gws-oauth-lifecycle|omitted|${count}`),
    sources: ["Google Workspace"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "oauth-lifecycle", action: "omitted" },
      cloud: { provider: "google-workspace" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "google-workspace-reports", locator: "omitted" }] },
      producer: {
        importer: "google-workspace",
        parserVersion: "1",
        mappingVersion: "gws-oauth-lifecycle-v1",
      },
    }),
  };
}
