// Google Workspace OAuth token events, read one at a time (#931 item 10).
//
// The Reports API's `token` application records four things, and each record establishes ONE of
// them: `authorize` — a user granted an application a set of scopes; `activity` — the application
// called an API method on the user's behalf (with the bytes the response carried); `request` — an
// application asked for access (not granted by this record); `revoke` — the grant was withdrawn;
// `deny` — the request was refused. The application's identity is its `client_id` (two apps can
// share a display name); `app_name` is a label. An authorization does not evidence API use, bytes
// returned do not prove a download, and a revocation says nothing about what followed — the row
// says exactly that. Grading follows the SCOPES granted, by a literal table of scope URIs: the
// content-wide read scopes (mail, Drive, Docs, Calendar, Contacts, Directory) are the prize.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";

type Row = Record<string, unknown>;

export interface GwsParam {
  name: string;
  value?: string;
  multiValue?: string[];
  /** The int64 as a number — only when it is a safe integer. */
  intValue?: number;
  /** The int64's exact decimal digits — always present when the wire value is a valid int64. */
  intText?: string;
  boolValue?: boolean;
  /** `messageValue` → one message; `multiMessageValue` → many. Each message is its own list. */
  messages?: GwsParam[][];
}

export type GwsTokenKind = "authorize" | "activity" | "request" | "revoke" | "deny";
export type ScopeTier = "High" | "Medium" | "Low";

export interface GwsTokenReading {
  kind: GwsTokenKind;
  /** The verb slot of the row. */
  posture: string;
  /** The client words — `<app_name> (client <client_id>, <client_type>)`. */
  object: string;
  optional: string[];
  qualifiers: string[];
  severity: Severity;
  mitre: string[];
  client: { id: string; name: string; type: string };
  /** Sorted, deduplicated scope URIs — the union of `scope` and every `scope_data.scope_name`. */
  scopes: string[];
  /** Digest of the scope set; "" when the record carries none. */
  scopeDigest: string;
  productBuckets: string[];
  api: { name: string; method: string };
  /** `num_response_bytes` as its exact decimal digits (an int64 may exceed a safe integer). */
  bytes?: string;
  requester: string;
  requestInfo: string;
  rejection: string;
  /** `|oauth:<kind>|<client_id>|<scope digest>|<api:bytes:bucket>|<request info:requester:rejection>`. */
  keySegment: string;
}

const PARAMS_MAX = 64;
const DEPTH_MAX = 3;
const NAME_MAX = 60;
const CLIENT_ID_MAX = 100;
const TYPE_MAX = 20;
const CLASS_MAX = 40;
const CLASSES_SHOWN = 4;
const WORD_MAX = 80;
const DIGEST_HEX = 16;
const GOOGLE_AUTH = "https://www.googleapis.com/auth/";
const OIDC_SCOPES = new Set(["openid", "email", "profile"]);
const DELEGATED = "APP_REQUEST_TYPE_DELEGATED";

export const AUTHORIZE_NOTE = "authorization recorded; this record does not evidence API use";
export const BYTES_NOTE = "bytes returned are not proof that file contents were downloaded";
export const REQUEST_NOTE = "access requested, not granted by this record";
export const DELEGATED_NOTE = "delegated request — Google does not display the requested scopes";
const NO_SCOPES = "scopes not in this record";

const isObject = (v: unknown): v is Row => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string =>
  typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "";
const getCI = (row: Row, key: string): unknown => {
  if (key in row) return row[key];
  const lower = key.toLowerCase();
  for (const k of Object.keys(row)) if (k.toLowerCase() === lower) return row[k];
  return undefined;
};
const clip = (s: string, max: number): string => (s.length <= max ? s : `${s.slice(0, max - 1)}…`);
const digest = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, DIGEST_HEX);

// ── the typed reader ────────────────────────────────────────────────────────────────────────────

const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;

// The wire type is an int64 carried as a string of digits (a number in some exports). The exact
// digits are kept for the words and the key — 2^53 and 2^53+1 must stay two values — and a
// number is offered only when it is safe.
function readInt(v: unknown): { intText: string; intValue?: number } | undefined {
  const raw =
    typeof v === "number" && Number.isInteger(v) ? String(v) : typeof v === "string" ? v.trim() : "";
  if (!/^[+-]?\d{1,20}$/.test(raw)) return undefined;
  const big = BigInt(raw);
  if (big < INT64_MIN || big > INT64_MAX) return undefined;
  const intText = big.toString();
  const n = Number(intText);
  return Number.isSafeInteger(n) ? { intText, intValue: n } : { intText };
}

function readList(v: unknown, depth: number): GwsParam[] {
  if (!Array.isArray(v)) return [];
  const out: GwsParam[] = [];
  for (const entry of v) {
    if (out.length >= PARAMS_MAX) break;
    if (!isObject(entry)) continue;
    const name = str(getCI(entry, "name")).trim();
    if (!name) continue;
    const param: GwsParam = { name };
    const value = getCI(entry, "value");
    if (typeof value === "string") param.value = value;
    const multi = getCI(entry, "multiValue");
    if (Array.isArray(multi)) param.multiValue = multi.filter((x): x is string => typeof x === "string");
    const int = readInt(getCI(entry, "intValue"));
    if (int) {
      param.intText = int.intText;
      if (int.intValue !== undefined) param.intValue = int.intValue;
    }
    const bool = getCI(entry, "boolValue");
    if (typeof bool === "boolean") param.boolValue = bool;
    if (depth < DEPTH_MAX) {
      const messages: GwsParam[][] = [];
      const single = getCI(entry, "messageValue");
      if (isObject(single)) messages.push(readList(getCI(single, "parameter"), depth + 1));
      const many = getCI(entry, "multiMessageValue");
      if (Array.isArray(many)) {
        for (const m of many) if (isObject(m)) messages.push(readList(getCI(m, "parameter"), depth + 1));
      }
      if (messages.length) param.messages = messages;
    }
    out.push(param);
  }
  return out;
}

/** The event's `parameters[]`, each value read by its wire kind. Malformed input reads as empty. */
export function readGwsParams(event: unknown): GwsParam[] {
  if (!isObject(event)) return [];
  return readList(getCI(event, "parameters"), 1);
}

const find = (params: readonly GwsParam[], name: string): GwsParam | undefined =>
  params.find((p) => p.name.toLowerCase() === name);
const text = (params: readonly GwsParam[], name: string): string => (find(params, name)?.value ?? "").trim();
const list = (params: readonly GwsParam[], name: string): string[] => {
  const p = find(params, name);
  if (!p) return [];
  return [...(p.multiValue ?? []), ...(p.value !== undefined ? [p.value] : [])]
    .map((s) => s.trim())
    .filter(Boolean);
};

// ── the scope table — literal; the highest tier wins ────────────────────────────────────────────
// Every entry is a full scope URI (or an OpenID Connect scope), taken from Google's OAuth scope
// catalogue as of 2026-09: no family shorthand, no prefix match. A scope the table does not
// name is Medium — the conservative reading for a grant whose reach is not classified here —
// and the manual says so. High is content-wide read or write (mail, Drive, Docs, Forms,
// Calendar, Contacts, the Directory and Cloud Identity, Vault, Apps Script, Chat messages);
// Medium is metadata, activity, read-only settings and the People fields; Low is per-file or
// app-data Drive, free/busy, and identity-only scopes.

const tiered = (tier: ScopeTier, names: readonly string[]): Array<[string, ScopeTier]> =>
  names.map((n) => [n.startsWith("https://") || OIDC_SCOPES.has(n) ? n : GOOGLE_AUTH + n, tier]);

export const GWS_SCOPE_TIERS: Readonly<Record<string, ScopeTier>> = Object.fromEntries([
  ...tiered("High", [
    "https://mail.google.com/",
    "gmail.readonly",
    "gmail.modify",
    "gmail.insert",
    "gmail.compose",
    "gmail.send",
    "gmail.settings.basic",
    "gmail.settings.sharing",
    "drive",
    "drive.readonly",
    "drive.meet.readonly",
    "drive.scripts",
    "documents",
    "documents.readonly",
    "spreadsheets",
    "spreadsheets.readonly",
    "presentations",
    "presentations.readonly",
    "forms",
    "forms.body",
    "forms.body.readonly",
    "forms.responses.readonly",
    "calendar",
    "calendar.events",
    "calendar.events.owned",
    "calendar.calendars",
    "calendar.acls",
    "https://www.google.com/calendar/feeds",
    "contacts",
    "contacts.other.readonly",
    "https://www.google.com/m8/feeds",
    "admin.directory.user",
    "admin.directory.user.readonly",
    "admin.directory.user.alias",
    "admin.directory.user.security",
    "admin.directory.userschema",
    "admin.directory.group",
    "admin.directory.group.readonly",
    "admin.directory.group.member",
    "admin.directory.group.member.readonly",
    "admin.directory.orgunit",
    "admin.directory.device.mobile",
    "admin.directory.device.mobile.action",
    "admin.directory.device.chromeos",
    "admin.directory.customer",
    "admin.directory.domain",
    "admin.directory.rolemanagement",
    "admin.reports.audit.readonly",
    "admin.reports.usage.readonly",
    "admin.datatransfer",
    "apps.groups.settings",
    "apps.groups.migration",
    "cloud-identity",
    "cloud-identity.groups",
    "cloud-identity.inboundsso",
    "cloud-identity.policies",
    "ediscovery",
    "ediscovery.readonly",
    "cloud-platform",
    "cloud-platform.read-only",
    "script.projects",
    "script.projects.readonly",
    "script.external_request",
    "script.scriptapp",
    "script.deployments",
    "script.send_mail",
    "chat.messages",
    "chat.messages.readonly",
    "chat.spaces",
    "chat.import",
  ]),
  ...tiered("Medium", [
    "gmail.metadata",
    "gmail.labels",
    "gmail.addons.current.message.readonly",
    "gmail.addons.current.message.metadata",
    "gmail.addons.current.message.action",
    "gmail.addons.current.action.compose",
    "drive.metadata",
    "drive.metadata.readonly",
    "drive.photos.readonly",
    "drive.activity",
    "drive.activity.readonly",
    "calendar.readonly",
    "calendar.events.readonly",
    "calendar.events.owned.readonly",
    "calendar.calendars.readonly",
    "calendar.acls.readonly",
    "calendar.settings.readonly",
    "contacts.readonly",
    "directory.readonly",
    "user.addresses.read",
    "user.birthday.read",
    "user.emails.read",
    "user.gender.read",
    "user.organization.read",
    "user.phonenumbers.read",
    "profile.emails.read",
    "keep",
    "keep.readonly",
    "tasks",
    "tasks.readonly",
    "chat.spaces.readonly",
    "chat.spaces.create",
    "chat.messages.create",
    "chat.memberships",
    "chat.memberships.readonly",
    "chat.delete",
    "chat.bot",
    "admin.directory.orgunit.readonly",
    "admin.directory.device.mobile.readonly",
    "admin.directory.device.chromeos.readonly",
    "admin.directory.customer.readonly",
    "admin.directory.domain.readonly",
    "admin.directory.rolemanagement.readonly",
    "admin.directory.resource.calendar",
    "admin.directory.resource.calendar.readonly",
    "admin.datatransfer.readonly",
    "apps.licensing",
    "apps.alerts",
    "apps.order",
    "admin.chrome.printers",
    "cloud-identity.groups.readonly",
    "cloud-identity.devices",
    "cloud-identity.devices.readonly",
    "cloud-identity.devices.lookup",
    "cloud-identity.userinvitations",
    "cloud-identity.orgunits",
    "script.deployments.readonly",
    "script.processes",
    "script.metrics",
    "script.webapp.deploy",
  ]),
  ...tiered("Low", [
    "drive.file",
    "drive.appdata",
    "drive.install",
    "drive.apps.readonly",
    "calendar.events.public.readonly",
    "calendar.freebusy",
    "calendar.app.created",
    "script.container.ui",
    "script.locale",
    "script.storage",
    "openid",
    "email",
    "profile",
    "userinfo.email",
    "userinfo.profile",
    "profile.agerange.read",
    "profile.language.read",
  ]),
]);

/** The tier of one scope URI; a scope not in the table is Medium (conservative). */
export function scopeTier(scope: string): ScopeTier {
  return GWS_SCOPE_TIERS[scope.trim().toLowerCase()] ?? "Medium";
}

const RANK: Record<ScopeTier, number> = { Low: 0, Medium: 1, High: 2 };

function highestTier(scopes: readonly string[]): ScopeTier {
  return scopes.reduce<ScopeTier>((best, s) => {
    const t = scopeTier(s);
    return RANK[t] > RANK[best] ? t : best;
  }, "Low");
}

/** The short form shown in a row: the Google prefix stripped, bounded. */
const scopeClass = (scope: string): string =>
  clip(
    scope.startsWith(GOOGLE_AUTH) ? scope.slice(GOOGLE_AUTH.length) : scope.replace(/^https:\/\//, ""),
    CLASS_MAX,
  );

function scopeWords(scopes: readonly string[]): string {
  const shown = scopes.slice(0, CLASSES_SHOWN).map(scopeClass).join(", ");
  const more = scopes.length > CLASSES_SHOWN ? ` (+${scopes.length - CLASSES_SHOWN})` : "";
  return `${shown}${more}`;
}

const countWords = (scopes: readonly string[]): string =>
  scopes.length
    ? `for ${scopes.length} scope${scopes.length === 1 ? "" : "s"}: ${scopeWords(scopes)}`
    : NO_SCOPES;

// ── the decoder ─────────────────────────────────────────────────────────────────────────────────

function readScopes(params: readonly GwsParam[]): { scopes: string[]; buckets: string[] } {
  const scopes = new Set(list(params, "scope"));
  const buckets = new Set(list(params, "product_bucket"));
  for (const message of find(params, "scope_data")?.messages ?? []) {
    for (const s of list(message, "scope_name")) scopes.add(s);
    for (const b of list(message, "product_bucket")) buckets.add(b);
  }
  return { scopes: [...scopes].sort(), buckets: [...buckets].sort() };
}

function clientWords(client: { id: string; name: string; type: string }, withType: boolean): string {
  const name = clip(client.name, NAME_MAX);
  const id = clip(client.id, CLIENT_ID_MAX);
  const type = withType && client.type ? `, ${clip(client.type, TYPE_MAX)}` : "";
  if (!id) return name ? `${name} (client id not in this record)` : "client id not in this record";
  return name ? `${name} (client ${id}${type})` : `client ${id}${type}`;
}

/**
 * Decode one `token` application event, or null when the name is not one of the five the
 * application records. Every claim is bounded to what the record carries.
 */
export function decodeGwsToken(eventName: string, params: readonly GwsParam[]): GwsTokenReading | null {
  const kind = eventName.trim().toLowerCase();
  if (!["authorize", "activity", "request", "revoke", "deny"].includes(kind)) return null;
  const client = {
    id: text(params, "client_id"),
    name: text(params, "app_name"),
    type: text(params, "client_type"),
  };
  const { scopes, buckets } = readScopes(params);
  const scopeDigest = scopes.length ? digest(scopes.join("\n")) : "";
  const api = { name: text(params, "api_name"), method: text(params, "method_name") };
  const bytes = find(params, "num_response_bytes")?.intText;
  const requester = text(params, "requester_email");
  const requestInfo = text(params, "app_request_info");
  const rejection = text(params, "rejection_type");
  const base = {
    client,
    scopes,
    scopeDigest,
    productBuckets: buckets,
    api,
    ...(bytes !== undefined ? { bytes } : {}),
    requester,
    requestInfo,
    rejection,
  };
  const apiPart =
    kind === "activity"
      ? `${[api.name, api.method].filter(Boolean).join(".")}:${bytes ?? ""}:${buckets.join(",")}`
      : "";
  const reqPart = kind === "request" || kind === "deny" ? `${requestInfo}:${requester}:${rejection}` : "";
  const keySegment = `|oauth:${kind}|${client.id}|${scopeDigest}|${apiPart}|${reqPart}`;

  if (kind === "authorize") {
    const tier: ScopeTier = scopes.length ? highestTier(scopes) : "High";
    return {
      ...base,
      kind,
      posture: "authorises",
      object: clientWords(client, true),
      optional: [countWords(scopes)],
      qualifiers: [AUTHORIZE_NOTE],
      severity: tier,
      mitre: tier === "High" ? ["T1528"] : [],
      keySegment,
    };
  }
  if (kind === "activity") {
    const method = [api.name, api.method].filter(Boolean).join(".");
    return {
      ...base,
      kind,
      posture: `API call ${method ? clip(method, WORD_MAX) : "(method not in this record)"}`,
      object: `by ${clientWords(client, false)}`,
      optional: [
        ...(bytes !== undefined ? [`${bytes} bytes returned`] : []),
        ...(buckets.length ? [`product ${clip(buckets.join(", "), WORD_MAX)}`] : []),
      ],
      qualifiers: bytes !== undefined ? [BYTES_NOTE] : [],
      severity: "Info",
      mitre: [],
      keySegment,
    };
  }
  if (kind === "request") {
    const delegated = requestInfo === DELEGATED;
    return {
      ...base,
      kind,
      posture: "requests access:",
      object: clientWords(client, true),
      optional: [
        ...(delegated ? [DELEGATED_NOTE] : [countWords(scopes)]),
        ...(requester ? [`requester ${clip(requester, WORD_MAX)}`] : []),
        ...(requestInfo && !delegated ? [clip(requestInfo, WORD_MAX)] : []),
      ],
      qualifiers: [REQUEST_NOTE],
      severity: "Low",
      mitre: [],
      keySegment,
    };
  }
  if (kind === "deny") {
    return {
      ...base,
      kind,
      posture: "denied access:",
      object: clientWords(client, true),
      optional: [rejection ? `rejection ${clip(rejection, WORD_MAX)}` : "rejection type not in this record"],
      qualifiers: [],
      severity: "Low",
      mitre: [],
      keySegment,
    };
  }
  return {
    ...base,
    kind: "revoke",
    posture: "revokes",
    object: clientWords(client, false),
    optional: scopes.length ? [`scopes: ${scopeWords(scopes)}`] : [],
    qualifiers: [],
    severity: "Low",
    mitre: [],
    keySegment,
  };
}
