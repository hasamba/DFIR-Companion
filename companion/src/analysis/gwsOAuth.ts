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
  intValue?: number;
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
  bytes?: number;
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

function readInt(v: unknown): number | undefined {
  if (typeof v === "number") return Number.isFinite(v) ? v : undefined;
  if (typeof v === "string" && /^-?\d{1,18}$/.test(v.trim())) return Number(v.trim());
  return undefined;
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
    if (int !== undefined) param.intValue = int;
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

// ── the scope table — literal, exhaustive; the highest tier wins ────────────────────────────────

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
    "documents",
    "documents.readonly",
    "spreadsheets",
    "spreadsheets.readonly",
    "presentations",
    "presentations.readonly",
    "calendar",
    "calendar.events",
    "calendar.acls",
    "contacts",
    "contacts.other.readonly",
    "admin.directory.user",
    "admin.directory.user.readonly",
    "admin.directory.group",
    "admin.directory.group.readonly",
    "admin.directory.orgunit",
    "admin.directory.device.mobile",
    "admin.directory.device.chromeos",
    "admin.directory.customer",
    "admin.directory.domain",
    "admin.directory.rolemanagement",
    "admin.reports.audit.readonly",
    "admin.reports.usage.readonly",
    "apps.groups.settings",
    "ediscovery",
    "cloud-platform",
    "script.projects",
    "script.external_request",
    "script.scriptapp",
    "script.deployments",
    "chat.messages",
    "chat.messages.readonly",
    "chat.spaces",
  ]),
  ...tiered("Medium", [
    "gmail.metadata",
    "gmail.labels",
    "drive.metadata",
    "drive.metadata.readonly",
    "drive.photos.readonly",
    "drive.activity",
    "drive.activity.readonly",
    "calendar.readonly",
    "calendar.events.readonly",
    "calendar.settings.readonly",
    "contacts.readonly",
    "keep",
    "keep.readonly",
    "tasks",
    "tasks.readonly",
    "chat.spaces.readonly",
    "directory.readonly",
    "user.addresses.read",
    "user.birthday.read",
    "user.emails.read",
    "user.phonenumbers.read",
  ]),
  ...tiered("Low", [
    "drive.file",
    "drive.appdata",
    "drive.install",
    "openid",
    "email",
    "profile",
    "userinfo.email",
    "userinfo.profile",
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
  const bytes = find(params, "num_response_bytes")?.intValue;
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
