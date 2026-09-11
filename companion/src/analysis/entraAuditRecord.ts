import { createHash } from "node:crypto";

// Local shape helpers: this module sits in the detect tier and must not import the ingest tier.
const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string =>
  typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "";
const getCI = (row: Record<string, unknown>, key: string): unknown => {
  if (key in row) return row[key];
  const lower = key.toLowerCase();
  for (const k of Object.keys(row)) if (k.toLowerCase() === lower) return row[k];
  return undefined;
};

// One normalised view of an Entra directory-audit record, from either export shape (#931 item 1):
// the Graph `directoryAudits` object (`activityDisplayName`, `initiatedBy`, `targetResources[]` each
// with `modifiedProperties[]`) and the Unified Audit Log's AzureActiveDirectory record (`Operation`,
// `Actor[]`, `Target[]`, top-level `ModifiedProperties[]`). The UAL identity arrays are read by the
// SHAPE of each entry — a GUID is an object id, an address with `@` is a UPN, a type-label word
// (`User`, `ServicePrincipal`, …) types the entries before it — never by the numeric `Type` code,
// which is not documented as stable.
//
// Property values arrive JSON-encoded in the Graph shape (`"[\"a\"]"`, `"\"x\""`, `"true"`) and either
// encoded or plain in UAL; every value is bounded before it is parsed, and an over-bound value is
// unreadable — its digest still identifies the row.

type Row = Record<string, unknown>;

export interface EntraTarget {
  type: string;
  id: string;
  name: string;
  upn: string;
}

export interface EntraProp {
  name: string;
  oldValue: unknown;
  newValue: unknown;
  /** Digest of the bounded raw new value — the row's identity when the value cannot be read. */
  rawDigest: string;
  unreadable: boolean;
  /** Which target the property belonged to (Graph shape); -1 for a top-level property (UAL). */
  targetIndex: number;
}

export interface EntraInitiator {
  kind: "user" | "app" | "unknown";
  id: string;
  upn: string;
  appId: string;
  name: string;
  ip: string;
}

export interface EntraAuditRecord {
  shape: "graph" | "ual";
  /** Normalised: dash variants → `-`, whitespace collapsed, trailing period stripped. */
  operation: string;
  /** Graph's four-valued result plus absent: a timeout is not a failure, and unknownFutureValue is not either. */
  outcome: "success" | "failure" | "timeout" | "unknownFutureValue" | "unknown";
  tenant: string;
  recordId: string;
  time: string;
  initiator: EntraInitiator;
  targets: EntraTarget[];
  props: EntraProp[];
}

export interface KeyDescription {
  keyId: string;
  keyType: string;
  usage: string;
  displayName: string;
}

export interface ConsentEntry {
  id: string;
  clientId: string;
  principalId: string;
  resourceId: string;
  consentType: string;
  scopes: string[];
}

const VALUE_MAX = 4096;
const DIGEST_HEX = 16;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TYPE_LABELS = new Set([
  "user",
  "serviceprincipal",
  "application",
  "role",
  "group",
  "directory",
  "policy",
  "device",
  "other",
]);

const digest = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, DIGEST_HEX);
export const isGuid = (s: string): boolean => GUID.test(s.trim());

/** Microsoft's operation literals use an ASCII hyphen; exports vary the dash and the spacing. */
export function normalizeOperation(op: string): string {
  return op
    .replace(/[‐-―−]/g, "-")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\.$/, "");
}

/** JSON first (the documented encoding), the trimmed text otherwise; bounded before either. */
export function parseAuditValue(v: unknown): { value: unknown; unreadable: boolean; rawDigest: string } {
  const text = typeof v === "string" ? v : v === undefined || v === null ? "" : JSON.stringify(v);
  const rawDigest = digest(text);
  if (text.length > VALUE_MAX) return { value: null, unreadable: true, rawDigest };
  if (typeof v !== "string") return { value: v ?? null, unreadable: false, rawDigest };
  const t = v.trim();
  if (!t) return { value: "", unreadable: false, rawDigest };
  try {
    return { value: JSON.parse(t), unreadable: false, rawDigest };
  } catch {
    return { value: t, unreadable: false, rawDigest };
  }
}

const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : typeof v === "string" ? [v] : [];

// `[KeyIdentifier=…,KeyType=…,KeyUsage=…,DisplayName=…]` — one string per credential. Only the four
// named fields are read; anything else in the bracket is dropped, never rendered, never hashed.
export function parseKeyDescriptions(v: unknown): KeyDescription[] {
  return strings(v)
    .map((s) => {
      const m = /^\s*\[(.*)\]\s*$/s.exec(s);
      if (!m) return null;
      const fields = new Map<string, string>();
      for (const part of m[1].split(/,(?=\s*[A-Za-z]+=)/)) {
        const eq = part.indexOf("=");
        if (eq > 0) fields.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim());
      }
      const keyId = fields.get("keyidentifier") ?? "";
      if (!keyId) return null;
      return {
        keyId,
        keyType: fields.get("keytype") ?? "",
        usage: fields.get("keyusage") ?? "",
        displayName: fields.get("displayname") ?? "",
      };
    })
    .filter((k): k is KeyDescription => k !== null);
}

// `[] => [[Id: …, ClientId: …, PrincipalId: …, ResourceId: …, ConsentType: …, Scope: a b c, …]]` —
// the composite form of ConsentAction.Permissions. Each `[...]` entry is a list of `Key: value`
// pairs; the Scope value is a space-separated list.
export function parseConsentPermissions(v: unknown): ConsentEntry[] {
  const text = typeof v === "string" ? v : strings(v).join(" ");
  const after = text.includes("=>") ? text.slice(text.lastIndexOf("=>") + 2) : text;
  const entries: ConsentEntry[] = [];
  const re = /\[([^[\]]*)\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(after)) !== null) {
    const body = m[1];
    if (!/\b(?:Id|ClientId|ResourceId|Scope|ConsentType)\s*:/i.test(body)) continue;
    const fields = new Map<string, string>();
    for (const part of body.split(/,(?=\s*[A-Za-z]+\s*:)/)) {
      const colon = part.indexOf(":");
      if (colon > 0) fields.set(part.slice(0, colon).trim().toLowerCase(), part.slice(colon + 1).trim());
    }
    entries.push({
      id: fields.get("id") ?? "",
      clientId: fields.get("clientid") ?? "",
      principalId: fields.get("principalid") ?? "",
      resourceId: fields.get("resourceid") ?? "",
      consentType: fields.get("consenttype") ?? "",
      scopes: (fields.get("scope") ?? "").split(/\s+/).filter(Boolean),
    });
  }
  return entries;
}

function outcomeOf(result: string): EntraAuditRecord["outcome"] {
  const r = result.trim().toLowerCase();
  if (/^(success|succeeded|successful|ok)$/.test(r)) return "success";
  if (/^(failure|failed)$/.test(r)) return "failure";
  if (r === "timeout") return "timeout";
  if (r === "unknownfuturevalue") return "unknownFutureValue";
  return "unknown";
}

/** The outcome as a word next to the posture: a change that is not a success is an attempt. */
export function outcomeWord(outcome: EntraAuditRecord["outcome"]): string {
  return outcome === "success"
    ? ""
    : outcome === "failure"
      ? "failed"
      : outcome === "timeout"
        ? "timed out"
        : "result unknown";
}

function prop(
  raw: unknown,
  targetIndex: number,
  nameKey: string,
  oldKey: string,
  newKey: string,
): EntraProp | null {
  if (!isObject(raw)) return null;
  const name = str(getCI(raw, nameKey)).trim();
  if (!name) return null;
  const nv = parseAuditValue(getCI(raw, newKey));
  const ov = parseAuditValue(getCI(raw, oldKey));
  return {
    name,
    oldValue: ov.value,
    newValue: nv.value,
    rawDigest: nv.rawDigest,
    unreadable: nv.unreadable || ov.unreadable,
    targetIndex,
  };
}

function readGraph(rec: Row): EntraAuditRecord {
  const by = getCI(rec, "initiatedBy");
  const user = isObject(by) ? getCI(by, "user") : undefined;
  const app = isObject(by) ? getCI(by, "app") : undefined;
  const initiator: EntraInitiator =
    isObject(app) && (str(getCI(app, "servicePrincipalId")) || str(getCI(app, "appId")))
      ? {
          kind: "app",
          id: str(getCI(app, "servicePrincipalId")),
          upn: "",
          appId: str(getCI(app, "appId")),
          name: str(getCI(app, "displayName")),
          ip: "",
        }
      : isObject(user) && (str(getCI(user, "id")) || str(getCI(user, "userPrincipalName")))
        ? {
            kind: "user",
            id: str(getCI(user, "id")),
            upn: str(getCI(user, "userPrincipalName")),
            appId: "",
            name: str(getCI(user, "displayName")),
            ip: str(getCI(user, "ipAddress")),
          }
        : { kind: "unknown", id: "", upn: "", appId: "", name: "", ip: "" };
  const rawTargets = getCI(rec, "targetResources");
  const targets: EntraTarget[] = [];
  const props: EntraProp[] = [];
  (Array.isArray(rawTargets) ? rawTargets : []).forEach((t, i) => {
    if (!isObject(t)) return;
    targets.push({
      type: str(getCI(t, "type")),
      id: str(getCI(t, "id")),
      name: str(getCI(t, "displayName")),
      upn: str(getCI(t, "userPrincipalName")),
    });
    const mp = getCI(t, "modifiedProperties");
    for (const p of Array.isArray(mp) ? mp : []) {
      const parsed = prop(p, i, "displayName", "oldValue", "newValue");
      if (parsed) props.push(parsed);
    }
  });
  return {
    shape: "graph",
    operation: normalizeOperation(str(getCI(rec, "activityDisplayName"))),
    outcome: outcomeOf(str(getCI(rec, "result"))),
    tenant: str(getCI(rec, "tenantId")),
    recordId: str(getCI(rec, "id")),
    time: str(getCI(rec, "activityDateTime")),
    initiator,
    targets,
    props,
  };
}

// UAL Actor/Target arrays: `[{ID, Type}, …]`. Grouped into identities by SHAPE: a type-label word
// closes the group of entries before it; a GUID is an object id; an address is a UPN; any other
// text is a name.
function readIdentities(raw: unknown): EntraTarget[] {
  const out: EntraTarget[] = [];
  let cur: EntraTarget = { type: "", id: "", name: "", upn: "" };
  let open = false;
  for (const e of Array.isArray(raw) ? raw : []) {
    const id = isObject(e) ? str(getCI(e, "ID")) || str(getCI(e, "Id")) : "";
    if (!id) continue;
    const lower = id.trim().toLowerCase();
    if (TYPE_LABELS.has(lower)) {
      cur.type = id.trim();
      continue;
    }
    if (isGuid(id)) {
      if (cur.id) {
        out.push(cur);
        cur = { type: cur.type, id: "", name: "", upn: "" };
      }
      cur.id = id.trim();
    } else if (id.includes("@")) cur.upn = id.trim();
    else cur.name = id.trim();
    open = true;
  }
  if (open && (cur.id || cur.upn || cur.name)) out.push(cur);
  return out;
}

function readUal(rec: Row): EntraAuditRecord {
  const actors = readIdentities(getCI(rec, "Actor"));
  const actor = actors[0];
  const actorIsApp = actors.some((a) => /^(serviceprincipal|application)$/i.test(a.type));
  const initiator: EntraInitiator = actor
    ? {
        kind: actorIsApp ? "app" : actor.upn || /^user$/i.test(actor.type) ? "user" : "unknown",
        id: actor.id,
        upn: actor.upn,
        appId: "",
        name: actor.name,
        ip: str(getCI(rec, "ActorIpAddress")) || str(getCI(rec, "ClientIP")),
      }
    : { kind: "unknown", id: "", upn: "", appId: "", name: "", ip: str(getCI(rec, "ActorIpAddress")) };
  const props: EntraProp[] = [];
  const mp = getCI(rec, "ModifiedProperties");
  for (const p of Array.isArray(mp) ? mp : []) {
    const parsed = prop(p, -1, "Name", "OldValue", "NewValue");
    if (parsed) props.push(parsed);
  }
  return {
    shape: "ual",
    operation: normalizeOperation(str(getCI(rec, "Operation")) || str(getCI(rec, "Operations"))),
    outcome: outcomeOf(str(getCI(rec, "ResultStatus"))),
    tenant: str(getCI(rec, "OrganizationId")) || str(getCI(rec, "TargetContextId")),
    recordId: str(getCI(rec, "Id")),
    time: str(getCI(rec, "CreationTime")) || str(getCI(rec, "CreationDate")),
    initiator,
    targets: readIdentities(getCI(rec, "Target")),
    props,
  };
}

/** True for a UAL record that carries Entra directory-audit detail. */
export function isEntraUalRecord(rec: Row): boolean {
  return (
    /^azureactivedirectory/i.test(str(getCI(rec, "Workload"))) &&
    (Array.isArray(getCI(rec, "ModifiedProperties")) || Array.isArray(getCI(rec, "Target")))
  );
}

/** Read either shape; null when the row is neither. */
export function readEntraAuditRecord(rec: Row): EntraAuditRecord | null {
  if (getCI(rec, "activityDisplayName") !== undefined) return readGraph(rec);
  if (isEntraUalRecord(rec)) return readUal(rec);
  return null;
}
