// Azure RBAC role assignment reading — what a `Microsoft.Authorization/roleAssignments/write` or
// `/delete` Activity Log record actually granted. The record's own title names only the caller and
// the assignment id; the substance (which role, to whom, at which scope) sits in the request body
// of the BeginRequest row, and the EndRequest row carries only the HTTP status. This module turns
// both into a short title phrase, a one-fact-per-line message for the [details] panel, and an
// aggregation-key segment so two different grants by one caller never fold into one row.
//
// The request body is adversary-reachable: anyone who can write a role assignment chooses its
// text. It is length-capped before JSON.parse, parsed in a try, shape-checked, and every string
// shown is neutralised (brackets, control, format and bidi characters) and bounded. Never throws.

import { getCI, getPath, isObject, str } from "./siemImport.js";
import { showToken } from "./recordIdentity.js";
import { FORMAT_CHARS } from "./bidiControl.js";
import { azureRoleName } from "./azureBuiltInRoles.js";

type Row = Record<string, unknown>;

/** A request body longer than this is not parsed: a real role assignment body is under 2 KB. */
export const ROLE_BODY_MAX = 64 * 1024;
const KEY_PART_MAX = 400;
const ROLE_ASSIGNMENT_OP = /microsoft\.authorization\/roleassignments\/(write|delete)$/i;
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface AzureRoleAssignmentReading {
  /** Replaces the ` on roleAssignments/<id>` title tail; absent when the body did not decode. */
  titleSuffix?: string;
  /** One fact per line, for the event's message. */
  message: string;
  /** Appended to the aggregation key: the assignment id, and role + principal + scope when decoded. */
  keySegment: string;
}

/** The request body under any of the spellings the Activity Log exports use. */
export function azureRequestBody(rec: Row): unknown {
  return (
    getPath(rec, "properties.requestbody") ??
    getPath(rec, "properties.requestBody") ??
    getPath(rec, "Properties.requestbody") ??
    getPath(rec, "Properties.requestBody")
  );
}

const safe = (v: string, max: number): string => {
  const shown = showToken(v.replace(FORMAT_CHARS, ""));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};

function firstStr(rec: Row, keys: string[]): string {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(rec, k) : getCI(rec, k);
    if (typeof v === "string" || typeof v === "number") {
      const s = String(v).trim();
      if (s) return s;
    }
  }
  return "";
}

const lastSegment = (s: string): string => s.replace(/\/+$/, "").split("/").pop() ?? "";

type Body = { state: "absent" } | { state: "bad" } | { state: "ok"; props: Row; id: string };

function parseBody(raw: unknown): Body {
  if (raw === undefined || raw === null || raw === "") return { state: "absent" };
  let o: unknown = raw;
  if (typeof raw === "string") {
    if (raw.length > ROLE_BODY_MAX) return { state: "bad" };
    try {
      o = JSON.parse(raw);
    } catch {
      return { state: "bad" };
    }
  }
  if (!isObject(o) || Array.isArray(o)) return { state: "bad" };
  const inner = getCI(o, "properties");
  const props = isObject(inner) && !Array.isArray(inner) ? inner : o;
  const role = getCI(props, "roleDefinitionId");
  const principal = getCI(props, "principalId");
  if (typeof role !== "string" && typeof principal !== "string") return { state: "bad" };
  return { state: "ok", props, id: str(getCI(o, "id")).trim() };
}

/** A role assignment scope shortened to its kind and id, for the title. */
export function shortAzureScope(scope: string): string {
  const s = scope.trim();
  if (s === "/") return "tenant root /";
  const mg = /^\/providers\/microsoft\.management\/managementgroups\/([^/]+)\/?$/i.exec(s);
  if (mg) return `management group ${mg[1]}`;
  const sub = /^\/subscriptions\/([^/]+)\/?$/i.exec(s);
  if (sub) return `subscription ${sub[1]}`;
  const rg = /^\/subscriptions\/[^/]+\/resourcegroups\/([^/]+)\/?$/i.exec(s);
  if (rg) return `resource group ${rg[1]}`;
  const parts = s.replace(/\/+$/, "").split("/").filter(Boolean);
  return parts.length >= 2 ? `resource ${parts.slice(-2).join("/")}` : s;
}

function assignmentId(rec: Row, body: Body): string {
  if (body.state === "ok" && body.id) return lastSegment(body.id);
  const res = firstStr(rec, ["resourceId", "ResourceId"]);
  const m = /\/roleassignments\/([^/]+)/i.exec(res);
  return m ? m[1] : "";
}

function bodyNote(body: Body, isEnd: boolean): string | undefined {
  if (body.state === "bad")
    return `The request body could not be read (malformed, or over ${ROLE_BODY_MAX} characters).`;
  if (body.state === "absent")
    return isEnd
      ? "The request body is on the matching Begin request row (same correlationId)."
      : "The request body is not in this record.";
  return undefined;
}

/**
 * Read a role assignment write/delete record. Null for every other operation, so no other
 * operation's output changes.
 */
export function decodeAzureRoleAssignment(op: string, rec: Row): AzureRoleAssignmentReading | null {
  const opMatch = ROLE_ASSIGNMENT_OP.exec(op.trim());
  if (!opMatch) return null;
  const removes = opMatch[1].toLowerCase() === "delete";
  let body: Body;
  try {
    body = parseBody(azureRequestBody(rec));
  } catch {
    body = { state: "bad" };
  }
  const eventName = firstStr(rec, ["eventName.value", "eventName", "EventName", "EventNameValue"]);
  const isEnd = /endrequest$/i.test(eventName);
  const status = firstStr(rec, ["properties.statusCode", "Properties.statusCode"]);
  const id = assignmentId(rec, body);

  const lines: string[] = [];
  let titleSuffix: string | undefined;
  let keySegment = "";
  if (body.state === "ok") {
    const p = body.props;
    const roleRaw = lastSegment(str(getCI(p, "roleDefinitionId")).trim());
    const principalRaw = str(getCI(p, "principalId")).trim();
    const scopeRaw = str(getCI(p, "scope")).trim();
    const typeRaw = str(getCI(p, "principalType")).trim();
    const conditionRaw = str(getCI(p, "condition")).trim();
    const descRaw = str(getCI(p, "description")).trim();
    const roleName = GUID_RE.test(roleRaw) ? azureRoleName(roleRaw) : undefined;
    const role = roleRaw ? safe(roleRaw, 120) : "";
    const roleLabel = roleName ?? `custom or unlisted role ${role}`;
    const principal = safe(principalRaw, 80);
    if (role) lines.push(roleName ? `Role: ${roleName} (${role})` : `Role: ${roleLabel}`);
    if (principal)
      lines.push(
        `${removes ? "Removed from" : "Assigned to"}: ${principal}${typeRaw ? ` (${safe(typeRaw, 40)})` : ""}`,
      );
    if (scopeRaw) lines.push(`Scope: ${safe(scopeRaw, 400)}`);
    if (role) {
      const who = principal ? (removes ? ` from ${principal}` : ` → ${principal}`) : "";
      const where = scopeRaw ? ` at ${safe(shortAzureScope(scopeRaw), 200)}` : "";
      titleSuffix = `: ${removes ? "removes " : ""}${roleLabel}${who}${where}`;
      keySegment = `|ra|${roleRaw.slice(0, KEY_PART_MAX)}|${principalRaw.slice(0, KEY_PART_MAX)}|${scopeRaw.slice(0, KEY_PART_MAX)}`;
    }
    if (id) lines.push(`Assignment id: ${safe(id, 120)}`);
    if (conditionRaw) lines.push(`Condition: ${safe(conditionRaw, 400)}`);
    if (descRaw) lines.push(`Description: ${safe(descRaw, 200)}`);
  } else if (id) {
    lines.push(`Assignment id: ${safe(id, 120)}`);
  }
  if (status) lines.push(`HTTP status: ${safe(status, 40)}`);
  const note = bodyNote(body, isEnd);
  if (note) lines.push(note);
  // The assignment id is in every row's resource id, so two bodiless End rows for two different
  // assignments by one caller stay two rows as well.
  if (id) keySegment += `|ra-id|${id.slice(0, KEY_PART_MAX)}`;
  return { ...(titleSuffix ? { titleSuffix } : {}), message: lines.join("\n"), keySegment };
}
