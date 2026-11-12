import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import type { EntraAuditRecord, EntraProp, EntraTarget } from "./entraAuditRecord.js";
import { additionalDetailUpdates, parseLicence, type Licence } from "./entraLicenceDetail.js";

// Entra directory changes graded by the property delta the record itself holds (#2604). The
// operation name says nothing ("Update user" is the most common change in any tenant), so only a
// parsed, structurally valid old AND new value grades, compared as real add/remove sets — never a
// substring of the raw text:
//   - Update user: StrongAuthenticationRequirement from a non-empty list to `[]` clears the
//     per-user MFA requirement — High, T1556.006 (the same grade as "Disable Strong Authentication").
//   - Update user / Change user license: a licence's DisabledPlans gaining a plan named
//     *ADVANCED_AUDITING*, for a SKU the prior value also lists — Medium, T1562.008. Read from the
//     Graph `AssignedLicense` property and, on a UAL record, from additionalDetails
//     (entraLicenceDetail.ts). A licence with no parsed prior value proves no change.
//   - Update authorization policy: PermissionGrantPolicyIdsAssignedToDefaultUserRole gaining a
//     `ManagePermissionGrantsForSelf.*` policy lets every user consent to apps — Medium, T1528.
// Each target is read against its own properties (Graph), and each signal is its own row whose key
// holds the property and the delta, so it never folds with a routine change. A result that is not
// a success is an attempt: Medium, no technique, never the completed verb. Pure.

const NAME_MAX = 60;
const LIST_MAX = 4096;
const MFA = "StrongAuthenticationRequirement";
const CONSENT = "PermissionGrantPolicyIdsAssignedToDefaultUserRole";
const SELF_CONSENT = /^ManagePermissionGrantsForSelf\.\S+$/i;
const AUDIT_PLAN = /ADVANCED_AUDITING/i;
const ATTEMPT_NOTE = "not confirmed applied";

/** One graded setting change — the fields the audit importer renders, like a decoded app change. */
export interface EntraSettingSignal {
  posture: string;
  object: string;
  words: string;
  qualifiers: string[];
  severity: Severity;
  mitre: string[];
  /** The WHOLE aggregation key — the importer bounds it. */
  aggKey: string;
  subject: { id: string; name: string };
  resource: { id: string; name: string; api: string };
  role: null;
  /** The changed object — the user (an account) or the policy — for the row's envelope. */
  target: { kind: "account" | "cloud_principal" | "other"; id: string; name: string };
}

interface Reading {
  property: string;
  verb: string;
  infinitive: string;
  words: string;
  severity: Severity;
  mitre: string[];
  delta: string;
}

interface Group {
  target: EntraTarget | undefined;
  props: EntraProp[];
}

const digest = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 16);
const label = (t: EntraTarget | undefined): string => (t?.upn || t?.name || t?.id || "").slice(0, NAME_MAX);

/** A list value: an array, or a JSON array encoded once more as a string (Graph). Null otherwise. */
function asList(v: unknown): unknown[] | null {
  if (Array.isArray(v)) return v;
  if (typeof v !== "string" || v.length > LIST_MAX || !v.trim().startsWith("[")) return null;
  try {
    const parsed: unknown = JSON.parse(v);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
const asStrings = (v: unknown): string[] | null => {
  const l = asList(v);
  return l && l.every((x) => typeof x === "string") ? l : null;
};
const propNamed = (g: Group, name: string): EntraProp | undefined =>
  g.props.find((p) => p.name.toLowerCase() === name.toLowerCase() && !p.unreadable);

function mfaCleared(g: Group): Reading | null {
  const p = propNamed(g, MFA);
  const before = p ? asList(p.oldValue) : null;
  const after = p ? asList(p.newValue) : null;
  if (!before || !after || !before.length || after.length) return null;
  if (!before.every((x) => typeof x === "object" && x !== null && !Array.isArray(x))) return null;
  return {
    property: MFA,
    verb: `clears the per-user MFA requirement (${MFA} → [])`,
    infinitive: `clear the per-user MFA requirement (${MFA} → [])`,
    words: "",
    severity: "High",
    mitre: ["T1556.006"],
    delta: "cleared",
  };
}

function consentOpened(g: Group): Reading | null {
  const p = propNamed(g, CONSENT);
  const before = p ? asStrings(p.oldValue) : null;
  const after = p ? asStrings(p.newValue) : null;
  if (!before || !after) return null;
  const had = new Set(before.map((x) => x.trim().toLowerCase()));
  const added = after.map((x) => x.trim()).filter((x) => SELF_CONSENT.test(x) && !had.has(x.toLowerCase()));
  if (!added.length) return null;
  return {
    property: CONSENT,
    verb: "lets every user consent to apps for themselves",
    infinitive: "let every user consent to apps for themselves",
    words: `adds ${added.join(", ")} to the default user role`,
    severity: "Medium",
    mitre: ["T1528"],
    delta: added.map((x) => x.toLowerCase()).join(","),
  };
}

const licences = (v: unknown): Licence[] | null => {
  const list = asList(v);
  if (!list) return null;
  const parsed = list.map(parseLicence);
  return parsed.every((l): l is Licence => l !== null) ? parsed : null;
};

function auditPlanDisabled(updates: { oldValue: unknown; newValue: unknown }[]): Reading | null {
  for (const u of updates) {
    const before = licences(u.oldValue);
    const after = licences(u.newValue);
    if (!before || !after) continue;
    for (const now of after) {
      const prior = before.find((b) => b.skuId === now.skuId);
      if (!prior) continue;
      const had = new Set(prior.disabledPlans.map((x) => x.toLowerCase()));
      const added = now.disabledPlans.filter((x) => AUDIT_PLAN.test(x) && !had.has(x.toLowerCase()));
      if (!added.length) continue;
      const sku = now.skuName ? ` (${now.skuName.slice(0, NAME_MAX)})` : "";
      return {
        property: "AssignedLicense",
        verb: "disables the advanced auditing plan in a licence",
        infinitive: "disable the advanced auditing plan in a licence",
        words: `DisabledPlans adds ${added.join(", ")}${sku}`,
        severity: "Medium",
        mitre: ["T1562.008"],
        delta: `${now.skuId}:${added.map((x) => x.toLowerCase()).join(",")}`,
      };
    }
  }
  return null;
}

function groupsOf(r: EntraAuditRecord): Group[] {
  if (r.shape === "graph")
    return r.targets.map((target, i) => ({ target, props: r.props.filter((p) => p.targetIndex === i) }));
  return [{ target: r.targets[0], props: r.props }];
}

function readingsOf(op: string, g: Group, details: { oldValue: unknown; newValue: unknown }[]): Reading[] {
  if (op === "update authorization policy") return [consentOpened(g)].filter((x): x is Reading => !!x);
  const licence = propNamed(g, "AssignedLicense");
  const updates = [...(licence ? [licence] : []), ...details];
  if (op === "change user license") return [auditPlanDisabled(updates)].filter((x): x is Reading => !!x);
  if (op !== "update user") return [];
  return [mfaCleared(g), auditPlanDisabled(updates)].filter((x): x is Reading => !!x);
}

function signal(r: EntraAuditRecord, g: Group, x: Reading): EntraSettingSignal {
  const attempted = r.outcome !== "success";
  const who = label(g.target);
  const targetId = g.target?.id || g.target?.upn || g.target?.name || "-";
  return {
    posture: attempted ? `attempted to ${x.infinitive}` : x.verb,
    object: who ? `on ${who}` : "",
    words: x.words,
    qualifiers: attempted ? [ATTEMPT_NOTE] : [],
    severity: attempted ? "Medium" : x.severity,
    mitre: attempted ? [] : x.mitre,
    aggKey:
      `entra-setting|${r.tenant}|${r.operation}|${r.outcome}|${r.initiator.id || r.initiator.appId || r.initiator.upn}|${targetId}|${x.property}|${digest(x.delta)}`.toLowerCase(),
    subject: { id: "", name: "" },
    resource: { id: "", name: "", api: "" },
    role: null,
    target: {
      kind: /user/i.test(g.target?.type ?? "")
        ? "account"
        : /serviceprincipal|application/i.test(g.target?.type ?? "")
          ? "cloud_principal"
          : "other",
      id: g.target?.id ?? "",
      name: g.target?.upn || g.target?.name || "",
    },
  };
}

/** Every graded setting change one Entra audit record establishes; empty when none does. */
export function decodeEntraSettingSignals(
  r: EntraAuditRecord,
  rec: Record<string, unknown>,
): EntraSettingSignal[] {
  const op = r.operation.toLowerCase();
  if (!["update user", "change user license", "update authorization policy"].includes(op)) return [];
  // The additionalDetails licence detail is record-level: a UAL record names one target.
  const details =
    r.shape === "ual" && op !== "update authorization policy"
      ? additionalDetailUpdates(rec).filter((d) => d.name.toLowerCase() === "assignedlicense")
      : [];
  return groupsOf(r).flatMap((g, i) => readingsOf(op, g, i === 0 ? details : []).map((x) => signal(r, g, x)));
}
