import { SEVERITY_RANK, type ForensicEvent } from "./stateTypes.js";

// Which cloud account or tenant a row belongs to, for the gap and wave readings (#2606).
//
// gapEdgeClass.ts (#1503) refuses to call a silence a dwell interval when the High rows on either
// side sit on different hosts. Cloud rows name no host, so they fell into its "environment-wide"
// wildcard and matched everything: two waves in two unrelated AWS accounts, or two M365 tenants,
// read as one intrusion with a dwell interval between them, and a hole between two separate log
// sources read as cleared logs. This module gives such rows a scope key, read from the canonical
// cloud block (never from the description), so the same footing rule applies to them.
//
// A leaf: it imports only stateTypes, so gapDetect.ts and gapEdgeClass.ts can both use it.
//
// Keys: `<provider>-account:<id>` for the caller's account (`accountId`) and the account the record
// was delivered to (`recipientAccountId`) — both, so a cross-account AssumeRole from A into B still
// matches a wave in A or in B — and `tenant:<id>` for a tenant. Ids are evidence-controlled and
// reach reports and the dashboard, so they are cut to a strict charset and length here.

const MAX_ID_LENGTH = 64;
const UNSAFE_ID_CHARS = /[^a-z0-9._:@-]/g;
const SAFE_PROVIDER_CHARS = /[^a-z0-9]/g;

const ACCOUNT_LABEL: Readonly<Record<string, string>> = {
  aws: "AWS account",
  gcp: "GCP project",
  azure: "Azure subscription",
};

function cleanId(raw: string | undefined): string {
  return (raw ?? "").trim().toLowerCase().replace(UNSAFE_ID_CHARS, "").slice(0, MAX_ID_LENGTH);
}

// The scope keys of one row. Empty when the row carries no cloud account or tenant.
export function cloudScopesOf(e: ForensicEvent): string[] {
  const c = e.canonical?.cloud;
  if (!c) return [];
  const provider = (c.provider ?? "").toLowerCase().replace(SAFE_PROVIDER_CHARS, "") || "cloud";
  const out = new Set<string>();
  for (const raw of [c.accountId, c.recipientAccountId]) {
    const id = cleanId(raw);
    if (id) out.add(`${provider}-account:${id}`);
  }
  const tenant = cleanId(c.tenant);
  if (tenant) out.add(`tenant:${tenant}`);
  return [...out];
}

// A row is purely cloud-scoped when it carries a scope and names no host. A row that names a host
// keeps the host rule; mixed endpoint + cloud data behaves as it did before #2606.
function pureCloudScopes(e: ForensicEvent): string[] {
  if ((e.asset ?? "").trim() !== "") return [];
  return cloudScopesOf(e);
}

// The scopes of a wave's High/Critical rows, or null when the wave has no such row or any of them
// is not purely cloud-scoped (a host row, or a row with no scope at all). Null never yields a
// cross-scope verdict, so the existing asset rule and its wildcard decide.
export function severeCloudScopesOf(wave: readonly ForensicEvent[]): Set<string> | null {
  const out = new Set<string>();
  for (const e of wave) {
    if (SEVERITY_RANK[e.severity] > SEVERITY_RANK.High) continue;
    const scopes = pureCloudScopes(e);
    if (scopes.length === 0) return null;
    for (const s of scopes) out.add(s);
  }
  return out.size > 0 ? out : null;
}

function disjoint(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  for (const s of a) if (b.has(s)) return false;
  return true;
}

// Two adjacent waves sit in separate accounts/tenants: every severe row on both sides is
// cloud-scoped and the two scope sets share nothing. Such an interval is not dwell time.
export function crossScopeInterval(
  before: ReadonlySet<string> | null,
  after: ReadonlySet<string> | null,
): boolean {
  return before !== null && after !== null && disjoint(before, after);
}

function scopeLabel(key: string): string {
  const sep = key.indexOf(":");
  const kind = key.slice(0, sep);
  const id = key.slice(sep + 1);
  if (kind === "tenant") return `tenant ${id}`;
  const provider = kind.replace(/-account$/, "");
  return `${ACCOUNT_LABEL[provider] ?? "cloud account"} ${id}`;
}

// The boundary reading of a complete gap: both edge rows are purely cloud-scoped and their scopes
// share nothing. Returns the "A → B" label to show, or null when the edges share a footing.
export function scopeBoundaryLabel(
  before: ForensicEvent | undefined,
  after: ForensicEvent | undefined,
): string | null {
  if (!before || !after) return null;
  const a = pureCloudScopes(before);
  const b = pureCloudScopes(after);
  if (a.length === 0 || b.length === 0 || !disjoint(new Set(a), new Set(b))) return null;
  return `${a.map(scopeLabel).join(" / ")} → ${b.map(scopeLabel).join(" / ")}`;
}

// The same "A → B" label for two waves' scope sets (#2610). Wave-level, because crossScopeInterval
// decides on every severe row of each wave, not on the two edge rows (which may be unscoped/Info).
export function scopeSetBoundaryLabel(before: ReadonlySet<string>, after: ReadonlySet<string>): string {
  return `${[...before].map(scopeLabel).join(" / ")} → ${[...after].map(scopeLabel).join(" / ")}`;
}
