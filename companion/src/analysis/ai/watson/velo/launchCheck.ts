import { vqlFingerprint } from "../../../huntOutcomes.js";
import { vqlSizeProblem } from "../../../vqlInput.js";
import { canonicalVqlFingerprint, vqlAllowed } from "./vqlAllowed.js";

// The pure gate every Watson launch passes through (phase 3). Order: shape → size → allowlist →
// already-ran → host. Any failure refuses; there is no path from a failed check to a launch, and an
// unknown or ambiguous host never widens into a fleet hunt.

/** The part of a Velociraptor inventory record the check reads (structurally a LaunchClient). */
export interface LaunchClient {
  clientId: string;
  hostname: string;
  fqdn: string;
}

export type LaunchMode = "hunt" | "collection";

export interface LaunchInput {
  vql: string;
  mode: LaunchMode;
  hostname?: string;
}

export interface LaunchContext {
  inventory: readonly LaunchClient[];
  /** Fingerprints that already ran on the case (see fingerprintIndex.ts → loadLaunchFingerprints). */
  deployed: ReadonlySet<string>;
  /**
   * The inventory host matcher — pass `matchClient` from integrations/velociraptor/clientInventory.ts
   * (injected: analysis/ai may not import integrations at runtime).
   */
  matchClient: (records: readonly LaunchClient[], host: string) => LaunchClient | undefined;
}

export type LaunchCheck =
  | { ok: true; mode: LaunchMode; clientHost?: string; fingerprint: string }
  | { ok: false; reason: string; reasons?: string[] };

export const ALREADY_RAN = "this hunt already ran on the case";
export const HOST_NOT_IN_FLEET = "host not in the case's Velociraptor fleet";
const AMBIGUOUS_HOST = "host name matches more than one client in the case's Velociraptor fleet";

const refuse = (reason: string): LaunchCheck => ({ ok: false, reason });

/** Clients a host name could mean: an exact hostname/FQDN match, else every first-label match. */
function candidates(inventory: readonly LaunchClient[], host: string): LaunchClient[] {
  const target = host.toLowerCase();
  const exact = inventory.filter((r) => lcEq(r.hostname, target) || lcEq(r.fqdn, target));
  if (exact.length > 0) return exact;
  const short = target.split(".")[0];
  return inventory.filter((r) => firstLabel(r.hostname) === short || firstLabel(r.fqdn) === short);
}

const lcEq = (a: string, b: string): boolean => String(a ?? "").toLowerCase() === b;
const firstLabel = (s: string): string =>
  String(s ?? "")
    .toLowerCase()
    .split(".")[0];

function resolveHost(hostname: unknown, ctx: LaunchContext): LaunchCheck | LaunchClient {
  const inventory = ctx.inventory;
  const host = typeof hostname === "string" ? hostname.trim() : "";
  if (!host) return refuse(HOST_NOT_IN_FLEET);
  const rec = ctx.matchClient(inventory, host);
  if (!rec) return refuse(HOST_NOT_IN_FLEET);
  const ids = new Set(candidates(inventory, host).map((r) => r.clientId));
  if (ids.size > 1) return refuse(AMBIGUOUS_HOST);
  return rec;
}

/** May this VQL be launched? Pure — the caller supplies the inventory and what already ran. */
export function checkLaunch(input: LaunchInput, ctx: LaunchContext): LaunchCheck {
  const { vql, mode, hostname } = input ?? ({} as LaunchInput);
  if (typeof vql !== "string" || !vql.trim()) return refuse("the VQL is empty");
  if (mode !== "hunt" && mode !== "collection") return refuse("unknown launch mode");
  const size = vqlSizeProblem(vql);
  if (size) return refuse(size);
  const allowed = vqlAllowed(vql);
  if (!allowed.ok)
    return { ok: false, reason: `blocked: ${allowed.reasons.join("; ")}`, reasons: allowed.reasons };
  const fingerprint = vqlFingerprint(vql);
  if (ctx.deployed.has(fingerprint) || ctx.deployed.has(canonicalVqlFingerprint(vql)))
    return refuse(ALREADY_RAN);
  if (mode === "hunt") {
    if (typeof hostname === "string" && hostname.trim()) return refuse("a fleet hunt does not take a host");
    return { ok: true, mode, fingerprint };
  }
  const rec = resolveHost(hostname, ctx);
  if ("ok" in rec) return rec;
  return { ok: true, mode, clientHost: rec.hostname, fingerprint };
}
