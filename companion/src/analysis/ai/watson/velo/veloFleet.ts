import type { CaseFleetInventory } from "../../../velociraptorClientStore.js";
import type { LaunchClient } from "./launchCheck.js";

// What a Watson round knows about the case's Velociraptor: whether the case has a server, and its
// enrolled hosts. The inventory is the snapshot the dashboard keeps (never a live query), so a round
// reaches no endpoint and no server to build a prompt.

/** The parts of a round context the fleet read needs (the route supplies them; analysis/ai imports no integration). */
export interface VeloFleetSeams {
  veloConnected?(caseId: string): boolean;
  velociraptorClientStore?: CaseFleetInventory;
}

export interface VeloFleet {
  records: LaunchClient[];
  prompt: { hostCount: number; hosts: { hostname: string; fqdn: string }[] };
}

const text = (v: unknown): string => (typeof v === "string" ? v : "");

/** The fleet of a case that has a Velociraptor server; undefined when it has none. */
export async function loadVeloFleet(ctx: VeloFleetSeams, caseId: string): Promise<VeloFleet | undefined> {
  if (!ctx.veloConnected?.(caseId)) return undefined;
  const inv = await ctx.velociraptorClientStore?.load(caseId).catch(() => undefined);
  const records = (inv?.clients ?? []).map((c) => ({
    clientId: text(c.clientId),
    hostname: text(c.hostname),
    fqdn: text(c.fqdn),
  }));
  const hosts = records
    .filter((r) => r.hostname || r.fqdn)
    .map((r) => ({ hostname: r.hostname || r.fqdn, fqdn: r.fqdn }));
  return { records, prompt: { hostCount: hosts.length, hosts } };
}
