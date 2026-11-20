// AI Agent Forensics (#2734): which host names more than one Velociraptor client shares, in one file.
// Learned over the WHOLE file before any row is mapped (the same pattern as the rename evidence,
// #1489), so the first row of a shared host name is labelled the same as the last. The run report
// does the same for its endpoints (aiAgentEndpointLabels, aiAgentReport.ts).
//
// The client id, not this ledger, keeps two clients' events apart (it is the aggKey part); the ledger
// only decides the label: "WS-01 (C.aaa111)" when two or more clients share "WS-01", else "WS-01".

import { aiAgentClientId, isAiAgentRow } from "./aiAgentRows.js";

type Row = Record<string, unknown>;

/** The row's own host name, as resolveRowHost reads it for a hunt_results() row. */
function rowHostName(row: Row): string {
  for (const k of ["Fqdn", "Hostname"]) {
    const v = row[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "";
}

export class AiAgentHostLedger {
  private readonly clientsByHost = new Map<string, Set<string>>();

  /** Record every AI Agent Forensics row's host name → client id. Other rows are ignored. */
  learn(rows: readonly Row[]): void {
    for (const row of rows) {
      if (!isAiAgentRow(row)) continue;
      const host = rowHostName(row).toLowerCase();
      const clientId = aiAgentClientId(row);
      if (!host || !clientId) continue;
      const set = this.clientsByHost.get(host) ?? new Set<string>();
      this.clientsByHost.set(host, set.add(clientId));
    }
  }

  /** "WS-01 (C.aaa111)" when another client shares the host name, else the host name unchanged. */
  label(host: string, clientId: string): string {
    if (!host || !clientId) return host;
    const shared = (this.clientsByHost.get(host.toLowerCase())?.size ?? 0) > 1;
    return shared ? `${host} (${clientId})` : host;
  }
}

/** The parse context's part this module owns: filled by learnWholeFile, read by the mapper. */
export interface AiAgentHostsCtx {
  aliases: { learn(rows: Row[]): void };
  aiHosts?: AiAgentHostLedger;
}

/**
 * Learn everything the whole file must tell before the first row is mapped: the rename evidence
 * (#1489) and the AI Agent Forensics shared host names (#2734). Called once per file by the two
 * whole-file drivers, and once per row by the bulk driver's evidence pass, so the ledger accumulates.
 */
export function learnWholeFile(ctx: AiAgentHostsCtx, rows: Row[]): void {
  ctx.aliases.learn(rows);
  (ctx.aiHosts ??= new AiAgentHostLedger()).learn(rows);
}
