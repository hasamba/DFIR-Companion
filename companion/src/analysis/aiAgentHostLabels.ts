// AI Agent Forensics (#2734): which host names more than one Velociraptor client shares, in one file.
// Learned over the WHOLE file before any row is mapped (the same pattern as the rename evidence,
// #1489), so the first row of a shared host name is labelled the same as the last. The run report
// does the same for its endpoints (aiAgentEndpointLabels, aiAgentReport.ts).
//
// The client id, not this ledger, keeps two clients' events apart (it is the aggKey part); the ledger
// only decides the label: "WS-01 (C.aaa111)" when two or more clients share "WS-01", else "WS-01".

import { aiAgentClientId, isAiAgentRow } from "./aiAgentRows.js";
import { recordCollector } from "./hostIdentity.js";

type Row = Record<string, unknown>;

/** One host name → client id pair; a sweep hands its shared ones to every batch it files (#2745). */
export type AiAgentHostClient = readonly [host: string, clientId: string];

/** Import option: the host names a whole sweep shows two or more clients sharing (#2745). */
export interface AiAgentHostOptions {
  aiAgentHostClients?: readonly AiAgentHostClient[];
}

// The row's own host name, read exactly as resolveRowHost reads the collector (case-insensitive,
// "-" and "N/A" absent), so the ledger key and the mapper's host can never differ (#2745).
const rowHostName = (row: Row): string => recordCollector(row);

export class AiAgentHostLedger {
  private readonly clientsByHost = new Map<string, Set<string>>();

  /** A ledger seeded with pairs learned elsewhere: the other batches of the same sweep (#2745). */
  static from(pairs: readonly AiAgentHostClient[] = []): AiAgentHostLedger {
    const ledger = new AiAgentHostLedger();
    for (const [host, clientId] of pairs) ledger.add(host, clientId);
    return ledger;
  }

  /** Record every AI Agent Forensics row's host name → client id. Other rows are ignored. */
  learn(rows: readonly Row[]): void {
    for (const row of rows) {
      if (isAiAgentRow(row)) this.add(rowHostName(row), aiAgentClientId(row));
    }
  }

  /** Only the host names two or more clients share: the label needs nothing else (#2745). */
  sharedPairs(): AiAgentHostClient[] {
    return [...this.clientsByHost].flatMap(([host, ids]) =>
      ids.size > 1 ? [...ids].map((id): AiAgentHostClient => [host, id]) : [],
    );
  }

  private add(host: string, clientId: string): void {
    const key = host.trim().toLowerCase();
    if (!key || !clientId) return;
    const set = this.clientsByHost.get(key) ?? new Set<string>();
    this.clientsByHost.set(key, set.add(clientId));
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
