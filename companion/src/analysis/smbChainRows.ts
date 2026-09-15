// SMB operation rows: one MappedEvent per operation, from the chains smbChainJoin.ts builds
// (importer half of #933 item 4, #1085 / #1010).
//
// Severity is Info for every row — pure telemetry, matching flow/http/transfer rows. Grading is
// the deterministic content tagger's job after import (CLAUDE.md §7), not this parser's; a denied
// operation is a fact in the description, not a severity bump this layer should own.
//
// This module NEVER concludes lateral movement or execution from a share write — that is the rest
// of #933 item 4 (tracked on #1010), explicitly out of scope here. A separate, pre-existing tagger
// rule (`tags.yaml`'s `win_smb_admin_share`) may still promote a row whose description mentions
// ADMIN$/psexec; that is a downstream, unrelated concern this file does not control.
//
// The aggregation key hashes every analyst-visible fact in the canonical `smb` block (status,
// disposition, outcome, everything) rather than a hand-picked flat string, so a success and a
// later denial on the same file can never silently collapse into one aggregated row — the shared
// aggregator keeps the FIRST row's description on a key collision (eventAggregate.ts) and a flat
// key that omits status would let that happen. Same pattern as webChainRows.ts's
// requestKey/transferKey.

import { createCanonicalEvent, type CanonicalEventEnvelope } from "./canonicalEvent.js";
import type { MappedEvent } from "./siemImport.js";
import { breakHashRuns, identityMark, keyDigest, showToken } from "./recordIdentity.js";
import type { SmbChain, SmbJoinState } from "./smbChainJoin.js";
import type { SmbObservation } from "./smbChainRead.js";
import type { TransferObservation } from "./webChainRead.js";
import type { SmbBlock, SmbFileinfoJoin, SmbOutcome } from "./canonicalSmb.js";

const DESCRIPTION_MAX = 600;

// A digest is stable regardless of key order, so two chains with the same facts in a different
// field order still fold into one aggregated row.
const stableJson = (v: unknown): string =>
  JSON.stringify(v, (_k, val) =>
    val && typeof val === "object" && !Array.isArray(val)
      ? Object.fromEntries(
          Object.entries(val as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : 1)),
        )
      : val,
  );

// Locators (fuid, flowId, txId, smbId) identify WHICH record said something; they are never part
// of what a row's fact-digest keys on, or two records of one operation would never fold together.
function stripLocators(block: SmbBlock): Omit<SmbBlock, "fuid"> {
  const { fuid: _fuid, ...rest } = block;
  return rest;
}

const KNOWN_CREATE = new Set(["SMB2_COMMAND_CREATE", "CREATE"]);

function isSuccess(status: string | undefined): boolean {
  return status !== undefined && status.toUpperCase() === "STATUS_SUCCESS";
}

/**
 * FILE_OPEN / FILE_CREATE / FILE_OVERWRITE each have exactly one success meaning. FILE_OPEN_IF,
 * FILE_OVERWRITE_IF and FILE_SUPERSEDE do not — MS-SMB2's response `CreateAction` would settle it,
 * but Suricata's eve.json does not export that field, so those stay "requested-ambiguous" rather
 * than a guess. Any non-success status is a denial regardless of disposition.
 */
function classifyOutcome(op: SmbObservation): SmbOutcome {
  if (op.status === undefined) return "unknown";
  if (!isSuccess(op.status)) return "denied";
  const d = op.disposition?.toUpperCase();
  if (d === "FILE_OPEN") return "opened-existing";
  if (d === "FILE_CREATE") return "created-new";
  if (d === "FILE_OVERWRITE") return "overwritten-existing";
  if (d === "FILE_OPEN_IF" || d === "FILE_OVERWRITE_IF" || d === "FILE_SUPERSEDE")
    return "requested-ambiguous";
  return "unknown";
}

// Two address sets agree when every address one side names is named by the other — order-free,
// since a fileinfo record states flow endpoints, not sender/receiver (webChainRead.ts's own note).
function endpointsAgree(op: SmbObservation, t: TransferObservation): boolean {
  const opAddrs = [op.src, op.dst].filter((a): a is string => !!a);
  if (opAddrs.length === 0) return true; // nothing to disagree with
  const tAddrs = [t.flowSrc, t.flowDst].filter((a): a is string => !!a);
  if (tAddrs.length === 0) return true;
  return opAddrs.every((a) => tAddrs.includes(a));
}

/**
 * The fileinfo record over SMB (`app_proto: "smb"`) matching this operation's `flowId + txId` —
 * Suricata's own identifier pair for the transaction. `flow_id` is a per-sensor correlation id,
 * not a global one: two independent sensors (or two unrelated captures merged into one upload)
 * can emit the same small flow_id/tx_id pair, so a candidate whose sensor or endpoints contradict
 * this operation is excluded before matching — never joined just because the ids happen to agree.
 * More than one remaining candidate is a stated conflict, never a first-wins pick (webChainJoin.ts's
 * own rule for a shared identifier).
 */
function matchFileinfo(
  op: SmbObservation,
  transfers: readonly TransferObservation[],
): { join: SmbFileinfoJoin; transfer?: TransferObservation } {
  if (!op.flowId || !op.txId) return { join: "not applicable" };
  const candidates = transfers.filter((t) => {
    if (t.source !== "suricata-fileinfo" || t.flowId !== op.flowId || t.txId !== op.txId) return false;
    if (op.observer?.name && t.observer?.name && op.observer.name !== t.observer.name) return false;
    return endpointsAgree(op, t);
  });
  if (candidates.length === 0) return { join: "no match" };
  if (candidates.length > 1) return { join: "conflict" };
  return { join: "matched", transfer: candidates[0] };
}

// SmbJoinState's "joined" case carries no fact onto the row (it is the ordinary, expected case);
// only a non-"joined" state is worth an analyst's attention, so createJoinState omits it.
function createJoinFact(joinState: SmbJoinState): SmbBlock["createJoinState"] {
  return joinState === "joined" ? undefined : joinState;
}

function smbBlock(
  op: SmbObservation,
  join: SmbFileinfoJoin,
  joinState: SmbJoinState,
  operationsOmitted: number,
): SmbBlock {
  return {
    command: op.command,
    ...(op.status ? { status: op.status } : {}),
    ...(op.statusCode ? { statusCode: op.statusCode } : {}),
    ...(op.dialect ? { dialect: op.dialect } : {}),
    ...(op.disposition ? { disposition: op.disposition } : {}),
    ...(op.share ? { share: op.share } : {}),
    ...(op.shareType ? { shareType: op.shareType } : {}),
    ...(op.filename ? { filename: op.filename } : {}),
    ...(op.access ? { access: op.access } : {}),
    ...(op.fuid ? { fuid: op.fuid } : {}),
    ...(op.sessionId ? { sessionId: op.sessionId } : {}),
    ...(op.treeId ? { treeId: op.treeId } : {}),
    ...(op.clientGuid ? { clientGuid: op.clientGuid } : {}),
    ...(op.ntlmDomain ? { ntlmDomain: op.ntlmDomain } : {}),
    ...(op.ntlmUser ? { ntlmUser: op.ntlmUser } : {}),
    ...(op.krbRealm ? { krbRealm: op.krbRealm } : {}),
    ...(op.krbService ? { krbService: op.krbService } : {}),
    ...(KNOWN_CREATE.has(op.command) ? { outcome: classifyOutcome(op) } : {}),
    fileinfoJoin: join,
    ...(op.size !== undefined ? { requestedSize: op.size } : {}),
    ...(createJoinFact(joinState) ? { createJoinState: createJoinFact(joinState) } : {}),
    ...(operationsOmitted > 0 ? { operationsOmitted } : {}),
  };
}

function outcomeWords(outcome: SmbOutcome | undefined): string {
  switch (outcome) {
    case "opened-existing":
      return "opened an existing object";
    case "created-new":
      return "created a new object";
    case "overwritten-existing":
      return "overwrote an existing object";
    case "requested-ambiguous":
      return "outcome not determinable from this record";
    case "denied":
      return "denied";
    default:
      return "outcome unknown";
  }
}

function targetOf(op: SmbObservation): string {
  const path = op.filename
    ? showToken(op.filename)
    : op.share
      ? `share ${showToken(op.share)}`
      : "(no target named)";
  return breakHashRuns(path);
}

function authWords(op: SmbObservation): string | undefined {
  const isStr = (v: string | undefined): v is string => !!v;
  if (op.ntlmDomain || op.ntlmUser) {
    const user = [op.ntlmDomain, op.ntlmUser].filter(isStr).map(showToken).join("\\");
    return `ntlm: ${user}`;
  }
  if (op.krbRealm || op.krbService) {
    const who = [op.krbService, op.krbRealm].filter(isStr).map(showToken).join("@");
    return `kerberos: ${who}`;
  }
  return undefined;
}

function describeOperation(op: SmbObservation, block: SmbBlock, fileinfo?: TransferObservation): string {
  const parts: string[] = [`SMB ${op.command}`, targetOf(op)];
  if (block.outcome) parts.push(`— ${outcomeWords(block.outcome)}`);
  else if (op.status && !isSuccess(op.status)) parts.push(`— denied (${op.status})`);
  if (op.status) parts.push(`(${op.status}${op.statusCode ? ` ${op.statusCode}` : ""})`);
  if (op.shareType) parts.push(`[share type: ${op.shareType}]`);
  if (op.src && op.dst) parts.push(`[from ${op.src} to ${op.dst}]`);
  const auth = authWords(op);
  if (auth) parts.push(`[${auth}]`);
  if (fileinfo) {
    const bytes =
      fileinfo.seenBytes !== undefined ? `${fileinfo.seenBytes} bytes observed` : "size unrecorded";
    parts.push(`[transfer: ${bytes}${fileinfo.sha256 ? `, sha256 ${breakHashRuns(fileinfo.sha256)}` : ""}]`);
  } else if (block.fileinfoJoin === "no match") {
    parts.push("[transfer: no matching fileinfo record in this upload]");
  } else if (block.fileinfoJoin === "conflict") {
    parts.push("[transfer: conflicting fileinfo records — not joined]");
  }
  if (block.createJoinState) parts.push(`[create: ${block.createJoinState}]`);
  if (block.operationsOmitted)
    parts.push(`[+${block.operationsOmitted} earlier operations on this file not shown]`);
  const identity = identityMark(keyDigest(stableJson(stripLocators(block))));
  return `${parts.join(" ")}${identity}`.slice(0, DESCRIPTION_MAX);
}

function canonicalOf(
  op: SmbObservation,
  block: SmbBlock,
  fileinfo?: TransferObservation,
): CanonicalEventEnvelope {
  const rawRecords = [
    { source: "suricata-smb" as const, locator: op.locator, ...(op.smbId ? { recordId: op.smbId } : {}) },
    ...(fileinfo
      ? [
          {
            source: fileinfo.source,
            locator: fileinfo.locator,
            ...(fileinfo.fuid ? { recordId: fileinfo.fuid } : {}),
          },
        ]
      : []),
  ];
  return createCanonicalEvent({
    event: {
      category: "network",
      type: "smb",
      action: op.command.toLowerCase(),
      ...(op.status ? { outcome: op.status.toLowerCase() } : {}),
    },
    ...(op.src ? { actor: { kind: "network", address: op.src } } : {}),
    ...(op.dst
      ? { target: { kind: "network", address: op.dst, ...(op.port ? { port: op.port } : {}) } }
      : {}),
    network: {
      ...(op.src ? { source: { address: op.src } } : {}),
      ...(op.dst ? { destination: { address: op.dst, ...(op.port ? { port: op.port } : {}) } } : {}),
      protocol: "smb",
    },
    smb: block,
    time: { observed: op.timestamp, normalized: op.timestamp },
    evidence: { rawRecords },
    producer: { importer: "network", parserVersion: "1", mappingVersion: "smb-chain-v1" },
    rawFieldMap: {
      "smb.command": ["smb.command"],
      "time.observed": ["timestamp"],
      ...(op.src ? { "actor.address": ["src_ip"], "network.source.address": ["src_ip"] } : {}),
      ...(op.dst ? { "target.address": ["dest_ip"], "network.destination.address": ["dest_ip"] } : {}),
    },
    ...(fileinfo ? { locatorMap: { "smb.fileinfoJoin": fileinfo.locator } } : {}),
  });
}

function mapOperation(
  op: SmbObservation,
  fileinfo: { join: SmbFileinfoJoin; transfer?: TransferObservation },
  joinState: SmbJoinState,
  operationsOmitted: number,
): MappedEvent {
  const block = smbBlock(op, fileinfo.join, joinState, operationsOmitted);
  const canonical = canonicalOf(op, block, fileinfo.transfer);
  const factDigest = keyDigest(stableJson(stripLocators(block)));
  return {
    timestamp: op.timestamp,
    description: describeOperation(op, block, fileinfo.transfer),
    severity: "Info",
    mitre: [],
    canonical,
    origin: "wire",
    aggKey: `smb|${op.command}|${factDigest}`,
    sources: ["Suricata"],
    ...(op.src ? { srcIp: op.src } : {}),
    ...(op.dst ? { dstIp: op.dst } : {}),
    ...(op.port ? { port: op.port } : {}),
  };
}

/** Chains biggest-first is meaningless for SMB (no byte total to rank by); budget by arrival order. */
export function tallySmbChains(chains: readonly SmbChain[], budget: number): SmbChain[] {
  return chains.slice(0, budget);
}

/** One Info row disclosing SMB records the importer never read — the global SMB_OBSERVATIONS_MAX bound. */
function overflowRow(count: number): MappedEvent {
  return {
    timestamp: "",
    description: `SMB: ${count} record${count === 1 ? "" : "s"} not read — the upload's SMB record bound was reached`,
    severity: "Info",
    mitre: [],
    origin: "wire",
    aggKey: "smb|overflow",
    sources: ["Suricata"],
  };
}

/**
 * One row per operation: the CREATE (when present) plus every READ/WRITE/CLOSE/etc. in the chain.
 * `fileinfoTransfers` is the upload's already-collected `app_proto: "smb"` fileinfo rows
 * (webObs.transfers, filtered by the caller or here) — READ/WRITE bytes are matched to them by
 * flowId + txId rather than re-derived from `smb.size` (the requested size, not observed bytes).
 * `overflow` is the count of records the global SMB_OBSERVATIONS_MAX bound never let the importer
 * read at all — surfaced as its own row, never silently folded into the generic import-drop count.
 */
export function mapSmbRows(
  chains: readonly SmbChain[],
  fileinfoTransfers: readonly TransferObservation[],
  overflow = 0,
): MappedEvent[] {
  const smbFileinfo = fileinfoTransfers.filter((t) => (t.over ?? "").toUpperCase() === "SMB");
  const rows: MappedEvent[] = [];
  for (const chain of chains) {
    if (chain.create)
      rows.push(mapOperation(chain.create, matchFileinfo(chain.create, smbFileinfo), chain.joinState, 0));
    const omitted = chain.operationsTotal - chain.operations.length;
    for (const op of chain.operations)
      rows.push(mapOperation(op, matchFileinfo(op, smbFileinfo), chain.joinState, omitted));
  }
  if (overflow > 0) rows.push(overflowRow(overflow));
  return rows;
}
