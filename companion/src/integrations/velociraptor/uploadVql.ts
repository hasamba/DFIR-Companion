import type { UploadManifestEntry } from "../../analysis/aiAgentRunStore.js";

// The VQL that reads a hunt's or a flow's UPLOADED files. Lifted out of velociraptorApi.ts (at its
// size-ledger cap) so the AI Agent Forensics manifest-only reader sits beside the readers it must
// never fall back to (#2690).

// Extensions treated as a readable text report upload (e.g. THOR's --jsonfile, a CSV/log export).
// Anything else (a raw .zip, a binary) is invisible to the upload-reading VQLs below — reading those
// needs server-side unzip, which is out of scope for now. Shared by DEFAULT_UPLOAD_VQL (hunt-scoped)
// and DEFAULT_FLOW_UPLOAD_VQL (flow-scoped) so the two never drift apart.
export const UPLOAD_EXT_PATTERN = "(?i)\\.(json|jsonl|ndjson|csv|txt|log)$";

// Default VQL to enumerate a hunt's uploaded text-report files and read their content server-side.
// Walks the hunt's flows → each flow's uploads → reads matching-extension ones from the filestore
// (`fs` accessor + the upload's filestore components). __HUNT_ID__ is replaced with the validated hunt
// id. Override per Velociraptor version with DFIR_VELOCIRAPTOR_UPLOAD_VQL (keep the __HUNT_ID__
// placeholder + a Name/ClientId/Content column shape).
export const DEFAULT_UPLOAD_VQL =
  "LET flows = SELECT Flow.client_id AS ClientId, Flow.session_id AS FlowId FROM hunt_flows(hunt_id='__HUNT_ID__')\n" +
  "LET ups = SELECT * FROM foreach(row=flows, query={ SELECT ClientId, vfs_path AS Path, file_size AS Size, _Components AS Components FROM uploads(client_id=ClientId, flow_id=FlowId) })\n" +
  "SELECT ClientId, Path, basename(path=Path) AS Name, read_file(accessor='fs', filename=Components) AS Content FROM ups WHERE Path =~ '" +
  UPLOAD_EXT_PATTERN +
  "' AND Size < __MAX_BYTES__ AND Content";

// Default VQL to read ONE external flow's uploaded text-report files (content included) — the
// flow-scoped analogue of DEFAULT_UPLOAD_VQL, needed because hunt_flows(hunt_id=) has no flow-scoped
// equivalent. __CLIENT_ID__/__FLOW_ID__ are replaced with the validated ids. Override per Velociraptor
// version with DFIR_VELOCIRAPTOR_FLOW_UPLOAD_VQL (keep both placeholders + the same column shape).
export const DEFAULT_FLOW_UPLOAD_VQL =
  "LET ups = SELECT '__CLIENT_ID__' AS ClientId, vfs_path AS Path, file_size AS Size, _Components AS Components FROM uploads(client_id='__CLIENT_ID__', flow_id='__FLOW_ID__')\n" +
  "SELECT ClientId, Path, basename(path=Path) AS Name, read_file(accessor='fs', filename=Components) AS Content FROM ups WHERE Path =~ '" +
  UPLOAD_EXT_PATTERN +
  "' AND Size < __MAX_BYTES__ AND Content";

// ── AI Agent Forensics (#2690): manifest only ─────────────────────────────────────────────────────
// An AI Agent Forensics run preserves agent transcripts, configs and possibly credential files in
// Velociraptor's file store. Their CONTENTS are never read by the Companion: no upload importer, no
// override VQL, no single-flow variant. The run keeps a manifest instead (path, size, hash).

/** Every artifact an AI Agent Forensics run collects starts with this. */
export const AI_AGENT_RUN_ARTIFACT_MARK = "Custom.DFIRCompanion.AIAgentForensics.";

/** The hunt's uploads, without content: client, path, size and the server-side SHA-256. */
export const HUNT_UPLOAD_MANIFEST_VQL =
  "LET flows = SELECT Flow.client_id AS ClientId, Flow.session_id AS FlowId FROM hunt_flows(hunt_id='__HUNT_ID__')\n" +
  "SELECT ClientId, FlowId, vfs_path AS Path, file_size AS Size, " +
  "hash(accessor='fs', path=_Components).SHA256 AS SHA256 FROM foreach(row=flows, " +
  "query={ SELECT ClientId, FlowId, vfs_path, file_size, _Components FROM uploads(client_id=ClientId, flow_id=FlowId) })";

/** Does this hunt / flow belong to an AI Agent Forensics run? Read BEFORE any upload-content VQL. */
export function externalRetentionProbe(
  target: { huntId: string } | { clientId: string; flowId: string },
): string {
  // The same row shapes getHuntArtifacts() and flowStatus() read; the whole row is checked.
  return "huntId" in target
    ? `SELECT * FROM hunts() WHERE hunt_id='${target.huntId}' LIMIT 1`
    : `SELECT * FROM flows(client_id='${target.clientId}') WHERE session_id='${target.flowId}' LIMIT 1`;
}

/** True when a probe's rows name an AI Agent Forensics artifact. */
export function isExternalRetentionRun(rows: readonly unknown[]): boolean {
  return JSON.stringify(rows).includes(AI_AGENT_RUN_ARTIFACT_MARK);
}

export class ExternalRetentionError extends Error {
  constructor(unconfirmed = "") {
    super(
      unconfirmed
        ? `could not confirm this is not an AI Agent Forensics run, so its uploads were not read (${unconfirmed})`
        : "this is an AI Agent Forensics run: its collected files stay in Velociraptor and are never imported (manifest only)",
    );
    this.name = "ExternalRetentionError";
  }
}

export type { UploadManifestEntry };

/** The hunt's uploads as a manifest — path, size, server-side hash. Contents are never fetched. */
export async function readUploadManifest(
  client: { runProgram(program: string): Promise<{ rows: unknown[]; reason: string }> },
  huntId: string,
): Promise<UploadManifestEntry[]> {
  if (!/^H\.[A-Za-z0-9]+$/.test(huntId)) throw new Error("invalid hunt id");
  const { rows } = await client.runProgram(HUNT_UPLOAD_MANIFEST_VQL.split("__HUNT_ID__").join(huntId));
  return (rows as Record<string, unknown>[]).map((r) => ({
    clientId: String(r.ClientId ?? ""),
    flowId: String(r.FlowId ?? ""),
    path: String(r.Path ?? ""),
    size: Number(r.Size) || 0,
    sha256: String(r.SHA256 ?? ""),
  }));
}
