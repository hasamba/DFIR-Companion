// What one Suricata `smb` record SAYS — read, bounded, and nothing joined yet (importer half of
// #933 item 4, tracked on #1085 / #1010). Zeek `smb_files.log` / `smb_mapping.log` are out of
// scope (no Zeek dependency, per #1010): this reads Suricata's own `event_type: "smb"` record.
//
// Field names are Suricata's own documented EVE-JSON output
// (docs.suricata.io/en/latest/output/eve/eve-json-format.html): `id`, `dialect`, `command`,
// `status`, `status_code`, `session_id`, `tree_id`, `filename`, `share`, `share_type`, `fuid`,
// `disposition`, `access`, `size`, `client_guid`, `ntlmssp.*`, `kerberos.*`. Every field is read
// defensively — an absent field is `undefined`, never a guessed default — because a Suricata build
// can omit any of these depending on version and log config.
//
// `status` and `status_code` are kept as two separate fields: one is the symbolic name
// (STATUS_SUCCESS), the other the raw code — neither is a fallback for the other, so a row never
// loses the distinction between "we don't know the code" and "we don't know the name".
//
// Every identifier that can exceed Number.MAX_SAFE_INTEGER (session id, tree id, fuid, the
// transaction id) is kept as a STRING throughout — never coerced through Number().

import { getCI, str } from "./siemImport.js";
import { normalizeTime } from "./siemImport.js";
import type { SensorRef } from "./webChainRead.js";
import { sensorOf } from "./webChainRead.js";

type Row = Record<string, unknown>;

export interface SmbObservation {
  timestamp: string;
  /** `record:<index>` — the row's place in the upload, the evidence pointer. */
  locator: string;
  observer?: SensorRef;
  src?: string;
  dst?: string;
  port?: number;
  /** Scopes every other id below — two sensors/flows must never share one bucket. */
  flowId?: string;
  txId?: string;
  /** `smb.id` — Suricata's own per-transaction identifier. */
  smbId?: string;
  /** Share CONTEXT (which session, which tree) — never the file-join key; see smbChainJoin.ts. */
  sessionId?: string;
  treeId?: string;
  /** SMB2+ file GUID / SMB1 FID as hex — the file-join key. Absent on TREE_CONNECT / negotiate. */
  fuid?: string;
  /** `smb.command`, verbatim and uppercased; "-" when the record carries none. */
  command: string;
  status?: string;
  statusCode?: string;
  dialect?: string;
  share?: string;
  /** FILE / PIPE / PRINT / unknown, verbatim. */
  shareType?: string;
  filename?: string;
  /** FILE_OPEN / FILE_CREATE / FILE_OVERWRITE(_IF) / FILE_OPEN_IF / FILE_SUPERSEDE, verbatim. */
  disposition?: string;
  /** "normal" or "delete on close". */
  access?: string;
  clientGuid?: string;
  ntlmDomain?: string;
  ntlmUser?: string;
  krbRealm?: string;
  krbService?: string;
  /** The size of the REQUESTED file per Suricata's own docs — never transferred bytes. */
  size?: number;
}

const text = (v: unknown): string | undefined =>
  v === undefined || v === null ? undefined : typeof v === "string" ? v : String(v);
const num = (v: unknown): number | undefined => {
  if (v === undefined || v === null || v === "") return undefined;
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : undefined;
};

function suricataTime(row: Row): string {
  return normalizeTime(str(getCI(row, "timestamp"))) || "";
}

export function readSuricataSmb(row: Row, recordIndex: number): SmbObservation {
  const smb = getCI(row, "smb");
  const s = smb && typeof smb === "object" ? (smb as Row) : {};
  const ntlmssp = getCI(s, "ntlmssp");
  const ntlm = ntlmssp && typeof ntlmssp === "object" ? (ntlmssp as Row) : {};
  const kerberos = getCI(s, "kerberos");
  const krb = kerberos && typeof kerberos === "object" ? (kerberos as Row) : {};

  const command = text(getCI(s, "command"))?.trim().toUpperCase() || "-";
  const flowId = text(getCI(row, "flow_id"))?.trim() || undefined;
  const txId = text(getCI(row, "tx_id"))?.trim() || undefined;

  return {
    timestamp: suricataTime(row),
    locator: `record:${recordIndex}`,
    observer: sensorOf(row),
    src: text(getCI(row, "src_ip"))?.trim() || undefined,
    dst: text(getCI(row, "dest_ip"))?.trim() || undefined,
    port: num(getCI(row, "dest_port")),
    ...(flowId ? { flowId } : {}),
    ...(txId ? { txId } : {}),
    smbId: text(getCI(s, "id"))?.trim() || undefined,
    sessionId: text(getCI(s, "session_id"))?.trim() || undefined,
    treeId: text(getCI(s, "tree_id"))?.trim() || undefined,
    fuid: text(getCI(s, "fuid"))?.trim() || undefined,
    command,
    status: text(getCI(s, "status"))?.trim() || undefined,
    statusCode: text(getCI(s, "status_code"))?.trim() || undefined,
    dialect: text(getCI(s, "dialect"))?.trim() || undefined,
    share: text(getCI(s, "share"))?.trim() || undefined,
    shareType: text(getCI(s, "share_type"))?.trim() || undefined,
    filename: text(getCI(s, "filename"))?.slice(0, 260) || undefined,
    disposition: text(getCI(s, "disposition"))?.trim() || undefined,
    access: text(getCI(s, "access"))?.trim() || undefined,
    clientGuid: text(getCI(s, "client_guid"))?.trim() || undefined,
    ntlmDomain: text(getCI(ntlm, "domain"))?.trim() || undefined,
    ntlmUser: text(getCI(ntlm, "user"))?.trim() || undefined,
    krbRealm: text(getCI(krb, "realm"))?.trim() || undefined,
    krbService: text(getCI(krb, "snames"))?.trim() || undefined,
    size: num(getCI(s, "size")),
  };
}
