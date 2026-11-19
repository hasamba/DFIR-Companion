/**
 * Synthetic Velociraptor hunt exports for #2714, built at test time — no binary zip is committed and
 * nothing comes from a real case. Hosts, client ids, the hunt id and the IPs are all invented
 * (documentation ranges only).
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import yazl from "yazl";

export const CLIENTS = [
  { host: "WS-ALPHA", id: "C.0000000000000001" },
  { host: "WS-BRAVO", id: "C.0000000000000002" },
  { host: "SRV-CHARLIE", id: "C.0000000000000003" },
] as const;

export const ARTIFACTS = ["Windows.System.Pslist", "Windows.Network.Netstat", "Windows.Sys.Users%2FUsers"];

export type HuntLayout = "full" | "perClientJson" | "huntWide" | "csvOnlyUsers";

type Row = Record<string, string | number>;

const fqdn = (host: string): string => `${host.toLowerCase()}.example.test`;

/** One artifact's rows for one client. `Pid` doubles as a per-row identity across copies. */
export function rowsFor(artifact: string, clientIndex: number): Row[] {
  const base = (clientIndex + 1) * 100;
  if (artifact === "Windows.System.Pslist")
    return [0, 1].map((k) => ({
      Pid: base + k,
      Ppid: 4,
      Name: `proc${k}.exe`,
      CommandLine: `proc${k}.exe --run`,
      CreateTime: "2026-01-02T03:04:05Z",
    }));
  if (artifact === "Windows.Network.Netstat")
    return [
      {
        Pid: base + 50,
        Name: "svc.exe",
        Family: "IPv4",
        Type: "TCP",
        Status: "ESTAB",
        "Laddr.IP": `192.0.2.${clientIndex + 10}`,
        "Raddr.IP": `198.51.100.${clientIndex + 20}`,
        Timestamp: "2026-01-02T03:04:05Z",
      },
    ];
  return [{ Pid: base + 90, Name: `user${clientIndex}`, Uid: 1001, Type: "local" }];
}

const jsonl = (rows: Row[]): string => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
const csv = (rows: Row[]): string => {
  const cols = Object.keys(rows[0]);
  return [cols.join(","), ...rows.map((r) => cols.map((c) => String(r[c])).join(","))].join("\n") + "\n";
};
const huntWideRows = (artifact: string): Row[] =>
  CLIENTS.flatMap((c, i) => rowsFor(artifact, i).map((r) => ({ ClientId: c.id, Fqdn: fqdn(c.host), ...r })));

/** relpath → content for one layout. `prefix` puts the hunt in a subfolder. */
export function huntTree(layout: HuntLayout, prefix = ""): Record<string, string> {
  const p = prefix ? `${prefix}/` : "";
  const tree: Record<string, string> = {
    [`${p}hunt_info.json`]: JSON.stringify({ hunt_id: "H.TEST0001" }),
  };
  const perClient = layout !== "huntWide";
  const huntWide = layout === "full" || layout === "huntWide" || layout === "csvOnlyUsers";
  for (const [i, c] of CLIENTS.entries()) {
    if (!perClient) break;
    const dir = `${p}${c.host}-${c.id}`;
    tree[`${dir}/client_info.json`] = JSON.stringify({ client_id: c.id, hostname: c.host });
    tree[`${dir}/collection_context.json`] = "{}";
    tree[`${dir}/log.json`] = "{}\n";
    tree[`${dir}/uploads.json`] = "";
    for (const a of ARTIFACTS) {
      const rows = rowsFor(a, i);
      const csvOnly = layout === "csvOnlyUsers" && a === "Windows.Sys.Users%2FUsers";
      if (!csvOnly) tree[`${dir}/results/${a}.json`] = jsonl(rows);
      if (layout === "full" || csvOnly) tree[`${dir}/results/${a}.csv`] = csv(rows);
    }
  }
  if (huntWide) {
    for (const a of ARTIFACTS) {
      const csvOnly = layout === "csvOnlyUsers" && a === "Windows.Sys.Users%2FUsers";
      if (!csvOnly) tree[`${p}results/All ${a}.json`] = jsonl(huntWideRows(a));
      if (layout === "full" || csvOnly) tree[`${p}results/All ${a}.csv`] = csv(huntWideRows(a));
    }
  }
  return tree;
}

export async function writeTree(dir: string, tree: Record<string, string>): Promise<void> {
  for (const [rel, text] of Object.entries(tree)) {
    const parts = rel.split("/");
    await mkdir(join(dir, ...parts.slice(0, -1)), { recursive: true });
    await writeFile(join(dir, ...parts), text, "utf8");
  }
}

export interface ZipOptions {
  /** Members stored with a symlink mode. */
  symlinks?: readonly string[];
  /** Same-length byte replacements applied to the finished archive (a name yazl refuses to write). */
  patch?: readonly [string, string][];
  /** Members whose stored bytes are corrupted after writing (stored, so the CRC check fails). */
  corrupt?: readonly string[];
  /** Write every entry in ZIP64 format. */
  zip64?: boolean;
}

/** The tree as a zip archive, built with yazl. */
export async function buildZip(tree: Record<string, string>, opts: ZipOptions = {}): Promise<Buffer> {
  const zip = new yazl.ZipFile();
  for (const [rel, text] of Object.entries(tree)) {
    const link = opts.symlinks?.includes(rel);
    const corrupt = opts.corrupt?.includes(rel);
    zip.addBuffer(Buffer.from(text, "utf8"), rel, {
      mtime: new Date("2026-01-02T03:04:05Z"),
      mode: link ? 0o120777 : 0o100644,
      compress: !corrupt,
      forceZip64Format: !!opts.zip64,
    });
  }
  zip.end();
  const chunks: Buffer[] = [];
  for await (const c of zip.outputStream) chunks.push(c as Buffer);
  let out: Buffer = Buffer.concat(chunks);
  for (const [from, to] of opts.patch ?? []) out = replaceAll(out, Buffer.from(from), Buffer.from(to));
  for (const rel of opts.corrupt ?? []) {
    const body = Buffer.from(tree[rel], "utf8");
    const at = out.indexOf(body);
    if (at >= 0) out[at] = out[at] ^ 0xff;
  }
  return out;
}

function replaceAll(buf: Buffer, from: Buffer, to: Buffer): Buffer {
  if (from.length !== to.length) throw new Error("patch must keep the length");
  const out = Buffer.from(buf);
  for (let at = out.indexOf(from); at >= 0; at = out.indexOf(from, at + 1)) to.copy(out, at);
  return out;
}

/** "host|artifact|pid" for every row a client contributes — the set a correct import covers once. */
export function expectedRowKeys(layout: HuntLayout): string[] {
  void layout;
  return CLIENTS.flatMap((c, i) =>
    ARTIFACTS.flatMap((a) => rowsFor(a, i).map((r) => `${c.host}|${a}|${r.Pid}`)),
  ).sort();
}

/** The row keys one ingest call covered: host from the declared asset host, else the row's Fqdn. */
export function rowKeysOf(name: string, text: string, assetHost: string | undefined): string[] {
  const artifact = name.replace(/\.(json|csv)$/i, "").replace(/^All /, "");
  const rows: Row[] = /\.csv$/i.test(name)
    ? parseCsv(text)
    : text
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l));
  return rows.map((r) => {
    const host = assetHost || CLIENTS.find((c) => fqdn(c.host) === r.Fqdn)?.host || "?";
    return `${host}|${artifact}|${r.Pid}`;
  });
}

function parseCsv(text: string): Row[] {
  const [head, ...lines] = text.trim().split("\n");
  const cols = head.split(",");
  return lines.map((l) => Object.fromEntries(l.split(",").map((v, i) => [cols[i], v])));
}
