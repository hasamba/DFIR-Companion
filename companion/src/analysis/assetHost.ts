// The analyst's "asset for this import" (#1496).
//
// A Windows log export downloaded from the Velociraptor GUI, a notebook or a triage ZIP carries no
// collector column, so nothing inside it says which machine it came from and every name the
// machine ever had becomes its own host (#1489). The analyst knows — they took the file from that
// client's page — and this is where they say so. The declared host stands in exactly as a flow's
// client does (#1458): a per-row Fqdn still wins, a differing Computer becomes a former name with
// the note, and the case's rename ledger records the pair with basis `analyst`, kept apart from
// what a collector or the machine itself wrote.
//
// Two ways in, one validator: the import body (`assetHost`, refused with a reason when present but
// malformed — a silently ignored declaration would leave the analyst believing it took) and a drop
// subfolder named `asset=<HOST>` (an invalid name there is simply not a declaration; the file
// imports as it would anywhere else in the folder). Pure.

const MAX_HOST = 253;
const MAX_LABEL = 63;
// A label as Windows accepts it for a computer name: alphanumeric at both ends, `-` and `_` inside
// (NetBIOS allows the underscore; DNS does not, but a lab host named with one still needs a home).
const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?$/;
const SEPARATOR = /[\\/]/;
const ASSET_FOLDER = /^asset=(.*)$/i;
// A Velociraptor hunt export's per-client folder: `<hostname>-C.<16 hex>` (#2714).
const CLIENT_FOLDER = /^(.+)-C\.[0-9a-f]{16}$/i;

export type AssetHostParse = { ok: true; host: string } | { ok: false; error: string };

/**
 * Normalise a declared host: trimmed, one trailing root dot removed. `{ ok: true, host: "" }` for
 * an absent or blank value (no declaration); `{ ok: false, error }` names the first rule a
 * present value breaks.
 */
export function parseAssetHost(value: unknown): AssetHostParse {
  if (typeof value !== "string") return { ok: true, host: "" };
  const host = value.trim().replace(/\.$/, "");
  if (!host) return { ok: true, host: "" };
  if (host.length > MAX_HOST) return { ok: false, error: `asset host is longer than ${MAX_HOST} characters` };
  for (const label of host.split(".")) {
    if (!label) return { ok: false, error: `asset host "${host}" has an empty label` };
    if (label.length > MAX_LABEL)
      return { ok: false, error: `asset host label "${label}" is longer than ${MAX_LABEL} characters` };
    if (/[^A-Za-z0-9_-]/.test(label))
      return {
        ok: false,
        error: `asset host "${host}" has a character that is not a letter, digit, "-" or "_"`,
      };
    if (!LABEL.test(label))
      return { ok: false, error: `asset host label "${label}" must start or end with a letter or digit` };
  }
  return { ok: true, host };
}

/**
 * The hostname a Velociraptor hunt export's per-client folder names (`<hostname>-C.<16 hex>`), or
 * null when the segment is not a client folder. "" when it is one but the hostname is not a valid
 * host (the folder still counts as a client folder; it just declares nothing). (#2714)
 */
export function clientFolderHost(segment: string): string | null {
  const m = CLIENT_FOLDER.exec(segment);
  if (!m) return null;
  const parsed = parseAssetHost(m[1]);
  return parsed.ok ? parsed.host : "";
}

/**
 * The host a drop-folder relpath declares, on either separator; "" when it declares none or names
 * an invalid host. Two conventions, the first winning:
 *  - a hunt export's per-client result, `…/<hostname>-C.<16 hex>/results/<file>` (#2714): the
 *    folder Velociraptor named after the client the rows came from;
 *  - the FIRST segment `asset=<HOST>` (#1496): the analyst makes that folder at the top of drop/,
 *    and a deeper one is not a convention this reads.
 */
export function assetHostFromDropRelpath(relpath: string): string {
  const segs = relpath.split(SEPARATOR);
  if (segs.length >= 3 && segs[segs.length - 2].toLowerCase() === "results") {
    const client = clientFolderHost(segs[segs.length - 3]);
    if (client) return client;
  }
  const m = ASSET_FOLDER.exec(segs[0] ?? "");
  if (!m) return "";
  const parsed = parseAssetHost(m[1]);
  return parsed.ok ? parsed.host : "";
}
