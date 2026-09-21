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
 * The host a drop-folder relpath declares through its FIRST segment, `asset=<HOST>`, on either
 * separator; "" when the path declares none or names an invalid host. Only the first segment
 * counts: the analyst makes the folder at the top of drop/, and a deeper one is not a convention
 * this reads.
 */
export function assetHostFromDropRelpath(relpath: string): string {
  const first = relpath.split(SEPARATOR)[0] ?? "";
  const m = ASSET_FOLDER.exec(first);
  if (!m) return "";
  const parsed = parseAssetHost(m[1]);
  return parsed.ok ? parsed.host : "";
}
