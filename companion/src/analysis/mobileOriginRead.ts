import type { MobileBlock } from "./canonicalMobile.js";
import {
  REGISTRY_PINS,
  REGISTRY_VERSION,
  headersMatch,
  platformAdmits,
  registryEntry,
} from "./mobileOriginRegistry.js";

// The row reader of the LEAPP origin registry (#988): readOrigin() turns one row's cells into the
// typed MobileBlock and the bounded words of its `[origin: …]` tag. Split out of
// mobileOriginRegistry.ts (data + lookup) when #1363's permission/proxy facets took that file over
// its size cap; nothing here changed in the move.

const norm = (s: string) => s.trim();

export interface OriginReading {
  block: MobileBlock;
  /** The bounded words for the description tag. */
  words: string;
}

const NAME_MAX = 60;
const PACKAGE_MAX = 200;
/** A name inside the tag: brackets to parentheses so the tag's own bracket stays its end. */
const tagSafe = (v: string): string => v.replace(/\[/g, "(").replace(/\]/g, ")");

/**
 * Read one row's origin against the registry. Pure. The block names every column that
 * established a facet; a facet with none is `not-established`.
 */
export function readOrigin(
  platform: MobileBlock["platform"],
  artifact: string,
  headers: readonly string[],
  cells: readonly string[],
): OriginReading {
  const found = registryEntry(artifact);
  // The registry entry must be the requested platform's: an Android import of a file named like
  // an iOS artifact is not evidence of anything and is said so, not read as iOS.
  const entry = found && !platformAdmits(found, platform) ? undefined : found;
  const col = (name: string): string => {
    const i = headers.findIndex((h) => norm(h) === name);
    return i >= 0 ? (cells[i] ?? "").trim() : "";
  };
  const base: MobileBlock = {
    platform,
    artifact: norm(artifact).slice(0, 120),
    registry: { version: REGISTRY_VERSION, coverage: "not-covered" },
    facets: {
      acquisition: "not-established",
      locality: "not-established",
      record: "other",
      authorship: "not-established",
    },
    evidence: [],
    conflicts: [],
  };
  if (!entry) {
    const words = found
      ? `not established — the artifact is a ${found.platform === "ios" ? "iLEAPP" : "ALEAPP"} table imported as ${platform} — ${REGISTRY_VERSION}`
      : `not established — ${REGISTRY_VERSION}`;
    return { block: base, words };
  }
  const pinned = `${entry.platform === "ios" ? "iLEAPP" : "ALEAPP"}@${REGISTRY_PINS[entry.platform === "ios" ? "iLEAPP" : "ALEAPP"].commit}`;
  if (!headersMatch(entry, headers)) {
    return {
      block: { ...base, registry: { version: REGISTRY_VERSION, coverage: "headers-differ", pinned } },
      words: `artifact known, headers differ from the pinned release (${pinned}) — ${REGISTRY_VERSION}`,
    };
  }
  if (entry.excluded) {
    return {
      block: { ...base, registry: { version: REGISTRY_VERSION, coverage: "excluded", pinned } },
      words: `excluded (${entry.excluded}) — ${REGISTRY_VERSION}`,
    };
  }
  const evidence: MobileBlock["evidence"] = [];
  const conflicts: string[] = [];
  let acquisition: MobileBlock["facets"]["acquisition"] = "not-established";
  if (entry.acquisitionFrom) {
    const v = col(entry.acquisitionFrom.column);
    const read = entry.acquisitionFrom.values[v];
    if (read) {
      acquisition = read;
      evidence.push({ facet: "acquisition", column: entry.acquisitionFrom.column, value: v });
    } else if (v)
      conflicts.push(
        `${entry.acquisitionFrom.column} reads "${v.slice(0, NAME_MAX)}", a value the pinned release does not define`,
      );
  } else if (entry.acquisition && entry.acquisitionColumn) {
    const v = col(entry.acquisitionColumn);
    if (v) {
      acquisition = entry.acquisition;
      evidence.push({ facet: "acquisition", column: entry.acquisitionColumn, value: v.slice(0, NAME_MAX) });
    } else
      conflicts.push(
        `${entry.acquisitionColumn} is empty on a row of an artifact that establishes ${entry.acquisition} through it`,
      );
  }
  evidence.push({ facet: "record", column: "(artifact)", value: entry.name });
  evidence.push({ facet: "locality", column: "(artifact)", value: entry.name });
  const transition = entry.transitionColumn ? col(entry.transitionColumn) : "";
  if (transition)
    evidence.push({
      facet: "transition",
      column: entry.transitionColumn!,
      value: transition.slice(0, NAME_MAX),
    });
  const access = entry.accessColumn ? col(entry.accessColumn) : "";
  if (access)
    evidence.push({ facet: "access", column: entry.accessColumn!, value: access.slice(0, NAME_MAX) });
  // Bounded like `app.package` (200): a permission or a proxy is a package-shaped name, and a
  // vendor permission (`com.google.android.gms.permission.…`) already runs past NAME_MAX.
  const permission = entry.permissionColumn ? col(entry.permissionColumn).slice(0, PACKAGE_MAX) : "";
  if (permission) evidence.push({ facet: "permission", column: entry.permissionColumn!, value: permission });
  const proxy = entry.proxyColumn ? col(entry.proxyColumn).slice(0, PACKAGE_MAX) : "";
  if (proxy) evidence.push({ facet: "proxy", column: entry.proxyColumn!, value: proxy });
  const deviceName = entry.device ? col(entry.device.name) : "";
  const deviceId = entry.device?.id ? col(entry.device.id) : "";
  const accountName = entry.account ? col(entry.account.name) : "";
  const accountType = entry.account?.type ? col(entry.account.type) : "";
  const appPackage = entry.app?.package ? col(entry.app.package) : "";
  const appSha = entry.app?.sha256 ? col(entry.app.sha256).toLowerCase() : "";
  const block: MobileBlock = {
    ...base,
    registry: { version: REGISTRY_VERSION, coverage: "schema-matches", pinned },
    facets: {
      acquisition,
      locality: entry.locality,
      record: entry.record,
      authorship: "not-established",
      ...(transition ? { transition: transition.slice(0, NAME_MAX) } : {}),
    },
    evidence,
    conflicts,
    ...(deviceName
      ? {
          device: {
            name: deviceName.slice(0, NAME_MAX),
            ...(deviceId ? { id: deviceId.slice(0, NAME_MAX) } : {}),
          },
        }
      : {}),
    ...(accountName
      ? {
          account: {
            name: accountName.slice(0, NAME_MAX),
            ...(accountType ? { type: accountType.slice(0, NAME_MAX) } : {}),
          },
        }
      : {}),
    ...(permission ? { permission } : {}),
    ...(proxy ? { proxy: { package: proxy } } : {}),
    ...(appPackage || /^[0-9a-f]{64}$/.test(appSha)
      ? {
          app: {
            ...(appPackage ? { package: appPackage.slice(0, PACKAGE_MAX) } : {}),
            ...(/^[0-9a-f]{64}$/.test(appSha) ? { sha256: appSha } : {}),
          },
        }
      : {}),
  };
  const parts = [acquisition, entry.locality, entry.record];
  const names = [
    ...(deviceName ? [`row names device "${tagSafe(deviceName.slice(0, NAME_MAX))}"`] : []),
    ...(accountName ? [`row names account "${tagSafe(accountName.slice(0, NAME_MAX))}"`] : []),
    ...(transition ? [`transition ${tagSafe(transition.slice(0, NAME_MAX))}`] : []),
    // The column's own name, lowercased, so a configured `mode`, an at-access `op mode` and a
    // stored `granted` never read as one shared fact; TCC's column is literally `Access`.
    ...(entry.accessColumn && access
      ? [`${entry.accessColumn.toLowerCase()} ${tagSafe(access.slice(0, NAME_MAX))}`]
      : []),
    // A proxied op is said in the row's own words: it is not the named package's own act.
    ...(proxy ? [`proxy "${tagSafe(proxy)}"`] : []),
  ];
  const words = `${parts.join(", ")}${names.length ? ` (${names.join("; ")})` : ""}${conflicts.length ? "; conflict: " + conflicts.map(tagSafe).join("; ") : ""} — ${REGISTRY_VERSION}`;
  return { block, words };
}
