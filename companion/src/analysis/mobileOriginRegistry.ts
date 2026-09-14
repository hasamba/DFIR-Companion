// The LEAPP origin registry (#932 item 18 — #988): what a row of a KNOWN iLEAPP / ALEAPP artifact
// establishes about where its content came from, read from the artifact's own columns and from
// nothing else.
//
// PINNED TO UPSTREAM. Every entry names the artifact exactly as upstream names it (the TSV
// filename LEAPP writes), the module's `last_update_date` where the module has one, and the
// header tuple the module's `data_headers` emits, in order. Read from the upstream sources on
// 2026-09-14: iLEAPP main @ 925f3d71e2e0, ALEAPP main @ 498491475597 (both 2026-09-13). A TSV
// whose headers differ from the pinned tuple is `headers-differ` even when its name matches — a
// guess about a renamed column would mislabel a row both ways. A bare TSV carries no producer
// version, so coverage is `schema-matches`, never `producer-verified`: the headers match the
// pinned release; the file's own LEAPP version is not recorded.
//
// FACETS, NOT A CLASS. Acquisition, locality, record type and authorship are orthogonal and each
// names the column that established it. A facet with no establishing column is `not-established`
// and is never inferred from another facet. In this build `authorship` is `not-established` on
// every row: no pinned column identifies a person. Safari's `Origin` is a RECORD-origin fact in
// Safari's own words (the visit record originated on this device, or was synced from another) —
// not "a person visited"; a Chromium `Transition Type` is a navigation fact, not an author.
//
// WHAT IS NEVER CLAIMED. Device possession does not establish authorship. Shared accounts and
// synchronised browsing or media place content on a device without a local action. A cached link
// is not an opened link. A notification is a message received, not read. An account or device a
// row names is an association ("the row names account X"), never an actor or a source.

export const REGISTRY_VERSION = "leapp-origin-2026-09-13";
export const REGISTRY_PINS = {
  iLEAPP: { ref: "main", commit: "925f3d71e2e0", date: "2026-09-13" },
  ALEAPP: { ref: "main", commit: "498491475597", date: "2026-09-13" },
} as const;

import { ACQUISITIONS, LOCALITIES, RECORD_TYPES, type MobileBlock } from "./canonicalMobile.js";

interface RegistryEntry {
  platform: "ios" | "android";
  /** Upstream `name` — the TSV filename LEAPP writes. */
  name: string;
  lastUpdate?: string;
  /** Upstream `data_headers` names, in order. */
  headers: readonly string[];
  excluded?: string;
  record: (typeof RECORD_TYPES)[number];
  locality: (typeof LOCALITIES)[number];
  /** A fixed acquisition the artifact establishes for every row, when it does. */
  acquisition?: (typeof ACQUISITIONS)[number];
  acquisitionColumn?: string;
  /** Column-driven acquisition: the column and the readings it establishes. */
  acquisitionFrom?: { column: string; values: Record<string, (typeof ACQUISITIONS)[number]> };
  transitionColumn?: string;
  device?: { name: string; id?: string };
  account?: { name: string; type?: string };
  /** App-inventory identity columns: the typed values the infection window compares. */
  app?: { package?: string; sha256?: string };
}

const SAFARI_ICLOUD_TABS = [
  "Created Timestamp",
  "Modified Timestamp",
  "Title",
  "URL",
  "Device Name",
  "Device UUID",
  "Tab UUID",
  "Modified By",
];

export const REGISTRY: readonly RegistryEntry[] = [
  {
    platform: "ios",
    name: "Safari Browser - History",
    lastUpdate: "2026-07-30",
    headers: [
      "Visit Timestamp",
      "Title",
      "URL",
      "Visit Count",
      "Redirect Source",
      "Redirect Destination",
      "Visit ID",
      "Origin",
      "Profile",
    ],
    record: "history",
    locality: "device-local",
    acquisitionFrom: {
      column: "Origin",
      values: {
        "Local Device": "recorded-on-this-device",
        "iCloud Synced Device": "synced-from-another-device",
      },
    },
  },
  {
    platform: "ios",
    name: "Safari Browser - iCloud Tabs",
    headers: SAFARI_ICLOUD_TABS,
    record: "tab",
    locality: "cloud",
    acquisition: "synced",
    acquisitionColumn: "Device Name",
    device: { name: "Device Name", id: "Device UUID" },
  },
  {
    platform: "ios",
    name: "Safari Browser - Tabs (BrowserState)",
    headers: [
      "Associated Timestamp",
      "Title",
      "URL",
      "User Visible URL",
      "Opened from Link",
      "Private Browsing",
    ],
    record: "tab",
    locality: "device-local",
  },
  {
    platform: "ios",
    name: "Safari Browser - Tabs (SafariTabs)",
    headers: [
      "Last Modified",
      "Date Closed",
      "Tab ID",
      "Title",
      "URL",
      "Parent ID",
      "Parent / Tab Group",
      "Browsing Mode",
      "Last Visit Time",
      "Date Last Viewed",
      "Opened from Link",
      "Tab Index",
      "Muted",
      "Showing Reader",
      "Tab UUID",
    ],
    record: "tab",
    locality: "device-local",
  },
  {
    platform: "ios",
    name: "Notification Duet",
    headers: [
      "SEGB Timestamp",
      "Notification Time",
      "Notification Time 2",
      "SEGB State",
      "GUID",
      "Title",
      "Subtitle",
      "Body",
      "Bundle ID",
      "Bundle ID 2",
      "Optional Data",
      "Person Identifier",
      "Person Info",
      "GUID 2",
      "Filename",
      "Offset",
    ],
    // A notification is a record the device holds; the bundle id names the app that posted it and
    // establishes neither delivery from outside nor that anyone read it.
    record: "notification",
    locality: "device-local",
  },
  {
    platform: "ios",
    name: "Account Data",
    headers: ["Timestamp", "Account Desc.", "Username", "Description", "Identifier", "Bundle ID"],
    record: "account",
    locality: "device-local",
    account: { name: "Username", type: "Account Desc." },
  },
  {
    platform: "ios",
    name: "Apple Account - Device List",
    headers: [
      "Last Updated",
      "Last Cache Updated",
      "Device Name",
      "Model",
      "OS",
      "OS Version",
      "Build Number",
      "Serial Number",
      "IMEI",
      "Trusted",
      "Circle Status",
      "Services",
      "Machine ID (mid)",
      "altDSID",
      "dc",
      "clcg",
      "clbg",
      "clhs",
      "dec",
      "Additional Info",
    ],
    record: "device",
    locality: "cloud",
    device: { name: "Device Name", id: "Serial Number" },
  },
  {
    platform: "android",
    name: "Web History",
    lastUpdate: "2020-03-19",
    headers: [
      "Last Visit Time",
      "URL",
      "Title",
      "Visit Count",
      "Typed Count",
      "ID",
      "Hidden",
      "Browser Name",
    ],
    record: "history",
    locality: "device-local",
  },
  {
    platform: "android",
    name: "Web Visits",
    lastUpdate: "2026-08-01",
    headers: [
      "Visit Timestamp",
      "URL",
      "Title",
      "Duration",
      "Transition Type",
      "Qualifier(s)",
      "From Visit URL",
      "Browser Name",
    ],
    record: "history",
    locality: "device-local",
    transitionColumn: "Transition Type",
  },
  {
    platform: "android",
    name: "Search Terms",
    headers: ["Last Visit Time", "Search Term", "URL", "Title", "Visit Count", "Browser Name"],
    record: "history",
    locality: "device-local",
  },
  {
    platform: "android",
    name: "Android Notification History",
    lastUpdate: "2026-08-01",
    headers: [
      "Posted Time",
      "Title",
      "Text",
      "Package Name",
      "User ID",
      "UID",
      "Package Index",
      "Channel Name",
      "Channel Name Index",
      "Channel ID",
      "Channel ID Index",
      "Conversation ID",
      "Conversation ID Index",
      "Major Version",
      "Image Type",
      "Image Bitmap Filename",
      "Image Resource ID",
    ],
    // As for Notification Duet: the package posted it; that is all the column says.
    record: "notification",
    locality: "device-local",
  },
  {
    platform: "android",
    name: "Android Notification History - Status",
    lastUpdate: "2024-07-02",
    headers: ["Status", "User"],
    excluded: "a settings row (whether the feature is enabled), not a notification",
    record: "other",
    locality: "device-local",
  },
  {
    platform: "android",
    name: "Android Notification History - Snoozed",
    headers: ["Reminder Time", "Snoozed Notification"],
    excluded: "a policy row (a snoozed reminder), not a received notification",
    record: "other",
    locality: "device-local",
  },
  {
    platform: "android",
    name: "Accounts_ce",
    lastUpdate: "2025-03-14",
    headers: ["Account Type", "Account Name", "Password"],
    record: "account",
    locality: "device-local",
    account: { name: "Account Name", type: "Account Type" },
  },
  {
    platform: "android",
    name: "installedappsGass",
    lastUpdate: "2026-09-12",
    headers: ["User", "Bundle ID", "Version Code", "SHA-256 Hash"],
    record: "app-inventory",
    locality: "device-local",
    app: { package: "Bundle ID", sha256: "SHA-256 Hash" },
  },
  {
    platform: "android",
    name: "InstalledappsLibrary",
    headers: ["User", "Purchase Time", "Account", "Doc ID"],
    record: "app-inventory",
    locality: "device-local",
    acquisition: "from-store-account",
    acquisitionColumn: "Account",
    account: { name: "Account" },
  },
];

const norm = (s: string) => s.trim();

/** The pinned entry for an artifact name, matched exactly (case and spacing are the identity). */
export function registryEntry(artifact: string): RegistryEntry | undefined {
  return REGISTRY.find((e) => e.name === norm(artifact));
}

/** Whether a TSV's headers are the pinned tuple, in order, exactly. */
export function headersMatch(entry: RegistryEntry, headers: readonly string[]): boolean {
  const have = headers.map(norm);
  return have.length === entry.headers.length && have.every((h, i) => h === entry.headers[i]);
}

export interface OriginReading {
  block: MobileBlock;
  /** The bounded words for the description tag. */
  words: string;
}

const NAME_MAX = 60;
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
  const entry = found && found.platform !== platform && platform !== "unknown" ? undefined : found;
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
    ...(appPackage || /^[0-9a-f]{64}$/.test(appSha)
      ? {
          app: {
            ...(appPackage ? { package: appPackage.slice(0, 200) } : {}),
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
  ];
  const words = `${parts.join(", ")}${names.length ? ` (${names.join("; ")})` : ""}${conflicts.length ? "; conflict: " + conflicts.map(tagSafe).join("; ") : ""} — ${REGISTRY_VERSION}`;
  return { block, words };
}

/** The guard the manual and the module header state, for tests and the timeline note. */
export const NON_INFERENCES = [
  "device possession does not establish authorship",
  "shared accounts and synchronised browsing or media place content on a device without a local action",
  "a cached link is not an opened link",
  "a notification is a message received, not read",
  "presence of malware alone neither attributes nor explains away unrelated activity",
] as const;
