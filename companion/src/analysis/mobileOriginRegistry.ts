// The LEAPP origin registry (#932 item 18 — #988): what a row of a KNOWN iLEAPP / ALEAPP artifact
// establishes about where its content came from, read from the artifact's own columns and from
// nothing else.
//
// PINNED TO UPSTREAM. Every entry names the artifact exactly as upstream names it (the TSV
// filename LEAPP writes), the module's `last_update_date` where the module has one, and the
// header tuple the module's `data_headers` emits, in order. Read from the upstream sources at
// REGISTRY_PINS below (see the dated comment above it for when/why each side last moved). A TSV
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

// 2026-09-16: four iOS entries added for #932 item 16 (usage/power/permission/network app-identity
// corroboration) from a fresh check of iLEAPP main @ 6dc251d857c0 (2026-09-14). Moving the shared
// iLEAPP pin re-verifies every EXISTING iOS entry too, since headersMatch is exact-and-ordered —
// every pre-existing iOS entry was re-diffed against the new commit before this change; every
// header tuple is unchanged.
// 2026-09-18: seven Android entries added for #1298 (932.15's granted/used-permission
// prerequisite: AppOps modern + legacy, Recent Accesses, Permission Modes, the two Permission
// Store views, Usage Stats) from ALEAPP main @ ce0880dc232c. Every pre-existing Android entry was
// re-diffed against that commit: eight unchanged; `Android Notification History` had pinned 17 of
// upstream's 23 columns since before the previous pin (#1336) and is corrected here. iLEAPP is
// untouched.
export const REGISTRY_VERSION = "leapp-origin-2026-09-18";
export const REGISTRY_PINS = {
  iLEAPP: { ref: "main", commit: "6dc251d857c0", date: "2026-09-14" },
  ALEAPP: { ref: "main", commit: "ce0880dc232c", date: "2026-09-18" },
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
  /** A second named column read into evidence/words, same shape as transitionColumn (#932 item
   * 16 — TCC's grant/deny outcome). Kept separate from transitionColumn's own name: the two read
   * different kinds of fact and a shared field would blur which artifact wrote which value. */
  accessColumn?: string;
  device?: { name: string; id?: string };
  account?: { name: string; type?: string };
  /** App identity columns: the typed values the infection window and the app-corroboration pass
   * compare. Named `app-inventory` originally (#988); now also populated on usage/power/permission/
   * network/notification rows (#932 item 16) so those join by the same identity. */
  app?: { package?: string; sha256?: string };
  /** Upstream's own `datetime`-typed headers, in upstream order — the row's clock candidates
   * (#1298). Declared only where the importer's generic picker (a header containing the word
   * `time` or `date`, or ending in `timestamp`) would miss a clock (`Timestamp TP` satisfies
   * neither rule) or take a duration for one (`Time Active (ms)` contains the word `time`); an
   * entry without it keeps the generic picker. Honoured only when the headers match the pin. */
  clocks?: readonly string[];
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
    // "Bundle ID 2" is a second, upstream-undocumented bundle field — never read as identity.
    app: { package: "Bundle ID" },
  },
  {
    platform: "ios",
    name: "knowledgeC - App Usage",
    lastUpdate: "2025-09-13",
    headers: ["Start Time", "End Time", "Time Added", "Application"],
    // A usage session's start/end (#932 item 16); "Application" is the row's bundle id, read as
    // stored. Neither foreground nor background is distinguished by this table — see PowerLog for
    // the artifact that actually splits background from screen-on time.
    record: "usage",
    locality: "device-local",
    app: { package: "Application" },
  },
  {
    platform: "ios",
    name: "PowerLog - Application Runtime",
    lastUpdate: "2026-09-01",
    headers: [
      "Timestamp",
      "Bundle ID",
      "Background Time (seconds)",
      "Screen-on Time (seconds)",
      "In-Call Background Time (seconds)",
      "In-Call Screen-on Time (seconds)",
      "Time Offset (seconds)",
      "Source File",
    ],
    // The direct background-activity artifact (#932 item 16): PLAppTimeService_Aggregate_AppRunTime
    // splits background time from screen-on time per app, per sampling window. The seconds
    // themselves are read as stored and never interpreted here — an app-corroboration pass reads
    // presence of this row, not its duration; "energy use is not execution of a particular
    // malicious function" per the item's own guardrail.
    record: "power",
    locality: "device-local",
    app: { package: "Bundle ID" },
  },
  {
    platform: "ios",
    name: "Application Permissions",
    lastUpdate: "2026-07-31",
    // The modern TCC.db schema (a `last_modified` column present, roughly iOS 13+). TCC.db has an
    // older schema too (no `last_modified`, a trailing `Prompt Count` column instead) that this
    // entry does not cover — a legacy-schema export reads headers-differ, same as any other
    // unregistered variant; not guessed at.
    headers: ["Last Modified Timestamp", "Bundle ID", "Service", "Access"],
    record: "permission",
    locality: "device-local",
    app: { package: "Bundle ID" },
    // Access is Allowed / Not allowed / Limited, per the module's own SQL CASE — carried into
    // evidence/words so a denied prompt never reads the same as a granted one.
    accessColumn: "Access",
  },
  {
    platform: "ios",
    name: "App Data",
    lastUpdate: "2026-07-31",
    headers: [
      "Live Usage Timestamp",
      "Process First Usage Timestamp",
      "Process Timestamp",
      "Bundle Name",
      "Process Name",
      "ZKIND (as stored)",
      "Wifi In (Bytes)",
      "Wifi Out (Bytes)",
      "Mobile/WWAN In (Bytes)",
      "Mobile/WWAN Out (Bytes)",
      "Wired In (Bytes)",
      "Wired Out (Bytes)",
    ],
    // netusage.sqlite's per-process network usage (#932 item 16) — the "matching network evidence"
    // half. Identity is "Bundle Name", never "Process Name" (daemons and system processes populate
    // that column too). "ZKIND (as stored)" is upstream-undocumented ("its values are not
    // documented" per the module's own note) and is read as stored, never interpreted; presence of
    // this row (a populated Bundle Name) is the corroborating fact, not a byte total.
    record: "network",
    locality: "device-local",
    app: { package: "Bundle Name" },
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
      // #1336: the six columns below were upstream at the previous pin too; the entry had stopped
      // at `Image Resource ID`, so every real export read headers-differ.
      "Image Resource ID Package",
      "Image Data Length",
      "Image Data Offset",
      "Image URI",
      "Protobuf File Name",
      "Timestamp From Protobuf File Name",
    ],
    // As for Notification Duet: the package posted it; that is all the column says.
    record: "notification",
    locality: "device-local",
    app: { package: "Package Name" },
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
  // #1298 (932.15's granted/used prerequisite). An AppOps row is evidence the OS recorded a
  // permission operation for that package — never proof the user consciously granted it, never
  // proof of malicious use. A stored grant (`Granted`, `Mode`) is a state at collection time, not
  // a grant event and not evidence the permission was ever exercised. A usage row is presence in
  // the OS's usage ledger, not execution of a particular function.
  {
    platform: "android",
    name: "App Ops Permissions",
    lastUpdate: "2026-08-01",
    // No outcome column: whether the op was allowed or rejected is which timestamp is populated,
    // and AppOps keeps both a last access and a last reject per op, so both can be. The importer
    // dates the row by the first populated declared clock and stamps that clock's name on it —
    // `[Reject Timestamp: …]` when only the reject is set; when both are, the row is dated by the
    // access and the reject survives only as a rendered cell. No facet restates it.
    headers: [
      "Access Timestamp",
      "Reject Timestamp",
      "Package Name",
      "ID",
      "Proxy Package Name",
      "Proxy Package UID",
      "Permission",
    ],
    clocks: ["Access Timestamp", "Reject Timestamp"],
    record: "permission",
    locality: "device-local",
    app: { package: "Package Name" },
  },
  {
    platform: "android",
    name: "App Ops Permissions - Legacy",
    lastUpdate: "2026-08-01",
    headers: [
      "Timestamp TP",
      "Timestamp TC",
      "Timestamp TB",
      "Timestamp TF",
      "Timestamp TFS",
      "Timestamp TT",
      "Package Name",
      "Duration",
      "Proxy Package Name",
      "Proxy Package UID",
      "Permission",
    ],
    clocks: ["Timestamp TP", "Timestamp TC", "Timestamp TB", "Timestamp TF", "Timestamp TFS", "Timestamp TT"],
    record: "permission",
    locality: "device-local",
    app: { package: "Package Name" },
  },
  {
    platform: "android",
    name: "App Ops Recent Accesses",
    lastUpdate: "2026-09-06",
    headers: [
      "Access Timestamp",
      "Reject Timestamp",
      "Package Name",
      "UID",
      "Permission",
      "Op Code",
      "Attribution Tag",
      "App State At Access",
      "Access Flag",
      "Access Duration (ms)",
      "Op Mode",
      "Proxy Package Name",
      "Proxy Attribution Tag",
      "Proxy UID",
      "Source File",
    ],
    clocks: ["Access Timestamp", "Reject Timestamp"],
    record: "permission",
    locality: "device-local",
    app: { package: "Package Name" },
    // The mode in force at access time: upstream's OP_MODES (AppOpsManager at android-15.0.0_r1)
    // is ALLOWED / IGNORED / ERRORED / DEFAULT / FOREGROUND, or the stored integer outside that
    // set — carried verbatim, as TCC's Access is. A different fact from a configured `Mode`.
    accessColumn: "Op Mode",
  },
  {
    platform: "android",
    name: "App Ops Permission Modes",
    lastUpdate: "2026-09-06",
    headers: [
      "Package Name",
      "UID",
      "Android User",
      "Permission",
      "Op Code",
      "Mode",
      "Mode Stored Against",
      "Source File",
    ],
    record: "permission",
    locality: "device-local",
    app: { package: "Package Name" },
    // The CONFIGURED mode for the op (same OP_MODES vocabulary), not an access — a state.
    accessColumn: "Mode",
  },
  {
    platform: "android",
    name: "App Op Modes (Permission Store)",
    lastUpdate: "2026-09-07",
    headers: ["Package Name", "App ID", "Android User", "App Op", "Op Code", "Mode", "Mode Stored Against"],
    record: "permission",
    locality: "device-local",
    app: { package: "Package Name" },
    accessColumn: "Mode",
  },
  {
    platform: "android",
    name: "Permission Grants (Permission Store)",
    lastUpdate: "2026-09-07",
    headers: ["Package Name", "App ID", "Android User", "Permission", "Granted", "Permission Flags"],
    record: "permission",
    locality: "device-local",
    app: { package: "Package Name" },
    // AOSP's own PermissionFlags.isPermissionGranted, ported upstream: Yes / No, or the raw flags
    // value when it cannot decide — never re-derived here.
    accessColumn: "Granted",
  },
  {
    platform: "android",
    name: "Usage Stats",
    lastUpdate: "2026-08-01",
    headers: [
      "User (UID)",
      "Timestamp / Last Time Active",
      "Usage Type",
      "Time Active (ms)",
      "Time Active (sec)",
      "Last Time Service Used",
      "Total Time Service Used (ms)",
      "Last Time Visible",
      "Total Time Visible (ms)",
      "Last Time Component Used",
      "App Launch Count",
      "Package",
      "Event Type",
      "Class",
      "Event Flags (as stored)",
      "Shortcut ID",
      "Standby Bucket (high 16 bits)",
      "Standby Reason (low 16 bits)",
      "Notification Channel",
      "Instance ID",
      "Task Root Package",
      "Task Root Class",
      "Locus ID",
      "Interaction Category",
      "Interaction Action",
      "Interval",
    ],
    // Four datetime columns upstream; `Time Active (ms)` and its siblings are durations and are
    // never a clock.
    clocks: [
      "Timestamp / Last Time Active",
      "Last Time Service Used",
      "Last Time Visible",
      "Last Time Component Used",
    ],
    record: "usage",
    locality: "device-local",
    app: { package: "Package" },
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

/** An entry may be read for its own platform, or for an `unknown` import; never across platforms.
 * One predicate for readOrigin and pinnedClocks, so a row can never be dated by a pin its origin
 * reading would not vouch for. */
function platformAdmits(entry: RegistryEntry, platform: MobileBlock["platform"]): boolean {
  return entry.platform === platform || platform === "unknown";
}

/** The column indices of an entry's declared clocks, in the order the entry declares them (the
 * registry test holds that to upstream's header order) — or undefined when the artifact declares
 * none, is not this platform's, or its headers do not match the pin (then the importer's generic
 * picker applies, as it always did). */
export function pinnedClocks(
  platform: MobileBlock["platform"],
  artifact: string,
  headers: readonly string[],
): number[] | undefined {
  const entry = registryEntry(artifact);
  if (!entry?.clocks || !platformAdmits(entry, platform) || !headersMatch(entry, headers)) return undefined;
  const have = headers.map(norm);
  const out = entry.clocks.map((c) => have.indexOf(norm(c))).filter((i) => i >= 0);
  return out.length ? out : undefined;
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
    // The column's own name, lowercased, so a configured `mode`, an at-access `op mode` and a
    // stored `granted` never read as one shared fact; TCC's column is literally `Access`.
    ...(entry.accessColumn && access
      ? [`${entry.accessColumn.toLowerCase()} ${tagSafe(access.slice(0, NAME_MAX))}`]
      : []),
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
