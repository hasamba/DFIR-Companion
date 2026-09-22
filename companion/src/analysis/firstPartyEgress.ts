// A Windows updater phoning its own vendor is not a detection (#1530).
//
// Velociraptor's Windows.Sigma.Base pack grades the rule "Net Conn (Sysmon Alert)" at medium, and
// that rule fires on EVERY Sysmon EID 3. On INC-2026-001 that put seven OneDrive update
// connections — OneDriveSetup.exe to Microsoft and Akamai addresses on 443 and 80, twenty-three
// days before the incident — into the forensic timeline at Medium, where synthesis fused them with
// the intrusion's real C2 metadata into one "Command & Control" finding, opened a thread asking the
// analyst to identify "six external IPs", and asked for firewall logs against Microsoft's CDN.
//
// So the grade is decided on WHAT CONNECTED and WHERE TO, not on the fact that a rule fired.
//
// ─────────────────────────────── WHY THIS IS SAFE TO LOWER ───────────────────────────────
//
// The image path is NOT the control. `%LOCALAPPDATA%\Microsoft\OneDrive\` is where OneDrive really
// installs itself, and it is also a directory any user — or anything running as that user — can
// write to. An intruder can put a file called OneDriveSetup.exe there. Every argument that a path
// alone is enough has been rejected in this codebase before (veloDetectionNoise.ts); it is rejected
// here too.
//
// The DESTINATION is the control. The connection must land in a vendor range nobody can rent —
// ipHygiene.ts's `single-tenant` tier, which today is Microsoft's own service edges and nothing
// else. Azure, AWS and GCP compute space is excluded there, and so is every CDN edge, Akamai's
// included: an edge that fronts other people's origins can front a compromised one. So an intruder
// would have to both plant the binary AND serve their C2 from inside Microsoft's own
// infrastructure. The price of that strictness is visible in the case this came from: the OneDrive
// updater's fetch from an Akamai node keeps the rule's Medium grade, and the analyst still sees it.
//
// Four more bounds keep the blast radius at the generic verdict this exists to quiet:
//   • ≤ Medium only. A High or Critical keeps its grade whatever the image is.
//   • No ATT&CK technique on the row. A rule that named a technique adjudicated the row; this did not.
//   • Port 80 or 443 only.
//   • An analyst-promoted row (`promotedAt`) and a row already carrying an `origin` are untouched.
//
// And the row is not deleted. Info means the super-timeline keeps it, the analyst can still search
// it, and — because this runs BEFORE the content tagger at the import seam — a tagger rule that
// matches the row raises it straight back out of Info. Lowering, then one chance to raise, then
// demote: the order ARCHITECTURE.md already documents.
//
// PURE — no I/O, returns new events, never mutates its input.

import { canonicalFile, canonicalNetwork } from "./canonicalEvent.js";
import { isNonIndicatorVendorIp, vendorForIp } from "./ipHygiene.js";
import type { ForensicEvent } from "./stateTypes.js";

/** The ports a first-party client fetches over. Anything else keeps the rule's grade. */
const VENDOR_PORTS = new Set([80, 443]);

/** Severities this pass may lower. A named rule that reached High or Critical is never touched. */
const LOWERABLE = new Set(["Low", "Medium"]);

const PATH_TRAVERSAL = /(?:^|[\\/])\.\.(?:[\\/]|$)/;

/**
 * The first-party clients whose egress this covers: updaters and background services that talk to
 * exactly one vendor. A general-purpose browser is NOT here on purpose — msedge.exe legitimately
 * connects anywhere, so "it is Edge" says nothing about the destination being benign.
 *
 * Each entry pairs the install-directory shape with the executables that belong in it, so a file
 * dropped beside a real OneDrive install under a different name matches nothing.
 */
interface FirstPartyClient {
  /** What the analyst should read in the note. */
  product: string;
  /** The install directory shape, matched against the path with `/` folded to `\`. */
  dir: RegExp;
  /** The executables that legitimately live there, lower-cased. */
  executables: ReadonlySet<string>;
}

const ONEDRIVE_EXES = new Set([
  "onedrive.exe",
  "onedrivesetup.exe",
  "onedrivestandaloneupdater.exe",
  "onedrive.sync.service.exe",
  "filecoauth.exe",
  "filesynchelper.exe",
  "filesyncconfig.exe",
]);

const DEFENDER_EXES = new Set(["msmpeng.exe", "mpcmdrun.exe", "nissrv.exe", "mpdefendercoreservice.exe"]);

const FIRST_PARTY_CLIENTS: readonly FirstPartyClient[] = [
  {
    product: "OneDrive",
    dir: /\\appdata\\local\\microsoft\\onedrive\\/,
    executables: ONEDRIVE_EXES,
  },
  {
    product: "OneDrive",
    dir: /\\program files(?: \(x86\))?\\microsoft onedrive\\/,
    executables: ONEDRIVE_EXES,
  },
  {
    product: "Microsoft Edge Update",
    dir: /\\(?:appdata\\local|program files(?: \(x86\))?)\\microsoft\\edgeupdate\\/,
    executables: new Set(["microsoftedgeupdate.exe"]),
  },
  {
    product: "Microsoft Defender",
    dir: /\\programdata\\microsoft\\windows defender\\platform\\/,
    executables: DEFENDER_EXES,
  },
  {
    product: "Microsoft Defender",
    dir: /\\program files\\windows defender\\/,
    executables: DEFENDER_EXES,
  },
];

/** The product whose install shape this image path matches, or "" for anything else. */
export function firstPartyClientProduct(imagePath: string): string {
  const p = (imagePath ?? "").trim().toLowerCase().replace(/\//g, "\\");
  if (!p || PATH_TRAVERSAL.test(p)) return "";
  const exe = p.slice(p.lastIndexOf("\\") + 1);
  if (!exe) return "";
  for (const c of FIRST_PARTY_CLIENTS) if (c.executables.has(exe) && c.dir.test(p)) return c.product;
  return "";
}

/** Why a row reads Info, written into the row itself so the record explains its own grade. */
export function firstPartyEgressNote(event: ForensicEvent): string {
  if (!event || event.promotedAt || event.origin) return "";
  if (!LOWERABLE.has(event.severity)) return "";
  if (event.mitreTechniques?.length) return "";

  // A network record, read from the envelope: a logon record also carries a network block (its
  // source address), and this pass must never touch one.
  if (event.canonical?.event?.category !== "network") return "";
  const net = canonicalNetwork(event);
  const destination = net?.destination?.address ?? event.dstIp ?? "";
  const port = net?.destination?.port ?? event.port;
  if (!destination || typeof port !== "number" || !VENDOR_PORTS.has(port)) return "";
  if (!isNonIndicatorVendorIp(destination)) return "";

  const imagePath = canonicalFile(event)?.path ?? event.path ?? "";
  const product = firstPartyClientProduct(imagePath);
  if (!product) return "";

  const vendor = vendorForIp(destination)?.vendor ?? "the vendor";
  return ` [first-party update traffic — ${product} to a ${vendor} service address on ${port}]`;
}

export interface FirstPartyEgressResult {
  events: ForensicEvent[];
  /** Ids this pass lowered, for the import log line. */
  downgraded: string[];
}

/**
 * Lower every qualifying row to Info, with its reason appended. Returns new objects; the input
 * array and its events are untouched. Idempotent: a row already carrying the note is left alone.
 */
export function downgradeFirstPartyEgress(events: readonly ForensicEvent[]): FirstPartyEgressResult {
  const downgraded: string[] = [];
  const out = events.map((e) => {
    const note = firstPartyEgressNote(e);
    if (!note || e.description.includes(note)) return e;
    downgraded.push(e.id);
    return { ...e, severity: "Info" as const, description: `${e.description}${note}`.slice(0, 1200) };
  });
  return { events: downgraded.length ? out : [...events], downgraded };
}
