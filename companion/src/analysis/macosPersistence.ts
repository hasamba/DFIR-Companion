// macOS persistence artifact PARSING (#908 item 6).
//
// launchd is how almost everything on macOS starts, malicious or not. A LaunchAgent runs when a user
// logs in; a LaunchDaemon runs as root when the machine boots. Both are one property list naming a
// program to run, and both directories are writable by anything running with the right privileges.
//
// ─────────────────────────── WHY A HAND-WRITTEN PLIST READER ───────────────────────────
//
// A collected plist is adversary-controlled input. An XML parser that resolves DOCTYPE entities on
// input like that is an XXE vulnerability and a decompression bomb in one, and no plist the Companion
// needs to read requires entities at all. So the reader below is a bounded scanner: it skips the XML
// declaration, the DOCTYPE and comments outright, expands only the five predefined XML entities, and
// stops at a fixed nesting depth. It reads plists; it does not implement XML.
//
// BINARY PLISTS ARE NOT READ. `bplist00` is the on-disk format for most of /System, and it is not
// text — an upload of one arrives as mojibake. isBinaryPlist recognises it so the importer can SAY
// the file needs converting (`plutil -convert xml1`) instead of silently reading nothing out of it.
//
// ─────────────────────────── SHARED WITH LINUX ───────────────────────────
//
// macOS cron and shell profiles ARE the Linux ones: same crontab grammar, same `.zshrc`. Those are
// parsed and graded by linuxPersistence.ts / linuxPersistRules.ts rather than copied here. This
// module adds only what is macOS's own — launchd, and the classifier that knows where macOS keeps
// its cron spool.

import { classifyLinuxArtifact, type LinuxArtifactKind } from "./linuxPersistence.js";

export type PlistValue = string | number | boolean | PlistValue[] | { [k: string]: PlistValue };

/** How deep the reader will follow nested dicts and arrays. */
export const MAX_PLIST_DEPTH = 24;

/** How many entries one dict or array may hold. */
export const MAX_PLIST_ENTRIES = 2_000;

/** Does this upload look like a binary plist, which is not text and cannot be read here? */
export function isBinaryPlist(text: string): boolean {
  return (text ?? "").slice(0, 16).startsWith("bplist0");
}

/** Does this upload look like an XML property list? */
export function isXmlPlist(text: string): boolean {
  const head = (text ?? "").slice(0, 4096);
  return /<plist\b/i.test(head) || /<!DOCTYPE\s+plist\b/i.test(head);
}

/** Which artifact class a collected macOS path holds. Falls through to the Linux classifier. */
export function classifyMacArtifact(path: string): LinuxArtifactKind {
  const p = path.toLowerCase();
  if (p.endsWith(".plist")) return "launchd";
  if (/\/library\/launch(agents|daemons)\//.test(p)) return "launchd";
  return classifyLinuxArtifact(path);
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

/**
 * The five predefined entities and NUMERIC character references. No custom entity, ever.
 *
 * Numeric references were left as written, so `&#47;tmp&#47;evil.sh` came back as that literal
 * string and the path rules saw no `/tmp/` — a one-line evasion that made a malicious job read as
 * clean. A numeric reference is a plain character, not a document-defined name, so expanding it
 * carries none of the risk that expanding a DOCTYPE entity does. Values are capped so a reference
 * cannot be used to inflate the text.
 */
function unescapeXml(s: string): string {
  return s
    .replace(/&(amp|lt|gt|quot|apos);/g, (m, name: string) => ENTITIES[name] ?? m)
    .replace(/&#(x?)([0-9a-f]{1,6});/gi, (m, hex: string, digits: string) => {
      const code = parseInt(digits, hex ? 16 : 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : m;
    });
}

interface Scanner {
  s: string;
  i: number;
}

// Skip whitespace, comments, the XML declaration and the DOCTYPE. The DOCTYPE is SKIPPED, never
// read: an internal subset is where entity-expansion attacks live, and no plist needs one.
function skipNoise(sc: Scanner): void {
  for (;;) {
    while (sc.i < sc.s.length && /\s/.test(sc.s[sc.i])) sc.i++;
    if (sc.s.startsWith("<!--", sc.i)) {
      const end = sc.s.indexOf("-->", sc.i + 4);
      sc.i = end < 0 ? sc.s.length : end + 3;
      continue;
    }
    if (sc.s.startsWith("<?", sc.i)) {
      const end = sc.s.indexOf("?>", sc.i + 2);
      sc.i = end < 0 ? sc.s.length : end + 2;
      continue;
    }
    if (/^<!DOCTYPE/i.test(sc.s.slice(sc.i, sc.i + 9))) {
      // Step over a possible internal subset, then the closing angle bracket.
      const bracket = sc.s.indexOf("[", sc.i);
      const close = sc.s.indexOf(">", sc.i);
      if (bracket >= 0 && close >= 0 && bracket < close) {
        const endSubset = sc.s.indexOf("]", bracket);
        const after = endSubset < 0 ? sc.s.length : sc.s.indexOf(">", endSubset);
        sc.i = after < 0 ? sc.s.length : after + 1;
      } else sc.i = close < 0 ? sc.s.length : close + 1;
      continue;
    }
    return;
  }
}

/** Read the next tag name, or "" at end of input. Self-closing tags are reported with a trailing "/". */
function nextTag(sc: Scanner): string {
  skipNoise(sc);
  if (sc.i >= sc.s.length || sc.s[sc.i] !== "<") return "";

  // A `>` inside a quoted attribute value is not the end of the tag. A raw indexOf(">") cut
  // `<key attr="a>b">Program</key>` in the middle, and the key became `b">Program` — so the value
  // was never associated with Program and the job read as clean.
  let close = -1;
  let quote = "";
  for (let i = sc.i + 1; i < sc.s.length; i++) {
    const ch = sc.s[i];
    if (quote) {
      if (ch === quote) quote = "";
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === ">") {
      close = i;
      break;
    }
  }
  if (close < 0) {
    sc.i = sc.s.length;
    return "";
  }
  const raw = sc.s.slice(sc.i + 1, close).trim();
  sc.i = close + 1;
  const selfClosing = raw.endsWith("/");
  const name = raw.replace(/\/$/, "").split(/\s/, 1)[0];
  return selfClosing ? `${name}/` : name;
}

/**
 * Read character data up to the closing tag, through CDATA sections and comments.
 *
 * Stopping at the first `<` dropped both. `<string><![CDATA[/tmp/evil.sh]]></string>` yielded an
 * empty program, and `<string>/tmp<!-- x -->/evil.sh</string>` yielded `/tmp` — which the path
 * rules do not match, because they need the trailing slash. Both were one-line evasions.
 */
function readText(sc: Scanner): string {
  let out = "";
  for (let guard = 0; guard < 64; guard++) {
    if (sc.s.startsWith("<![CDATA[", sc.i)) {
      const end = sc.s.indexOf("]]>", sc.i + 9);
      out += end < 0 ? sc.s.slice(sc.i + 9) : sc.s.slice(sc.i + 9, end);
      sc.i = end < 0 ? sc.s.length : end + 3;
      continue;
    }
    if (sc.s.startsWith("<!--", sc.i)) {
      const end = sc.s.indexOf("-->", sc.i + 4);
      sc.i = end < 0 ? sc.s.length : end + 3;
      continue;
    }
    const next = sc.s.indexOf("<", sc.i);
    const end = next < 0 ? sc.s.length : next;
    out += unescapeXml(sc.s.slice(sc.i, end));
    sc.i = end;
    if (next < 0 || !sc.s.startsWith("<![CDATA[", sc.i)) {
      if (!sc.s.startsWith("<!--", sc.i)) break;
    }
  }
  return out.trim();
}

function readValue(sc: Scanner, tag: string, depth: number): PlistValue | undefined {
  if (depth > MAX_PLIST_DEPTH) return undefined;
  switch (tag) {
    case "true/":
      return true;
    case "false/":
      return false;
    case "dict/":
      return {};
    case "array/":
      return [];
    case "string":
    case "key":
    case "data":
    case "date": {
      const text = readText(sc);
      nextTag(sc); // the closing tag
      return text;
    }
    case "integer":
    case "real": {
      const text = readText(sc);
      nextTag(sc);
      const n = Number(text);
      return Number.isFinite(n) ? n : text;
    }
    case "dict": {
      const out: Record<string, PlistValue> = {};
      for (let n = 0; n < MAX_PLIST_ENTRIES; n++) {
        const t = nextTag(sc);
        if (!t || t === "/dict") break;
        if (t !== "key") continue;
        const key = readText(sc);
        nextTag(sc); // </key>
        const vt = nextTag(sc);
        if (!vt || vt === "/dict") break;
        // A dangling `<key>Orphan</key>` followed by another `<key>` is malformed, and the first
        // version read the NEXT KEY'S NAME as the orphan's value and then broke out of the dict —
        // so every remaining pair, Program included, was lost and the job read as clean. Skip the
        // orphan and carry on: what follows is still readable.
        if (vt === "key") {
          const nextKey = readText(sc);
          nextTag(sc); // </key>
          const nextValueTag = nextTag(sc);
          if (!nextValueTag || nextValueTag === "/dict") break;
          const nextValue = readValue(sc, nextValueTag, depth + 1);
          if (nextValue !== undefined) out[nextKey] = nextValue;
          continue;
        }
        const value = readValue(sc, vt, depth + 1);
        if (value !== undefined) out[key] = value;
      }
      return out;
    }
    case "array": {
      const out: PlistValue[] = [];
      for (let n = 0; n < MAX_PLIST_ENTRIES; n++) {
        const t = nextTag(sc);
        if (!t || t === "/array") break;
        const value = readValue(sc, t, depth + 1);
        if (value !== undefined) out.push(value);
      }
      return out;
    }
    default:
      return undefined;
  }
}

/** Parse an XML property list into its root dictionary, or null when it holds none. */
export function parsePlist(xml: string): Record<string, PlistValue> | null {
  if (!xml || isBinaryPlist(xml)) return null;
  const sc: Scanner = { s: xml, i: 0 };
  for (let n = 0; n < MAX_PLIST_ENTRIES; n++) {
    const tag = nextTag(sc);
    if (!tag) return null;
    if (tag === "dict") {
      const v = readValue(sc, tag, 0);
      return v && typeof v === "object" && !Array.isArray(v) ? v : null;
    }
    if (tag === "dict/") return {};
  }
  return null;
}

// ─────────────────────────── launchd jobs ───────────────────────────

export interface LaunchJob {
  label: string;
  /** The executable, from Program or the first element of ProgramArguments. */
  program: string;
  /** Arguments after the executable. */
  arguments: string[];
  /** The whole command line as written, for the payload graders. */
  commandLine: string;
  runAtLoad: boolean;
  keepAlive: boolean;
  /** Seconds, when the job re-runs on a timer. */
  startInterval: number | null;
  scheduled: boolean;
  watchPaths: string[];
  userName: string;
  disabled: boolean;
  /**
   * EnvironmentVariables. Read because DYLD_INSERT_LIBRARIES is macOS persistence in one key: the
   * program can be entirely legitimate while the library loaded into it is not.
   */
  environment: Record<string, string>;
}

function str(v: PlistValue | undefined): string {
  return typeof v === "string" ? v : "";
}

function bool(v: PlistValue | undefined): boolean {
  // KeepAlive is a boolean OR a dictionary of conditions. A dictionary means "kept alive under these
  // conditions", which for this purpose is still kept alive — reading it as false lost the job.
  if (typeof v === "boolean") return v;
  if (v && typeof v === "object" && !Array.isArray(v)) return Object.keys(v).length > 0;
  return false;
}

/** Read a launchd job out of a parsed plist. */
export function readLaunchJob(plist: Record<string, PlistValue>): LaunchJob {
  const args = Array.isArray(plist.ProgramArguments)
    ? plist.ProgramArguments.filter((a): a is string => typeof a === "string")
    : [];
  // Program wins when both are present, which is launchd's own rule: ProgramArguments[0] is then
  // argv[0] and NOT the executable. Reading argv[0] as the program is how a job that sets Program to
  // a dropper and argv[0] to "/usr/sbin/cupsd" would have been read as cupsd.
  const program = str(plist.Program) || args[0] || "";
  const rest = str(plist.Program) ? args : args.slice(1);
  const interval = typeof plist.StartInterval === "number" ? plist.StartInterval : null;

  return {
    label: str(plist.Label),
    program,
    arguments: rest,
    commandLine: [program, ...rest].filter(Boolean).join(" "),
    runAtLoad: bool(plist.RunAtLoad),
    keepAlive: bool(plist.KeepAlive),
    startInterval: interval,
    scheduled: plist.StartCalendarInterval !== undefined,
    watchPaths: Array.isArray(plist.WatchPaths)
      ? plist.WatchPaths.filter((a): a is string => typeof a === "string")
      : [],
    userName: str(plist.UserName),
    disabled: plist.Disabled === true,
    environment:
      plist.EnvironmentVariables &&
      typeof plist.EnvironmentVariables === "object" &&
      !Array.isArray(plist.EnvironmentVariables)
        ? Object.fromEntries(
            Object.entries(plist.EnvironmentVariables).map(([k, v]) => [
              k,
              typeof v === "string" ? v : String(v),
            ]),
          )
        : {},
  };
}

/** Where a launchd plist sits, which decides what runs it and with what privileges. */
export type LaunchScope = "apple" | "system-daemon" | "system-agent" | "user-agent" | "elsewhere";

export function launchScope(path: string): LaunchScope {
  const p = path.toLowerCase();
  if (p.startsWith("/system/library/launch")) return "apple";
  if (p.startsWith("/library/launchdaemons/")) return "system-daemon";
  if (p.startsWith("/library/launchagents/")) return "system-agent";
  if (/\/users\/[^/]+\/library\/launchagents\//.test(p)) return "user-agent";
  return "elsewhere";
}
