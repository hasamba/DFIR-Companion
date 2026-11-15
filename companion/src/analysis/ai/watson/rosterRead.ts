import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../../../storage/atomicWrite.js";
import { WATSON_ROSTER_FILE } from "../../investigationStateFiles.js";
import { mergeMaskRoster, type WatsonMaskRoster } from "./superRoster.js";

export { WATSON_ROSTER_FILE };

// The mask roster every masker on the case reads (rosterNames.ts). It is the union of two files in the
// case's state dir: the chat's own roster (watson-chat.json, rewound by a backup restore) and the
// durable sidecar (watson-mask-roster.json, never rewound). The sidecar is a superset of every roster
// the chat ever saved, so the history's old answers stay masked after a restore.
//
// Fail closed: a file that exists but cannot be read as a roster throws WatsonRosterUnreadable, and
// the AI call that needed it is not sent. "Absent" is not "unreadable": no file gives no roster.
//
// The read is cheap: one module-level cache, keyed by the state dir and validated by both files'
// stat, so every WatsonChatStore instance and every direct file write (restore, import) is seen.

export const WATSON_CHAT_FILE = "watson-chat.json";
export const WATSON_ROSTER_CACHE_MAX = 256;

export class WatsonRosterUnreadable extends Error {
  constructor() {
    super(
      "Watson cannot read its list of masked names for this case, so nothing went to the AI. " +
        "Restore the file or ask an administrator.",
    );
    this.name = "WatsonRosterUnreadable";
  }
}

export interface RosterFs {
  stat(path: string): Promise<{ mtimeMs: number; size: number; ino: number }>;
  readFile(path: string, enc: "utf8"): Promise<string>;
}

export interface RosterReader {
  read(stateDir: string): Promise<WatsonMaskRoster | undefined>;
  forget(stateDir: string): void;
}

const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((e): e is string => typeof e === "string") : [];

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const hasNames = (r: WatsonMaskRoster): boolean =>
  r.hosts.length > 0 || r.users.length > 0 || r.ips.length > 0;

/** The persisted mask roster, read leniently (an older chat has none). Undefined when it holds no name. */
export function maskRosterOf(raw: unknown): WatsonMaskRoster | undefined {
  if (!isRecord(raw)) return undefined;
  const roster = mergeMaskRoster(undefined, {
    hosts: strings(raw.hosts),
    users: strings(raw.users),
    ips: strings(raw.ips),
  });
  return hasNames(roster) ? roster : undefined;
}

const isStringList = (v: unknown): boolean =>
  v === undefined || (Array.isArray(v) && v.every((e) => typeof e === "string"));

/** The sidecar's roster. Throws WatsonRosterUnreadable for bad JSON, a non-object, or bad hosts/users. */
export function parseRosterSidecar(text: string): WatsonMaskRoster {
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    throw new WatsonRosterUnreadable();
  }
  if (!isRecord(raw) || !isStringList(raw.hosts) || !isStringList(raw.users))
    throw new WatsonRosterUnreadable();
  return maskRosterOf(raw) ?? { hosts: [], users: [], ips: [] };
}

/** The chat file's roster; `corrupt` when the file is bad JSON or not an object. */
function chatRosterOf(text: string): { roster?: WatsonMaskRoster; corrupt: boolean } {
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    return { corrupt: true };
  }
  if (!isRecord(raw)) return { corrupt: true };
  const roster = maskRosterOf(raw.maskRoster);
  return roster ? { roster, corrupt: false } : { corrupt: false };
}

const isMissing = (err: unknown): boolean => (err as NodeJS.ErrnoException).code === "ENOENT";

/** A file's stat key, or null when it does not exist. Any other error is rethrown. */
async function statKey(fs: RosterFs, path: string): Promise<string | null> {
  try {
    const s = await fs.stat(path);
    return `${s.mtimeMs}:${s.size}:${s.ino}`;
  } catch (err) {
    if (isMissing(err)) return null;
    throw err;
  }
}

/** A file's text, or null when it went missing after its stat. */
async function readText(fs: RosterFs, path: string, key: string | null): Promise<string | null> {
  if (key === null) return null;
  try {
    return await fs.readFile(path, "utf8");
  } catch (err) {
    if (isMissing(err)) return null;
    throw err;
  }
}

/** The merged roster of the two files' texts, under the fail-closed rules above. */
function mergedRoster(chatText: string | null, sideText: string | null): WatsonMaskRoster | undefined {
  const side = sideText === null ? undefined : parseRosterSidecar(sideText);
  const chat = chatText === null ? { corrupt: false } : chatRosterOf(chatText);
  // A corrupt chat with a valid sidecar reads the sidecar alone: it is the superset. Without one, a
  // legacy chat's names cannot be known, so the read fails closed.
  if (chat.corrupt && !side) throw new WatsonRosterUnreadable();
  if (!side && !chat.roster) return undefined;
  return maskRosterOf(mergeMaskRoster(side, chat.roster));
}

const copyOf = (r: WatsonMaskRoster | undefined): WatsonMaskRoster | undefined =>
  r ? { hosts: [...r.hosts], users: [...r.users], ips: [...r.ips] } : undefined;

const nodeFs: RosterFs = { stat, readFile: (p, enc) => readFile(p, enc) };

export function createRosterReader(fs: RosterFs = nodeFs, max = WATSON_ROSTER_CACHE_MAX): RosterReader {
  const cache = new Map<string, { key: string; roster: WatsonMaskRoster | undefined }>();
  const generations = new Map<string, number>();
  const generation = (dir: string): number => generations.get(dir) ?? 0;

  const store = (dir: string, key: string, roster: WatsonMaskRoster | undefined): void => {
    cache.delete(dir);
    if (cache.size >= max) {
      const oldest = cache.keys().next();
      if (!oldest.done) cache.delete(oldest.value);
    }
    cache.set(dir, { key, roster });
  };

  return {
    async read(stateDir) {
      const gen = generation(stateDir);
      const chatPath = join(stateDir, WATSON_CHAT_FILE);
      const sidePath = join(stateDir, WATSON_ROSTER_FILE);
      const [chatKey, sideKey] = await Promise.all([statKey(fs, chatPath), statKey(fs, sidePath)]);
      if (chatKey === null && sideKey === null) return undefined;
      const key = `${chatKey ?? "-"}|${sideKey ?? "-"}`;
      const hit = cache.get(stateDir);
      if (hit && hit.key === key) return copyOf(hit.roster);
      const [chatText, sideText] = await Promise.all([
        readText(fs, chatPath, chatKey),
        readText(fs, sidePath, sideKey),
      ]);
      const roster = mergedRoster(chatText, sideText);
      if (generation(stateDir) === gen) store(stateDir, key, roster);
      return copyOf(roster);
    },
    forget(stateDir) {
      cache.delete(stateDir);
      generations.set(stateDir, generation(stateDir) + 1);
    },
  };
}

/** The one reader every WatsonChatStore instance shares. */
export const watsonRosterReader: RosterReader = createRosterReader();

const sidecarChains = new Map<string, Promise<unknown>>();

/** The sidecar's roster, or undefined when it is absent or unreadable (a save never overwrites it). */
async function sidecarForSave(path: string): Promise<WatsonMaskRoster | undefined | "unreadable"> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if (isMissing(err)) return undefined;
    throw err;
  }
  try {
    return parseRosterSidecar(text);
  } catch (err) {
    if (err instanceof WatsonRosterUnreadable) return "unreadable";
    throw err;
  }
}

async function syncSidecar(path: string, roster: WatsonMaskRoster): Promise<void> {
  const side = await sidecarForSave(path);
  // A corrupt sidecar is never overwritten: that would turn "unreadable" into "readable with names
  // missing". The read keeps failing closed until the file is restored.
  if (side === "unreadable") return;
  const union = mergeMaskRoster(side, roster);
  const grew =
    union.hosts.length > (side?.hosts.length ?? 0) || union.users.length > (side?.users.length ?? 0);
  if (grew) await atomicWrite(path, JSON.stringify(union, null, 2));
}

/**
 * Fold a saved chat's roster into the durable sidecar when it holds a host or user the sidecar lacks.
 * Writes for one state dir run one at a time, so two WatsonChatStore instances never lose a name.
 */
export function keepRosterDurable(stateDir: string, roster: WatsonMaskRoster | undefined): Promise<void> {
  if (!roster || (!roster.hosts.length && !roster.users.length)) return Promise.resolve();
  const path = join(stateDir, WATSON_ROSTER_FILE);
  const prev = sidecarChains.get(path) ?? Promise.resolve();
  const run = prev.then(() => syncSidecar(path, roster));
  const tail = run.catch(() => undefined);
  sidecarChains.set(path, tail);
  void tail.then(() => {
    if (sidecarChains.get(path) === tail) sidecarChains.delete(path);
  });
  return run;
}
