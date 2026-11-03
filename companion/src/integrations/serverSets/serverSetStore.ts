import { randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { open, seal } from "./secretBox.js";
import { secretsOfSet } from "./setSecrets.js";
import { MASKED_SECRET, type ServerSet, type ServerSetInput } from "./types.js";

interface Links {
  defaultId?: string;
  cases: Record<string, string>;
}

const MAX_NAME = 80;

// Re-reads the JSON files on every call (no cache), so a second instance or a hand edit is
// seen at once. Secrets are sealed in sets.json and opened on read.
export class ServerSetStore {
  private readonly setsPath: string;
  private readonly linksPath: string;

  constructor(
    dir: string,
    private readonly key: Buffer,
  ) {
    mkdirSync(dir, { recursive: true });
    this.setsPath = join(dir, "sets.json");
    this.linksPath = join(dir, "links.json");
  }

  list(): ServerSet[] {
    return this.readRaw().map((s) => this.openSet(s));
  }

  // The decrypted secrets of every set, for log redaction. A set that cannot be opened is skipped.
  secretValues(): string[] {
    const out: string[] = [];
    for (const raw of this.readRaw()) {
      try {
        out.push(...secretsOfSet(this.openSet(raw)));
      } catch {
        /* undecryptable set: nothing to redact, keep going */
      }
    }
    return out;
  }

  // Whether a set with this id exists. Reads no secret, so a store with a changed key still answers.
  has(id: string): boolean {
    return this.readRaw().some((s) => s.id === id);
  }

  get(id: string): ServerSet | undefined {
    const raw = this.readRaw().find((s) => s.id === id);
    return raw ? this.openSet(raw) : undefined;
  }

  create(input: ServerSetInput): ServerSet {
    if (input.iris?.apiKey === MASKED_SECRET || input.timesketch?.password === MASKED_SECRET) {
      throw new Error("secret required");
    }
    const clean = this.validate(input);
    const set: ServerSet = { ...clean, id: randomUUID(), revision: 1 };
    this.writeSets([...this.readRaw(), this.sealSet(set)]);
    return set;
  }

  update(id: string, input: ServerSetInput): ServerSet {
    const raw = this.readRaw();
    const idx = raw.findIndex((s) => s.id === id);
    if (idx < 0) throw new Error("server set not found");
    const prev = this.openSet(raw[idx]);
    const merged: ServerSetInput = { ...input };
    if (input.iris) {
      merged.iris = {
        ...input.iris,
        apiKey: input.iris.apiKey === MASKED_SECRET ? (prev.iris?.apiKey ?? "") : input.iris.apiKey,
      };
    }
    if (input.timesketch) {
      merged.timesketch = {
        ...input.timesketch,
        password:
          input.timesketch.password === MASKED_SECRET
            ? (prev.timesketch?.password ?? "")
            : input.timesketch.password,
      };
    }
    const clean = this.validate(merged, id);
    const next: ServerSet = { ...clean, id, revision: prev.revision + 1 };
    const out = [...raw];
    out[idx] = this.sealSet(next);
    this.writeSets(out);
    return next;
  }

  remove(id: string): { ok: true } | { ok: false; usedBy: string[] } {
    if (this.defaultId() === id) return { ok: false, usedBy: [] };
    const usedBy = this.casesUsing(id);
    if (usedBy.length > 0) return { ok: false, usedBy };
    this.writeSets(this.readRaw().filter((s) => s.id !== id));
    return { ok: true };
  }

  defaultId(): string | undefined {
    return this.readLinks().defaultId;
  }

  setDefault(id: string): void {
    if (!this.readRaw().some((s) => s.id === id)) throw new Error("server set not found");
    const links = this.readLinks();
    this.writeLinks({ ...links, defaultId: id });
  }

  linkCase(caseId: string, setId: string): void {
    if (!this.readRaw().some((s) => s.id === setId)) throw new Error("server set not found");
    const links = this.readLinks();
    this.writeLinks({ ...links, cases: { ...links.cases, [caseId]: setId } });
  }

  // Links a newly created case to the default set and returns that set's id. With no usable default
  // the case stays unlinked (any stale link from a deleted case of the same id is dropped).
  // `keepExisting` leaves a case that already has a link alone (a demo reseed keeps its set).
  linkToDefault(caseId: string, opts: { keepExisting?: boolean } = {}): string | undefined {
    const current = this.caseSetId(caseId);
    if (opts.keepExisting && current) return current;
    const id = this.defaultId();
    if (id && this.has(id)) {
      this.linkCase(caseId, id);
      return id;
    }
    if (current) this.unlinkCase(caseId);
    return undefined;
  }

  unlinkCase(caseId: string): void {
    const links = this.readLinks();
    const { [caseId]: _gone, ...rest } = links.cases;
    this.writeLinks({ ...links, cases: rest });
  }

  caseSetId(caseId: string): string | undefined {
    return this.readLinks().cases[caseId];
  }

  casesUsing(setId: string): string[] {
    return Object.entries(this.readLinks().cases)
      .filter(([, sid]) => sid === setId)
      .map(([cid]) => cid);
  }

  private validate(input: ServerSetInput, selfId?: string): ServerSetInput {
    const name = (input.name ?? "").trim();
    if (!name) throw new Error("name required");
    if (name.length > MAX_NAME) throw new Error(`name must be at most ${MAX_NAME} characters`);
    const lower = name.toLowerCase();
    if (this.readRaw().some((s) => s.id !== selfId && s.name.toLowerCase() === lower)) {
      throw new Error("name already used");
    }
    checkUrl("iris", input.iris?.url);
    checkUrl("timesketch", input.timesketch?.url);
    return { ...input, name };
  }

  private sealSet(set: ServerSet): ServerSet {
    const out: ServerSet = { ...set };
    if (set.iris) out.iris = { ...set.iris, apiKey: this.sealSecret(set.iris.apiKey) };
    if (set.timesketch)
      out.timesketch = { ...set.timesketch, password: this.sealSecret(set.timesketch.password) };
    return out;
  }

  private openSet(set: ServerSet): ServerSet {
    const out: ServerSet = { ...set };
    if (set.iris) out.iris = { ...set.iris, apiKey: this.openSecret(set.iris.apiKey) };
    if (set.timesketch)
      out.timesketch = { ...set.timesketch, password: this.openSecret(set.timesketch.password) };
    return out;
  }

  // An empty secret stays empty on disk, so "no key yet" needs no key to read.
  private sealSecret(v: string): string {
    return v ? seal(v, this.key) : "";
  }

  private openSecret(v: string): string {
    return v ? open(v, this.key) : "";
  }

  private readRaw(): ServerSet[] {
    const parsed = readJson<unknown>(this.setsPath, []);
    return Array.isArray(parsed) ? (parsed as ServerSet[]) : [];
  }

  private readLinks(): Links {
    const l = readJson<Partial<Links>>(this.linksPath, {});
    return { defaultId: l.defaultId, cases: l.cases && typeof l.cases === "object" ? l.cases : {} };
  }

  private writeSets(sets: ServerSet[]): void {
    atomicWriteSync(this.setsPath, JSON.stringify(sets, null, 2));
  }

  private writeLinks(links: Links): void {
    atomicWriteSync(this.linksPath, JSON.stringify(links, null, 2));
  }
}

function checkUrl(tool: string, url: string | undefined): void {
  if (!url) return;
  let ok = false;
  try {
    const p = new URL(url).protocol;
    ok = p === "http:" || p === "https:";
  } catch {
    ok = false;
  }
  if (!ok) throw new Error(`${tool} url must be http(s)`);
}

function readJson<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback;
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function atomicWriteSync(path: string, text: string): void {
  const tmp = `${path}.${randomUUID()}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  renameSync(tmp, path);
  try {
    chmodSync(path, 0o600);
  } catch {
    // chmod is best effort on Windows.
  }
}
