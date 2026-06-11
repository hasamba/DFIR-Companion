import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { atomicWrite } from "../storage/atomicWrite.js";
import { sanitizeRuleInput, type IocWhitelistRule, type WhitelistRuleInput } from "./iocWhitelist.js";

// Persists the IOC whitelist. GLOBAL (shared across cases, like TemplateStore / ArtifactBundleStore):
// internal IP ranges and known-good system hashes are environment-level and reused across
// investigations. A single JSON file next to `cases/`. Auto-marking writes per-case legitimate
// markers, so the whitelist itself stays case-agnostic.
export class IocWhitelistStore {
  constructor(private readonly file: string) {}

  async load(): Promise<IocWhitelistRule[]> {
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as unknown;
      if (!Array.isArray(raw)) return [];
      // Re-validate on read so a hand-edited file can't inject a bad regex/CIDR into matching.
      return raw
        .map((r) => {
          const core = sanitizeRuleInput(r);
          if (!core) return null;
          const o = r as Record<string, unknown>;
          const id = typeof o.id === "string" && o.id.trim() ? o.id.trim() : randomUUID();
          const addedAt = typeof o.addedAt === "string" && o.addedAt ? o.addedAt : new Date(0).toISOString();
          return { id, addedAt, ...core } as IocWhitelistRule;
        })
        .filter((r): r is IocWhitelistRule => r !== null);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async save(rules: IocWhitelistRule[]): Promise<void> {
    // Create the parent dir only if it's missing. `mkdir(recursive)` on an existing path that is a
    // drive root (e.g. C:\ when cases root is C:\cases) throws EPERM on Windows, so guard on exists.
    const dir = dirname(this.file);
    if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, JSON.stringify(rules, null, 2));
  }

  private key(r: WhitelistRuleInput): string {
    return `${r.match}|${r.pattern.trim().toLowerCase()}|${r.iocType ?? ""}`;
  }

  // Add one rule (server-assigned id + addedAt). Idempotent: an identical rule (same match +
  // pattern + type) returns the existing one instead of duplicating.
  async add(input: WhitelistRuleInput): Promise<IocWhitelistRule> {
    const rules = await this.load();
    const dup = rules.find((r) => this.key(r) === this.key(input));
    if (dup) return dup;
    const rule: IocWhitelistRule = { id: randomUUID(), addedAt: new Date().toISOString(), ...input };
    await this.save([...rules, rule]);
    return rule;
  }

  // Bulk add (CSV/JSON import). Skips entries that duplicate an existing rule or one earlier in the
  // same batch. Returns only the rules actually added.
  async addMany(inputs: WhitelistRuleInput[]): Promise<IocWhitelistRule[]> {
    const rules = await this.load();
    const seen = new Set(rules.map((r) => this.key(r)));
    const added: IocWhitelistRule[] = [];
    for (const input of inputs) {
      const k = this.key(input);
      if (seen.has(k)) continue;
      seen.add(k);
      added.push({ id: randomUUID(), addedAt: new Date().toISOString(), ...input });
    }
    if (added.length) await this.save([...rules, ...added]);
    return added;
  }

  // Remove one rule by id; returns true if it existed.
  async remove(id: string): Promise<boolean> {
    const rules = await this.load();
    const next = rules.filter((r) => r.id !== id);
    if (next.length === rules.length) return false;
    await this.save(next);
    return true;
  }
}
