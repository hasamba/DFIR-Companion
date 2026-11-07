import { randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { buildCredential, cleanName } from "./accountInput.js";
import { atomicWriteFileSync } from "../../storage/atomicWriteSync.js";
import { StateLock } from "../../analysis/stateLock.js";
import { CloudVaultError } from "./errors.js";
import {
  secretsOfAccount,
  storedSecretNames,
  type CloudAccountAdder,
  type CloudAccountInput,
  type CloudAccountView,
  type CloudCredential,
  type OpenCloudAccount,
  type ReleasedCloudAccount,
  type StoredCloudAccount,
} from "./types.js";
import { deriveCloudVaultKey, openSecrets, sealSecrets } from "./vaultCrypto.js";
import type { VaultKeyFile } from "./vaultKeyFile.js";

export type VaultKeyState = "present" | "missing" | "invalid" | "insecure";

export interface VaultStatus {
  keyPath: string;
  keyState: VaultKeyState;
  accounts: number;
}

type Key = { ok: true; key: Buffer } | { ok: false; reason: string; state: VaultKeyState };

/** What `releaseCase` returns: the accounts erased and the accounts only detached. */
export interface CaseRelease {
  deleted: ReleasedCloudAccount[];
  detached: ReleasedCloudAccount[];
}

// One file, one key: every vault critical section queues behind the same tail.
const VAULT_LOCK_KEY = "accounts.json";

export const RELEASE_PLAN_CHANGED =
  "the case's cloud accounts changed while the release was being recorded; nothing was released";

// The cloud account vault. Re-reads accounts.json and the key file on every call (no cache), so a
// restored key file unlocks the accounts at once and a hand edit is seen. The key is read lazily:
// listing, deleting and resetting work with no key at all, and a missing key never deletes anything.
export class CloudAccountVault {
  private readonly file: string;
  // In-process mutex (#2371). A synchronous vault call can never interleave with another, but a
  // caller that awaits between reading the vault and changing it can. Every route that changes the
  // vault runs its whole check-then-act under exclusive(), and releaseCaseRecorded holds it across
  // its custody writes, so the custody log and the release come from one snapshot.
  private readonly lock = new StateLock();

  constructor(
    dir: string,
    private readonly keyFile: VaultKeyFile,
  ) {
    mkdirSync(dir, { recursive: true });
    this.file = join(dir, "accounts.json");
  }

  get keyPath(): string {
    return this.keyFile.path;
  }

  status(): VaultStatus {
    const read = this.keyFile.read();
    return { keyPath: this.keyFile.path, keyState: read.state, accounts: this.readRaw().length };
  }

  /** Every account, without secrets. An account the key cannot open is listed as locked, with why. */
  list(): CloudAccountView[] {
    const key = this.key();
    return this.readRaw().map((raw) => this.viewWith(raw, key));
  }

  /** The accounts attached to one case (#2308), without secrets. */
  listForCase(caseId: string): CloudAccountView[] {
    return this.list().filter((a) => a.caseIds.includes(caseId));
  }

  /** One account without secrets. Throws `not-found`. */
  view(id: string): CloudAccountView {
    return this.viewWith(this.find(id), this.key());
  }

  /**
   * Attaches a case to an account (#2308). Attaching an attached case changes nothing. With
   * `fromCase`, refuses (`not-found`) unless the account is STILL attached to that case at the
   * moment of the write — a detach that won a race with the caller's checks wins. A name already
   * used in the target case is a `conflict` that names only that case.
   */
  attach(id: string, caseId: string, fromCase?: string): CloudAccountView {
    return this.setCases(id, (cases, account, raw) => {
      if (fromCase !== undefined && !cases.includes(fromCase))
        throw new CloudVaultError("not-found", "cloud account not found");
      if (cases.includes(caseId)) return cases;
      const lower = account.name.toLowerCase();
      if (
        raw.some((a) => a.id !== id && (a.caseIds ?? []).includes(caseId) && a.name.toLowerCase() === lower)
      )
        throw new CloudVaultError("conflict", "name already used in that case");
      return [...cases, caseId];
    });
  }

  /** Detaches one case. The account and its other cases stay; the last detach leaves it unattached. */
  detach(id: string, caseId: string): CloudAccountView {
    return this.setCases(id, (cases) => cases.filter((c) => c !== caseId));
  }

  /** Drops a deleted case from every account; returns how many accounts it was attached to. */
  detachCase(caseId: string): number {
    const raw = this.readRaw();
    const hit = raw.filter((a) => (a.caseIds ?? []).includes(caseId)).length;
    if (hit === 0) return 0;
    this.write(raw.map((a) => ({ ...a, caseIds: (a.caseIds ?? []).filter((c) => c !== caseId) })));
    return hit;
  }

  /** One account with its secrets, for a collector. Throws `locked` when the key cannot open it. */
  open(id: string): OpenCloudAccount {
    const raw = this.find(id);
    const key = this.requireKey();
    const secrets = openSecrets(raw.sealed, key);
    if (!secrets) throw new CloudVaultError("locked", this.wrongKeyReason());
    return { ...raw, secrets } as unknown as OpenCloudAccount;
  }

  /**
   * Adds an account. With no key file and an empty vault, the key is made first (`keyCreated`);
   * with no key file and accounts already stored, it refuses — a new key would orphan them.
   */
  create(
    input: CloudAccountInput,
    caseId?: string,
    createdBy?: CloudAccountAdder,
  ): { account: CloudAccountView; keyCreated: boolean } {
    const raw = this.readRaw();
    const credential = buildCredential(input);
    const caseIds = caseId ? [caseId] : [];
    const name = this.uniqueName(raw, input.name, caseIds);
    let keyCreated = false;
    let key = this.key();
    if (!key.ok && key.state === "missing" && raw.length === 0) {
      key = { ok: true, key: deriveCloudVaultKey(this.keyFile.create()) };
      keyCreated = true;
    }
    if (!key.ok) throw new CloudVaultError("locked", key.reason);
    const now = new Date().toISOString();
    const adder = createdBy ? { createdBy: { id: createdBy.id, displayName: createdBy.displayName } } : {};
    const meta = { id: randomUUID(), name, revision: 1, createdAt: now, updatedAt: now, ...adder, caseIds };
    const stored = this.sealed(meta, credential, key.key);
    this.write([...raw, stored]);
    return { account: viewOf(stored, storedSecretNames(credential.secrets)), keyCreated };
  }

  /** Edits an account. A secret the request leaves out keeps its stored value; rotation is a new value. */
  update(id: string, input: CloudAccountInput): CloudAccountView {
    const raw = this.readRaw();
    const prev = this.find(id, raw);
    if (input.provider !== prev.provider) throw new CloudVaultError("invalid", "provider cannot change");
    const name = this.uniqueName(raw, input.name, prev.caseIds ?? [], id);
    const opened = this.open(id);
    const credential = buildCredential(input, opened);
    const meta = {
      id,
      name,
      revision: prev.revision + 1,
      createdAt: prev.createdAt,
      updatedAt: new Date().toISOString(),
      // Who added it and when it was last used survive an edit (#2347).
      ...(prev.createdBy ? { createdBy: prev.createdBy } : {}),
      ...(prev.lastUsedAt ? { lastUsedAt: prev.lastUsedAt } : {}),
      caseIds: prev.caseIds ?? [],
    };
    const next = this.sealed(meta, credential, this.requireKey());
    this.write(raw.map((a) => (a.id === id ? next : a)));
    return viewOf(next, storedSecretNames(credential.secrets));
  }

  /** Deletes an account, overwriting its sealed entry first. Needs no key: a locked account can go. */
  remove(id: string): Pick<StoredCloudAccount, "id" | "name" | "provider"> {
    const raw = this.readRaw();
    const gone = this.find(id, raw);
    this.overwriteSealed(raw.map((a) => (a.id === id ? { ...a, sealed: "0".repeat(a.sealed.length) } : a)));
    this.write(raw.filter((a) => a.id !== id));
    return { id: gone.id, name: gone.name, provider: gone.provider };
  }

  /**
   * Erases several accounts in one write, each sealed entry overwritten first (#2347). Throws
   * `not-found` — and erases nothing — when any id is unknown.
   */
  removeMany(ids: readonly string[]): ReleasedCloudAccount[] {
    const raw = this.readRaw();
    const wanted = new Set(ids);
    const gone = ids.map((id) => this.find(id, raw));
    this.overwriteSealed(
      raw.map((a) => (wanted.has(a.id) ? { ...a, sealed: "0".repeat(a.sealed.length) } : a)),
    );
    this.write(raw.filter((a) => !wanted.has(a.id)));
    return gone.map(releasedOf);
  }

  /**
   * A case ends (#2347): an account only this case used is erased (sealed entry overwritten first),
   * an account other cases share is detached from it. One pass, one write.
   */
  releaseCase(caseId: string): CaseRelease {
    const raw = this.readRaw();
    const attached = raw.filter((a) => (a.caseIds ?? []).includes(caseId));
    if (attached.length === 0) return { deleted: [], detached: [] };
    const sole = new Set(attached.filter((a) => (a.caseIds ?? []).length === 1).map((a) => a.id));
    const deleted = attached.filter((a) => sole.has(a.id)).map(releasedOf);
    if (sole.size)
      this.overwriteSealed(
        raw.map((a) => (sole.has(a.id) ? { ...a, sealed: "0".repeat(a.sealed.length) } : a)),
      );
    const kept = raw
      .filter((a) => !sole.has(a.id))
      .map((a) => ({ ...a, caseIds: (a.caseIds ?? []).filter((c) => c !== caseId) }));
    this.write(kept);
    const detached = kept.filter((a) => attached.some((b) => b.id === a.id)).map(releasedOf);
    return { deleted, detached };
  }

  /**
   * Runs `fn` with no other exclusive section of this vault running. Not re-entrant: never call it
   * from inside another exclusive section (it would wait for itself).
   */
  exclusive<T>(fn: () => T | Promise<T>): Promise<T> {
    return this.lock.runExclusive(VAULT_LOCK_KEY, async () => fn());
  }

  /**
   * A case ends, with the detaches recorded first (#2347, #2371): under the vault lock, reads which
   * accounts would only be detached, awaits `recordDetach(those)`, then releases. No locked change
   * can land in between, so what was recorded is what is done. A `recordDetach` that throws stops
   * the release with the vault unchanged. If the plan changed anyway — only a writer outside the
   * lock can do that: a hand edit or a second process — nothing is released (`conflict`): acting on
   * a plan the custody log does not describe is the outcome this guards against.
   */
  releaseCaseRecorded(
    caseId: string,
    recordDetach: (shared: ReleasedCloudAccount[]) => Promise<void>,
  ): Promise<CaseRelease> {
    return this.exclusive(async () => {
      const before = this.releasePlan(caseId);
      await recordDetach(this.sharedWith(caseId));
      if (this.releasePlan(caseId) !== before) throw new CloudVaultError("conflict", RELEASE_PLAN_CHANGED);
      return this.releaseCase(caseId);
    });
  }

  /** The attached accounts and which of them are shared, as one comparable string. */
  private releasePlan(caseId: string): string {
    return JSON.stringify(
      this.readRaw()
        .filter((a) => (a.caseIds ?? []).includes(caseId))
        .map((a) => [a.id, (a.caseIds ?? []).length > 1])
        .sort(([x], [y]) => String(x).localeCompare(String(y))),
    );
  }

  /**
   * The accounts `releaseCase(caseId)` would detach rather than erase — attached to this case and
   * at least one other — without changing anything, so the detach can be recorded first (#2347).
   */
  sharedWith(caseId: string): ReleasedCloudAccount[] {
    return this.readRaw()
      .filter((a) => (a.caseIds ?? []).includes(caseId) && (a.caseIds ?? []).length > 1)
      .map(releasedOf);
  }

  /** Stamps when collection or a read check last opened the account (#2347). A gone account is ignored. */
  markUsed(id: string): void {
    const raw = this.readRaw();
    if (!raw.some((a) => a.id === id)) return;
    const now = new Date().toISOString();
    this.write(raw.map((a) => (a.id === id ? { ...a, lastUsedAt: now } : a)));
  }

  /** Reset vault: wipes every account (overwritten first). The key file is left alone. */
  reset(): number {
    const raw = this.readRaw();
    if (raw.length === 0) return 0;
    this.overwriteSealed(raw.map((a) => ({ ...a, sealed: "0".repeat(a.sealed.length) })));
    this.write([]);
    return raw.length;
  }

  /** Every secret the vault holds, for redaction. Never throws; a locked vault yields nothing. */
  secretValues(): string[] {
    try {
      const key = this.key();
      if (!key.ok) return [];
      return this.readRaw().flatMap((raw) => {
        const secrets = openSecrets(raw.sealed, key.key);
        return secrets ? secretsOfAccount({ ...raw, secrets } as unknown as CloudCredential) : [];
      });
    } catch {
      return [];
    }
  }

  private key(): Key {
    const read = this.keyFile.read();
    if (read.state === "present") return { ok: true, key: deriveCloudVaultKey(read.key) };
    const reasons: Record<Exclude<VaultKeyState, "present">, string> = {
      missing: `Locked — key file not found at ${this.keyFile.path}`,
      invalid: `Locked — the key file at ${this.keyFile.path} is not a valid vault key`,
      insecure: `Locked — key file permissions too open at ${this.keyFile.path}`,
    };
    const reason = reasons[read.state];
    return { ok: false, reason, state: read.state };
  }

  private viewWith(raw: StoredCloudAccount, key: Key): CloudAccountView {
    const view = viewOf(raw, []);
    if (!key.ok) return { ...view, locked: key.reason };
    const secrets = openSecrets(raw.sealed, key.key);
    if (!secrets) return { ...view, locked: this.wrongKeyReason() };
    return { ...view, storedSecrets: storedSecretNames(secrets) };
  }

  private setCases(
    id: string,
    next: (cases: string[], account: StoredCloudAccount, raw: StoredCloudAccount[]) => string[],
  ): CloudAccountView {
    const raw = this.readRaw();
    const prev = this.find(id, raw);
    const updated = { ...prev, caseIds: next(prev.caseIds ?? [], prev, raw) };
    this.write(raw.map((a) => (a.id === id ? updated : a)));
    return this.viewWith(updated, this.key());
  }

  private requireKey(): Buffer {
    const key = this.key();
    if (!key.ok) throw new CloudVaultError("locked", key.reason);
    return key.key;
  }

  private wrongKeyReason(): string {
    return `Locked — the key file at ${this.keyFile.path} does not open this account`;
  }

  private find(id: string, raw = this.readRaw()): StoredCloudAccount {
    const hit = raw.find((a) => a.id === id);
    if (!hit) throw new CloudVaultError("not-found", "cloud account not found");
    return hit;
  }

  // Names are unique per case (#2308), so a clash never reveals an account in a case the caller
  // cannot see: an account's peers are the accounts sharing one of its cases, and an unattached
  // account's peers are the other unattached ones (the instance administrator's scope).
  private uniqueName(raw: StoredCloudAccount[], wanted: string, caseIds: string[], selfId?: string): string {
    const name = cleanName(wanted);
    const lower = name.toLowerCase();
    const peer = (a: StoredCloudAccount): boolean => {
      const theirs = a.caseIds ?? [];
      return caseIds.length === 0 ? theirs.length === 0 : theirs.some((c) => caseIds.includes(c));
    };
    if (raw.some((a) => a.id !== selfId && peer(a) && a.name.toLowerCase() === lower))
      throw new CloudVaultError("conflict", "name already used");
    return name;
  }

  private sealed(
    meta: Omit<StoredCloudAccount, "provider" | "settings" | "sealed">,
    credential: CloudCredential,
    key: Buffer,
  ): StoredCloudAccount {
    const { provider, settings, secrets } = credential;
    return { ...meta, provider, settings, sealed: sealSecrets(secrets, key) };
  }

  private readRaw(): StoredCloudAccount[] {
    if (!existsSync(this.file)) return [];
    const parsed = JSON.parse(readFileSync(this.file, "utf8")) as { accounts?: unknown };
    return Array.isArray(parsed.accounts) ? (parsed.accounts as StoredCloudAccount[]) : [];
  }

  private text(accounts: StoredCloudAccount[]): string {
    return JSON.stringify({ version: 1, accounts }, null, 2);
  }

  // Writes the zeroed copy over the CURRENT file in place when it is the same length, so the bytes
  // of the sealed entry are overwritten on that inode; otherwise as a normal atomic write.
  private overwriteSealed(zeroed: StoredCloudAccount[]): void {
    const text = Buffer.from(this.text(zeroed), "utf8");
    const fd = openSync(this.file, "r+");
    try {
      if (fstatSync(fd).size === text.length) {
        writeSync(fd, text, 0, text.length, 0);
        fsyncSync(fd);
        return;
      }
    } finally {
      closeSync(fd);
    }
    this.write(zeroed);
  }

  private write(accounts: StoredCloudAccount[]): void {
    atomicWriteFileSync(this.file, this.text(accounts));
  }
}

function releasedOf(raw: StoredCloudAccount): ReleasedCloudAccount {
  const { sealed: _sealed, caseIds, ...rest } = raw;
  return { ...rest, settings: { ...raw.settings }, caseIds: [...(caseIds ?? [])] };
}

function viewOf(raw: StoredCloudAccount, storedSecrets: string[]): CloudAccountView {
  const { id, name, revision, createdAt, updatedAt, provider, settings } = raw;
  const caseIds = [...(raw.caseIds ?? [])];
  return {
    id,
    name,
    revision,
    createdAt,
    updatedAt,
    ...(raw.createdBy ? { createdBy: { ...raw.createdBy } } : {}),
    ...(raw.lastUsedAt ? { lastUsedAt: raw.lastUsedAt } : {}),
    provider,
    settings: { ...settings },
    storedSecrets,
    caseIds,
  };
}
