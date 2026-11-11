// The AWS account-weakness fold (#2560): one upload's facts into a draft, and a draft into the case
// file. Like cloudCoverageFold.ts, each upload folds into ONE bounded per-case record, so the cost
// of an upload never grows with the uploads before it (the SANS 504 lab is 3,872 files).
//
// Deterministic and order-independent: counts are sets of record identities (union), each set and
// list keeps its smallest members past its cap with a sticky `overflow` flag, cites are the earliest
// (or latest) by time then eventID. So batch by batch equals the whole file, and a record read twice
// changes nothing. Pure: no input is changed.

import {
  ACCOUNTS_MAX,
  BUCKETS_PER_ACCOUNT_MAX,
  ROOT_IDS_MAX,
  type AccountWeakness,
  type IdSet,
  type WeaknessCite,
  type WeaknessFact,
  type WeaknessInput,
  weaknessFacts,
  type VersioningFact,
  type WeaknessFile,
  EMPTY_WEAKNESSES,
} from "./awsAccountWeakness.js";

const order = (a: WeaknessCite, b: WeaknessCite): number =>
  Date.parse(a.time) - Date.parse(b.time) || a.eventId.localeCompare(b.eventId);
const earliest = (a?: WeaknessCite, b?: WeaknessCite): WeaknessCite | undefined =>
  !a ? b : !b ? a : order(a, b) <= 0 ? a : b;
const latest = (a?: WeaknessCite, b?: WeaknessCite): WeaknessCite | undefined =>
  !a ? b : !b ? a : order(a, b) >= 0 ? a : b;
const earlierTime = (a?: string, b?: string): string | undefined =>
  !a ? b : !b ? a : Date.parse(a) <= Date.parse(b) ? a : b;

function mergeIds(a: IdSet | undefined, b: IdSet | undefined): IdSet {
  const all = [...new Set([...(a?.keys ?? []), ...(b?.keys ?? [])])].sort();
  return {
    keys: all.slice(0, ROOT_IDS_MAX),
    overflow: !!a?.overflow || !!b?.overflow || all.length > ROOT_IDS_MAX,
  };
}

/** Union keyed by `keyOf`, the earliest cite per key, the smallest keys past the cap. */
function mergeKeyed<T extends { cite: WeaknessCite }>(
  a: readonly T[],
  b: readonly T[],
  keyOf: (x: T) => string,
): { list: T[]; overflow: boolean } {
  const byKey = new Map<string, T>();
  for (const x of [...a, ...b]) {
    const prev = byKey.get(keyOf(x));
    byKey.set(keyOf(x), prev && order(prev.cite, x.cite) <= 0 ? prev : x);
  }
  const sorted = [...byKey.entries()].sort(([x], [y]) => x.localeCompare(y)).map(([, v]) => v);
  return {
    list: sorted.slice(0, BUCKETS_PER_ACCOUNT_MAX),
    overflow: sorted.length > BUCKETS_PER_ACCOUNT_MAX,
  };
}

type RootFact = NonNullable<AccountWeakness["rootNoMfaLogin"]>;

function mergeRoot<T extends RootFact>(a?: T, b?: T): RootFact | undefined {
  if (!a || !b) return a ?? b;
  return { ids: mergeIds(a.ids, b.ids), first: earliest(a.first, b.first)!, last: latest(a.last, b.last)! };
}

function mergeAccount(a: AccountWeakness, b: AccountWeakness): AccountWeakness {
  const rootUse =
    a.rootUse && b.rootUse
      ? { ...mergeRoot(a.rootUse, b.rootUse)!, mutating: mergeIds(a.rootUse.mutating, b.rootUse.mutating) }
      : (a.rootUse ?? b.rootUse);
  const lock =
    a.objectLock || b.objectLock
      ? mergeKeyed(a.objectLock?.buckets ?? [], b.objectLock?.buckets ?? [], (x) => x.bucket)
      : undefined;
  const ver =
    a.versioning || b.versioning
      ? mergeKeyed(a.versioning?.facts ?? [], b.versioning?.facts ?? [], (x) => `${x.bucket}\n${x.fact}`)
      : undefined;
  const rootNoMfaLogin = mergeRoot(a.rootNoMfaLogin, b.rootNoMfaLogin);
  const firstRecordAt = earlierTime(a.firstRecordAt, b.firstRecordAt);
  const objectSelector = earliest(a.objectSelector, b.objectSelector);
  const firstObjectRecord = earliest(a.firstObjectRecord, b.firstObjectRecord);
  return {
    account: a.account,
    ...(firstRecordAt ? { firstRecordAt } : {}),
    ...(rootNoMfaLogin ? { rootNoMfaLogin } : {}),
    ...(rootUse ? { rootUse } : {}),
    ...(lock
      ? {
          objectLock: {
            buckets: lock.list,
            overflow: !!a.objectLock?.overflow || !!b.objectLock?.overflow || lock.overflow,
          },
        }
      : {}),
    ...(ver
      ? {
          versioning: {
            facts: ver.list,
            overflow: !!a.versioning?.overflow || !!b.versioning?.overflow || ver.overflow,
          },
        }
      : {}),
    ...(objectSelector ? { objectSelector } : {}),
    ...(firstObjectRecord ? { firstObjectRecord } : {}),
  };
}

/**
 * `acc` with `next` folded in. Pure; the result is bounded by the caps whatever the inputs. Past the
 * account cap the smallest account ids are kept, by id alone: an order that looked at an account's
 * facts would change as records arrive, so an account dropped early (and its earlier object record
 * with it) could come back on a later fact and claim a logging gap the evidence does not show.
 */
export function foldWeaknesses(acc: WeaknessFile, next: WeaknessFile): WeaknessFile {
  const byAccount = new Map(acc.accounts.map((a) => [a.account, a] as const));
  for (const a of next.accounts) {
    const prev = byAccount.get(a.account);
    byAccount.set(a.account, prev ? mergeAccount(prev, a) : a);
  }
  const all = [...byAccount.values()].sort((x, y) => x.account.localeCompare(y.account));
  return {
    accounts: all.slice(0, ACCOUNTS_MAX),
    accountsOverflow: acc.accountsOverflow || next.accountsOverflow || all.length > ACCOUNTS_MAX,
  };
}

/** The smallest keys of a set, with the overflow flag. */
function idSet(keys: ReadonlySet<string>): IdSet {
  const sorted = [...keys].sort();
  return { keys: sorted.slice(0, ROOT_IDS_MAX), overflow: sorted.length > ROOT_IDS_MAX };
}

interface RootAcc {
  keys: Set<string>;
  mutating: Set<string>;
  first?: WeaknessCite;
  last?: WeaknessCite;
}

/** Everything one account's facts hold, gathered in one linear pass before the caps apply. */
interface AccountAcc {
  login: RootAcc;
  use: RootAcc;
  locks: Array<{ bucket: string; cite: WeaknessCite }>;
  versions: Array<{ bucket: string; fact: VersioningFact; cite: WeaknessCite }>;
  firstRecordAt?: string;
  objectSelector?: WeaknessCite;
  firstObjectRecord?: WeaknessCite;
}

const rootAcc = (): RootAcc => ({ keys: new Set(), mutating: new Set() });

function addRoot(r: RootAcc, key: string, cite: WeaknessCite, mutating = false): void {
  r.keys.add(key);
  if (mutating) r.mutating.add(key);
  r.first = earliest(r.first, cite);
  r.last = latest(r.last, cite);
}

function addFact(a: AccountAcc, f: WeaknessFact): void {
  if (f.kind === "root-login") addRoot(a.login, f.key, f.cite);
  else if (f.kind === "root-use") addRoot(a.use, f.key, f.cite, f.mutating);
  else if (f.kind === "object-lock") a.locks.push({ bucket: f.bucket, cite: f.cite });
  else if (f.kind === "versioning") a.versions.push({ bucket: f.bucket, fact: f.fact, cite: f.cite });
  else if (f.kind === "selector") a.objectSelector = earliest(a.objectSelector, f.cite);
  else if (f.kind === "object-record") a.firstObjectRecord = earliest(a.firstObjectRecord, f.cite);
  else a.firstRecordAt = earlierTime(a.firstRecordAt, f.time);
}

function finishAccount(account: string, a: AccountAcc): AccountWeakness {
  const root = (r: RootAcc): RootFact | undefined =>
    r.first && r.last ? { ids: idSet(r.keys), first: r.first, last: r.last } : undefined;
  const login = root(a.login);
  const use = root(a.use);
  const locks = a.locks.length ? mergeKeyed(a.locks, [], (x) => x.bucket) : undefined;
  const versions = a.versions.length
    ? mergeKeyed(a.versions, [], (x) => `${x.bucket}\n${x.fact}`)
    : undefined;
  return {
    account,
    ...(a.firstRecordAt ? { firstRecordAt: a.firstRecordAt } : {}),
    ...(login ? { rootNoMfaLogin: login } : {}),
    ...(use ? { rootUse: { ...use, mutating: idSet(a.use.mutating) } } : {}),
    ...(locks ? { objectLock: { buckets: locks.list, overflow: locks.overflow } } : {}),
    ...(versions ? { versioning: { facts: versions.list, overflow: versions.overflow } } : {}),
    ...(a.objectSelector ? { objectSelector: a.objectSelector } : {}),
    ...(a.firstObjectRecord ? { firstObjectRecord: a.firstObjectRecord } : {}),
  };
}

/** One upload's (or batch's) facts as a draft in the case-file shape. Linear in the facts. */
export function weaknessDraft(facts: readonly WeaknessFact[]): WeaknessFile {
  const byAccount = new Map<string, AccountAcc>();
  for (const f of facts) {
    let a = byAccount.get(f.account);
    if (!a) {
      a = { login: rootAcc(), use: rootAcc(), locks: [], versions: [] };
      byAccount.set(f.account, a);
    }
    addFact(a, f);
  }
  const accounts = [...byAccount.entries()].map(([account, a]) => finishAccount(account, a));
  return foldWeaknesses(EMPTY_WEAKNESSES, { accounts, accountsOverflow: false });
}

/** One upload's draft from its mapped rows, each beside its own raw record (#2560). */
export function awsWeaknessDraft(rows: readonly WeaknessInput[]): WeaknessFile {
  return weaknessDraft(rows.flatMap(weaknessFacts));
}
