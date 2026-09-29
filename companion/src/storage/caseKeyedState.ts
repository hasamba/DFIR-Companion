/**
 * In-memory per-case state that cannot leak into a same-id successor (#1866).
 *
 * A case id outlives its folder: after a delete, a new case may take the id. A timer map, an
 * in-flight set or a pending set keyed by the case id alone then mixes the two incarnations. An old
 * synthesis's `finally` removes the new case's in-flight mark, an old debounce timer is cancelled by
 * the new case's kick (or cancels it), and a poller resumes a deleted case's work under the new one.
 *
 * CaseKeyedMap and CaseKeyedSet key every entry by (case id, generation). The generation comes from
 * the async context (see currentGeneration in caseIncarnation.ts): work captured in a case scope
 * sees only its own incarnation's entries, so old callbacks cannot coalesce with, cancel or clear a
 * successor's. `forgetCaseKeyedState` drops every entry of a deleted case (and runs `onForget`, e.g.
 * to clear a timer); the delete route calls it through clearStateOutlivingCase.
 */
import { resolve } from "node:path";
import { currentGeneration } from "./caseIncarnation.js";

type CasesRoot = string | (() => string);

/** The part of a per-case Map its consumers use; a plain Map and a CaseKeyedMap both satisfy it. */
export interface PerCaseMap<V> {
  get(caseId: string): V | undefined;
  set(caseId: string, value: V): unknown;
  has(caseId: string): boolean;
  delete(caseId: string): boolean;
}

/** The part of a per-case Set its consumers use; a plain Set and a CaseKeyedSet both satisfy it. */
export interface PerCaseSet {
  add(caseId: string): unknown;
  has(caseId: string): boolean;
  delete(caseId: string): boolean;
  readonly size: number;
}

interface Forgettable {
  readonly root: () => string;
  forget(caseId: string): void;
}

const instances = new Set<WeakRef<Forgettable>>();

function register(instance: Forgettable): void {
  instances.add(new WeakRef(instance));
}

type ForgetListener = (casesRoot: string, caseId: string) => void;
const listeners = new Set<ForgetListener>();

/**
 * Be told when a case's in-memory state is dropped — for state that is not a CaseKeyedMap, e.g.
 * a cached file handle under the case folder. Returns the unsubscribe.
 */
export function onCaseForgotten(listener: ForgetListener): () => void {
  listeners.add(listener);
  return () => void listeners.delete(listener);
}

/** Drop every in-memory entry, of every incarnation, that a deleted case left behind. */
export function forgetCaseKeyedState(casesRoot: string, caseId: string): void {
  const root = resolve(casesRoot);
  for (const listener of [...listeners]) {
    try {
      listener(root, caseId);
    } catch {
      /* a listener never fails the delete */
    }
  }
  for (const ref of [...instances]) {
    const instance = ref.deref();
    if (!instance) {
      instances.delete(ref);
      continue;
    }
    let owner: string;
    try {
      owner = resolve(instance.root());
    } catch {
      continue; // a test double without a cases root
    }
    if (owner === root) instance.forget(caseId);
  }
}

/**
 * Run `forget(caseId)` when a case under `casesRoot` is forgotten — for per-case state that is not a
 * CaseKeyedMap (open sockets, file handles). Held weakly: the owner keeps the returned handle.
 */
export class CaseForgetter implements Forgettable {
  readonly root: () => string;
  constructor(
    casesRoot: CasesRoot,
    private readonly onForget: (caseId: string) => void,
  ) {
    this.root = typeof casesRoot === "function" ? casesRoot : () => casesRoot;
    register(this);
  }

  forget(caseId: string): void {
    this.onForget(caseId);
  }
}

interface Entry<V> {
  readonly caseId: string;
  readonly generation: string;
  readonly sub: string;
  readonly value: V;
}

const SEP = "\u0000";

/** A Map keyed by case id whose entries belong to the incarnation that wrote them. */
export class CaseKeyedMap<V> implements Forgettable, PerCaseMap<V> {
  private readonly entries_ = new Map<string, Entry<V>>();
  readonly root: () => string;

  constructor(
    casesRoot: CasesRoot,
    private readonly onForget?: (value: V, caseId: string) => void,
  ) {
    this.root = typeof casesRoot === "function" ? casesRoot : () => casesRoot;
    register(this);
  }

  private generation(caseId: string): string {
    let root: string;
    try {
      root = this.root();
    } catch {
      return "";
    }
    return currentGeneration(root, caseId);
  }

  // `sub` names one of several entries a case holds (a monitor id, a hunt id); "" when one per case.
  private key(caseId: string, sub: string, generation = this.generation(caseId)): string {
    return caseId + SEP + generation + SEP + sub;
  }

  get(caseId: string, sub = ""): V | undefined {
    return this.entries_.get(this.key(caseId, sub))?.value;
  }

  has(caseId: string, sub = ""): boolean {
    return this.entries_.has(this.key(caseId, sub));
  }

  set(caseId: string, value: V, sub = ""): this {
    const generation = this.generation(caseId);
    this.entries_.set(this.key(caseId, sub, generation), { caseId, generation, sub, value });
    return this;
  }

  delete(caseId: string, sub = ""): boolean {
    return this.entries_.delete(this.key(caseId, sub));
  }

  /** Every entry, of every incarnation still held, with the generation it belongs to. */
  list(): Entry<V>[] {
    return [...this.entries_.values()];
  }

  get size(): number {
    return this.entries_.size;
  }

  values(): V[] {
    return this.list().map((entry) => entry.value);
  }

  /** Drop every entry of every case (a sweep that took them all). */
  clear(): void {
    this.entries_.clear();
  }

  forget(caseId: string): void {
    for (const [key, entry] of [...this.entries_]) {
      if (entry.caseId !== caseId) continue;
      this.entries_.delete(key);
      try {
        this.onForget?.(entry.value, caseId);
      } catch {
        /* a disposer never fails the delete */
      }
    }
  }
}

/** A Set of case ids whose members belong to the incarnation that added them. */
export class CaseKeyedSet implements PerCaseSet {
  private readonly map: CaseKeyedMap<true>;

  constructor(casesRoot: CasesRoot) {
    this.map = new CaseKeyedMap<true>(casesRoot);
  }

  add(caseId: string): this {
    this.map.set(caseId, true);
    return this;
  }

  has(caseId: string): boolean {
    return this.map.has(caseId);
  }

  delete(caseId: string): boolean {
    return this.map.delete(caseId);
  }

  /** Every member, with the generation it was added under. */
  list(): { caseId: string; generation: string }[] {
    return this.map.list().map(({ caseId, generation }) => ({ caseId, generation }));
  }

  get size(): number {
    return this.map.size;
  }

  clear(): void {
    this.map.clear();
  }
}
