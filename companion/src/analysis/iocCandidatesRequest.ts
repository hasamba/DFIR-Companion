// #2131: the IOC-provenance candidate request, read first. The SQLite pool counts every writer op as
// a write at submission, so posting the writer op `iocCandidates` on every /ioc-provenance and
// /ioc-provenance-chain GET moved the case write sequence even when the term index was current, and
// defeated the caches keyed on it (#2126 case-open share, #2057 report-lite). The read op answers
// needsIndex when the index is missing or stale; only then does the writer build it and answer. The
// sequence is never rolled back after a reply (same ABA reason as #2129).
import { caseSqliteWorker } from "./caseSqliteWorker.js";

export interface RawIocCandidates<E> {
  forensic: E[];
  super: E[];
  candidates: number;
}

type ReadReply<E> = RawIocCandidates<E> | { needsIndex: true };

export async function requestIocCandidates<E>(
  dbPath: string,
  keys: readonly string[],
  ids: readonly string[],
): Promise<RawIocCandidates<E>> {
  const message = { dbPath, keys: [...keys], ids: [...ids] };
  const read = await caseSqliteWorker.request<ReadReply<E>>({ ...message, op: "iocCandidatesRead" });
  if (!("needsIndex" in read)) return read;
  return caseSqliteWorker.request<RawIocCandidates<E>>({ ...message, op: "iocCandidates" });
}
