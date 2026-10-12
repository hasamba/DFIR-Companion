import type { IOC } from "./stateTypes.js";
export interface IocValueCoercion {
  iocs: IOC[];
  coerced: { id: string; from: string }[]; // id + original JSON type of each row whose value was not a string
}

// Load-time guard (#2178): a stored row whose `value` is not a string (hand-edited state, a legacy
// migration, a foreign backup) would make every reader that calls `.toLowerCase()`/`.trim()` on it
// throw. Repair-ONLY, as above — the value becomes text and the row is never dropped, because the
// loaded state is what the next save writes back. Healthy rows (and a healthy list) are returned as-is.
export function coerceIocValues(iocs: IOC[]): IocValueCoercion {
  const coerced: IocValueCoercion["coerced"] = [];
  const out = iocs.map((ioc) => {
    const value: unknown = ioc.value;
    if (typeof value === "string") return ioc;
    const from = value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
    coerced.push({ id: ioc.id, from });
    return { ...ioc, value: valueAsText(value) };
  });
  return coerced.length === 0 ? { iocs, coerced } : { iocs: out, coerced };
}

function valueAsText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value) ?? "";
  return String(value);
}

const COERCION_LOG_SAMPLE = 5;

/** coerceIocValues on a loaded state, with one warn line naming the case — ids and types only, never values. */
export function withStringIocValues<S extends { caseId: string; iocs: IOC[] }>(state: S): S {
  const { iocs, coerced } = coerceIocValues(state.iocs);
  if (coerced.length === 0) return state;
  const sample = coerced.slice(0, COERCION_LOG_SAMPLE).map((c) => `${c.id}(${c.from})`);
  console.warn(
    `[stateStore] case ${state.caseId}: coerced ${coerced.length} non-string IOC value(s) to text: ${sample.join(", ")}`,
  );
  return { ...state, iocs };
}
