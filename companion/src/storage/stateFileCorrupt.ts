/**
 * A case's `state/<file>.json` exists but does not hold a readable record (#2760): it does not parse,
 * or it parses to something that is not an object. Before this type a bare `SyntaxError` reached the
 * analyst as a raw parser 500 that named neither the case nor the file.
 *
 * Each store decides what a damaged file means. ai-control.json fails CLOSED (AI held off until the
 * analyst rewrites the switch); import-meta.json is derived data and falls back to "no import".
 */
export class StateFileCorruptError extends Error {
  readonly code = "state_file_corrupt";

  constructor(
    readonly caseId: string,
    /** The file name inside the case's state folder — never an absolute path. */
    readonly file: string,
    readonly consequence: string,
    reason: string,
  ) {
    super(`Case "${caseId}": state/${file} is damaged and could not be read (${reason}). ${consequence}`);
    this.name = "StateFileCorruptError";
  }
}

/** What a route hands the dashboard about a damaged state file. */
export interface StateFileCorruptNotice {
  file: string;
  message: string;
}

export function corruptNotice(err: StateFileCorruptError): StateFileCorruptNotice {
  return { file: err.file, message: err.message };
}

/**
 * Parse a state file's text into a plain object, or throw StateFileCorruptError naming the case and
 * the file. `null`, arrays and scalars count as damage: no state record has that shape.
 */
export function parseStateObject(
  text: string,
  caseId: string,
  file: string,
  consequence: string,
): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (err) {
    throw new StateFileCorruptError(caseId, file, consequence, (err as Error).message);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    const kind = value === null ? "null" : Array.isArray(value) ? "an array" : typeof value;
    throw new StateFileCorruptError(caseId, file, consequence, `expected an object, found ${kind}`);
  }
  return value as Record<string, unknown>;
}
