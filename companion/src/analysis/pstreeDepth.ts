import { isObject, getCI } from "./siemImport.js";

type Row = Record<string, unknown>;

/**
 * How deep a Volatility pstree may nest before the file is treated as malformed.
 *
 * The nesting comes straight from evidence — a `vol -r json` array, a volatility-map, a jsonl dump
 * — and mapProcess recurses over it twice, once to index PIDs and once to emit events. V8's
 * JSON.parse is iterative, so it accepts arbitrarily deep JSON without complaint; the depth only
 * becomes call frames during those walks. Measured on the Node version this project targets,
 * JSON.parse takes 300k levels happily while a recursive walk over the same structure dies at
 * about 20k — roughly a 1 MB crafted file. The import already failed safely (every call site
 * catches), but it failed with a raw "Maximum call stack size exceeded" instead of saying what was
 * wrong with the file (#429).
 *
 * 128 is far past any real process tree — a deep Windows tree is a dozen levels — so nothing
 * forensic is lost, and far below the stack limit. Every other walker over untrusted input in this
 * codebase is bounded the same way (siemImport's `flatten` returns past depth > 3,
 * velociraptorImport's pickTime fallback stops at depth < 1); pstree was the exception.
 */
export const MAX_PSTREE_DEPTH = 128;

/**
 * The child rows of a pstree node, ready to recurse into — empty when it has none.
 *
 * `parentDepth` is the depth of `row` itself, so descending into the result costs one more level.
 * Throws when that would pass the cap, rather than truncating: silently dropping a subtree would
 * be evidence loss, and this shape of file is malformed either way.
 */
export function pstreeChildren(row: Row, parentDepth: number): Row[] {
  const kids = getCI(row, "__children");
  if (!Array.isArray(kids) || kids.length === 0) return [];
  if (parentDepth >= MAX_PSTREE_DEPTH) {
    throw new Error(
      `pstree __children nesting is deeper than ${MAX_PSTREE_DEPTH} levels — no real process tree ` +
        `is, so this file is malformed or crafted. Re-export the pstree output, or import the flat ` +
        `pslist/psscan output instead.`,
    );
  }
  return kids.filter(isObject);
}
