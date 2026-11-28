import { TOKEN_DELIMITER } from "./anonTokenLiterals.js";

// The profile pass reads everything after the profile folder up to a path separator, a quote or the
// line end as the user name, and it runs before the encoded-command, SID, address, card, phone and
// national-ID passes, so a value later on that line was hidden only inside the user token and carried
// no token of its own (#3047). Stopping the name earlier would put the rest of the line in clear: a
// real profile name holds spaces, and a glued value its own pass cannot read whole (an address with
// digits glued on) was hidden only by the user token. So the name is carved, not cut: the value passes
// run over it, each value they mint keeps its own token, and every other piece of the old name that
// holds a letter or digit stays a user token, masked in place and never saved. Each character is
// still inside a token.

const TOKEN = /ANON_[A-Z]+_\d+/g;
const WORD = /[\p{L}\p{N}]/u;
const EDGE_SPACE = /^(\s*)([\s\S]*?)(\s*)$/;

export interface CarveMint {
  real: (token: string) => string | undefined; // the value a minted token stands for
  cut: (piece: string) => string; // a user token that is never saved
}

/**
 * The profile name with the values `passes` mints given their own tokens, or null when they mint
 * nothing or the output cannot be lined up with the name (the name is then one user token, as before).
 */
export function carveProfileName(
  name: string,
  passes: (text: string) => string,
  mint: CarveMint,
): string | null {
  const out = passes(name);
  if (out === name) return null;
  let carved = "";
  let at = 0; // position in `name`
  let last = 0; // position in `out`
  for (const m of out.matchAll(TOKEN)) {
    const gap = gapIn(name, at, out.slice(last, m.index));
    if (gap === null) return null;
    carved += mintPiece(gap, mint.cut);
    at += gap.length;
    const len = valueLength(name, at, m[0], mint.real);
    if (len < 0) return null;
    carved += m[0];
    at += len;
    last = m.index + m[0].length;
  }
  const tail = gapIn(name, at, out.slice(last));
  return tail === null || at + tail.length !== name.length ? null : carved + mintPiece(tail, mint.cut);
}

// The clear text between two tokens as it stands in the name: a digit delimiter a pass put after a
// token is not part of it.
function gapIn(name: string, at: number, gap: string): string | null {
  if (name.startsWith(gap, at)) return gap;
  const bare = gap.startsWith(TOKEN_DELIMITER) ? gap.slice(TOKEN_DELIMITER.length) : null;
  return bare !== null && name.startsWith(bare, at) ? bare : null;
}

// How much of the name a token covers: its own text when it was already in the name, else its value.
function valueLength(name: string, at: number, token: string, real: CarveMint["real"]): number {
  if (name.startsWith(token, at)) return token.length;
  const value = real(token);
  if (value === undefined) return -1;
  return name.slice(at, at + value.length).toLowerCase() === value.toLowerCase() ? value.length : -1;
}

function mintPiece(piece: string, cut: (piece: string) => string): string {
  if (!WORD.test(piece)) return piece;
  const [, lead = "", core = "", trail = ""] = EDGE_SPACE.exec(piece) ?? [];
  return lead + cut(core) + trail;
}

/** The value passes in the order apply() runs them, each only when its category is on. */
export function valuePasses(
  on: Readonly<Partial<Record<string, boolean>>>,
  passes: Readonly<Record<string, (text: string) => string>>,
): (text: string) => string {
  return (text) => Object.entries(passes).reduce((t, [cat, pass]) => (on[cat] ? pass(t) : t), text);
}
