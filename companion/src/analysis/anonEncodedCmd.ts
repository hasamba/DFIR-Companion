import { ENC_CMD_RE, FROM_B64_RE, ipv4StartsAt } from "./anonPiiPatterns.js";

// The encoded-command pass of the anonymizer (moved out of anonymize.ts for #3067): the base64 blob
// after -e/-enc/-EncodedCommand and inside FromBase64String('…') gets a CMD token, the cue stays.

export interface EncodedCmdDeps {
  /** The CMD token for a blob. */
  cmd: (blob: string) => string;
  /** The IP category is on. */
  ip: boolean;
  /** tokenEnds().ended: a token a digit may follow gets its delimiter. */
  ended: (result: string, value: string, at: number, end: number, text: string) => string;
}

// The dotted rest of an IPv4 address whose first number the blob class read (#3067):
// `-enc <blob>10.0.0.5` read `10` into the blob and left `.0.0.5` in clear.
const DOTTED_TAIL = /(?:\.\d{1,3}){3,}(?!\d)/y;
const ENDS_IN_DIGIT = /\d$/;

/** The dotted tail after a blob that ends in a digit and has no padding, or "". */
function dottedTail(blob: string, pad: string, t: string, end: number): string {
  if (pad || !ENDS_IN_DIGIT.test(blob)) return "";
  DOTTED_TAIL.lastIndex = end;
  return DOTTED_TAIL.exec(t)?.[0] ?? "";
}

/**
 * Tokenize every encoded blob in `t`. A blob glued to an IPv4 address with no padding takes the
 * address's tail into its token: the blob class already holds the address's first number, so the
 * address can only be hidden whole with it. Splitting it off instead minted a blob value that a
 * seeded call could not find again, glued to the address's digits.
 */
export function replaceEncodedCommands(t: string, deps: EncodedCmdDeps): string {
  const re = new RegExp(ENC_CMD_RE.source, ENC_CMD_RE.flags);
  let out = "";
  let last = 0;
  for (let m = re.exec(t); m; m = re.exec(t)) {
    const [whole, flag, blob, pad] = m;
    const at = m.index;
    const tail = dottedTail(blob, pad, t, at + whole.length);
    const end = at + whole.length + tail.length;
    const keep = pad && deps.ip && ipv4StartsAt(t, end); // the address keeps its `=` (#3060)
    const result = flag + (keep ? deps.cmd(blob) + pad : deps.cmd(blob + pad + tail));
    out += t.slice(last, at) + deps.ended(result, whole + tail, at, end, t);
    last = end;
    re.lastIndex = end;
  }
  out += t.slice(last);
  return out.replace(FROM_B64_RE, (_m, a: string, blob: string, c: string) => a + deps.cmd(blob) + c);
}
