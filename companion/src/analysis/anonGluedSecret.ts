import { GLUED_VENDOR_SECRETS, redactSecretText } from "./anonSecrets.js";
import { locateSecrets, type SecretSpan } from "./anonSecretCustom.js";
import { findCustomSpans, type CompiledCustom } from "./anonCustomSpans.js";
import { CARD_RE, NATID_RE, PHONE_E164, PHONE_IL, PHONE_NANP } from "./anonPiiPatterns.js";

// #3003: a secret glued into a name ("C:\Users\bob<key>", "/home/<key>x") can be missed by the
// edge-guarded vendor shapes, and the later passes then minted the whole name as a reversible USER
// token: restore() handed the secret back and the OCR path saved it as a discovery. Inside a name the
// vendor shapes are tested with no edge guard (GLUED_VENDOR_SECRETS, derived in anonSecrets.ts).
export { GLUED_VENDOR_SECRETS };
const SENTINELS = /[\uE000\uE001]/; // an address set aside or a secret already redacted
const SECRET_SENTINEL = "\uE001"; // the anonymizer's stand-in for [REDACTED_SECRET] until its last pass

/** True when the name holds a vendor secret glued to other text, or a secret key=value. */
export function holdsGluedSecret(name: string): boolean {
  return name.split(SENTINELS).some((part) => {
    const n = ` ${part}`; // a key=value straight after a path separator reads as its own word
    return GLUED_VENDOR_SECRETS.some((re) => re.test(n)) || redactSecretText(n) !== n;
  });
}

/** The one-way check, plus `claim`: mark a value one way untested and hand it to `onClaim` (#3028). */
export type OneWayCheck = ((value: string) => boolean) & { claim: (value: string) => void };

/**
 * The anonymizer's one-way check for a value it is about to mint: `false` always when secrets are
 * not redacted. A value found to hold a secret is remembered in lower case, because the bare-name
 * pass matches in any case while the vendor shapes are case-sensitive. A value found clean is NOT
 * remembered in lower case: that would hide the secret-case spelling seen later.
 */
export function createOneWayCheck(
  enabled: boolean,
  onClaim: (value: string) => void = () => {},
): OneWayCheck {
  const claimed = new Set<string>();
  const check = (value: string): boolean => {
    if (!enabled) return false;
    const k = value.toLowerCase();
    if (claimed.has(k)) return true;
    if (!holdsGluedSecret(value)) return false;
    claimed.add(k);
    return true;
  };
  const claim = (value: string): void => {
    claimed.add(value.toLowerCase());
    onClaim(value);
  };
  return Object.assign(check, { claim });
}

// #3028: since #3005 the vendor pass redacts a key glued inside a word, so the account, e-mail, path
// and bare-name passes saw only what was left around it ("bob" + placeholder + "@<mail domain>"), and
// that text went out in clear where the whole value used to sit in one token. Each placeholder now
// grows over the name characters glued to it, so the rest of that word goes one way with the key.
// - It crosses an "@" either way, so an e-mail is hidden whole (as #3006 does), but not URL userinfo:
//   a key right after ":" (user:<key>@host) or a bare key after "/" (https://<key>@host) leaves the
//   host as it was.
// - A DOMAIN\ qualifier right in front goes with it, or it would be left without its user and go out
//   in clear (the account pass hid both before). A glued tail that reads as a DOMAIN
//   ("<key>MSSQL$SQLEXPRESS" + "\AppData") takes the user after it, for the same reason.
// - It never enters a value a later pass masks as one unit: an IPv4 or IPv6 address (#3016), an
//   encoded command, a card or phone number, a custom value.
// The scan walks out from each placeholder, so a long run of name characters is read once.
const NAME_CHAR = /[A-Za-z0-9._%+$-]/;
const MAX_NAME = 1024;
// NETBIOS_ACCT's qualifier and user half, read the #3049 way: Unicode letters, a qualifier from the
// start of its word, no cap on the user half (#3058). Where only the old ASCII reading (LEGACY_*)
// finds one, as before #3058, that one is used, so nothing it took is left behind.
const QUALIFIER = /(?<![\\/:.\p{L}\p{N}_-])\p{L}[\p{L}\p{N}.-]{0,14}$/u;
const TAIL_QUALIFIER = /(?<![\\/:.\p{L}\p{N}_\uE001-])\p{L}[\p{L}\p{N}.-]{1,14}$/u;
const NEXT_USER = /^\\[\p{L}\p{N}._$-]{2,}(?![\\/\p{L}\p{N}_])/u;
const LEGACY_QUALIFIER = /(?<![\\/:.\w-])[A-Za-z][A-Za-z0-9.-]{0,14}$/;
const LEGACY_TAIL_QUALIFIER = /(?<![\\/:.\w\uE001-])[A-Za-z][A-Za-z0-9.-]{1,14}$/;
const LEGACY_NEXT_USER = /^\\[A-Za-z0-9._$-]{2,20}(?![\\/\w])/;
const ADDRESS =
  /(?<![\w:])(?:[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){1,7}:\d{1,3}(?:\.\d{1,3}){3}|\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,8})/g;

// An encoded command, as anonymize.ts finds the blob it masks (ENC_CMD_RE, FROM_B64_RE): eating its
// cue or the end of its blob would leave the blob in clear instead of a CMD token (#3005).
const ENC_CMD =
  /(?<![A-Za-z0-9])-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/_-]{16,}={0,2}|FromBase64String\(\s*["'][A-Za-z0-9+/_-]{16,}={0,2}/gi;
const UNITS = [ADDRESS, ENC_CMD, CARD_RE, PHONE_E164, PHONE_IL, PHONE_NANP, NATID_RE];

/** Where `r` holds a value a later pass masks as one unit: a walk stops at it, so it is never cut. */
function stopMask(r: string, compiled: CompiledCustom): Uint8Array {
  const mask = new Uint8Array(r.length);
  for (const re of UNITS) for (const m of r.matchAll(re)) mask.fill(1, m.index, m.index + m[0].length);
  for (const c of findCustomSpans(r, compiled)) mask.fill(1, c.start, c.end);
  return mask;
}

interface Run {
  from: number; // after any DOMAIN\ qualifier
  to: number;
  name: [number, number]; // the name itself: no qualifier, no e-mail domain
  qual: string; // that qualifier without its "\", or ""
}

function walk(r: string, at: number, step: 1 | -1, s: string, stop: Uint8Array): number {
  const ok = (i: number) => i >= 0 && i < r.length && !stop[i] && (r[i] === s || NAME_CHAR.test(r[i]));
  let i = at;
  if (step < 0) while (ok(i - 1)) i -= 1;
  else while (ok(i)) i += 1;
  return i;
}

function gluedRun(r: string, p: number, s: string, stop: Uint8Array): Run {
  let from = walk(r, p, -1, s, stop);
  let to = walk(r, p + 1, 1, s, stop);
  // A unit the walk stopped at keeps its separator ("zq marker-"), or the placeholder would touch it.
  while (from < p && stop[from - 1] && !/[A-Za-z0-9]/.test(r[from])) from += 1;
  while (to > p + 1 && stop[to] && !/[A-Za-z0-9]/.test(r[to - 1])) to -= 1;
  while (to > p + 1 && r[to - 1] === ".") to -= 1; // a full stop ends the sentence, not the name
  const name: [number, number] = [from, to];
  // A bare key as URL userinfo (user:<key>@host, https://<key>@host) keeps the host after it.
  const userinfo = (r[from - 1] === ":" || r[from - 1] === "/") && from === p;
  if (r[to] === "@" && !userinfo && NAME_CHAR.test(r[to + 1] ?? "") && !stop[to + 1]) {
    to = walk(r, to + 1, 1, s, stop);
    while (r[to - 1] === ".") to -= 1;
  } else if (
    r[to] === "\\" &&
    [TAIL_QUALIFIER, LEGACY_TAIL_QUALIFIER].some((re) => re.test(r.slice(p, to)))
  ) {
    const next = r.slice(to);
    to += (NEXT_USER.exec(next) ?? LEGACY_NEXT_USER.exec(next))?.[0].length ?? 0;
  }
  if (r[from - 1] === "@" && NAME_CHAR.test(r[from - 2] ?? "") && !stop[from - 2])
    from = walk(r, from - 1, -1, s, stop);
  const before = r[from - 1] === "\\" ? r.slice(Math.max(0, from - 17), from - 1) : null;
  const q = before === null ? null : (QUALIFIER.exec(before) ?? LEGACY_QUALIFIER.exec(before));
  return { from, to, name, qual: q ? q[0] : "" };
}

// The clear spelling of r[a, b): each sentinel is put back from where locateSecrets placed it.
function clearSpelling(
  clear: string,
  r: string,
  [a, b]: [number, number],
  index: ReadonlyMap<number, number>,
  spans: readonly SecretSpan[],
): string | null {
  let out = "";
  for (let i = a; i < b; i++) {
    const k = index.get(i);
    if (k === undefined) out += r[i];
    else if (spans[k]?.form.length !== 1)
      return null; // a quoted placeholder is no name
    else out += clear.slice(spans[k].exact.start, spans[k].exact.end);
  }
  return out;
}

export interface RemnantContext {
  remember: (name: string) => void;
  compiled: CompiledCustom; // custom values, which are never cut
}

/**
 * Grow each secret sentinel in `redacted` over the name text glued to it (#3028). `clear` is the text
 * the secret pass read; `ctx.remember` gets each grown name in its clear spelling, so the caller can
 * send a later repeat of the name one way. Pure apart from `remember`.
 */

export function growGluedRemnants(clear: string, redacted: string, ctx: RemnantContext): string {
  const sentinel = SECRET_SENTINEL;
  if (!redacted.includes(sentinel)) return redacted;
  const index = new Map<number, number>(); // sentinel position -> its order
  for (let p = redacted.indexOf(sentinel); p >= 0; p = redacted.indexOf(sentinel, p + 1))
    index.set(p, index.size);
  const stop = stopMask(redacted, ctx.compiled);
  let spans: SecretSpan[] | null | undefined;
  let out = "";
  let last = 0;
  for (const p of index.keys()) {
    if (p < last) continue; // taken by the run before
    const run = gluedRun(redacted, p, sentinel, stop);
    run.from = Math.max(run.from, last); // never back into the run before
    if (run.qual && run.from - run.qual.length - 1 >= last) run.from -= run.qual.length + 1;
    const held = redacted.slice(run.from, run.to).split(sentinel).length - 1;
    if (run.to - run.from === held) continue; // nothing glued
    spans ??= locateSecrets(clear, redacted, sentinel);
    const name = spans && clearSpelling(clear, redacted, run.name, index, spans);
    if (name && name.length <= MAX_NAME) ctx.remember(name); // a longer run is no name to look for again
    out += redacted.slice(last, run.from) + sentinel;
    last = run.to;
  }
  return out + redacted.slice(last);
}
