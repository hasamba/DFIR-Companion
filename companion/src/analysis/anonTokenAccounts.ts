import {
  freshQualifier,
  isNoiseAccount,
  isNoiseDomain,
  PATH_DOMAINS,
  splitGluedSid,
} from "./anonUsernames.js";

// The custom pass mints a custom or saved value before the account pass runs, so on a later call
// `CORP\bob` reached the account pass as `ANON_DOMAIN_1\bob` and `<user>@<internal domain>` as
// `<user>@ANON_DOMAIN_2`, which the account and email patterns cannot read, and the user went out in
// clear (#3020). This reads an account that holds a minted token, in whole or in part, resolves the
// token, and applies the rules a call without the saved value applies to the real text.
const TOKEN = String.raw`ANON_[A-Z]+_\d+`;
const HAS_TOKEN = new RegExp(TOKEN);
const ONE_TOKEN = new RegExp(`^${TOKEN}$`);
const ANY_TOKEN = new RegExp(TOKEN, "g");
const NETBIOS = new RegExp(
  String.raw`(?<![\\/:.\w-])((?:${TOKEN}|[\p{L}\p{N}.-])+)\\((?:${TOKEN}|[\p{L}\p{N}._$-])+)(?![\\/\p{L}\p{N}_])`,
  "gu",
);
// `<profile path>\dave élan\xC`: a call without the saved profile name reads `élan\xC` as an account.
const TAIL_ACCOUNT = new RegExp(
  String.raw`(?<=[\\/:.-])(${TOKEN})\\([\p{L}\p{N}._$-]+)(?![\\/\p{L}\p{N}_])`,
  "gu",
);
const UPN = new RegExp(
  String.raw`(?<![\w.%+-])((?:${TOKEN}|[A-Za-z0-9._%+-])+)@((?:${TOKEN}|[A-Za-z0-9.-])+)`,
  "g",
);
// The fresh account and email patterns (NETBIOS_ACCT, UPN_ACCT, EMAIL_RE), read on the real text.
const NETBIOS_QUALIFIER = /^\p{L}[\p{L}\p{N}.-]{1,14}$/u;
const NETBIOS_AFTER = /^[\p{L}\p{N}._$-]{2}$/u; // the first two characters of a NETBIOS user
const LONG_USER = /^[\p{L}\p{N}._$-]{2,}$/u;
const UPN_USER = /^[A-Za-z0-9._%+-]{2,}$/;
const UPN_DOMAIN = /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;
const EMAIL = /^[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+(?:\.[A-Za-z]{2,}|\.xn--[A-Za-z0-9-]+)$/;

export interface TokenAccountRules {
  tokens: ReadonlyMap<string, string>; // minted token -> real value
  suppressed: ReadonlySet<string>; // lowercased values the analyst left visible
  internal: (domain: string) => boolean;
  fileUser: RegExp; // a user half that is a file name (Folder\evil.exe) is not a person
  email: boolean; // the EMAIL category is on
}
export interface TokenAccountMint {
  // A qualifier or user half that holds a token is minted from its raw text: a custom value inside
  // it beats a suppression of the whole (#1822), or the expanded text would go out in clear.
  qualifier: (real: string, raw: string) => string; // a HOST or DOMAIN token
  user: (real: string, raw: string) => string; // a USER token for the user half
  whole: (category: "USER" | "EMAIL" | "REG", value: string) => string; // one token; tokens inside expand
  // A splice of text[at, end) before a glued digit (tokenEnds): the token gets its delimiter.
  ended: (result: string, value: string, at: number, end: number, text: string) => string;
}
type Ctx = TokenAccountRules &
  TokenAccountMint & { expand: (s: string) => string; single: (s: string) => boolean };

export function tokenQualifiedAccounts(
  text: string,
  rules: TokenAccountRules,
  mint: TokenAccountMint,
): string {
  const expand = (s: string) => s.replace(ANY_TOKEN, (t) => rules.tokens.get(t) ?? t);
  const single = (s: string) => ONE_TOKEN.test(s) && rules.tokens.has(s);
  const c: Ctx = { ...rules, ...mint, expand, single };
  const out = text
    .replace(TAIL_ACCOUNT, (all, tok: string, u: string, at: number, s: string) =>
      tailAccount(c, all, tok, u, s[at - 1] ?? ""),
    )
    .replace(NETBIOS, (all, q: string, u: string) => (HAS_TOKEN.test(all) ? netbios(c, all, q, u) : all));
  // `x@CORP\\bob` is an account behind `CORP`: the NETBIOS pattern reads it before the UPN one.
  const behind = (s: string, end: number, d: string) =>
    s[end] === "\\" && NETBIOS_AFTER.test(s.slice(end + 1, end + 3)) && NETBIOS_QUALIFIER.test(expand(d));
  const email = (s: string) => EMAIL.test(expand(s));
  return replaceUpns(out, email, (all, user, d, at, s) => {
    if (!HAS_TOKEN.test(all) || behind(s, at + all.length, d)) return all;
    const hit = upn(c, all, user, d);
    // Behind another `@` the fresh email pattern masks the whole address, its `@` included (#3074).
    if (hit !== all && s[at - 1] === "@" && c.email) return c.whole("EMAIL", all);
    return hit !== all ? hit : gluedUpn(c, all, user, d, at, s);
  });
}

// Like `text.replace(UPN, fn)`, but a match left as it is, followed by another `@` and not itself an
// address the email pass masks later, is read again from its first `@`: `<user>@<domain>N@ANON_DOMAIN_1`
// holds the account `<domain>N@ANON_DOMAIN_1`, as the fresh email pattern reads it (#3074).
type UpnFn = (all: string, user: string, d: string, at: number, s: string) => string;
function replaceUpns(text: string, email: (s: string) => boolean, fn: UpnFn): string {
  const re = new RegExp(UPN.source, "g");
  let out = "";
  let last = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const hit = fn(m[0], m[1], m[2], m.index, text);
    if (hit === m[0]) {
      if (text[m.index + m[0].length] === "@" && !email(m[0])) re.lastIndex = m.index + m[1].length + 1;
      continue;
    }
    out += text.slice(last, m.index) + hit;
    last = m.index + m[0].length;
  }
  return out + text.slice(last);
}

// Digits glued after the TLD (`<user>@<domain>1`), as GLUED_EMAIL_RE reads the real text (#3050): a
// saved qualifier minted first left `<user>@ANON_DOMAIN_1.local1`, which no reader took (#3069).
const GLUED_TLD = /\.[A-Za-z]{2,}(\d{1,3})$/;
function gluedUpn(c: Ctx, all: string, user: string, d: string, at: number, s: string): string {
  const digits = GLUED_TLD.exec(d)?.[1];
  if (!digits || /[_%+@]/.test(s[at + all.length] ?? "")) return all;
  const head = all.slice(0, -digits.length);
  const hit = upn(c, head, user, d.slice(0, -digits.length));
  return hit === head ? all : c.ended(hit, head, at, at + head.length, s) + digits;
}

// The longest prefix of `run` that ends where the fresh pattern may end (the run's end, or before a
// non-word character) and passes `ok` once its tokens are resolved, as a backtracking regex reads it.
function longestPrefix(run: string, ok: (prefix: string) => boolean): number {
  for (let end = run.length; end > 0; end--) {
    if (end < run.length && /\w/.test(run[end])) continue;
    if (ok(run.slice(0, end))) return end;
  }
  return -1;
}

// The user half is read whole, as the fresh pattern reads it (#3049). A domain SID glued to its end
// gets its own token (`rest`), as on a call without saved values (#3020, #3049).
interface Half {
  part: string;
  user: string;
  rest: () => string;
}
function userHalf(c: Ctx, u: string): Half | null {
  const sid = splitGluedSid(u, c.expand(u).length);
  const part = sid ? sid.user : u;
  const user = c.expand(part);
  if (HAS_TOKEN.test(user) || !LONG_USER.test(user)) return null;
  return { part, user, rest: () => (sid ? sid.sep + c.whole("REG", sid.sid) + sid.rest : "") };
}

// The qualifier is the last word of one minted value (a saved profile name with a space), read as
// the fresh pattern reads it; one it read as a noise word (`lan` of `élan`) hides the account whole.
function tailAccount(c: Ctx, all: string, tok: string, u: string, before: string): string {
  const fresh = c.single(tok) ? freshQualifier(before + (c.tokens.get(tok) ?? "")) : null;
  const q = fresh?.qualifier ?? "";
  const half = fresh && !PATH_DOMAINS.test(q) ? userHalf(c, u) : null;
  if (!fresh || !half) return all;
  const account = `${q}\\${half.user}`;
  if (c.suppressed.has(account.toLowerCase())) return all;
  if (isNoiseDomain(fresh.cut)) return c.whole("USER", `${tok}\\${half.part}`) + half.rest(); // `élan\\x`
  if (isNoiseAccount(account) || c.fileUser.test(half.user)) return all;
  return `${tok}\\${c.user(half.user, half.part)}${half.rest()}`;
}

function netbios(c: Ctx, all: string, q: string, u: string): string {
  const real = c.expand(q);
  const fresh = HAS_TOKEN.test(real) ? null : freshQualifier(real);
  if (!fresh || PATH_DOMAINS.test(fresh.qualifier) || PATH_DOMAINS.test(fresh.cut)) return all;
  const half = userHalf(c, u);
  if (!half) return all;
  const { part, user } = half;
  const whole = fresh.qualifier === real;
  if (whole && (!HAS_TOKEN.test(q + part) || (c.single(q) && c.single(part)))) return all; // the account pass
  const account = `${fresh.qualifier}\\${user}`;
  if (c.suppressed.has(account.toLowerCase())) return all; // the analyst veto keeps the tokens it holds
  // `ANON_EMAIL_1-CORP\\007` reads `…local-CORP` (after the `@`): only that part is the qualifier (#3049).
  const raw = whole ? q : rawSuffix(c, q, fresh.qualifier);
  const lead = raw === null ? q : q.slice(0, q.length - raw.length);
  const noise = isNoiseAccount(account) || isNoiseDomain(fresh.cut) || c.fileUser.test(user);
  if (noise) return raw === null ? all : lead + c.whole("USER", `${raw}\\${part}`) + half.rest();
  const qualifier = raw === null ? "" : c.single(raw) ? raw : c.qualifier(fresh.qualifier, raw);
  return `${lead}${qualifier}\\${c.user(user, part)}${half.rest()}`;
}

// The end of the run `q` that holds exactly the qualifier, or null when it starts inside a token.
function rawSuffix(c: Ctx, q: string, qualifier: string): string | null {
  const tokens = [...q.matchAll(ANY_TOKEN)];
  let need = qualifier.length;
  let i = q.length;
  for (let t = tokens.length - 1; need > 0 && i > 0;) {
    const tok = tokens[t];
    if (tok && tok.index + tok[0].length === i) {
      need -= c.expand(tok[0]).length;
      i = tok.index;
      t--;
    } else {
      need--;
      i--;
    }
  }
  return need === 0 && c.expand(q.slice(i)) === qualifier ? q.slice(i) : null;
}

function upn(c: Ctx, all: string, run: string, d: string): string {
  // The fresh patterns start the user at any word boundary: `zoë-bob@…` and `ANON_EMAIL_1-bob@…`
  // read `bob@…`, so each start after a `.`, `%`, `+` or `-` is tried, leftmost first.
  for (let i = 0; i < run.length; i++) {
    if (i > 0 && !(/[.%+-]/.test(run[i - 1]) && /\w/.test(run[i]))) continue;
    // A `+` before a digit is a phone prefix: it stays inside the user token (#3074).
    const user = run.slice(i).replace(/^(?:[.%-]|\+(?!\d))+/, "");
    if (c.single(user) && c.single(d)) return all; // already masked whole
    const hit = upnFrom(c, user, d);
    if (hit !== null) return run.slice(0, run.length - user.length) + hit;
  }
  return all;
}

function upnFrom(c: Ctx, user: string, d: string): string | null {
  const realUser = c.expand(user);
  if (HAS_TOKEN.test(realUser)) return null;
  // Like the email pattern, the domain may end early: `<user>@<domain>-alpha` reads `<user>@<domain>`.
  const found = { hit: "" };
  const end = longestPrefix(d, (p) => (found.hit = upnDomain(c, user, realUser, p) ?? "") !== "");
  return end < 0 ? null : found.hit + d.slice(end);
}

function upnDomain(c: Ctx, user: string, realUser: string, d: string): string | null {
  if (!HAS_TOKEN.test(user + d)) return null;
  const real = c.expand(d);
  if (HAS_TOKEN.test(real) || !UPN_DOMAIN.test(real)) return null;
  const account = `${realUser}@${real}`;
  if (!UPN_USER.test(realUser) || !c.internal(real))
    return c.email && EMAIL.test(account) ? c.whole("EMAIL", `${user}@${d}`) : null;
  if (c.suppressed.has(account.toLowerCase())) return `${user}@${d}`;
  return `${c.user(realUser, user)}@${c.single(d) ? d : c.qualifier(real, d)}`;
}
