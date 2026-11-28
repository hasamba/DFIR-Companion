import { isNoiseAccount, PATH_DOMAINS } from "./anonUsernames.js";

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
  String.raw`(?<![\\/:.\w-])((?:${TOKEN}|[A-Za-z0-9.-])+)\\((?:${TOKEN}|[\p{L}\p{N}._$-])+)(?![\\/\w])`,
  "gu",
);
// `<profile path>\dave élan\xC`: a call without the saved profile name reads `élan\xC` as an account.
const TAIL_ACCOUNT = new RegExp(String.raw`(?<=\\)(${TOKEN})\\([\p{L}\p{N}._$-]+)(?![\\/\w])`, "gu");
const TAIL_QUALIFIER = /[^\w.:\\/-]([A-Za-z][A-Za-z0-9.-]{1,14})$/;
const UPN = new RegExp(
  String.raw`(?<![\w.%+-])((?:${TOKEN}|[A-Za-z0-9._%+-])+)@((?:${TOKEN}|[A-Za-z0-9.-])+)`,
  "g",
);
// The fresh account and email patterns (NETBIOS_ACCT, UPN_ACCT, EMAIL_RE), read on the real text.
const NETBIOS_QUALIFIER = /^[A-Za-z][A-Za-z0-9.-]{1,14}$/;
const NETBIOS_AFTER = /^[A-Za-z0-9._$-]{2}$/; // the first two characters of a NETBIOS user
// NETBIOS_ACCT reads at most 20 of [A-Za-z0-9._$-]; a user glued to `é` or `ø` is read on with it.
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
  whole: (category: "USER" | "EMAIL", value: string) => string; // one token; tokens inside expand
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
    .replace(TAIL_ACCOUNT, (all, tok: string, u: string) => tailAccount(c, all, tok, u))
    .replace(NETBIOS, (all, q: string, u: string) => (HAS_TOKEN.test(all) ? netbios(c, all, q, u) : all));
  // `x@CORP\\bob` is an account behind `CORP`: the NETBIOS pattern reads it before the UPN one.
  const behind = (s: string, end: number, d: string) =>
    s[end] === "\\" && NETBIOS_AFTER.test(s.slice(end + 1, end + 3)) && NETBIOS_QUALIFIER.test(expand(d));
  return out.replace(UPN, (all, user: string, d: string, at: number, s: string) =>
    HAS_TOKEN.test(all) && !behind(s, at + all.length, d) ? upn(c, all, user, d) : all,
  );
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

// A user half the fresh pattern would cut short (over 20 characters) is read whole, so the cut
// never leaves the tail of a value a later pass masks in clear; it stops before a SID (#3020).
function userHalf(c: Ctx, u: string): { part: string; rest: string; user: string } | null {
  const sid = /[.$-](?=S-1-5-21-)/i.exec(u);
  const [part, rest] = sid ? [u.slice(0, sid.index), u.slice(sid.index)] : [u, ""];
  const user = c.expand(part);
  return HAS_TOKEN.test(user) || !LONG_USER.test(user) ? null : { part, rest, user };
}

// The qualifier is the last word of one minted value (a saved profile name with a space).
function tailAccount(c: Ctx, all: string, tok: string, u: string): string {
  const q = c.single(tok) ? TAIL_QUALIFIER.exec(c.tokens.get(tok) ?? "")?.[1] : undefined;
  const half = q && !PATH_DOMAINS.test(q) ? userHalf(c, u) : null;
  if (!q || !half) return all;
  const account = `${q}\\${half.user}`;
  if (c.suppressed.has(account.toLowerCase()) || isNoiseAccount(account) || c.fileUser.test(half.user))
    return all;
  return `${tok}\\${c.user(half.user, half.part)}${half.rest}`;
}

function netbios(c: Ctx, all: string, q: string, u: string): string {
  const real = c.expand(q);
  if (HAS_TOKEN.test(real) || !NETBIOS_QUALIFIER.test(real) || PATH_DOMAINS.test(real)) return all;
  const half = userHalf(c, u);
  if (!half) return all;
  const { part, rest, user } = half;
  if (!HAS_TOKEN.test(q + part) || (c.single(q) && c.single(part))) return all; // read by the account pass
  const account = `${real}\\${user}`;
  if (c.suppressed.has(account.toLowerCase())) return all; // the analyst veto keeps the tokens it holds
  if (isNoiseAccount(account) || c.fileUser.test(user)) return c.whole("USER", `${q}\\${part}`) + rest;
  const qualifier = c.single(q) ? q : c.qualifier(real, q);
  return `${qualifier}\\${c.user(user, part)}${rest}`;
}

function upn(c: Ctx, all: string, run: string, d: string): string {
  // The fresh patterns start the user at any word boundary: `zoë-bob@…` and `ANON_EMAIL_1-bob@…`
  // read `bob@…`, so each start after a `.`, `%`, `+` or `-` is tried, leftmost first.
  for (let i = 0; i < run.length; i++) {
    if (i > 0 && !(/[.%+-]/.test(run[i - 1]) && /\w/.test(run[i]))) continue;
    const user = run.slice(i).replace(/^[.%+-]+/, "");
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
