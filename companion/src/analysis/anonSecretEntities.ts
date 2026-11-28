import { locateSecrets } from "./anonSecretCustom.js";
import {
  NETBIOS_ACCT,
  PATH_DOMAINS,
  UPN_ACCT,
  USER_PATH_RE,
  WELL_KNOWN_PROFILE,
  isFragmentName,
  isNoiseAccount,
} from "./anonUsernames.js";

// #3039: a credential value that holds an account, an internal e-mail or a profile path
// (password=<user>@<internal domain>, a DefaultPassword holding C:\Users\<user>) is redacted one way
// before the account, e-mail and path passes run, so they never learned that user and a bare mention
// of the same user elsewhere went to the AI in clear. The user name in such a value is handed to the
// caller, which learns it (or claims it one way when it holds a secret). Only the user name, never
// the value, and no token is minted here.
//
// #3059: the entity may sit anywhere in the value (after other text, after a JSON line break, inside
// a long here-string), and the value may be JSON-escaped more than once. The value is read twice:
// with every run of backslashes read as one, and the same with a backslash run before n, r or t read
// as a line break (a JSON escape). A DOMAIN\user counts only at the value start or after a space, a
// quote or a separator, so a password that merely holds a backslash (P@ss\w0rd) teaches nothing, and
// it must end at a non-name character. An e-mail keeps the e-mail pass's own word boundaries (so
// `\njdoe@…` read without the JSON escape still lends `njdoe`, as the e-mail pass learns it), and a
// profile name found after other text lends only its first word.
//
// #3061: a learned name is never a piece of the credential itself. A password shaped `Zx9-ab\cdefgh`
// or `Winter\cdefgh` read as DOMAIN\user and lent `cdefgh`, which was then stored as a reversible
// USER token. A DOMAIN\user now counts only as the whole value or a whole word of it (whitespace or a
// quote on both sides; a trailing `, ; . ) ] } > |` is allowed), and only when the qualifier is
// written as a NetBIOS domain is (upper case): shape alone cannot tell CORP\jdoe from a password.
// An e-mail must start a word too, so the plain reading no longer lends `njdoe` out of a JSON
// `\njdoe@…` (the JSON-break reading still lends `jdoe`), and a profile path must start the value
// or follow a space, quote or separator.

const NAME_CHAR = /[A-Za-z0-9._%+$@\\-]/;
// Built from the patterns' own flags, so the account pattern keeps its `u` flag (#3049).
const scanner = (re: RegExp) => new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
const ACCOUNT = scanner(NETBIOS_ACCT);
const UPN = scanner(UPN_ACCT);
const PROFILE = scanner(USER_PATH_RE);
const OPENS = /[\s"'`=,;(|[{<>]/; // what may stand right before a profile path inside a value
const WORD_OPEN = /[\s"'`]/; // what may stand right before a DOMAIN\user or e-mail inside a value
const WORD_CLOSE = /^[,;.)\]}>|]*(?:[\s"'`]|$)/; // what may follow a DOMAIN\user inside a value
const DOMAIN_CASE = /^\p{Lu}[\p{Lu}\p{N}.-]*$/u; // a qualifier written as a NetBIOS domain is (#3061)
const EDGES = /^[\s"'`]+|[\s"'`]+$/g;
const BACKSLASHES = /\\+/g;
const JSON_BREAK = /\\+[nrt]/g;
const FIRST_WORD = /^\S+/;
const MAY_HOLD = /[\\@/]/; // every entity shape needs one of these

// The e-mail pattern is the account pass's own (UPN_ACCT, run over every text already); the timing
// test covers its use here.
export const ENTITY_PATTERNS: readonly RegExp[] = [
  ACCOUNT,
  PROFILE,
  OPENS,
  WORD_OPEN,
  WORD_CLOSE,
  DOMAIN_CASE,
  BACKSLASHES,
  JSON_BREAK,
];

/**
 * What the account pass would see: `internal` (a UPN domain is internal), `fileUser` (Folder\file.exe),
 * and `addressAt`, where the first IPv6 address the anonymizer sets aside starts (-1 for none): the
 * passes read a name only up to it (jdoe@<internal domain> + fd00::2).
 */
export interface EntityRules {
  internal: (domain: string) => boolean;
  fileUser: RegExp;
  addressAt: (value: string) => number;
}

const startsWord = (text: string, at: number): boolean => at === 0 || WORD_OPEN.test(text[at - 1]);
const endsWord = (text: string, end: number): boolean =>
  !NAME_CHAR.test(text[end] ?? "") && WORD_CLOSE.test(text.slice(end, end + 64));

function profileNames(text: string, out: string[]): void {
  for (const m of text.matchAll(PROFILE)) {
    if (m.index > 0 && !OPENS.test(text[m.index - 1])) continue;
    const name = m.index === 0 ? m[2].trim() : (FIRST_WORD.exec(m[2])?.[0] ?? "");
    if (name && !WELL_KNOWN_PROFILE.test(name)) out.push(name);
  }
}

function accountNames(text: string, { fileUser }: EntityRules, out: string[]): void {
  for (const m of text.matchAll(ACCOUNT)) {
    const [whole, dom, user] = m;
    if (!startsWord(text, m.index) || !endsWord(text, m.index + whole.length)) continue;
    if (!DOMAIN_CASE.test(dom) || PATH_DOMAINS.test(dom) || isNoiseAccount(whole) || fileUser.test(user))
      continue;
    out.push(user);
  }
}

function mailNames(text: string, { internal }: EntityRules, out: string[]): void {
  for (const m of text.matchAll(UPN)) {
    const upn = m[0];
    if (!startsWord(text, m.index)) continue;
    const at = upn.lastIndexOf("@");
    if (internal(upn.slice(at + 1)) && !isNoiseAccount(upn)) out.push(upn.slice(0, at));
  }
}

function readingNames(reading: string, rules: EntityRules, out: string[]): void {
  const cut = rules.addressAt(reading);
  const text = cut > 0 ? reading.slice(0, cut) : reading;
  profileNames(text, out);
  accountNames(text, rules, out);
  mailNames(text, rules, out);
}

/** Every user name a credential value holds. A short or digit-only name is never one (#3030). */
export function valueEntities(raw: string, rules: EntityRules): string[] {
  const value = raw.replace(EDGES, "");
  if (!MAY_HOLD.test(value)) return [];
  const names: string[] = [];
  const plain = value.replace(BACKSLASHES, "\\");
  readingNames(plain, rules, names);
  const broken = value.replace(JSON_BREAK, " ").replace(BACKSLASHES, "\\");
  if (broken !== plain) readingNames(broken, rules, names);
  return [...new Set(names)].filter((n) => !isFragmentName(n));
}

/**
 * Hand `onEntity` every user name held by a redacted value in `redacted` (`clear` with each secret
 * replaced by `sentinel`). Nothing when the secrets cannot be located.
 */
export function learnRedactedEntities(
  clear: string,
  redacted: string,
  sentinel: string,
  rules: EntityRules,
  onEntity: (name: string) => void,
): void {
  if (!redacted.includes(sentinel) || !MAY_HOLD.test(clear)) return;
  for (const span of locateSecrets(clear, redacted, sentinel) ?? []) {
    for (const { start, end } of [span.exact, span.loose]) {
      for (const name of valueEntities(clear.slice(start, end), rules)) onEntity(name);
    }
  }
}
