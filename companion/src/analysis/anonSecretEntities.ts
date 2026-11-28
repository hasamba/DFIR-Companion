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

// #3039: a credential value that is itself an account, an internal e-mail or a profile path
// (password=<user>@<internal domain>, a DefaultPassword holding C:\Users\<user>) is redacted one way
// before the account, e-mail and path passes run, so they never learned that user and a bare mention
// of the same user elsewhere went to the AI in clear. The user name in such a value is handed to the
// caller, which learns it (or claims it one way when it holds a secret). Only the user name, never
// the value, and no token is minted here. A value counts only when it IS the entity: it starts with
// DOMAIN\user or a UPN on an internal domain that ends at a non-name character, or with a profile
// path. A password that merely holds a backslash (P@ss\w0rd) teaches nothing. A JSON-escaped "\\"
// reads as one backslash.

const NAME_END = "(?![A-Za-z0-9._%+$@\\\\-])";
const leading = (re: RegExp) => new RegExp(`^(?:${re.source})${NAME_END}`);
const ACCOUNT = leading(NETBIOS_ACCT);
const UPN = leading(UPN_ACCT);
const PROFILE = new RegExp(`^(?:${USER_PATH_RE.source})`);
const EDGES = /^[\s"'`]+|[\s"'`]+$/g;
const JSON_BACKSLASH = /\\\\/g;
const MAY_HOLD = /[\\@/]/; // every entity shape needs one of these

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

function readEntity(value: string, { internal, fileUser }: EntityRules): string | null {
  const path = PROFILE.exec(value);
  if (path) {
    const name = path[2].trim();
    return WELL_KNOWN_PROFILE.test(name) ? null : name;
  }
  const acct = ACCOUNT.exec(value);
  if (acct) {
    const [, dom, user] = acct;
    const skip = PATH_DOMAINS.test(dom) || isNoiseAccount(acct[0]) || fileUser.test(user);
    return skip ? null : user;
  }
  const upn = UPN.exec(value)?.[0];
  if (!upn) return null;
  const at = upn.lastIndexOf("@");
  return internal(upn.slice(at + 1)) && !isNoiseAccount(upn) ? upn.slice(0, at) : null;
}

/** The user name a credential value is, or null. A short or digit-only name is never one (#3030). */
export function valueEntity(raw: string, rules: EntityRules): string | null {
  const value = raw.replace(EDGES, "").replace(JSON_BACKSLASH, "\\");
  const cut = rules.addressAt(value);
  const name = readEntity(cut > 0 ? value.slice(0, cut) : value, rules);
  return name && !isFragmentName(name) ? name : null;
}

/**
 * Hand `onEntity` the user name of every redacted value in `redacted` (`clear` with each secret
 * replaced by `sentinel`) that is itself an entity. Nothing when the secrets cannot be located.
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
      const name = valueEntity(clear.slice(start, end), rules);
      if (name) onEntity(name);
    }
  }
}
