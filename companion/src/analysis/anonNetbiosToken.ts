import {
  isNoiseDomain,
  legacyReading,
  PATH_DOMAINS,
  splitGluedSid,
  type NetbiosMatch,
} from "./anonUsernames.js";

// #3049: the account pattern read at most 20 ASCII characters of the user half of DOMAIN\user and an
// ASCII-only qualifier. It now reads both whole, and this keeps what the old reading saved, so a later
// call masks what it masked:
// - the shorter old readings (qualifier `LAB` of `zoëLAB`, user `bob` of `bobélan-x`) are still learned
//   and saved;
// - a qualifier only the new reading finds (the old pattern read no account there) is masked in place
//   and never saved, unless an account the old pattern read mints it too: a saved `corp` cut
//   `<qualifier>.<internal domain>` apart on later calls;
// - a user half the old pattern did not read that runs into `@` is left to the e-mail pass, which hides
//   the whole address;
// - an e-mail local part glued in front of the qualifier is the user of that address.

export interface NetbiosTokenDeps {
  userToken: (user: string) => string;
  qualifier: (q: string) => string;
  accountToken: (account: string) => string;
  /** The token already minted for `q` as a qualifier, if any. */
  qualifierToken: (q: string) => string | undefined;
  suppressed: ReadonlySet<string>;
  savedUsers: Set<string>; // tokens saved as discoveries
  cutUsers: Set<string>; // tokens masked in place and never saved (unless also in savedUsers)
}

export function createNetbiosToken(d: NetbiosTokenDeps): (m: NetbiosMatch) => string {
  return ({ account, qualifier: q, user, local, after }) => {
    const old = legacyReading(q, user);
    if (after === "@" && !old.user) return (local ? `${local}@` : "") + account;
    const lead = local ? `${d.userToken(local)}@` : "";
    if (PATH_DOMAINS.test(q) || PATH_DOMAINS.test(old.qualifier)) return lead + account;
    const known = d.qualifierToken(q) !== undefined;
    const out = lead + d.accountToken(account);
    const plain = !d.suppressed.has(account.toLowerCase()) && !isNoiseDomain(old.qualifier);
    const qTok = plain ? d.qualifierToken(q) : undefined;
    if (qTok && (old.user || !known)) (old.user ? d.savedUsers : d.cutUsers).add(qTok);
    if (plain && old.qualifier !== q) d.qualifier(old.qualifier);
    if (plain && old.user && old.user !== user && !splitGluedSid(user)) d.userToken(old.user);
    return out;
  };
}

/** A user half with a glued domain SID split off into its own token (#3049), else one user token. */
export function sidUserToken(
  u: string,
  userToken: (user: string) => string,
  sidToken: (sid: string) => string,
): string {
  const sid = splitGluedSid(u);
  return sid ? `${userToken(sid.user)}${sid.sep}${sidToken(sid.sid)}${sid.rest}` : userToken(u);
}
