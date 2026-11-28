import { bareUsername, isLegacyNoiseAccount, type NetbiosMatch } from "./anonUsernames.js";

// DOMAIN\\user written with a JSON-doubled backslash (#3067): `{"m":"CORP\\zed"}` in a raw JSON
// line. The single-backslash pattern never reads it (a user half cannot start with `\`), so an unknown
// user went out in clear. Same qualifier and user classes and guards as NETBIOS_ACCT, with exactly two
// backslashes between them, minted through the same path as `DOMAIN\user`; the doubled separator is
// kept so the text restores as it came in. The qualifier is never saved: a saved `<QUAL>` cut
// `<qual>.<internal domain>` apart on a seeded call and restored it in the qualifier's case. Never
// right after `@`: `<local>@<domain>\\n…` is an address before a doubly escaped line break, left to
// the e-mail pass.
const DOUBLED_ACCT =
  /(?<![\\/:.\w@-])(\p{L}[\p{L}\p{N}.-]{1,14})\\\\([\p{L}\p{N}._$-]{2,})(?![\\/\p{L}\p{N}_])/gu;

/** Replace each `DOMAIN\\user` with what `mint` makes of `DOMAIN\user`, the separator doubled. */
export function replaceDoubledAccounts(
  text: string,
  mint: (m: NetbiosMatch) => string,
  fileUser: RegExp, // a user half that is a file name (Folder\evil.exe) is not a person
): string {
  if (!text.includes("\\\\")) return text;
  return text.replace(DOUBLED_ACCT, (whole, qualifier: string, user: string, at: number, w: string) => {
    const account = `${qualifier}\\${user}`;
    // A hive, Windows principal or Folder\file.exe keeps its single whole token in the plain form;
    // doubled, it stays as it was.
    if (isLegacyNoiseAccount(account) || fileUser.test(bareUsername(account))) return whole;
    const out = mint({ account, qualifier, user, local: "", after: w[at + whole.length] ?? "", cut: true });
    const sep = out.indexOf("\\");
    if (out === account || sep < 0 || out.indexOf("\\", sep + 1) >= 0) return whole;
    return `${out.slice(0, sep)}\\\\${out.slice(sep + 1)}`;
  });
}
