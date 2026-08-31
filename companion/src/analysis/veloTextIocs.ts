// Free-text IOC extraction for a Velociraptor row.
//
// Its own module because analysis/velociraptorImport.ts is frozen by the file-size ledger (#384).
//
// `genericIocs` only fires on structured keys, so an indicator that lives INSIDE a matched command
// `Line`, a collected file `Content`, a YARA `HitString` or a PowerShell script block — very often
// the exact thing the rule fired on — is otherwise missed entirely.
import { addIoc, cleanIp, str, getCI, type SiemIoc } from "./siemImport.js";
import { extractDomains } from "./textDomains.js";

const TEXT_URL = /\bhttps?:\/\/[^\s"'<>)\]}]+/gi;
// Octet-bounded, so a "10.0.22000" version string is not read as an address.
const TEXT_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const TEXT_HASH = /\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi;

// The vulnerability a tool says it targets. A scanner names its own exploit module in the clear —
// the Bissa eval's whole React2Shell/W3TC campaign said so in one script block — and until this ran
// the CVE was read by the importer and dropped, so no report named what was being exploited.
// The `CVE-` prefix carries the whole match; a bare `2025-55182` is a build number, not an id.
const TEXT_CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;

// A Telegram BOT handle, in the two forms a script writes one. Telegram requires a bot username to
// end in "bot", so that suffix is the platform's own rule rather than a guess, and an ordinary
// @mention (`@BonJoviGoesHard`) never matches either form.
//
//   @-prefixed   the handle as a human writes it. The `@` identifies it on its own, so the name only
//                has to be a legal username. The lookbehind keeps an email local-part out —
//                `abuse@robot.example.com` is not a bot named `@robot`.
//   assigned     the handle as a SCRIPT writes it: `AlertBotUsername = "bissapwned_bot"`. This is the
//                form the Bissa eval's script block actually used, and the `@` never appeared. With
//                no `@` to identify it the bar is higher on both sides — the KEY must name a bot too,
//                and the value needs 9+ characters, so `robot: "mybot"` does not qualify.
const TEXT_BOT_HANDLE = /(?<![A-Za-z0-9._%+-])@[A-Za-z][A-Za-z0-9_]{3,30}bot\b/gi;
// "The KEY must name a bot" means the word `bot`, not the three letters anywhere in it. Requiring
// only that the key CONTAIN them made `robot` qualify, so a home-automation line (`$robot =
// "vacuum_bot"`) or a config default (`robot_name: "placeholderbot"`) minted a Telegram-bot IOC and
// spent analyst attention on a script's own benign config (#743). A key that really names a bot
// field puts `bot` at a token boundary, in one of three shapes:
//
//   start        `botname`, `BOT_TOKEN`     — nothing before it
//   underscore   `alert_bot`, `tg_bot_user` — snake_case
//   camel hump   `AlertBotUsername`         — a capital B after a lowercase letter or digit
//
// Detecting the hump needs the case, so this regex is NOT /i — and because it is not, the `bot`
// the VALUE must end in is spelled out case-insensitively rather than left to the flag. Telegram
// usernames are case-insensitive, so a script writing `"BissaPwned_Bot"` still matches.
const TEXT_BOT_ASSIGNED =
  /(?<![A-Za-z0-9_])(?:[Bb][Oo][Tt]|[A-Za-z0-9_]*(?:_[Bb][Oo][Tt]|[a-z0-9](?:Bot|BOT)))[A-Za-z0-9_]*\s*[:=]\s*["']([A-Za-z][A-Za-z0-9_]{5,30}[Bb][Oo][Tt])["']/g;

// An object-store destination written as a URI. TEXT_URL only reads http(s), so the `s3://` form an
// exfil runner uses — `aws s3 cp results/*.zip s3://bucket/prefix/` — reached no scraper at all.
const TEXT_S3_URI = /\bs3:\/\/[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](?:\/[^\s"'<>)\]}]*)?/gi;

// Punctuation that ends a URI written into prose rather than the URI itself. A trailing SLASH is
// absent from the class on purpose: it is part of a bucket prefix, not the sentence.
const TRAILING_SENTENCE_PUNCTUATION = /[.,;:)\]]+$/;

/**
 * Drop the sentence's punctuation from the end of a matched URI — unless a quote proves the
 * punctuation belongs to the URI.
 *
 * `upload to s3://bucket/loot.` ends a sentence, so the period is the writer's, and keeping it
 * stores a destination that is not a usable URI and duplicates the same bucket written without it.
 *
 * `aws s3 cp x 's3://bucket/evidence.'` is the opposite case. An S3 object key may legally end in a
 * dot, and the closing quote says where the value ends — no sentence is being punctuated inside it.
 * Stripping there records a destination the script never used. The URI counts as quote-delimited
 * only when the character immediately before it opens a quote AND the character immediately after
 * it closes the SAME one, so `he said "go to s3://bucket/evidence."` still strips: the quote wraps
 * the sentence, not the URI.
 *
 * Both scrapers call this, because #744 was filed about the two disagreeing over one destination.
 */
function trimSentencePunctuation(match: string, text: string, index: number): string {
  const opener = index > 0 ? text[index - 1] : "";
  const closer = text[index + match.length] ?? "";
  if ((opener === '"' || opener === "'") && closer === opener) return match;
  return match.replace(TRAILING_SENTENCE_PUNCTUATION, "");
}

// URLs, IPv4, SHA256/SHA1/MD5 hashes, domains, CVE ids, Telegram bot handles and s3:// URIs. The
// domain pass came first: a collected script block names its C2 by name at least as often as by
// address, and until `extractDomains` ran here those names were simply lost (#648). The last three
// are the same lesson from the Bissa eval — a script block also names the vulnerability it exploits,
// the channel it reports hits on, and the bucket it ships them to, all in plain text.
export function scrapeText(text: string, sink: Map<string, SiemIoc>): void {
  if (!text) return;
  for (const m of text.matchAll(TEXT_URL))
    addIoc(sink, "url", trimSentencePunctuation(m[0], text, m.index ?? 0).slice(0, 300));
  for (const m of text.matchAll(TEXT_IPV4)) {
    // A dotted quad written right after a version marker is a version string, not an address:
    // `choco install openssh --version 8.0.0.1`, `$script:ModuleVersion = '1.0.0.0'`. Octet bounds
    // alone cannot tell these apart (their octets are all ≤ 255), so read the ~14 chars before it.
    const pre = text.slice(Math.max(0, (m.index ?? 0) - 14), m.index ?? 0).toLowerCase();
    if (/version\s*['"=:\s]*$/.test(pre)) continue;
    const ip = cleanIp(m[0]);
    if (ip) addIoc(sink, "ip", ip);
  }
  for (const m of text.matchAll(TEXT_HASH)) addIoc(sink, "hash", m[0].toLowerCase());
  for (const d of extractDomains(text)) addIoc(sink, "domain", d);
  // Canonical upper case, so `cve-2025-55182` and `CVE-2025-55182` are one indicator, not two.
  for (const m of text.matchAll(TEXT_CVE)) addIoc(sink, "other", m[0].toUpperCase());
  // Both forms normalize to `@handle`, so a script that names the same bot twice — once assigned,
  // once written out — yields one indicator rather than two spellings of it.
  for (const m of text.matchAll(TEXT_BOT_HANDLE)) addIoc(sink, "other", m[0]);
  for (const m of text.matchAll(TEXT_BOT_ASSIGNED)) addIoc(sink, "other", `@${m[1]}`);
  // The same trim the URL pass runs, by the same function: a bucket named mid-sentence would
  // otherwise be stored as "s3://b/prefix," — not a usable URI, and a second indicator for a
  // destination already recorded without the comma (#744).
  for (const m of text.matchAll(TEXT_S3_URI))
    addIoc(sink, "other", trimSentencePunctuation(m[0], text, m.index ?? 0).slice(0, 300));
}

// The free-text fields that carry a detection's evidence (and its embedded IOCs). `ScriptBlockText`
// is what Velociraptor's own Windows.EventLogs.PowershellScriptblock artifact — the ordinary way to
// collect EID 4104 — puts the script under, as a flat top-level column with no parsed event around
// it. Until it was listed here that row reached no scraper at all and produced zero IOCs (#652).
const EVIDENCE_TEXT_KEYS = [
  "Line",
  "Content",
  "CommandLine",
  "HitString",
  "StringHit",
  "Message",
  "Details",
  "ScriptBlockText",
];
export function scrapeEvidence(row: Record<string, unknown>, sink: Map<string, SiemIoc>): void {
  for (const k of EVIDENCE_TEXT_KEYS) scrapeText(str(getCI(row, k)), sink);
}
