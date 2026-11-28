import { israeliIdValid } from "./anonChecksums.js";
import { isIP } from "node:net";
import type { InvestigationState } from "./stateTypes.js";
import { learnableAccounts, FILE_EXT_USER } from "./assetGraph.js";
import { embeddedIpv4, expandIpv6Groups } from "./iocValue.js";
import { anonPairKey } from "./anonPatterns.js";
import { growSpansToKnown, replaceKnownValues, type KnownValue } from "./anonKnownValues.js";
import {
  compileCustomEntities,
  findCustomSpans,
  groupWithLiterals,
  rangeCategory,
  spliceSpans,
} from "./anonCustomSpans.js";
import { SECRET_PLACEHOLDER } from "./anonSecrets.js";
import { redactSecretsWithCustom } from "./anonSecretCustom.js";
import { createOneWayCheck, growGluedRemnants } from "./anonGluedSecret.js";
import { learnRedactedEntities } from "./anonSecretEntities.js"; // a user inside a redacted value (#3039)
import { NATID_RE, PHONE_E164, PHONE_IL, PHONE_NANP } from "./anonPiiPatterns.js";
import { replaceCards, replaceGluedIpv4 } from "./anonPiiPatterns.js";
import { scanTokenLiterals, tokenEnds, tokenReaders } from "./anonTokenLiterals.js";
import { createInputSpelling, literalEscapes } from "./anonTokenLiterals.js";
import { tokenQualifiedAccounts } from "./anonTokenAccounts.js";
import { createNetbiosToken, sidUserToken } from "./anonNetbiosToken.js";
import { carveProfileName, valuePasses } from "./anonProfileTail.js";
import { replaceEmails, UPN_SCAN } from "./anonAtScan.js"; // linear on long runs (#3055)
import { findIpv6Literals, groupAsRead, type Ipv6Grade, type Ipv6Span } from "./anonIpv6Scan.js";
import { createTailJoiner, gluedIpv4At, type ReservedLiteral as Reserved } from "./anonTailJoin.js";
import {
  replaceUserPaths,
  replaceNetbiosAccounts,
  isLegacyNoiseAccount,
  bareUsername,
  collectUsernames,
  isFragmentName,
  isGuardedUsername,
  shortHostLabels,
  isNoiseAccount,
  isNoiseDomain,
  replaceBareNames,
  replaceUncServers,
  usernameMatcher,
} from "./anonUsernames.js";

// Reversible anonymization of the TEXT sent to the LLM. Real values stay in state; only the
// wire is tokenized. Typed numbered tokens keep the model's semantic understanding (it still
// knows ANON_HOST_1 is a host) and within-call correlation (same value → same token). Restore
// walks the model's PARSED JSON response (not the raw string) so real values containing JSON
// metacharacters — e.g. a Windows path's backslashes — never corrupt parsing.

export type AnonCategory =
  "IP" | "EMAIL" | "USER" | "HOST" | "DOMAIN" | "PATH" | "CMD" | "REG" | "CARD" | "PHONE" | "NATID";

// OTHER and EXTIP are token-only: they never appear in the per-case `categories` toggle map.
// EXTIP is produced by the IP detector when maskPublicIps is on, so a public address stays
// distinguishable from an internal one in the token the model reads.
//
// PERSON is token-only: there is no local detector for it. It is minted solely from Presidio
// findings, which arrive as custom entities.
export type AnonTokenCategory = AnonCategory | "OTHER" | "EXTIP" | "PERSON";

// The single source of truth for every category assign() can mint. Declaring it as a
// Record<AnonTokenCategory, true> makes TypeScript reject any new union member that is not
// listed here — which is what stops a new category from silently failing to restore.
const TOKEN_CATEGORY_KEYS: Record<AnonTokenCategory, true> = {
  IP: true,
  EXTIP: true,
  EMAIL: true,
  USER: true,
  HOST: true,
  DOMAIN: true,
  PATH: true,
  CMD: true,
  REG: true,
  CARD: true,
  PHONE: true,
  NATID: true,
  PERSON: true,
  OTHER: true,
};

export const ALL_TOKEN_CATEGORIES = Object.keys(TOKEN_CATEGORY_KEYS) as readonly AnonTokenCategory[];

// Longest-first so no category can be shadowed by another that is a prefix of it.
const TOKEN_ALTERNATION = [...ALL_TOKEN_CATEGORIES].sort((a, b) => b.length - a.length).join("|");
const TOKEN_RE = new RegExp(`ANON_(?:${TOKEN_ALTERNATION})_\\d+`, "gi");

const READERS = tokenReaders(TOKEN_RE.source); // every reader takes the delimiter a token owns (#2992)
/** Every anonymization token in `text` replaced by `mark` — the token-neutral form of a text. */
export const neutralizeAnonTokens = (text: string, mark: string): string => READERS.replace(text, () => mark);
/** True when the whole string is a single token (a Presidio finding that fired on one). */
export const isAnonToken = (s: string): boolean => READERS.isToken(s);

export interface CustomEntity {
  value: string;
  category: AnonTokenCategory;
  match?: "pattern"; // #2946: a wildcard (any category) or a CIDR range (IP/EXTIP); absent = exact
}

export interface AnonPolicy {
  enabled: boolean;
  categories: Record<AnonCategory, boolean>;
  redactSecrets: boolean;
  // When true, PUBLIC addresses are tokenized as ANON_EXTIP_n as well. True on the AI wire
  // (nothing about an address is asked of the model, and restore() puts it back). False for
  // the redacted export, where the recipient needs adversary infrastructure to stay actionable.
  maskPublicIps: boolean;
}

// Known victim entities derived from the case, used for high-precision exact-match tokenizing
// of things regex can't reliably find (usernames, hostnames) and to decide which domains/UPNs
// are "internal" (tokenize) vs third-party/adversary (preserve).
export interface KnownEntities {
  hosts: string[]; // victim hostnames / FQDNs (longest-first)
  accounts: string[]; // DOMAIN\user or user@domain
  usernames?: string[]; // bare victim usernames (#1780) — replaced as whole words wherever they appear
  internalDomains: string[]; // AD/email domains to tokenize (lowercased, longest-first)
  custom?: CustomEntity[]; // analyst-added + auto-discovered exact-match entities (tokenized when enabled)
  // Values the analyst REMOVED from auto-discovery (lowercased). Never tokenized — even when a
  // pattern would match — so removing a false positive (e.g. a mis-matched path) actually stops it
  // being redacted. Checked at the single assign() chokepoint, so it covers every matcher.
  suppressed?: string[];
}

export interface Anonymizer {
  apply(text: string): string;
  restore(text: string): string;
  restoreDeep<T>(value: T): T;
  // The entities this anonymizer tokenized so far (across apply() calls), with their category —
  // used to feed OCR-discovered entities back into the case's auto-discovery list. Never includes
  // one-way secrets (those are redacted to a placeholder, not minted as a reversible token).
  discoveries(): CustomEntity[];
  // Every token this anonymizer minted, with the real value it stands for — the same map restore()
  // reads. Only "Preview what the AI will see" (#2531) asks for it, and only to mark the changes in
  // its own response; the real send never reads it. Never includes one-way secrets.
  pairs(): AnonPair[];
}

export interface AnonPair {
  readonly token: string;
  readonly value: string;
  readonly category: AnonTokenCategory;
}

export { SECRET_PLACEHOLDER };
export { israeliIdValid, luhnValid } from "./anonChecksums.js";

// RFC1918 + loopback + link-local + CGNAT = "internal/victim" IPv4s we tokenize as ANON_IP_n.
// A public IP is frequently adversary C2 — classification here is unchanged by maskPublicIps;
// it's the CALLER (anonIps in createAnonymizer) that decides whether a non-internal address is
// tokenized as ANON_EXTIP_n (AI wire) or left visible (redacted export), never this function.
export function isInternalIp(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if ([a, b, Number(m[3]), Number(m[4])].some((n) => n > 255)) return false;
  if (a === 10 || a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  return false;
}

// IPV4_RE is a DETECTOR, not a validator — \d{1,3} happily matches 999. Before treating a
// non-internal match as an address worth masking, require four in-range octets and exclude
// ranges that are never adversary infrastructure. This also spares the most common collision:
// four-part software version strings such as "1.0.0.0" still match the regex, so anything we
// can rule out structurally is worth ruling out.
export function isMaskableIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (nums[0] === 0) return false; // 0.0.0.0/8 "this network"
  if (nums[0] >= 224) return false; // 224/4 multicast, 240/4 reserved, 255.255.255.255 broadcast
  return true;
}

// NAT64 well-known prefix 64:ff9b::/96 (RFC 6052 §2.1). embeddedIpv4() deliberately does not
// cover this: it recognizes only the all-zero mapped (::ffff:0:0/96) and compatible (::/96)
// prefixes, so "64:ff9b::c000:201" parses as a perfectly well-formed literal whose first group
// is 0x0064 — outside 2000::/3 — and both isMaskableIpv6() and isInternalIpv6() said "no",
// leaving the address completely untouched. 64:ff9b::/96 is a real, allocated, routable prefix
// that appears wherever an IPv6-only network reaches IPv4, so "mask every IP on the wire" has to
// cover it.
//
// The embedded IPv4 is the last 32 bits, i.e. groups[6] and groups[7] — verified against
// expandIpv6Groups(), which zero-fills "::" in the middle: "64:ff9b::c000:201" expands to
// [0x0064, 0xff9b, 0, 0, 0, 0, 0xc000, 0x0201] → 192.0.2.1.
//
// Only the WELL-KNOWN /96 prefix is decoded. RFC 6052 also permits network-specific prefixes at
// /32…/64, where the embedded IPv4 straddles the u-octet at bits 64-71 and its position depends
// on a prefix length that is not recoverable from the address text, and RFC 8215 reserves
// 64:ff9b:1::/48 for local use with the same ambiguity. Guessing there would mint garbage
// tokens; those addresses fall through to the normal 2000::/3 test (which rejects them), same
// as before.
function nat64EmbeddedIpv4(groups: number[]): string | null {
  if (groups[0] !== 0x0064 || groups[1] !== 0xff9b) return null;
  if (groups[2] !== 0 || groups[3] !== 0 || groups[4] !== 0 || groups[5] !== 0) return null;
  return [(groups[6] >> 8) & 0xff, groups[6] & 0xff, (groups[7] >> 8) & 0xff, groups[7] & 0xff].join(".");
}

// IPv6: loopback, unique-local (fc00::/7), link-local (fe80::/10), IPv4-mapped/compatible
// (::ffff:x.x.x.x or its hex-canonicalized form). As with isInternalIp(), classification here is
// unchanged by maskPublicIps — the caller decides whether a non-internal address becomes
// ANON_EXTIP_n or stays visible. The mapped/compatible check delegates extraction to iocValue.ts's
// embeddedIpv4() rather than re-deriving it here: a naive dotted-decimal-only regex misses the
// hex-canonical spelling (e.g. "::ffff:127.0.0.1" as "::ffff:7f00:1") — a check that only
// recognizes the dotted form would let a victim's internal IPv6 address in that spelling reach
// the external AI provider unredacted. Classification uses the local isInternalIp() —
// iocValue.ts's isPrivateIpv4 now agrees on CGNAT too, but the two tables serve different
// callers and each is pinned by its own tests.
export function isInternalIpv6(ip: string): boolean {
  const lower = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (lower === "::1" || lower === "::") return true;
  // Unique-local fc00::/7 is a first 16-bit group of fc00-fdff: always four hex digits. A shorter
  // "fd"/"fc" first group (0x00fd) is not one — that is a fingerprint or EUI-64 byte run (#2959).
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;
  // Link-local fe80::/10 is a first group of fe80-febf: four hex digits too ("fe8" is 0x0fe8, #2966).
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;
  const mapped = embeddedIpv4(lower);
  if (mapped && isInternalIp(mapped)) return true;
  // Mirror the NAT64 branch in isMaskableIpv6() so an INTERNAL destination behind the well-known
  // prefix fails CLOSED (ANON_IP_n) rather than being judged as external.
  const groups = expandIpv6Groups(lower);
  const nat64 = groups ? nat64EmbeddedIpv4(groups) : null;
  if (nat64 && isInternalIp(nat64)) return true;
  return false;
}

// The IPv6 counterpart of isMaskableIpv4(), and for the same reason: IPV6_RE is a DETECTOR, not a
// validator. It fires on any "::" followed by hex, so ordinary text is full of matches that are
// syntactically legal IPv6 literals but are not addresses at all — "[Convert]::FromBase64String"
// yields "::F", "std::cout" yields "::c", "WIN11::admin" yields "11::ad".
//
// While public addresses were PRESERVED this was harmless (a junk match was left alone), but once
// they are tokenized every false positive is destructive: it mints a garbage ANON_EXTIP_n, that
// garbage is persisted into the case's auto-discovery store, and — because a reserved literal is
// hidden from every other pass (see reserveIpv6Literals) — it blinds the encoded-command, host,
// account, email, path, domain and custom detectors over the span it swallowed.
//
// So a non-internal match is only worth masking when it is a real, routable IPv6 address:
//   - 2000::/3 — the entire globally-routable unicast space. Adversary infrastructure lives here
//     (as does 2001:db8::/32 documentation space, which tests and sanitized reports use).
//   - an IPv4-mapped/compatible address whose embedded IPv4 is itself maskable, judged by
//     isMaskableIpv4 so the two families cannot disagree.
// Everything else (::F, ::a, 11::ad, abc::def, fe00::…) is left completely untouched — not
// reserved, not tokenized — so the pass that actually owns that text still gets to see it.
// Internal/victim addresses are NOT routed through here: isInternalIpv6() decides those, and they
// always fail CLOSED regardless of how odd the surrounding text looks.
export function isMaskableIpv6(ip: string): boolean {
  const lower = ip.toLowerCase().replace(/^\[|\]$/g, "");
  const mapped = embeddedIpv4(lower);
  if (mapped) return isMaskableIpv4(mapped);
  const groups = expandIpv6Groups(lower);
  if (!groups) return false; // not a well-formed IPv6 literal
  const nat64 = nat64EmbeddedIpv4(groups);
  if (nat64) return isMaskableIpv4(nat64); // NAT64 64:ff9b::/96 — judge by the embedded IPv4
  return groups[0] >= 0x2000 && groups[0] <= 0x3fff; // 2000::/3 global unicast
}

// IPV6_RE and its scan live in anonIpv6Scan.ts. An internal address fails closed even glued to a
// word; a routable one is masked unless it starts inside a word with an internal one inside (#2953).
function ipv6Grade(ip: string): Ipv6Grade {
  if (isInternalIpv6(ip)) return "keep";
  return isMaskableIpv6(ip) ? "weak" : null;
}

// Shared by the set-aside, the secret/custom pass (#2952) and the preview's leak hint (#2958), so all
// agree on what an address is; false positives stay put, a glued or "::"-ended one is found (#2953).
// `maskPublicIps` lets a public address after a label run into a word (#2971, #2974); every caller
// passes its policy's value, so the passes still agree.
export function findReservableIpv6Spans(text: string, maskPublicIps = false): Ipv6Span[] {
  return findIpv6Literals(text, ipv6Grade, {
    splitUnknown: true,
    wholeToken: false,
    publicRunsOn: maskPublicIps,
  });
}

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

export function createAnonymizer(
  policy: AnonPolicy,
  known: KnownEntities,
  seed: readonly AnonPair[] = [], // Watson D6: earlier sends' pairs keep their tokens; new ones number above
  identity: readonly AnonPair[] = [], // #2657: the case's saved map — which token, never whether to mask
): Anonymizer {
  const keyOf = (p: AnonPair) => anonPairKey(p.category, p.value);
  const toToken = new Map(seed.map((p) => [keyOf(p), p.token])); // CAT:real
  const toReal = new Map(seed.map((p) => [p.token, p.value])); // token (UPPER) -> real value
  const savedByKey = new Map(identity.map((p) => [keyOf(p), p.token]));
  const saved = new Set(identity.map((p) => p.token));
  const counters: Record<string, number> = {};
  for (const p of [...seed, ...identity])
    counters[p.category] = Math.max(counters[p.category] ?? 0, +p.token.split("_")[2]);
  const reserved = new Set<string>(); // token-shaped literals seen in the input — never minted (#2569)
  // Values the analyst removed from auto-discovery — never tokenize them (leave as-is), even when
  // a pattern matches. The check sits in assign(), the single point every matcher funnels through.
  // A value that is ALSO a custom entity is not vetoed (#1822): custom is an explicit "hide this",
  // and the stricter choice wins. Without this, a stale "Leave visible" in another tab, or a removal
  // from the auto list, sent a name the analyst had hidden to the AI in clear.
  const hidden = new Set((known.custom ?? []).map((e) => e.value.toLowerCase()));
  const suppressed = new Set(
    (known.suppressed ?? []).map((s) => s.toLowerCase()).filter((s) => !hidden.has(s)),
  );

  const compiled = compileCustomEntities(known.custom ?? [], policy.maskPublicIps);
  let forceCustom = false; // true while a custom match mints: the explicit "hide this" beats a veto
  const ends = tokenEnds(TOKEN_RE.source, ALL_TOKEN_CATEGORIES); // a token a digit may follow gets a delimiter (#2992)
  const spelling = createInputSpelling(TOKEN_RE.source); // a composite keeps the input's spelling (#3058)
  function assign(category: AnonTokenCategory, raw: string): string {
    const real = spelling.expand(raw, (tok) => toReal.get(tok)); // #2991: no nesting
    if (!forceCustom && real === raw && suppressed.has(real.toLowerCase())) return real; // suppressed → keep the real value verbatim
    const key = anonPairKey(category, real);
    const existing = toToken.get(key);
    if (existing) return existing;
    const kept = savedByKey.get(key);
    if (kept && !toReal.has(kept)) return (toToken.set(key, kept), toReal.set(kept, real), kept);
    let token: string;
    do {
      counters[category] = (counters[category] ?? 0) + 1;
      token = `ANON_${category}_${counters[category]}`;
    } while (reserved.has(token));
    toToken.set(key, token);
    toReal.set(token, real);
    return token;
  }

  // Every (real value, category) this anonymizer minted a token for. Secrets never appear here —
  // redactSecretText() replaces them with a placeholder rather than calling assign().
  function discoveries(): CustomEntity[] {
    const out: CustomEntity[] = [];
    const seen = new Set<string>();
    for (const [token, real] of toReal) {
      const cat = catOf(token);
      const key = anonPairKey(cat, real);
      if (seen.has(key) || tails.unsaved(key)) continue; // a cut phone number is never saved (#2995)
      if (cutUsers.has(token) && !savedUsers.has(token)) continue; // a cut profile name or joined run (#3000)
      seen.add(key);
      out.push({ value: real, category: cat });
    }
    return out;
  }

  const catOf = (token: string) => (/^ANON_([A-Z]+)_\d+$/.exec(token)?.[1] ?? "OTHER") as AnonTokenCategory;
  function pairs(): AnonPair[] {
    return [...toReal].map(([token, value]) => ({ token, value, category: catOf(token) }));
  }

  // ── detectors (filled in across later tasks; order is fixed in apply()) ──
  function isInternalDomain(domain: string): boolean {
    const d = domain.toLowerCase();
    return known.internalDomains.some((kd) => d === kd || d.endsWith("." + kd));
  }
  // #1780: ONE person, ONE token. The USER token is keyed by the bare username, so CORP\jdoe,
  // jdoe@corp.example, /home/jdoe and a bare "jdoe" all read ANON_USER_n. The qualifier gets its
  // own token (HOST when it is a known machine, else DOMAIN), so every token restores to exactly one
  // real piece and restore() still round-trips. It is tokenized whatever the HOST/DOMAIN toggles say:
  // the USER pass always hid the whole account, and a visible "ANON_USER_1@corp.example" would be
  // swept up whole by the EMAIL pass — a token nested in a token, which restore() cannot undo.
  const learned = new Set<string>();
  let bareRe: ReturnType<typeof usernameMatcher> | undefined;
  function learn(name: string): void {
    const k = name.toLowerCase();
    if (isGuardedUsername(k) || learned.has(k) || suppressed.has(k)) return;
    learned.add(k);
    bareRe = undefined;
  }
  for (const n of known.usernames ?? []) learn(n);
  const oneWay = createOneWayCheck(policy.redactSecrets, learn); // holds a glued secret (#3003, #3006)
  const entityRules = {
    internal: isInternalDomain,
    fileUser: FILE_EXT_USER,
    addressAt: (v: string) =>
      policy.categories.IP ? (findReservableIpv6Spans(v, policy.maskPublicIps)[0]?.start ?? -1) : -1,
  }; // #3039
  const guard = (cat: AnonTokenCategory, v: string) => (oneWay(v) ? SECRET_SENTINEL : assign(cat, v));
  const knownHosts = new Set(known.hosts.map((h) => h.toLowerCase()));
  const qualifier = (q: string) => assign(knownHosts.has(q.toLowerCase()) ? "HOST" : "DOMAIN", q);
  const savedUsers = new Set<string>(); // USER tokens, by how they were minted
  const cutUsers = new Set<string>(); // masked in place, never saved: replaceUserPaths, joined runs (#3013)
  function userToken(user: string, saved = true): string {
    if (saved) learn(user);
    if (oneWay(user)) return SECRET_SENTINEL; // the qualifier keeps its own token
    const token = assign("USER", user);
    (saved && !isFragmentName(user) ? savedUsers : cutUsers).add(token); // "12", "ab": never saved (#3014, #3030)
    return token;
  }
  function accountToken(account: string): string {
    if (!forceCustom && suppressed.has(account.toLowerCase())) return account; // analyst veto
    // A registry hive, Windows principal, tactic folder or Folder\file.exe is not a person: it keeps
    // its old single whole-value token and teaches the bare pass nothing ("evil.exe", "Execution").
    if (isLegacyNoiseAccount(account) || FILE_EXT_USER.test(bareUsername(account)))
      return guard("USER", account);
    const slash = account.lastIndexOf("\\");
    if (slash > 0) return `${qualifier(account.slice(0, slash))}\\${userHalfToken(account.slice(slash + 1))}`;
    const at = account.indexOf("@");
    if (at > 0) return `${userToken(account.slice(0, at))}@${qualifier(account.slice(at + 1))}`;
    return userToken(account);
  }
  const userHalfToken = (u: string) => sidUserToken(u, userToken, (sid) => assign("REG", sid));
  const qualifierToken = (q: string) =>
    toToken.get(anonPairKey(knownHosts.has(q.toLowerCase()) ? "HOST" : "DOMAIN", q));
  const deps = { userToken, qualifier, accountToken, qualifierToken, suppressed, savedUsers, cutUsers };
  const netbiosToken = createNetbiosToken(deps);
  function anonAccounts(t: string): string {
    // First an account whose qualifier or user a custom or saved value already tokenized (#3020).
    const rules = { tokens: toReal, suppressed, internal: isInternalDomain, fileUser: FILE_EXT_USER };
    const qualify = (real: string, raw: string) =>
      assign(knownHosts.has(real.toLowerCase()) ? "HOST" : "DOMAIN", raw);
    const user = (real: string, raw: string) =>
      raw === real ? userToken(real) : (learn(real), guard("USER", raw));
    const mint = { qualifier: qualify, user, whole: guard };
    let out = tokenQualifiedAccounts(t, { ...rules, email: policy.categories.EMAIL }, mint);
    out = replaceNetbiosAccounts(out, netbiosToken);
    // Only UPNs on an internal domain are AD accounts → USER. Others stay for the e-mail pass.
    return out.replace(UPN_SCAN, (m) => (isInternalDomain(m.split("@")[1] ?? "") ? accountToken(m) : m));
  }
  // Every learned username as a whole word, after HOST and DOMAIN have claimed their spans (so
  // "jdoe-laptop" is a host first). Guarded words (admin, test, root, …) are never learned.
  function anonBareUsernames(t: string): string {
    if (bareRe === undefined) bareRe = usernameMatcher(learned);
    return bareRe ? replaceBareNames(t, bareRe, suppressed, mintBareName) : t;
  }
  function mintBareName(m: string, joined?: string[]): string {
    for (const n of joined ?? []) userToken(n); // a run joining overlapping names is never saved; its names are (#3010)
    return joined ? userToken(m, false) : guard("USER", m);
  }
  // A secret in the local part hides the whole address (or an external domain would go out in clear); an
  // internal address the account pass read with a glued digit is still an account (#3050).
  function mintEmail(m: string, glued: boolean): string {
    const at = m.lastIndexOf("@");
    if (oneWay(m.slice(0, at))) return SECRET_SENTINEL;
    const account = glued && policy.categories.USER && isInternalDomain(m.slice(at + 1));
    return account ? accountToken(m) : assign("EMAIL", m);
  }
  function anonUserPaths(t: string): string {
    const carve = (name: string, saved: boolean) => {
      const out = carveProfileName(name, valuesIn, {
        real: (tok) => toReal.get(tok),
        cut: (p) => userToken(p, false),
      });
      return (out !== null && saved && userToken(name), out); // the whole old name stays saved (#3047)
    };
    return replaceUserPaths(t, userToken, carve);
  }
  const valuesIn = valuePasses(policy.categories, {
    ...{ CMD: anonEncodedCmd, REG: anonSids, IP: anonIpv4 },
    ...{ CARD: anonCards, PHONE: anonPhones, NATID: anonNatIds },
  });
  // Encoded command-line blobs: the base64 after PowerShell -e/-ec/-enc/-EncodedCommand and inside
  // FromBase64String('…'). Tokenize ONLY the blob — the verb + flag stay visible as tradecraft signal,
  // and victim data in the payload never reaches the wire. `=` padding is matched outside the class.
  const ENC_CMD_RE = /(?<![A-Za-z0-9])(-(?:e|ec|enc|encodedcommand)\s+)([A-Za-z0-9+\/_-]{16,}={0,2})/gi;
  const FROM_B64_RE = /(FromBase64String\(\s*["'])([A-Za-z0-9+\/_-]{16,}={0,2})(["'])/gi;
  function anonEncodedCmd(t: string): string {
    let out = t.replace(ENC_CMD_RE, (m, flag: string, blob: string, at: number, w: string) =>
      ends.ended(flag + assign("CMD", blob), flag + blob, at, at + m.length, w),
    );
    out = out.replace(FROM_B64_RE, (_m, a: string, blob: string, c: string) => a + assign("CMD", blob) + c);
    return out;
  }
  // Machine/domain-issued user SIDs (S-1-5-21-…-RID) are victim-identifying. Well-known SIDs
  // (S-1-5-18, S-1-5-19/20, S-1-5-32-*) lack the S-1-5-21 prefix and are preserved. A last number
  // of 11-13 digits is a RID with an IPv4 glued after it only when three dotted numbers follow, or
  // a saved address or phone value the custom pass masked already (#3048). Text glued after the RID
  // (`…-1001bob`) does not stop it (#3049).
  const SID_RE =
    /\bS-1-5-21(?:-\d{1,10}){3}-(?:\d{1,10}|\d{11,13}(?=(?:\.\d{1,3}){3}|(?:\.\d{1,3}){0,2}\.ANON_(?:IP|EXTIP|PHONE)_\d))(?!\d)/gi;
  function anonSids(t: string): string {
    return t.replace(SID_RE, (m) => assign("REG", m));
  }
  // Known hosts, then internal domains, longest first; overlapping values join one token (#3013).
  const knownOf = (on: boolean, list: string[], category: AnonTokenCategory): KnownValue[] =>
    on ? list.filter((v) => v.length >= 2).map((value) => ({ value, category })) : [];
  const knownValues = [
    ...knownOf(policy.categories.HOST, known.hosts, "HOST"),
    ...knownOf(policy.categories.DOMAIN, known.internalDomains, "DOMAIN"),
  ];
  const kept = (v: string) => suppressed.has(v.toLowerCase());
  function joinKnown(span: KnownValue, parts: KnownValue[]): string {
    for (const p of parts) assign(p.category, p.value); // the values it joined are saved, the run is not
    const lower = span.value.toLowerCase(); // ...unless the run is itself a known or already-minted value
    const run =
      !toToken.has(anonPairKey(span.category, span.value)) &&
      knownValues.every((v) => v.value.toLowerCase() !== lower);
    const token = assign(span.category, span.value);
    return (run && cutUsers.add(token), token);
  }
  // An IPv6 literal (especially an IPv4-mapped one like ::ffff:10.0.0.5) is an atomic lexical
  // unit: whatever text is embedded inside it must be classified and tokenized as ONE address,
  // never as a separately-matched substring. Every OTHER detector in apply() (anonCustom,
  // accounts, emails, paths, encoded commands, SIDs, hosts, domains) does word-boundary text
  // substitution and none of them know about IPv6 syntax — a known.custom IPv4 value (exactly
  // what pipeline.ts persists from auto-discovery and re-injects on the next call) or any other
  // pass that happens to substring-match inside "::ffff:10.0.0.5" would leave a mutated remnant
  // for IPV6_RE to (mis)parse when the real IP pass finally runs, corrupting the token. So an
  // IPv6 literal is pulled out and replaced with an inert placeholder BEFORE any other pass runs,
  // and only spliced back in — correctly classified via isInternalIpv6, exactly as if nothing had
  // run before it — right before the IPv4 pass. Placeholders are delimited by \uE000 so no other
  // detector's pattern can match one.
  //
  // Reservation is a BLINDFOLD: whatever it swallows becomes invisible to every later pass. So a
  // literal is reserved ONLY when this anonymizer would genuinely tokenize it — an internal/victim
  // address (isInternalIpv6, unconditionally, so it still fails CLOSED when it abuts trailing
  // text) or a real routable one (isMaskableIpv6). IPV6_RE's many false positives ("::F" out of
  // "[Convert]::FromBase64String(", "11::ad" out of "WIN11::admin", "::c" out of "std::cout") are
  // left in place verbatim, so the encoded-command / host / account / email / path / SID / domain /
  // custom passes still see the text they own. Reserving on the raw detector match with no
  // validator is what silently sent base64 payloads and hostnames to the wire in cleartext.
  const SECRET_SENTINEL = "\uE001";
  const SECRET_SENTINEL_RE = /\uE001/g;
  const IPV6_SENTINEL = "\uE000";
  const IPV6_SENTINEL_RE = /\uE000/g;
  const IPV6_PLACEHOLDER_RE = /\uE000IPV6:(\d+)\uE000/g;

  // A custom value that extends past an address is set aside WITH it, as one span that carries
  // the custom category (#2950); anonCustom() mints it, so the custom value wins as one token.
  function reserveIpv6Literals(t: string): { text: string; literals: Reserved[] } {
    // Case text is ATTACKER-INFLUENCED, so a forged "\uE000IPV6:0\uE000" can arrive in the input. It is
    // stripped first: it must never index the literals table and make restore() invent an address.
    const text = t.replace(IPV6_SENTINEL_RE, "");
    const found = findReservableIpv6Spans(text, policy.maskPublicIps);
    if (found.length === 0) return { text, literals: [] };
    const literals: Reserved[] = [];
    let out = "";
    let at = 0;
    for (const s of groupAsRead(found, (read) => groupWithLiterals(text, compiled, read))) {
      out += `${text.slice(at, s.start)}${IPV6_SENTINEL}IPV6:${literals.length}${IPV6_SENTINEL}`;
      literals.push({ value: text.slice(s.start, s.end), category: s.category, ...s.flags });
      at = s.end;
    }
    return { text: out + text.slice(at), literals };
  }

  // The dotted IPv4 tail after an address, cut or glued, joins late (#2990, #2995): anonTailJoin.ts.
  const tails = createTailJoiner({
    ...{ assign, forcing, mintCustom, ended: ends.ended, real: (tok) => toReal.get(tok), ipv4Category },
    ...{ suppressed, base: ipv6Base },
    crossers: () => (policy.categories.PHONE ? [PHONE_IL, PHONE_NANP] : []),
    range: (read) => rangeCategory(compiled, read), // #2946: a custom range names it
  });
  function ipv6Base(ip: string): AnonTokenCategory | null {
    return isInternalIpv6(ip) ? "IP" : policy.maskPublicIps ? "EXTIP" : null;
  }
  function ipv4Category(ip: string): AnonTokenCategory | null {
    if (isInternalIp(ip)) return "IP";
    return policy.maskPublicIps && isMaskableIpv4(ip) ? "EXTIP" : null;
  }

  function anonIpv4(t: string): string {
    const mask = (ip: string, m: string, cat = ipv4Category(ip)) => (cat ? assign(cat, m) : m);
    const plain = tails.gluedRaw(t).replace(IPV4_RE, (ip) => mask(ip, ip));
    return replaceGluedIpv4(plain, isInternalIp, mask); // an address with digits glued on (#3058)
  }

  function anonCards(t: string): string {
    return replaceCards(t, (m) => assign("CARD", m)); // prefix + Luhn; a glued digit too (#3058)
  }

  // E.164 runs first: it is the most specific, and an international number has no leading zero
  // for the Israeli pattern to latch onto.
  function anonPhones(t: string): string {
    let out = t.replace(PHONE_E164, (m) => assign("PHONE", m));
    out = out.replace(PHONE_IL, (m) => assign("PHONE", m));
    out = out.replace(PHONE_NANP, (m) => assign("PHONE", m));
    return out;
  }

  // KNOWN LIMITATION: roughly one in ten arbitrary nine-digit numbers passes the check digit, and
  // a Teudat Zehut has no other structure to filter on. In a case with no Israeli PII this WILL
  // tokenize the occasional file offset or sequence number. Two escape hatches exist: untick the
  // NATID category for the case, or add the specific value to the suppressed list, which is
  // honoured at the assign() chokepoint.
  function anonNatIds(t: string): string {
    return t.replace(NATID_RE, (m) => (israeliIdValid(m) ? assign("NATID", m) : m));
  }

  // Exact values, wildcard patterns and IPv4 ranges in ONE pass over the text (anonCustomSpans.ts).
  // An EXTIP entry is skipped there when maskPublicIps is off: the redacted export keeps adversary
  // infrastructure visible, so a screenshot-discovered public IP must not be re-hidden by value.
  // A custom group set aside with an IPv6 address (#2950) is minted here too: the custom pass's place.
  function anonCustom(t: string, literals: readonly Reserved[]): string {
    const spans = growSpansToKnown(t, findCustomSpans(t, compiled), knownValues, kept); // #3058
    const mark = (c: AnonTokenCategory, m: string) => tails.mark(mintRaw(c, m), m); // #2995: joins late
    const out = spans.length === 0 ? t : forcing(() => spliceSpans(t, spans, mark));
    return out.replace(IPV6_PLACEHOLDER_RE, (m, i: string, at: number, w: string) => {
      const e = literals[Number(i)]; // a group before a glued IPv4 is minted with it, late (#2995)
      if (!e?.category || gluedIpv4At(w, at + m.length)) return m;
      return ends.ended(tails.mark(mintCustom(e.category, e.value), e.value), e.value, at, at + m.length, w);
    });
  }
  function mintRaw(cat: AnonTokenCategory, m: string): string {
    return cat === "USER" ? accountToken(m) : guard(cat, m); // #2952: one way when it holds a secret
  }
  function mintCustom(cat: AnonTokenCategory, m: string): string {
    return forcing(() => mintRaw(cat, m));
  }
  function forcing<T>(fn: () => T): T {
    forceCustom = true;
    try {
      return fn();
    } finally {
      forceCustom = false;
    }
  }

  function apply(text: string): string {
    // A forged sentinel in attacker-influenced text must not turn into a placeholder at the end.
    let t = spelling.start(text.replace(SECRET_SENTINEL_RE, ""));
    ends.start(t, toReal);
    // A literal token in the input is never minted later, and one minted already is escaped (#2569).
    // A literal equal to a SAVED token is escaped too (#2657), or the saved value could adopt it.
    const scan = scanTokenLiterals(t, TOKEN_RE.source, (tok) => toReal.has(tok) || saved.has(tok), escapes);
    for (const lit of scan.literals) reserved.add(lit);
    t = scan.text;
    // One-way secrets go before anything is tokenized or set aside, so a secret that is also a
    // known or custom entity never becomes a reversible token (restore() and discoveries() would
    // hand it back), and the redactor sees every secret in its full context — a key outside a
    // custom group and the credential inside it (#2950). The placeholder then hides behind a
    // sentinel until the last pass, so no tokenizer rewrites it. A custom value that overlaps a
    // secret is redacted with it, whole and one way (#2952), so the secret, custom and IPv6 passes
    // must see one text: a forged IPv6 sentinel goes first, with or without the IP category — the
    // custom pass skips a match beside one.
    t = t.replace(IPV6_SENTINEL_RE, "");
    if (policy.redactSecrets) {
      const spans = () => (policy.categories.IP ? findReservableIpv6Spans(t, policy.maskPublicIps) : []);
      const red = redactSecretsWithCustom(t, compiled, SECRET_SENTINEL, spans);
      learnRedactedEntities(t, red, SECRET_SENTINEL, entityRules, (n) =>
        oneWay(n) ? oneWay.claim(n) : learn(n),
      );
      t = growGluedRemnants(t, red, { remember: oneWay.claim, compiled });
    }
    // Then reserve IPv6 literals — before anonCustom or any other pass — so nothing can substitute
    // inside one. Only when IP masking is active: if the IP category is off, no later step ever
    // reparses an IPv6 literal, so there is nothing to protect it FROM. A custom value that extends
    // past an address is reserved with it as one group (#2950).
    let ipv6Literals: Reserved[] = [];
    if (policy.categories.IP) {
      const reserved = reserveIpv6Literals(t);
      t = reserved.text;
      ipv6Literals = reserved.literals;
    }
    t = anonCustom(t, ipv6Literals); // analyst-added entities win over every detector
    // UNC server names before accounts, or \\DC-QA-01\C$ reads as an account (#2073).
    if (policy.categories.HOST) t = replaceUncServers(t, (s) => assign("HOST", s));
    if (policy.categories.USER) t = anonAccounts(t);
    if (policy.categories.EMAIL) t = replaceEmails(t, mintEmail, ends.ended);
    if (policy.categories.PATH) t = anonUserPaths(t);
    if (policy.categories.CMD) t = anonEncodedCmd(t);
    if (policy.categories.REG) t = anonSids(t);
    t = replaceKnownValues(t, knownValues, (v) => assign(v.category, v.value), joinKnown, kept);
    if (policy.categories.USER) t = anonBareUsernames(t);
    t = tails.joinMarked(t); // a custom value that ends in an address head takes its intact tail (#2995)
    if (policy.categories.IP) {
      t = tails.restore(t, ipv6Literals); // classify + tokenize the reserved literals
      t = anonIpv4(t); // then any standalone (non-embedded) IPv4 address
    }
    if (policy.categories.CARD) t = anonCards(t);
    if (policy.categories.PHONE) t = anonPhones(t);
    if (policy.categories.NATID) t = anonNatIds(t);
    t = ends.finish(t, toReal);
    return t.replace(SECRET_SENTINEL_RE, SECRET_PLACEHOLDER);
  }

  const escapes = literalEscapes(TOKEN_RE.source); // restore() undoes apply()'s escapes; restore ONCE (#3001)
  function restore(text: string): string {
    return escapes.restore(text, READERS, (tok) => toReal.get(tok));
  }

  function restoreDeep<T>(value: T): T {
    if (typeof value === "string") return restore(value) as unknown as T;
    if (Array.isArray(value)) return value.map((v) => restoreDeep(v)) as unknown as T;
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = restoreDeep(v);
      return out as unknown as T;
    }
    return value;
  }

  return { apply, restore, restoreDeep, discoveries, pairs };
}

// The noise vocabulary (registry hives, Windows principals, ATT&CK tactic folders, generic words)
// lives beside the username guard list in anonUsernames.ts; re-exported for existing importers.
export { NON_VICTIM_DOMAINS, isNoiseDomain, isNoiseAccount } from "./anonUsernames.js";

// Special-use / private-namespace TLDs (RFC 6761/6762 plus the conventional enterprise ones).
// A host under one of these is never routable adversary infrastructure, so a domain/url IOC on
// one is victim internal naming — the only IOC shape deriveKnownEntities can safely tokenize.
export const INTERNAL_TLDS: ReadonlySet<string> = new Set([
  "local",
  "localdomain",
  "internal",
  "intranet",
  "lan",
  "corp",
  "home",
  "arpa",
  "private",
]);
function hasInternalTld(host: string): boolean {
  const tld = host.slice(host.lastIndexOf(".") + 1);
  return INTERNAL_TLDS.has(tld);
}

export function isVictimSideHost(host: string, internalDomains: Iterable<string>): boolean {
  return hasInternalTld(host) || [...internalDomains].some((d) => host === d || host.endsWith("." + d));
}

// An IP literal (IPv4, IPv6, bracketed, IPv4-mapped) has no parent domain: "203.0.113.10" must not
// yield "0.113.10" as an internal domain (#2624). The IP itself still stays in hosts.
function isIpLiteralHost(h: string): boolean {
  return isIP(h.replace(/^\[|\]$/g, "")) !== 0;
}

// Derive the victim entities to tokenize from the case state: hosts (event.asset), accounts
// (DOMAIN\user / UPN in event text) and the internal domains those imply (NETBIOS name, UPN
// domain, and the parent domain of any FQDN host). Pure + deterministic. Noise accounts/domains
// (registry hives, Windows principals, ATT&CK tactic folders, generic words) are filtered out so
// they neither pollute the analyst's list nor get tokenized as common words across the timeline.
export function deriveKnownEntities(state: InvestigationState): KnownEntities {
  const hosts = new Set<string>();
  const accounts = new Set<string>();
  const internalDomains = new Set<string>();
  for (const e of state.forensicTimeline) {
    if (e.asset && e.asset.trim()) hosts.add(e.asset.trim());
    for (const acct of learnableAccounts(e.description)) {
      if (isNoiseAccount(acct)) continue; // registry hive / Windows principal / tactic folder, not a victim account
      accounts.add(acct);
      if (acct.includes("\\")) internalDomains.add(acct.split("\\")[0]);
      else if (acct.includes("@")) internalDomains.add(acct.split("@")[1]);
    }
  }
  for (const h of hosts) {
    const i = h.indexOf(".");
    if (i > 0 && !isIpLiteralHost(h)) internalDomains.add(h.slice(i + 1)); // FQDN → parent domain is internal
  }
  // Also scan IOCs for victim FQDNs. The redacted-export anonymizer is built from this set; a
  // victim internal AD domain that appears ONLY as an IOC value (e.g. dc01.globaltech.local as
  // IOC ioc013) never contributed its parent (globaltech.local) to internalDomains, so the
  // anonymizer's anonDomains had no entry and left it unredacted in the export.
  //
  // But most domain/url IOCs are ADVERSARY infrastructure, and this whole module preserves those
  // on purpose (see the public-IP note above: a redacted export is still shareable threat intel —
  // tokenizing the C2 is what makes it worthless to the recipient). So only take an IOC host we
  // can show is victim-side: one on a special-use/internal TLD that can never be reachable
  // adversary infrastructure, or one already under a domain the accounts/assets pass established
  // as internal. Everything else — c2.evil-apt.com, payload.badguys.net — stays in cleartext.
  for (const ioc of state.iocs) {
    if (ioc.type !== "domain" && ioc.type !== "url" && ioc.type !== "other") continue;
    const raw = ioc.value.trim().toLowerCase();
    if (!raw) continue;
    let host = raw;
    if (ioc.type === "url") {
      try {
        host = new URL(raw).hostname;
      } catch {
        host = raw;
      }
    }
    if (!host || !host.includes(".")) continue;
    if (isNoiseDomain(host) || isIpLiteralHost(host)) continue;
    const parent = host.slice(host.indexOf(".") + 1);
    if (!isVictimSideHost(host, internalDomains)) continue;
    hosts.add(host);
    if (!isNoiseDomain(parent)) internalDomains.add(parent);
  }
  const byLenDesc = (a: string, b: string) => b.length - a.length || a.localeCompare(b);
  const domains = [...internalDomains]
    .map((d) => d.toLowerCase())
    .filter((d) => !/^[\d.]+$/.test(d)) // an all-numeric dotted "domain" is an IP fragment (#2624)
    .filter((d) => !isNoiseDomain(d)) // belt-and-suspenders: also drops noisy FQDN-parent labels (dc.local → "local")
    .sort(byLenDesc);
  // #1780: every victim username the case names in a qualified shape, from the timeline AND the
  // findings (AI prose is where a bare name most often follows a qualified one) and IOC values.
  const texts = [
    ...state.forensicTimeline.flatMap((e) => [e.description, e.path ?? ""]),
    ...state.findings.flatMap((f) => [f.title, f.description]),
    ...state.iocs.map((i) => i.value),
  ];
  const usernames = collectUsernames({ texts, accountsOf: learnableAccounts, internalDomains: domains });
  const allHosts = [...new Set([...hosts, ...shortHostLabels(hosts, domains)])];
  return { hosts: allHosts.sort(byLenDesc), accounts: [...accounts], usernames, internalDomains: domains };
}

// Moved to localAiProvider.ts; re-exported for existing importers.
export { isLocalAiProvider } from "./localAiProvider.js";
