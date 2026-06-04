// CLI: look up one or more indicators in your YETI instance, using the same auth + search
// path the companion uses. Reads DFIR_YETI_URL / DFIR_YETI_KEY (and DFIR_YETI_CA /
// DFIR_YETI_INSECURE) from companion/.env — no need to paste the API key.
//
//   npm run yeti -- 43.134.22.100
//   npm run yeti -- 43.134.22.100 evil.com 9f86d0818...   (multiple, space-separated)
//   npx tsx scripts/yeti-lookup.ts 43.134.22.100
import { config as loadDotenv } from "dotenv";
loadDotenv();
import { YetiProvider } from "../src/enrichment/yeti.js";
import { buildTlsFetch } from "../src/enrichment/tlsFetch.js";
import type { IocKind } from "../src/enrichment/provider.js";

const values = process.argv.slice(2).filter(Boolean);
if (values.length === 0) {
  console.error("usage: npm run yeti -- <indicator> [<indicator> ...]\n       e.g. npm run yeti -- 43.134.22.100");
  process.exit(2);
}

const baseUrl = (process.env.DFIR_YETI_URL ?? "").trim();
const apiKey = (process.env.DFIR_YETI_KEY ?? "").trim();
if (!baseUrl || !apiKey) {
  console.error("DFIR_YETI_URL and DFIR_YETI_KEY must be set in companion/.env");
  process.exit(2);
}

// Best-effort kind detection (YETI searches by value, so this only labels the output).
function guessKind(v: string): IocKind {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || v.includes(":") && /^[0-9a-f:]+$/i.test(v)) return "ip";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return "hash";
  if (/^[a-z]+:\/\//i.test(v)) return "url";
  if (/\.[a-z]{2,}$/i.test(v)) return "domain";
  return "hash";
}

const fetchFn = buildTlsFetch({
  caCertPath: process.env.DFIR_YETI_CA,
  insecureSkipVerify: /^(1|true|yes|on)$/i.test(process.env.DFIR_YETI_INSECURE ?? ""),
});
const yeti = new YetiProvider({ baseUrl, apiKey, fetchFn });

console.log(`YETI: ${baseUrl}\n`);
for (const value of values) {
  const kind = guessKind(value);
  try {
    const r = await yeti.lookup(kind, value);
    if (!r) { console.log(`  ✗ ${value}  [${kind}]  not found in YETI`); continue; }
    console.log(`  ✓ ${value}  [${kind}]  ${r.verdict.toUpperCase()}`);
    if (r.score) console.log(`      ${r.score}`);
    if (r.tags?.length) console.log(`      tags: ${r.tags.join(", ")}`);
    if (r.link) console.log(`      ${r.link}`);
  } catch (e) {
    console.log(`  ! ${value}  [${kind}]  ERROR: ${(e as Error).message}`);
  }
}
