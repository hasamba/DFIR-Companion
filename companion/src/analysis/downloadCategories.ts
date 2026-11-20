import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The bundled download-source category list (#2670), companion/data/hunt/download-categories.json:
 * a versioned category → domain map authored for this project. Read once and cached; a missing or
 * corrupt file yields an EMPTY list (every site then reads Unknown — never approved, never guessed).
 */
export interface DownloadCategories {
  version: string;
  categories: Record<string, string[]>;
}

const EMPTY: DownloadCategories = { version: "none", categories: {} };
let cached: DownloadCategories | null = null;

function candidates(): string[] {
  const out: string[] = [];
  try {
    out.push(fileURLToPath(new URL("../../data/hunt/download-categories.json", import.meta.url)));
  } catch {
    // import.meta.url unavailable — fall through to the execPath candidate
  }
  out.push(join(dirname(process.execPath), "data", "hunt", "download-categories.json"));
  return out;
}

function parse(raw: unknown): DownloadCategories | null {
  const r = raw as Partial<DownloadCategories> | null;
  if (!r || typeof r.version !== "string" || !r.categories || typeof r.categories !== "object") return null;
  const categories: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(r.categories))
    if (Array.isArray(v))
      categories[k] = v.filter((d): d is string => typeof d === "string").map((d) => d.toLowerCase());
  return { version: r.version, categories };
}

export function loadDownloadCategories(): DownloadCategories {
  if (cached) return cached;
  for (const p of candidates()) {
    try {
      const parsed = parse(JSON.parse(readFileSync(p, "utf8")));
      if (parsed) return (cached = parsed);
    } catch {
      // next candidate
    }
  }
  return (cached = EMPTY);
}

/** `dl.example.com` is under `example.com`; `notexample.com` is not. */
export function domainUnder(host: string, domain: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  const d = domain.toLowerCase().replace(/\.$/, "");
  return h === d || h.endsWith(`.${d}`);
}

/** The host of an http(s) URL, or null. */
export function urlHost(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u.hostname.toLowerCase() : null;
  } catch {
    return null;
  }
}

/** The categories a host falls in. */
export function categoriesOf(host: string, list: DownloadCategories): string[] {
  return Object.entries(list.categories)
    .filter(([, domains]) => domains.some((d) => domainUnder(host, d)))
    .map(([c]) => c);
}
