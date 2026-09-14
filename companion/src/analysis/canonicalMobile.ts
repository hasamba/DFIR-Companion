import { z } from "zod";

// The typed block a LEAPP row carries on its envelope (#932 item 18 — #988): the origin registry's
// reading of the row — which facets its own columns established, which column said so, what the
// registry could not cover. mobileOriginRegistry.ts writes it; the infection-window pass and the
// reports read it. Lives here (shared) so the envelope schema can name it without the shared
// layer importing the importer's registry.
export const ACQUISITIONS = [
  "recorded-on-this-device",
  "synced-from-another-device",
  "synced",
  "received",
  "from-store-account",
  "not-established",
] as const;
export const LOCALITIES = ["device-local", "cloud", "not-established"] as const;
export const RECORD_TYPES = [
  "history",
  "tab",
  "notification",
  "account",
  "device",
  "app-inventory",
  "other",
] as const;
export const COVERAGES = [
  "schema-matches",
  "producer-verified",
  "headers-differ",
  "not-covered",
  "excluded",
] as const;

export const mobileBlockSchema = z.object({
  platform: z.enum(["ios", "android", "unknown"]),
  artifact: z.string(),
  registry: z.object({ version: z.string(), coverage: z.enum(COVERAGES), pinned: z.string().optional() }),
  facets: z.object({
    acquisition: z.enum(ACQUISITIONS),
    locality: z.enum(LOCALITIES),
    record: z.enum(RECORD_TYPES),
    authorship: z.enum(["established-by-field", "not-established"]),
    /** Chromium `Transition Type` as written — a navigation fact, not an author. */
    transition: z.string().optional(),
  }),
  /** Which column established each facet. */
  evidence: z.array(z.object({ facet: z.string(), column: z.string(), value: z.string() })),
  /** Two columns of one row that disagree: both said, nothing resolved. */
  conflicts: z.array(z.string()),
  device: z.object({ name: z.string(), id: z.string().optional() }).optional(),
  /** An app-inventory row's typed identity, from the registry's declared columns — what the infection window compares. */
  app: z.object({ package: z.string().optional(), sha256: z.string().optional() }).optional(),
  account: z.object({ name: z.string(), type: z.string().optional() }).optional(),
});
export type MobileBlock = z.infer<typeof mobileBlockSchema>;

export type MobileFacets = MobileBlock["facets"];
