import { isAnonToken, type AnonTokenCategory, type CustomEntity } from "./anonymize.js";

// Optional Presidio layer. Presidio runs AFTER the local anonymizer, on already-masked text, so
// it only ever sees scrubbed data and reports only what the regex layer missed — principally
// people's names, which no regex can find. Findings are injected as custom entities and minted by
// the same assign() the rest of the anonymizer uses, so restoreDeep() un-masks them for free.
//
// The container is the ANALYST's to run. Nothing here starts, stops or manages it.

export interface PresidioFinding {
  value: string;
  entityType: string;
  score: number;
}

/** Injectable so tests never open a socket, mirroring OcrRunner in ocrRedact.ts. */
export interface PresidioClient {
  analyze(text: string): Promise<PresidioFinding[]>;
}

// A STRICT allow-list with no catch-all. DATE_TIME is the reason this is an allow-list rather
// than a deny-list: Presidio flags timestamps as PII, and a DFIR timeline is almost entirely
// timestamps — mapping it would tokenize every event time in the case. LOCATION, URL and NRP are
// similarly destructive here. Anything absent from this table is DROPPED, never swept into OTHER.
const ENTITY_MAP: Readonly<Record<string, AnonTokenCategory>> = {
  PERSON: "PERSON",
  CREDIT_CARD: "CARD",
  PHONE_NUMBER: "PHONE",
  EMAIL_ADDRESS: "EMAIL",
  IBAN_CODE: "OTHER",
  // National identifiers, all folded into NATID.
  US_SSN: "NATID",
  IL_ID: "NATID",
  UK_NINO: "NATID",
  ES_NIF: "NATID",
  IT_FISCAL_CODE: "NATID",
  AU_TFN: "NATID",
  SG_NRIC_FIN: "NATID",
};

/** Sample text for the Settings "Test connection" button. Entirely synthetic. */
export const PRESIDIO_SAMPLE_TEXT =
  "Jane Doe called +972501234567 from jane.doe@example.com about card 4111111111111111.";

/**
 * Filter and map raw Presidio findings into anonymizer custom entities.
 * Drops: below-threshold scores, unlisted entity types, blank values, and anything that fired on
 * an anonymization token (Presidio's NER can tag ANON_USER_1 as a PERSON or ORG).
 */
export function mapFindings(findings: PresidioFinding[], minScore: number): CustomEntity[] {
  const out: CustomEntity[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    if (!Number.isFinite(f.score) || f.score < minScore) continue;
    const category = ENTITY_MAP[f.entityType];
    if (!category) continue;
    const value = (f.value ?? "").trim();
    if (!value) continue;
    if (isAnonToken(value)) continue;
    const key = `${category}:${value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ value, category });
  }
  return out;
}

/** Thrown by the pipeline when Presidio surfaces values this case has not seen before. The route
 *  layer turns this into HTTP 409 so the dashboard can render an approval panel. */
export class PresidioApprovalRequired extends Error {
  constructor(public readonly findings: CustomEntity[]) {
    super(`Presidio found ${findings.length} new PII value(s) awaiting approval`);
    this.name = "PresidioApprovalRequired";
  }
}

/** Real client. Presidio's /analyze returns OFFSETS, not text, so values are sliced here. */
export class HttpPresidioClient implements PresidioClient {
  constructor(
    private readonly baseUrl: string,
    private readonly timeoutMs = 10_000,
  ) {}

  async analyze(text: string): Promise<PresidioFinding[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl.replace(/\/+$/, "")}/analyze`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text, language: "en" }),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`/analyze returned HTTP ${res.status}`);
      const raw: unknown = await res.json();
      if (!Array.isArray(raw)) throw new Error("/analyze returned a non-array response");
      return raw.flatMap((item) => {
        const r = item as { entity_type?: unknown; start?: unknown; end?: unknown; score?: unknown };
        if (typeof r.entity_type !== "string" || typeof r.start !== "number" || typeof r.end !== "number") return [];
        return [{
          entityType: r.entity_type,
          value: text.slice(r.start, r.end),
          score: typeof r.score === "number" ? r.score : 0,
        }];
      });
    } finally {
      clearTimeout(timer);
    }
  }
}
