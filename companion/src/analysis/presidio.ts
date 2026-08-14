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

export const DEFAULT_PRESIDIO_MIN_SCORE = 0.6;

/**
 * Per-REQUEST budget for one /analyze call, not for a whole scan (a scan is chunked, and every
 * chunk gets a fresh budget).
 *
 * The old value was 10s, and what it failed to account for was QUEUEING, not raw analyzer speed.
 * The official image runs a SINGLE worker (WORKERS=1), so concurrent scans serialize and a request
 * spends most of its budget waiting for the ones ahead of it. Measured on the reference container:
 * a 50k-char chunk takes ~1.7s alone, and ~9.6s when five other scans are in flight — the same
 * request, 5.8x slower, landing right on the old 10s edge.
 *
 * That edge is where it turned into a collapse, because ABORTING A FETCH DOES NOT CANCEL THE
 * SERVER-SIDE WORK. Presidio keeps chewing on an abandoned request, so each retry queued behind
 * work nobody was waiting for any more, and the next attempt was slower than the last: four
 * attempts, four aborts, and — since this layer fails CLOSED — the whole AI stack down while the
 * container sat there healthy and idle-fast.
 *
 * 60s is ~6x the measured contended case and ~30x the idle one. Raise it with
 * DFIR_PRESIDIO_TIMEOUT_MS for a slow box or an analyzer shared between analysts; giving the
 * container more workers addresses the same problem from the other end.
 */
export const DEFAULT_PRESIDIO_TIMEOUT_MS = 60_000;

/**
 * Resolve DFIR_PRESIDIO_TIMEOUT_MS into a per-request budget, on the same terms as
 * resolvePresidioMinScore: an empty string (a compose file interpolating an unset variable) falls
 * back to the default rather than becoming `Number("")` → 0, which as a timeout would abort every
 * request before it started. Non-finite and non-positive values fall back too — a zero or negative
 * budget cannot express "wait less", only "always fail". There is deliberately no upper clamp: a
 * long scan on a slow box is the analyst's call, and capping it would reintroduce this same bug.
 */
export function resolvePresidioTimeoutMs(raw: string | undefined): number {
  const trimmed = (raw ?? "").trim();
  if (!trimmed) return DEFAULT_PRESIDIO_TIMEOUT_MS;
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_PRESIDIO_TIMEOUT_MS;
  return parsed;
}

/**
 * Resolve DFIR_PRESIDIO_MIN_SCORE into a usable threshold. Trims first and falls back to the
 * default on an EMPTY string, not just `undefined` — a compose file that interpolates an unset
 * variable (`DFIR_PRESIDIO_MIN_SCORE=${SOME_UNSET_VAR}`) hands the process an empty string, and
 * `Number("")` is `0`, which is finite. Treating that as "confidence threshold zero" would gate
 * the case on every finding of any score, however low. Also clamps to [0, 1]: Presidio scores are
 * a 0-1 confidence, so a value outside that range (typo, stray percentage) is nonsensical rather
 * than merely permissive/strict, and is clamped rather than silently accepted.
 */
export function resolvePresidioMinScore(raw: string | undefined): number {
  const trimmed = (raw ?? "").trim();
  if (!trimmed) return DEFAULT_PRESIDIO_MIN_SCORE;
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed)) return DEFAULT_PRESIDIO_MIN_SCORE;
  return Math.min(1, Math.max(0, parsed));
}

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

/**
 * A scan that ran out of budget, as opposed to one that could not reach the analyzer at all. Its
 * own type because the two need OPPOSITE advice — "start the container" is wrong and costly when
 * the container is up and merely busy — and a message string is too weak a thing to branch on.
 */
export class PresidioTimeoutError extends Error {
  constructor(
    readonly timeoutMs: number,
    readonly chars: number,
  ) {
    super(
      `timed out after ${timeoutMs}ms scanning ${chars} characters — Presidio is running but ` +
        `slower than the budget`,
    );
    this.name = "PresidioTimeoutError";
  }
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
    private readonly timeoutMs = DEFAULT_PRESIDIO_TIMEOUT_MS,
  ) {}

  async analyze(text: string): Promise<PresidioFinding[]> {
    const controller = new AbortController();
    // A bare abort() rejects the fetch with DOMException "This operation was aborted", which reads
    // as a dead container and says nothing about the budget that ran out — it cost a real debugging
    // session chasing a Presidio that was up and healthy the whole time. Abort with an explicit
    // reason instead: undici rejects with whatever is passed here, so the caller gets a typed
    // PresidioTimeoutError it can give the right advice for.
    const timer = setTimeout(
      () => controller.abort(new PresidioTimeoutError(this.timeoutMs, text.length)),
      this.timeoutMs,
    );
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
        if (typeof r.entity_type !== "string" || typeof r.start !== "number" || typeof r.end !== "number")
          return [];
        return [
          {
            entityType: r.entity_type,
            value: text.slice(r.start, r.end),
            score: typeof r.score === "number" ? r.score : 0,
          },
        ];
      });
    } finally {
      clearTimeout(timer);
    }
  }
}
