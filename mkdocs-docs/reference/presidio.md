# Presidio & PII Masking

## What it is

The built-in anonymizer (see [AI Analysis → What the AI Sees](ai-analysis.md#what-the-ai-sees-anonymization)) tokenizes IPs, hostnames, usernames, domains, emails, paths, credit cards, phone numbers and national ID numbers with regular expressions. Regular expressions cannot find a **person's name** — there is no pattern for "this word is a name" — and that is the one gap this optional layer closes.

[Microsoft Presidio](https://microsoft.github.io/presidio/) is an open-source PII-detection engine. Point the Companion at a Presidio Analyzer container you run yourself, and it scans the text the Companion is about to send to an AI provider, flagging anything its NER model recognizes as PII. This is an **extra** detector layered on top of the built-in one, not a replacement for it — leave `DFIR_PRESIDIO_URL` unset and nothing changes.

## Ordering: Presidio only ever sees masked text

The built-in anonymizer always runs **first**. Presidio scans the *already-tokenized* text — the version with `ANON_HOST_1`, `ANON_USER_1` and so on already substituted in — so it reports only what the regex layer missed, principally names.

This still means Presidio receives the shape and content of your case: the timeline text, minus the values the built-in anonymizer already knows how to catch. **The Presidio URL must therefore be local** — a container on this machine or your own LAN, never a public/hosted endpoint. The Settings panel warns when the configured URL doesn't look like `localhost` / `127.0.0.1` / `::1` / `0.0.0.0`.

## Running the container

The Companion never starts, stops, or manages the container — that's yours to run:

```bash
docker run -d --name presidio-analyzer -p 5002:3000 mcr.microsoft.com/presidio-analyzer:latest
```

This exposes the analyzer's `/analyze` endpoint on `http://localhost:5002`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_PRESIDIO_URL` | _(unset)_ | Base URL of the Presidio Analyzer, e.g. `http://localhost:5002`. Empty/unset = the layer is off and every code path around it is skipped. |
| `DFIR_PRESIDIO_MIN_SCORE` | `0.6` | Confidence floor, 0–1. A blank or non-numeric value falls back to the default; anything outside `[0, 1]` is clamped rather than rejected. |

Both are also editable in **Settings → AI → Presidio**, alongside a **Test connection** button: it sends a fixed, synthetic sample string (never anything from your case) through the currently-typed URL and shows the raw findings Presidio returns — entity type, matched value, and score — unfiltered by the confidence floor. That raw list is the practical way to decide where to set `DFIR_PRESIDIO_MIN_SCORE`.

## The approval flow

The first time an AI call reaches a value Presidio has flagged that this case has not seen before, the call does **not** go out. What happens next depends on how the call was triggered:

- **Interactive calls** — Ask, summaries, explain-event, remediation plans, and similar on-demand actions — fail with **HTTP 409**, and the dashboard immediately opens the anonymization panel's approval list so you can resolve it right there.
- **Imports** (CSV/log) are fire-and-forget: the request already answered `202` before the AI work runs in the background, so there is no synchronous 409 to catch. Instead, the whole import is scanned by Presidio **once, up front** (not once per internal batch, so a large file produces a single approval round trip rather than one per chunk), the pending findings are written to the case's state store, the background failure is broadcast as an AI-status error, and the dashboard reloads the approval panel from that store. If the import was too large to scan in full, the truncated byte count is logged rather than the scan silently passing as complete.

Either way, the panel lists each flagged value with two buttons:

- **Approve** — the value joins the case's known entities. From then on it is tokenized like anything else the built-in anonymizer catches, and it is never asked about again.
- **Not PII** — the value joins the suppression list instead. It is never tokenized and never asked about again — but note this only means an analyst judged it a false positive here, not that it's guaranteed harmless elsewhere.

Once every flagged value is resolved, re-run the action (or re-import the file) and it proceeds.

## Tuning

- Getting flagged constantly on things that aren't PII? Raise `DFIR_PRESIDIO_MIN_SCORE` — use the Test connection button's scores as a guide for where to set the floor for your data.
- One specific false positive, otherwise happy with the threshold? Use **Not PII** on that value rather than raising the global floor.

## Fail-closed behaviour

With `DFIR_PRESIDIO_URL` set but the container unreachable (not started, wrong port, network issue), **AI calls fail** with an explicit error naming the URL and telling you to start the container or clear the variable — they do not silently proceed as if Presidio had found nothing. An analyst who turned this on is trusting that names are being caught; silently skipping the scan would violate that trust.

To disable the layer, clear `DFIR_PRESIDIO_URL`.

## What Presidio detects, and what's deliberately ignored

Findings are mapped through a **strict allow-list** — an entity type not in this table is dropped outright, never swept into a generic catch-all:

| Presidio entity | Becomes |
|---|---|
| `PERSON` | `ANON_PERSON_n` |
| `CREDIT_CARD` | `ANON_CARD_n` |
| `PHONE_NUMBER` | `ANON_PHONE_n` |
| `EMAIL_ADDRESS` | `ANON_EMAIL_n` |
| `US_SSN`, `IL_ID`, `UK_NINO`, `ES_NIF`, `IT_FISCAL_CODE`, `AU_TFN`, `SG_NRIC_FIN` | `ANON_NATID_n` (folded into the same national-ID category as the built-in Teudat Zehut detector) |
| `IBAN_CODE` | `ANON_OTHER_n` |

**Deliberately dropped, on purpose:** `DATE_TIME`, `LOCATION`, `URL`, `NRP`, and anything else Presidio's model tags that isn't in the table above. `DATE_TIME` is the reason this is an allow-list rather than a deny-list — a DFIR timeline is almost entirely timestamps, and mapping it would tokenize every event time in the case. `LOCATION` and `URL` are similarly destructive to forensic text, and `NRP` (nationality/religion/political-affiliation) isn't a category this tool masks.

A finding that fires on an anonymization token itself (Presidio's NER occasionally tags something like `ANON_USER_1` as a name) is also discarded rather than re-tokenized.
