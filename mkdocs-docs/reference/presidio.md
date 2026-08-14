# Presidio & PII Masking

## What it is

The built-in anonymizer (see [AI Analysis → What the AI Sees](ai-analysis.md#what-the-ai-sees-anonymization)) tokenizes IPs, hostnames, usernames, domains, emails, paths, credit cards, phone numbers and national ID numbers with regular expressions. Regular expressions cannot find a **person's name** — there is no pattern for "this word is a name" — and that is the largest of the three gaps this optional layer closes; the other two are national IDs outside the Israeli format the local detector validates, and IBANs (see [What the Anonymization panel shows](#what-the-anonymization-panel-shows)).

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
| `DFIR_PRESIDIO_TIMEOUT_MS` | `60000` | Budget for **one** `/analyze` request, not for a whole scan — scans are split into 50,000-character chunks and each chunk gets the full budget. Blank, non-numeric, zero or negative falls back to the default. |

The budget has to cover **queueing**, not just analysis. The official image runs a single worker (`WORKERS=1`), so concurrent scans serialize: measured on the stock container, a 50,000-character chunk takes ~1.7s on its own and ~9.6s with five other scans in flight — the same request, 5.8x slower. That is why the default is 60s rather than something close to the idle figure.

It also matters that aborting a scan does not stop it. An HTTP client giving up does not cancel the analyzer's work, so a scan that times out keeps occupying the worker — which is how a budget set too close to the idle time turns one slow moment into a run of failures. For that reason a timed-out scan is **not retried**: the retry would queue behind the scan just abandoned and be slower than the attempt before it, so the failure is surfaced on the first timeout rather than after four budgets. Other scan failures, such as a refused connection, are still retried — nothing was left running on the other end.

A timeout says it timed out, and deliberately does **not** claim the analyzer is reachable. The same budget expires whether the analyzer is merely busy or the connection is hanging — a wrong port, a black-holing firewall — and the client has no evidence either way, so the message names both possibilities instead of sending you to the wrong one.

Raise `DFIR_PRESIDIO_TIMEOUT_MS` if you run the analyzer on a slow box, share one between analysts, or see timeouts in the log. Giving the container more workers addresses the same problem from the other end.

Both are also editable in **Settings → AI → Presidio**, alongside a **Test connection** button. It sends a fixed, synthetic sample string (never anything from your case) to the currently-typed URL and reports **Connected** or **Failed** with the reason — nothing more. It answers only "can the Companion reach this analyzer", which is the question you have when you're setting the URL.

## What the Anonymization panel shows

The panel's category list ends with a **Real names (people)** row, because that category is the one no local detector can provide: `PERSON` tokens are minted only from Presidio findings. With `DFIR_PRESIDIO_URL` unset the row is greyed as *needs Presidio* and cannot be ticked — there is nothing to switch on. With the layer configured the row becomes a live, per-case switch reading *via Presidio*. A note under the list explains which masking depends on the layer, in the terms below.

**Turning the layer off for a case.** Unticking that row stops Presidio scanning for that case only, takes effect immediately, and needs no restart — `DFIR_PRESIDIO_URL` stays configured, so ticking it again resumes scanning. This is the switch to reach for when the analyzer is down, too slow, or flagging noise mid-investigation; clearing the URL instead would mean editing `.env` and restarting the server, and would throw away the configuration you want back. The trade is real and the panel says so: with the switch off, names, non-Israeli national IDs and IBANs reach the model unmasked and no approval gate fires. Everything else is still masked by the built-in patterns. Flipping it either way is recorded in the case activity log, so the case record shows when coverage changed.

Three kinds of PII are **only** ever found by Presidio, and go undetected without it:

| Undetected without Presidio | Why the built-in layer misses it |
|---|---|
| Real names | There is no pattern for "this word is a name" — `PERSON` has no local detector at all. |
| National IDs other than Israeli (US SSN, UK NINO, ES NIF, IT fiscal code, AU TFN, SG NRIC/FIN) | `NATID` is local, but its detector validates the Israeli Teudat Zehut check digit, so it only fires on Israeli IDs. |
| IBANs | No local detector; Presidio's `IBAN_CODE` findings are masked as `ANON_OTHER_n`. |

The eleven checkboxes above the names row are all built-in detectors and stay available either way. For **Credit cards**, **Phone numbers** and **Emails**, Presidio only adds recall on formats the local patterns miss (Luhn + issuer prefix; E.164, Israeli and separated NANP; the email regex) — it does not provide them, so switching Presidio off does not stop those values being masked.

Until Presidio is configured, a value you already know can be masked by adding it under **Custom entities** — a name with category `PERSON`, an IBAN or anything else with `OTHER`.

## The approval flow

The first time an AI call reaches a value Presidio has flagged that this case has not seen before, the call does **not** go out. What happens next depends on how the call was triggered:

- **Interactive calls** — Ask, summaries, explain-event, remediation plans, and similar on-demand actions — fail with **HTTP 409**, and the dashboard immediately opens the anonymization panel's approval list so you can resolve it right there.
- **Imports** (CSV/log) are fire-and-forget: the request already answered `202` before the AI work runs in the background, so there is no synchronous 409 to catch. Instead, the whole import is scanned by Presidio **once, up front** (not once per internal batch, so a large file produces a single approval round trip rather than one per chunk), the pending findings are written to the case's state store, the background failure is broadcast as an AI-status error, and the dashboard reloads the approval panel from that store. If the import was too large to scan in full, the truncated character count is logged rather than the scan silently passing as complete.

    That up-front scan covers **both halves of what each batch actually sends**: the imported file *and* the case-state summary (existing findings, open threads, recent timeline events, known IOCs) that is prepended to every batch prompt. One thing it cannot cover: an import runs in batches, and each batch merges its results back into the case before the next one, so batch 3's prompt carries a summary that batches 1 and 2 revised — text that did not exist when the up-front scan ran. Those revisions are model output derived from payload text that *was* scanned, and the next non-import AI call (Ask, synthesis, explain-event, screenshot analysis) scans its own prompt including the then-current summary, so anything genuinely new surfaces there. Scanning it any earlier would mean one approval round trip per batch, which is the behaviour the up-front scan exists to avoid.

Either way, the panel lists each flagged value with two buttons:

- **Hide from AI** — the value is added to the **Custom entities** list in the same Anonymization panel. From then on it is tokenized like anything else the built-in anonymizer catches, restored in the answer you see, and never asked about again. Because it lands in the custom list rather than the read-only auto-detected one, you can edit or remove it later like any entity you added by hand.
- **Leave visible — not PII** — the value joins the suppression list instead. It is never tokenized and never asked about again — but note this only means an analyst judged it a false positive here, not that it's guaranteed harmless elsewhere.

    Both buttons name what happens to the *value*, deliberately. An earlier pair labelled **Approve** / **Not PII** was ambiguous in the one direction that matters: the gate is holding an AI call, so "Approve" reads naturally as "approve the send" — the exact opposite of what it does.

Once every flagged value is resolved, re-run the action (or re-import the file) and it proceeds.

## Tuning

- Getting flagged constantly on things that aren't PII? Raise `DFIR_PRESIDIO_MIN_SCORE`. The default of `0.6` already sits above the scores Presidio gives its weakest guesses. Only findings whose entity type is on the allow-list above ever reach you, so the floor is about *confidence*, not about which kinds of PII are considered.
- One specific false positive, otherwise happy with the threshold? Use **Leave visible — not PII** on that value rather than raising the global floor.

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
