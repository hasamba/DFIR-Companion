import { CSP_NONCE_PLACEHOLDER, withNonce } from "../http/securityHeaders.js";
import { readPublicAsset } from "../serverAssets.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { PresentationDeck } from "../analysis/presentation.js";
import { caseDomains } from "./defang.js";
import { defangDeck } from "./defangDeck.js";
import {
  checkEvidenceSafety,
  withEvidenceSafetyHtmlBanner,
  type EvidenceSafetyFinding,
} from "./evidenceSafety.js";

/** Build the presentation as one offline-safe file while retaining the live page's sink guard. */
export async function renderStandalonePresentation(deck: unknown, nonce: string): Promise<string> {
  const [template, safeDom] = await Promise.all([
    readPublicAsset("present.html", "utf8"),
    readPublicAsset("js/safe-dom.js", "utf8"),
  ]);
  const safeDomSource = safeDom.replace(/<\/script/gi, "<\\/script");
  const safeJson = JSON.stringify(deck).replace(/</g, "\\u003c");
  const embedded = template
    .replace(
      '<script src="/js/safe-dom.js"></script>',
      `<script nonce="${CSP_NONCE_PLACEHOLDER}">${safeDomSource}</script>`,
    )
    .replace(
      "<!--DECK_INJECT-->",
      `<script nonce="${CSP_NONCE_PLACEHOLDER}">window.__DECK__=${safeJson};</script>`,
    );
  return withNonce(embedded, nonce);
}

/**
 * The export boundary for the deck (#892, #1006): indicators are defanged HERE and not in the deck
 * builder — this file is handed to a stakeholder and opened from file:// with no CSP, while the
 * live viewer renders the same deck and must keep values an analyst can copy into a tool. The
 * case's own domain IOCs widen the bare-hostname pool (defangDeck.ts). Then the evidence-safety
 * check reads the finished file — the deck travels as a JSON embed, and a live indicator in it
 * appears verbatim there — and the warning is stamped in before the nonce is applied, so the
 * banner's style block gets one too.
 */
export async function renderStandalonePresentationChecked(
  state: InvestigationState,
  deck: PresentationDeck,
  nonce: string,
): Promise<{ html: string; evidenceSafety: EvidenceSafetyFinding[] }> {
  const html = await renderStandalonePresentation(
    defangDeck(deck, caseDomains(state)),
    CSP_NONCE_PLACEHOLDER,
  );
  const evidenceSafety = checkEvidenceSafety(state, html);
  return { html: withNonce(withEvidenceSafetyHtmlBanner(html, evidenceSafety), nonce), evidenceSafety };
}
