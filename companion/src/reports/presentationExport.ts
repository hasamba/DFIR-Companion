import { CSP_NONCE_PLACEHOLDER, withNonce } from "../http/securityHeaders.js";
import { readPublicAsset } from "../serverAssets.js";

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
