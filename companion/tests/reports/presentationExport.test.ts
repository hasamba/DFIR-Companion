import { describe, expect, it } from "vitest";
import { renderStandalonePresentation } from "../../src/reports/presentationExport.js";
import { CSP_NONCE_PLACEHOLDER } from "../../src/http/securityHeaders.js";

describe("renderStandalonePresentation", () => {
  it("embeds the sink guard and safely serializes adversarial deck fields", async () => {
    const payload = '</script><img src=x onerror="alert(1)">';
    const html = await renderStandalonePresentation({ title: payload }, "deck-nonce");

    expect(html).not.toContain('src="/js/safe-dom.js"');
    expect(html).toContain("installSafeDom");
    expect(html).toContain('nonce="deck-nonce"');
    expect(html).not.toContain(CSP_NONCE_PLACEHOLDER);
    expect(html).not.toContain(payload);
    expect(html).toContain("\\u003c/script>\\u003cimg");
  });
});
