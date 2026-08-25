import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";

// The dashboard's HTML is generated per request; its scripts and stylesheets are not. They were
// served with `Cache-Control: public, max-age=86400` and no version in the URL, so for a day after
// any change a browser paired TODAY'S markup with YESTERDAY'S script — controls on screen that no
// module wires and no rule styles. It looks exactly like a broken feature, an ordinary reload does
// not clear it, and it reaches every analyst who upgrades, not only whoever edited the file.

const app = async () => {
  setServerLogger(createConsoleLogger("info"));
  return createApp(new CaseStore(await mkdtemp(join(tmpdir(), "dfir-assets-"))), {});
};

describe("static client assets", () => {
  it("makes the browser revalidate rather than trust a stale copy for a day", async () => {
    const server = await app();
    for (const route of ["/js/dashboard-wizard-ai-step.js", "/css/dashboard-panels.css"]) {
      const res = await request(server).get(route);
      expect(res.status, `${route} is not served`).toBe(200);
      // "no-cache" is store-but-ask-first, NOT do-not-store: the ETag below turns an unchanged
      // asset into a bodiless 304, so freshness costs a round trip and no bytes.
      expect(res.headers["cache-control"], `${route} may be served stale`).toBe("no-cache");
      expect(res.headers.etag, `${route} has no ETag to revalidate against`).toBeTruthy();
    }
  });

  it("answers 304 when the browser already has the current bytes", async () => {
    const server = await app();
    const first = await request(server).get("/js/dashboard-wizard-ai-step.js");
    const again = await request(server)
      .get("/js/dashboard-wizard-ai-step.js")
      .set("If-None-Match", first.headers.etag);
    expect(again.status).toBe(304);
    expect(again.text ?? "").toBe("");
  });

  it("holds that policy for every whitelisted asset, not just the two above", async () => {
    const server = await app();
    const stale: string[] = [];
    for (const route of Object.keys(STATIC_ASSETS)) {
      const res = await request(server).get(route);
      if (res.status === 200 && res.headers["cache-control"] !== "no-cache") stale.push(route);
    }
    expect(stale, `assets a browser may serve stale: ${stale.join(", ")}`).toEqual([]);
  });
});
