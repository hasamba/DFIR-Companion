import { test, expect } from "../fixtures/test.js";

// Covers: US-272
// (feature-user-stories.csv) — reversible anonymization of everything sent to the AI provider.
//
// This is the product's core OPSEC promise: with anonymization enabled, real hosts/IPs/users are
// tokenized (ANON_HOST_1, …) BEFORE any text leaves the box, and the analyst keeps reading real
// values. Until now no browser test could see the provider's side of the wire. The AI stub now
// records every request body it receives (tests/e2e/aiStub.ts) and serves the recording on a
// fixed loopback port — so the suite can assert what actually LEFT the application, not what the
// application claims it sent.
//
// The stub is reached directly at 127.0.0.1:4789: server-entry.ts pins that port precisely so
// specs can read the recorder without a discovery channel (the harness's /settings/env reads a
// .env file that deliberately does not exist).
//
// Anonymization is enabled EXPLICITLY through the same control the toolbar's Anon toggle drives.
// The server default is enabled:false — the first version of this spec assumed "on by default"
// and read its own assumption back as a leak. The recorder is shared by every parallel test, and
// the anon-off tests legitimately send seeded hostnames in the clear, so the assertions below are
// scoped to THIS case's requests, found by a marker word that anonymization leaves alone.

const STUB_DEBUG_URL = "http://127.0.0.1:4789/debug/requests";
// Not a hostname, IP, user or email — the tokenizer must pass it through, which is what makes it
// usable as the needle that finds this test's requests among everyone else's.
const MARKER = "zephyr-quilt-4471";

test("US-272: with anonymization on, the provider sees tokens; the analyst still sees real values", async ({
  page,
  demoCase,
}) => {
  // 1. Enable anonymization for this case — the POST the Anon toolbar toggle makes.
  const enabled = await page.request.post(`/cases/${demoCase}/anon-control`, {
    data: { enabled: true },
  });
  expect(enabled.status(), await enabled.text()).toBe(200);

  // 2. Plant a High event that pairs the marker with a REAL seeded hostname, so the request that
  //    carries the marker must have carried the hostname's position too.
  const planted = await page.request.post(`/cases/${demoCase}/events`, {
    data: {
      timestamp: "2026-05-22T15:00:00Z",
      description: `${MARKER} beacon from WKSTN-JSMITH`,
      severity: "High",
    },
  });
  expect(planted.status(), await planted.text()).toBe(201);

  // 3. One stubbed synthesis sends the case to the "provider".
  const synth = await page.request.post(`/cases/${demoCase}/synthesize`, { data: {} });
  expect(synth.status(), await synth.text()).toBe(200);

  // 4. Read the wire. Every request that carries the marker is one of ours, sent after the toggle.
  const res = await page.request.get(STUB_DEBUG_URL);
  expect(res.status(), "the stub's recorder must be reachable on its fixed port").toBe(200);
  const bodies = (await res.json()) as string[];
  const mine = bodies.filter((b) => b.includes(MARKER));
  expect(mine.length, "the planted event must have reached the provider").toBeGreaterThan(0);

  for (const body of mine) {
    // THE OPSEC CLAIM: the hostname that sat six words from the marker never crossed the wire…
    expect(
      body.includes("WKSTN-JSMITH"),
      "a request carried the real hostname in the clear — anonymization failed",
    ).toBe(false);
    // …and a token stands where it was. Absence alone could mean the event was dropped; the token
    // proves the same text WAS sent, transformed. (Verified live: the recorded prompt reads
    // "zephyr-quilt-4471 beacon from ANON_HOST_1".)
    expect(/ANON_(HOST|IP|EXTIP)/.test(body), "no anonymization token replaced the hostname").toBe(true);
  }

  // 5. The reversal half: the analyst-facing state still holds the REAL hostname, and no token
  //    ever surfaces to the analyst.
  const state = await page.request.get(`/cases/${demoCase}/state`);
  const stateText = await state.text();
  expect(stateText, "the dashboard side must keep real values").toContain("WKSTN-JSMITH");
  expect(stateText, "tokens must never surface to the analyst").not.toContain("ANON_HOST");
});
