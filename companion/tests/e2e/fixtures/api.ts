// Thin HTTP client for test setup. Specs use this instead of clicking through the UI so that a
// broken create-case wizard fails ONE spec (workflows/caseCreate.spec.ts, which drives the real
// UI) rather than every spec that happens to need a case. Setup failures then surface as an HTTP
// contract error with a status code, not as a selector timeout in an unrelated assertion.
//
// There is deliberately no createCase() helper here: the only spec that creates an empty case is
// caseCreate.spec.ts, and it must do so through the wizard. An API shortcut would sit unused, and
// the first person to reach for it would quietly bypass the one path that spec exists to cover.

import type { APIRequestContext } from "@playwright/test";

/**
 * Seed a fully populated case via POST /cases/seed-demo.
 *
 * Preferred over importing a fixture file: seedDemoCase() builds findings f001-f007, a timeline,
 * IOCs, key questions and next steps server-side with fixed timestamps, so every spec starts from
 * identical, realistic data with no AI call and no import round-trip.
 */
export async function seedDemoCase(baseUrl: string, caseId: string): Promise<string> {
  const res = await fetch(`${baseUrl}/cases/seed-demo`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ caseId, force: true }),
  });
  if (!res.ok) throw new Error(`seedDemoCase ${caseId} failed: ${res.status} ${await res.text()}`);
  return caseId;
}

/**
 * Turn AI on for a case via POST /cases/:id/ai-control.
 *
 * AI is off on every new case, the seeded demo case included, and every model-calling route
 * answers 409 `aiOff` while it is off (#2757). A spec that calls such a route turns AI on first,
 * for its own case only. The demoCase fixture deliberately does not: the off-by-default state is
 * itself under test (US-136 in workflows/analysis.spec.ts).
 */
export async function enableAi(request: APIRequestContext, caseId: string): Promise<void> {
  const res = await request.post(`/cases/${encodeURIComponent(caseId)}/ai-control`, {
    data: { enabled: true },
  });
  if (res.status() !== 200) throw new Error(`enableAi ${caseId} failed: ${res.status()} ${await res.text()}`);
  const body = (await res.json()) as { enabled?: boolean };
  if (body.enabled !== true) throw new Error(`enableAi ${caseId}: the case still reports AI off`);
}
