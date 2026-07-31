// Thin HTTP client for test setup. Specs use this instead of clicking through the UI so that a
// broken create-case wizard fails ONE spec (workflows/caseCreate.spec.ts, which drives the real
// UI) rather than every spec that happens to need a case. Setup failures then surface as an HTTP
// contract error with a status code, not as a selector timeout in an unrelated assertion.
//
// There is deliberately no createCase() helper here: the only spec that creates an empty case is
// caseCreate.spec.ts, and it must do so through the wizard. An API shortcut would sit unused, and
// the first person to reach for it would quietly bypass the one path that spec exists to cover.

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
