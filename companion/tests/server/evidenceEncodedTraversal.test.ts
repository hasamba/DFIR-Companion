import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";

/**
 * #2173: GET /cases/:id/evidence/:file was only ever tested against plain bad names (`a..b.png`,
 * `bad@name.png`), never an ENCODED traversal payload. The route checks the already-decoded filename
 * against a strict allow-list and refuses "..", then reads through a case-scoped no-follow open — so
 * every payload below is refused today. These cases stop a future regression, such as loosening the
 * filename pattern to admit unicode names, from silently reopening a traversal.
 *
 * Three sentinel files sit outside the evidence folders: one at the cases root, one in the case
 * folder itself (not under screenshots/ or imports/), and one in an unrelated temp folder (the
 * /etc/passwd analogue). No response may ever contain any of them.
 */
const ROOT_SECRET = "ROOT-SENTINEL-not-evidence-2173";
const CASE_SECRET = "CASE-SENTINEL-not-evidence-2173";
const HOST_SECRET = "HOST-SENTINEL-not-evidence-2173";

let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-ev-enc-"));
  const store = new CaseStore(root);
  app = createApp(store, { stateStore: new StateStore(store) });
  await store.createCase({ caseId: "c1", name: "Case", investigator: "alice", aiProvider: null });
  await mkdir(store.importsDir("c1"), { recursive: true });
  await writeFile(join(store.importsDir("c1"), "0001_results.csv"), "a,b\n1,2\n");
  await writeFile(join(root, "SECRET.txt"), ROOT_SECRET);
  await writeFile(join(store.caseDir("c1"), "case-secret.txt"), CASE_SECRET);
  const outside = await mkdtemp(join(tmpdir(), "dfir-ev-enc-host-"));
  await writeFile(join(outside, "passwd"), HOST_SECRET);
});

function expectNoSecret(text: string): void {
  expect(text).not.toContain(ROOT_SECRET);
  expect(text).not.toContain(CASE_SECRET);
  expect(text).not.toContain(HOST_SECRET);
}

describe("GET /cases/:id/evidence/:file — encoded traversal payloads (#2173)", () => {
  it("serves real evidence, so the refusals below are meaningful", async () => {
    const res = await request(app).get("/cases/c1/evidence/0001_results.csv");
    expect(res.status).toBe(200);
    expect(res.text).toBe("a,b\n1,2\n");
  });

  // Each of these reaches the route; the decoded name fails the filename allow-list.
  it.each([
    ["encoded slash", "..%2F..%2Fetc%2Fpasswd"],
    ["encoded dots and slash, into the case folder", "%2e%2e%2fcase-secret.txt"],
    ["encoded dots and slash, to the cases root", "%2e%2e%2f%2e%2e%2fSECRET.txt"],
    ["double-encoded dots and slash", "%252e%252e%252fcase-secret.txt"],
    ["double-encoded slash", "..%252F..%252FSECRET.txt"],
    ["encoded backslash", "..%5C..%5CSECRET.txt"],
    ["fullwidth dots and solidus (unicode normalization)", "%EF%BC%8E%EF%BC%8E%EF%BC%8FSECRET.txt"],
    ["NUL byte before traversal", "%00..%2fSECRET.txt"],
  ])("refuses %s with 400 invalid evidence filename", async (_label, payload) => {
    const res = await request(app).get(`/cases/c1/evidence/${payload}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid evidence filename");
    expectNoSecret(res.text);
  });

  it("refuses an overlong UTF-8 dot sequence with 400", async () => {
    // Rejected before the route by the malformed-percent-encoding guard; only the status is
    // asserted so the test does not depend on which layer refuses it.
    const res = await request(app).get("/cases/c1/evidence/%C0%AE%C0%AE%2FSECRET.txt");
    expect(res.status).toBe(400);
    expectNoSecret(res.text);
  });

  it.each([
    ["bare encoded dots", "%2e%2e"],
    ["bare dots", ".."],
  ])("never serves a file for %s", async (_label, payload) => {
    // URL normalization drops a bare ".." segment before routing, so this lands on another path
    // (observed: 404). Either refusal is acceptable; serving anything is not.
    const res = await request(app).get(`/cases/c1/evidence/${payload}`);
    expect([400, 404]).toContain(res.status);
    expectNoSecret(res.text);
  });
});
