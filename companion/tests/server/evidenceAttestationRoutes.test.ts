import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { EvidenceAttestationStore } from "../../src/analysis/evidenceAttestationStore.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-evidence-attestation-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, {
    stateStore: new StateStore(cases),
    evidenceAttestationStore: new EvidenceAttestationStore(cases),
  });
});

describe("/cases/:id/evidence-attestations", () => {
  it("returns an empty list for a fresh case", async () => {
    const res = await request(app).get("/cases/c1/evidence-attestations");
    expect(res.status).toBe(200);
    expect(res.body.attestations).toEqual([]);
  });

  it("rejects an attestation with no reason", async () => {
    const res = await request(app).post("/cases/c1/evidence-attestations/execution").send({ reason: "" });
    expect(res.status).toBe(400);
  });

  it("rejects an unknown evidence class", async () => {
    const res = await request(app)
      .post("/cases/c1/evidence-attestations/not-a-real-class")
      .send({ reason: "x" });
    expect(res.status).toBe(400);
  });

  it("attests a class and reflects it in the list", async () => {
    const res = await request(app)
      .post("/cases/c1/evidence-attestations/execution")
      .send({ reason: "Reviewed the full Prefetch and Sysmon export against the window" });
    expect(res.status).toBe(200);
    expect(res.body.attestations).toHaveLength(1);
    expect(res.body.attestations[0].evidenceClass).toBe("execution");
    expect(res.body.attestations[0].reason).toBe(
      "Reviewed the full Prefetch and Sysmon export against the window",
    );
    expect(res.body.attestations[0].confirmedAt).toBeTruthy();
  });

  it("persists the attestation across requests", async () => {
    await request(app).post("/cases/c1/evidence-attestations/network").send({ reason: "Full PCAP reviewed" });
    const res = await request(app).get("/cases/c1/evidence-attestations");
    expect(res.body.attestations).toHaveLength(1);
    expect(res.body.attestations[0].evidenceClass).toBe("network");
  });

  it("revokes an attestation", async () => {
    await request(app)
      .post("/cases/c1/evidence-attestations/persistence")
      .send({ reason: "Registry reviewed" });
    const res = await request(app).delete("/cases/c1/evidence-attestations/persistence");
    expect(res.status).toBe(200);
    expect(res.body.attestations).toHaveLength(1);
    expect(res.body.attestations[0].revokedAt).toBeTruthy();
  });

  it("rejects an unknown evidence class on revoke too", async () => {
    const res = await request(app).delete("/cases/c1/evidence-attestations/not-a-real-class");
    expect(res.status).toBe(400);
  });
});
