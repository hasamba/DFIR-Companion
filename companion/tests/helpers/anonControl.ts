import request from "supertest";
import type { Express } from "express";

/**
 * POST /cases/:id/anon-control the way the dashboard does since #1839: read the current version
 * first and send it back, because a save without the version it was loaded at is refused.
 */
export async function postAnonControl(app: Express, caseId: string, body: Record<string, unknown>) {
  const version = (await request(app).get(`/cases/${caseId}/anon-control`)).body.version as string;
  return request(app)
    .post(`/cases/${caseId}/anon-control`)
    .send({ ...body, version });
}
