import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

// The AI rate limiter (20 req/min per case) must cover EVERY AI-cost route and NOT throttle
// the non-AI undo/redo/undo-stack routes under /import (which a prefix mount would swallow).
// We assert shape (429 vs non-429) against a real createApp, not the limiter in isolation, so
// the route-mounting wiring is what's tested. The case never exists, so AI-cost routes return
// 404/500 — but a 429 means the limiter fired FIRST, which is what we want to detect.

let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  resetLimiters();
  const root = await mkdtemp(join(tmpdir(), "dfir-ailimit-"));
  const cases = new CaseStore(root);
  app = createApp(cases, {});
});

async function fireManyPost(path: string, count: number, body?: unknown): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < count; i++) {
    const res = await request(app)
      .post(path)
      .send(body ?? {});
    out.push(res.status);
  }
  return out;
}

async function fireManyGet(path: string, count: number): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < count; i++) {
    const res = await request(app).get(path);
    out.push(res.status);
  }
  return out;
}

describe("AI rate limiter coverage", () => {
  it("throttles POST /cases/:id/synthesize after 20 req/min (existing coverage, no regression)", async () => {
    const statuses = await fireManyPost("/cases/nosuch/synthesize", 25);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });

  it("throttles POST /cases/:id/second-opinion (previously unthrottled — bug #25)", async () => {
    const statuses = await fireManyPost("/cases/nosuch/second-opinion", 25);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });

  it("throttles POST /cases/:id/ask (previously unthrottled — bug #25)", async () => {
    const statuses = await fireManyPost("/cases/nosuch/ask", 25);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });

  it("throttles POST /cases/:id/executive-summary (previously unthrottled — bug #25)", async () => {
    const statuses = await fireManyPost("/cases/nosuch/executive-summary", 25);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });

  it("throttles POST /cases/:id/events/:eid/explain (dynamic segment, previously unthrottled — bug #25)", async () => {
    const statuses = await fireManyPost("/cases/nosuch/events/ev1/explain", 25);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });

  // Express routes case-insensitively, so /SYNTHESIZE reaches the same handler as /synthesize. The
  // gate compared against a case-sensitive Set, so the uppercase spelling missed every entry, fell
  // through to next(), and ran the AI call unthrottled. The whole cap was one shift key from off.
  it("throttles POST /cases/:id/SYNTHESIZE — Express folds case, so the gate must too", async () => {
    const statuses = await fireManyPost("/cases/nosuch/SYNTHESIZE", 25);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });

  it("throttles POST /cases/:id/Events/:eid/Explain (the dynamic pattern folds case too)", async () => {
    const statuses = await fireManyPost("/cases/nosuch/Events/ev1/Explain", 25);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });

  // The routes the set had drifted past. Each issues an LLM call and each was unthrottled, so the
  // per-case cap could be walked around simply by using a different AI feature.
  const MISSING = [
    "/timeline-gaps/hypothesize",
    "/translate-query",
    "/false-positive/suggest",
    "/playbook/suggest-hunts",
    "/tagger/suggest-rule",
    "/velociraptor/suggest-hunts",
    "/adversary-hints/hunt-technique",
    "/anon-control",
  ];
  for (const path of MISSING) {
    it(`throttles POST /cases/:id${path}`, async () => {
      const statuses = await fireManyPost(`/cases/nosuch${path}`, 25);
      expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
    });
  }

  it("throttles POST /cases/:id/sessions/:sid/summary (dynamic segment)", async () => {
    const statuses = await fireManyPost("/cases/nosuch/sessions/s1/summary", 25);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });

  // Same non-strict-routing hazard as the case-folding one above, and the same consequence: the
  // handler runs, the Set lookup misses, the AI call goes out uncapped.
  it("throttles POST /cases/:id/synthesize/ (trailing slash)", async () => {
    const statuses = await fireManyPost("/cases/nosuch/synthesize/", 25);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });

  it("does NOT throttle GET /cases/:id/import/undo-stack (non-AI read — prefix-mount bug #23)", async () => {
    // 30 rapid GETs to the undo-stack read; none should be 429 (it costs zero AI tokens).
    const statuses = await fireManyGet("/cases/nosuch/import/undo-stack", 30);
    expect(statuses.filter((s) => s === 429).length).toBe(0);
  });

  it("does NOT throttle GET /cases/:id/synth-meta (read-only, zero AI cost)", async () => {
    const statuses = await fireManyGet("/cases/nosuch/synth-meta", 30);
    expect(statuses.filter((s) => s === 429).length).toBe(0);
  });
});
