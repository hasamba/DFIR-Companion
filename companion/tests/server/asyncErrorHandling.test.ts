import { describe, it, expect } from "vitest";
import express, { type Request, type Response, type NextFunction } from "express";
// Same side-effect patch server.ts applies. Importing it here (and there) monkeypatches the
// Express 4 router so a rejected async handler is forwarded to the error middleware instead of
// hanging the connection. This test pins that behaviour so nobody drops the dependency without
// a failing test.
import "express-async-errors";
import { ZodError, z } from "zod";
import request from "supertest";

/**
 * Builds a throwaway app whose only route rejects, wired with the SAME terminal error handler
 * shape as createApp() in src/server.ts. If express-async-errors is ever removed, the rejected
 * promise escapes and supertest times out / gets no clean response — turning this test red.
 */
function appThatThrows(makeError: () => never) {
  const app = express();
  app.get("/boom", async (_req: Request, _res: Response) => {
    makeError();
  });
  // Mirror of the terminal handler in createApp (kept in sync intentionally).
  app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(err);
    if (err instanceof ZodError) return res.status(400).json({ error: "invalid payload", details: err.issues });
    return res.status(500).json({ error: "internal server error" });
  });
  return app;
}

describe("async route error forwarding (express-async-errors)", () => {
  it("a rejected async route resolves to a clean 500 JSON instead of hanging", async () => {
    const app = appThatThrows(() => {
      throw new Error("kaboom");
    });
    const res = await request(app).get("/boom");
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: "internal server error" });
    expect(res.type).toMatch(/json/);
  });

  it("a ZodError thrown from an async route keeps its conventional 400", async () => {
    const app = appThatThrows(() => {
      // A parse failure raises ZodError synchronously inside the async handler.
      z.object({ n: z.number() }).parse({ n: "not-a-number" });
      throw new Error("unreachable");
    });
    const res = await request(app).get("/boom");
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid payload");
    expect(Array.isArray(res.body.details)).toBe(true);
  });
});
