import express, { type Express, type Request, type Response } from "express";
import { ZodError } from "zod";
import { CaseStore } from "./storage/caseStore.js";
import { ingestCapture } from "./ingest/captureIngest.js";

export function createApp(store: CaseStore): Express {
  const app = express();
  app.use(express.json({ limit: "25mb" })); // screenshots arrive base64-encoded

  app.post("/cases", async (req: Request, res: Response) => {
    try {
      const { caseId, name, investigator, aiProvider } = req.body ?? {};
      if (!caseId || !name) {
        return res.status(400).json({ error: "caseId and name are required" });
      }
      const meta = await store.createCase({
        caseId,
        name,
        investigator: investigator ?? "unknown",
        aiProvider: aiProvider ?? null,
      });
      return res.status(201).json(meta);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/captures", async (req: Request, res: Response) => {
    try {
      const metadata = await ingestCapture(store, req.body);
      return res.status(201).json(metadata);
    } catch (err) {
      if (err instanceof ZodError) {
        return res.status(400).json({ error: "invalid payload", details: err.issues });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  return app;
}

export function startServer(casesRoot: string, port = 4773): void {
  const app = createApp(new CaseStore(casesRoot));
  app.listen(port, "127.0.0.1", () => {
    console.log(`DFIR companion listening on http://127.0.0.1:${port}`);
  });
}

// Entry point when run directly.
if (process.argv[1] && process.argv[1].endsWith("server.ts")) {
  startServer(process.env.DFIR_CASES_ROOT ?? "cases");
}
