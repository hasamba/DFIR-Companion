import type { Express, Request, Response } from "express";
import { loadAttackMatrix } from "../analysis/attackMatrixData.js";
import { sendMaybeGzipped } from "../http/compressibleResponse.js";

/**
 * attackMatrix domain: the bundled MITRE ATT&CK Enterprise catalogue behind the MITRE panel's
 * Matrix view (#1764).
 *
 *   - GET /attack/matrix  — companion/data/attack-matrix.json, as loadAttackMatrix() parsed it.
 *
 * Public reference data, not case data: no case id, no state read. It always answers 200. A missing
 * or corrupt data file yields the empty catalogue (`techniques: []`), and the dashboard treats that
 * as "catalogue not available" and puts every case technique in its Unmapped column. The file only
 * changes with a release, so the browser may keep it for a day. ~90 KB raw, so it is gzipped when the
 * client accepts it, like the dashboard's own static files.
 */
export const ATTACK_MATRIX_CACHE_CONTROL = "public, max-age=86400";

export function registerAttackMatrixRoutes(app: Express): void {
  app.get("/attack/matrix", async (req: Request, res: Response) => {
    res.setHeader("Cache-Control", ATTACK_MATRIX_CACHE_CONTROL);
    await sendMaybeGzipped(req, res, "json", JSON.stringify(loadAttackMatrix()));
  });
}
