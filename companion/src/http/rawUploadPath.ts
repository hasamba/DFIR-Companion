import type { NextFunction, Request, RequestHandler, Response } from "express";

/**
 * The routes whose request body is the raw file, read by the route itself as a stream (#2336):
 * POST /cases/:id/import-upload. The generous JSON and text body parsers must never consume it,
 * whatever content type the client claims — a `.json` export sent with its own MIME type would
 * otherwise be buffered whole (up to DFIR_MAX_BODY_MB) before the route could spool it to disk.
 * Matched the way Express routes: case-insensitive, trailing slash optional.
 */
const RAW_UPLOAD_PATH = /^\/cases\/[^/]+\/import-upload\/?$/i;

export function isRawUploadRequest(req: Pick<Request, "method" | "path">): boolean {
  return req.method === "POST" && RAW_UPLOAD_PATH.test(req.path);
}

/** `parser`, skipped for a raw-upload request so its body stays unread for the route. */
export function skipRawUploads(parser: RequestHandler): RequestHandler {
  return function bodyParserUnlessRawUpload(req: Request, res: Response, next: NextFunction): void {
    if (isRawUploadRequest(req)) return next();
    parser(req, res, next);
  };
}

/**
 * `Connection: close` on a raw-upload request from the first layer on (#2353), so a refusal answered
 * before the route reads the body — origin guard, demo gate, team auth, the case gates — ends the
 * connection instead of letting Node read and discard a possibly multi-GB unread body. The route
 * takes the header off once it has read the whole body (routes/importUpload.ts), so an answer after
 * the read keeps the connection. Every other request is untouched.
 */
export function closeUnreadRawUploads(req: Request, res: Response, next: NextFunction): void {
  if (isRawUploadRequest(req)) res.setHeader("Connection", "close");
  next();
}
