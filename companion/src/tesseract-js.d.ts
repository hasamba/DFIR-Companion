// Minimal ambient declarations for tesseract.js so tsc resolves the dynamic import
// in TesseractOcrRunner before the package is installed in node_modules.
// When tesseract.js IS installed its own bundled types take precedence via skipLibCheck.
declare module "tesseract.js" {
  interface BBox {
    x0: number;
    y0: number;
    x1: number;
    y1: number;
  }
  interface Word {
    text: string;
    confidence: number;
    bbox: BBox;
  }
  interface RecognizeResult {
    data: { words: Word[] };
  }
  export function recognize(
    image: Buffer | string | ArrayBuffer,
    langs?: string,
    options?: { logger?: (msg: unknown) => void; [k: string]: unknown },
  ): Promise<RecognizeResult>;
  // Explicit worker lifecycle (createWorker → recognize → terminate). Used by
  // TesseractOcrRunner so a malformed-image WASM abort is contained via errorHandler
  // instead of throwing synchronously on the Worker message loop and killing the
  // process. Types are intentionally loose; tesseract.js's own .d.ts (when installed)
  // takes precedence under skipLibCheck.
  interface TesseractWorker {
    recognize(
      image: Buffer | string | ArrayBuffer,
      options?: { [k: string]: unknown },
    ): Promise<RecognizeResult>;
    terminate(): Promise<void>;
  }
  export function createWorker(
    langs?: string | string[],
    oem?: number,
    options?: { errorHandler?: (err: unknown) => void; [k: string]: unknown },
    config?: { [k: string]: unknown },
  ): Promise<TesseractWorker>;
  const _default: { recognize: typeof recognize; createWorker: typeof createWorker };
  export default _default;
}
