// SEA-only shim for the `sharp` import.
//
// The SEA-embedded `require()` is the embedder's built-in resolver — it only knows
// node:builtins, not disk-backed modules. So when the bundled `require("sharp")`
// fires inside the EXE, it throws ERR_UNKNOWN_BUILTIN_MODULE no matter where sharp
// lives on disk.
//
// `createRequire(<path>)` returns a real CJS require anchored at `<path>` that walks
// the normal node_modules resolution algorithm — and it works inside SEA. We anchor
// it at the EXE folder so it finds `<execdir>/node_modules/sharp` (and the platform
// `@img/sharp-*` peer that sharp's loader pulls in).
//
// esbuild's `alias` maps `"sharp"` → this file for the SEA bundle only; the regular
// tsc/Docker build still imports the package directly.
const { createRequire } = require("node:module");
const { join, dirname } = require("node:path");

const seaRequire = createRequire(join(dirname(process.execPath), "package.json"));
module.exports = seaRequire("sharp");
