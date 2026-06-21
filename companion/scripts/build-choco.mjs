// Materialize a packable Chocolatey package for the portable Windows build.
//
// The committed package under packaging/chocolatey/ is a TEMPLATE: the nuspec carries a
// __VERSION__ placeholder and tools/chocolateyinstall.ps1 + tools/VERIFICATION.txt carry
// __URL64__ / __CHECKSUM64__ (portable build) plus __EXT_URL64__ / __EXT_CHECKSUM64__ (the
// bundled capture extension). This script copies the template into companion/dist-choco/,
// substitutes those values, and (optionally) runs `choco pack` to produce the .nupkg.
//
// Run with:
//   node scripts/build-choco.mjs --version 0.25.0 --checksum <sha256> --ext-checksum <sha256> [--pack]
//   node scripts/build-choco.mjs --zip <win-x64.zip> --ext-zip <extension.zip> --pack
//
// Args:
//   --version <X.Y.Z>     Package version. A leading "v" is stripped. Default: companion/package.json.
//   --url <url>           Portable-build download URL. Default: the GitHub release asset URL.
//   --checksum <sha256>   SHA256 of the portable build. Required unless --zip is given.
//   --zip <path>          Local copy of the portable zip; its SHA256 is computed and used.
//   --ext-url <url>       Extension download URL. Default: the GitHub release asset URL.
//   --ext-checksum <sha>  SHA256 of the extension zip. Required unless --ext-zip is given.
//   --ext-zip <path>      Local copy of the extension zip; its SHA256 is computed and used.
//   --out <dir>           Output directory. Default: companion/dist-choco.
//   --pack                Run `choco pack` after templating (needs the Chocolatey CLI on PATH).
//
// CI passes --checksum + --ext-checksum (the hashes the windows-exe and extension-zip jobs
// already computed for the same assets), so no network or local build is required here.

import { mkdir, rm, readFile, writeFile, readdir, copyFile } from "node:fs/promises";
import { existsSync, createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { dirname, join, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const COMPANION_DIR = resolve(SCRIPT_DIR, "..");
const REPO_DIR = resolve(COMPANION_DIR, "..");
const TEMPLATE_DIR = join(REPO_DIR, "packaging", "chocolatey");
const DEFAULT_OUT = join(COMPANION_DIR, "dist-choco");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      args[key] = true; // boolean flag (e.g. --pack)
    } else {
      args[key] = next;
      i++;
    }
  }
  return args;
}

function fail(msg) {
  console.error(`[choco] ERROR: ${msg}`);
  process.exit(1);
}

async function readPackageVersion() {
  const pkg = JSON.parse(await readFile(join(COMPANION_DIR, "package.json"), "utf8"));
  return pkg.version;
}

function sha256File(path) {
  return new Promise((res, rej) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("error", rej);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => res(hash.digest("hex")));
  });
}

function run(cmd, args, opts = {}) {
  return new Promise((res, rej) => {
    const child = spawn(cmd, args, { stdio: "inherit", ...opts });
    child.on("error", rej);
    child.on("exit", (code) => (code === 0 ? res(undefined) : rej(new Error(`${cmd} exited with ${code}`))));
  });
}

function applyReplacements(text, repl) {
  let out = text;
  for (const [token, value] of Object.entries(repl)) {
    out = out.split(token).join(value);
  }
  return out;
}

// Resolve a SHA256: prefer the explicit value, else compute it from a local zip. `flag` is the
// CLI prefix ("" for the portable build, "ext-" for the extension) so error messages name the
// right options.
async function resolveChecksum(explicit, zipPath, flag) {
  let cs = explicit;
  if (!cs && zipPath) {
    if (!existsSync(zipPath)) fail(`--${flag}zip path not found: ${zipPath}`);
    console.log(`[choco] computing SHA256 of ${basename(zipPath)} …`);
    cs = await sha256File(zipPath);
  }
  if (!cs) fail(`no ${flag || "build "}checksum: pass --${flag}checksum <sha256> or --${flag}zip <path>.`);
  cs = String(cs).toLowerCase().trim();
  if (!/^[0-9a-f]{64}$/.test(cs)) fail(`--${flag}checksum "${cs}" is not a 64-char hex SHA256.`);
  return cs;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const version = String(args.version ?? (await readPackageVersion())).replace(/^v/, "");
  if (!/^\d+\.\d+\.\d+/.test(version)) {
    fail(`version "${version}" is not a SemVer (X.Y.Z[...]). Pass --version explicitly.`);
  }

  const owner = "hasamba";
  const releaseBase = `https://github.com/${owner}/DFIR-Companion/releases/download/v${version}`;
  const url = args.url ?? `${releaseBase}/dfir-companion-v${version}-win-x64.zip`;
  const extUrl = args["ext-url"] ?? `${releaseBase}/dfir-capture-extension-v${version}.zip`;

  const checksum = await resolveChecksum(args.checksum, args.zip, "");
  const extChecksum = await resolveChecksum(args["ext-checksum"], args["ext-zip"], "ext-");

  const outDir = args.out ? resolve(String(args.out)) : DEFAULT_OUT;
  const repl = {
    __VERSION__: version,
    __URL64__: url,
    __CHECKSUM64__: checksum,
    __EXT_URL64__: extUrl,
    __EXT_CHECKSUM64__: extChecksum,
  };

  console.log(`[choco] version:      ${version}`);
  console.log(`[choco] url:          ${url}`);
  console.log(`[choco] checksum:     ${checksum}`);
  console.log(`[choco] ext url:      ${extUrl}`);
  console.log(`[choco] ext checksum: ${extChecksum}`);
  console.log(`[choco] out:          ${outDir}`);

  // Fresh output tree.
  await rm(outDir, { recursive: true, force: true });
  await mkdir(join(outDir, "tools"), { recursive: true });

  // nuspec (version substitution).
  const nuspecSrc = await readFile(join(TEMPLATE_DIR, "dfir-companion.nuspec"), "utf8");
  await writeFile(join(outDir, "dfir-companion.nuspec"), applyReplacements(nuspecSrc, repl));

  // tools/* (url + checksum substitution; non-template files copied verbatim).
  const toolsSrc = join(TEMPLATE_DIR, "tools");
  for (const name of await readdir(toolsSrc)) {
    const src = join(toolsSrc, name);
    const dest = join(outDir, "tools", name);
    if (/\.(ps1|txt)$/i.test(name)) {
      const text = await readFile(src, "utf8");
      await writeFile(dest, applyReplacements(text, repl));
    } else {
      await copyFile(src, dest);
    }
  }

  console.log(`[choco] templated package → ${outDir}`);

  if (args.pack) {
    console.log("[choco] choco pack …");
    // Spawn choco.exe by its full name on Windows so no shell is needed (avoids arg-escaping
    // pitfalls + the DEP0190 deprecation warning).
    const chocoCmd = process.platform === "win32" ? "choco.exe" : "choco";
    try {
      await run(chocoCmd, ["pack", "dfir-companion.nuspec", "--outputdirectory", "."], { cwd: outDir });
      console.log(`[choco] done → ${join(outDir, `dfir-companion.${version}.nupkg`)}`);
    } catch (err) {
      fail(`choco pack failed (is the Chocolatey CLI installed and on PATH?): ${err.message ?? err}`);
    }
  } else {
    console.log("[choco] skip pack (pass --pack to produce the .nupkg).");
  }
}

main().catch((err) => {
  console.error("[choco] FAILED:", err.message ?? err);
  process.exit(1);
});
