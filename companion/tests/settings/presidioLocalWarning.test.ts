import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2197: the "this Presidio URL is not local" warning in Settings → AI and the setup wizard.
//
// It used to search the WHOLE URL for `//localhost` and friends, so a remote analyzer passed as
// local whenever a loopback name appeared anywhere in it — in the path, the query, or the userinfo.
// It now parses the URL and compares the hostname alone. The Compose service name
// `presidio-analyzer` is accepted too: inside the Compose network it is the sibling container.

type Surface = { isLocalPresidioUrl?: (url: string) => boolean };

const stubEl = () => ({
  textContent: "",
  value: "",
  style: { display: "" },
  dataset: {},
  addEventListener: () => {},
  appendChild: () => {},
  querySelectorAll: () => [],
});

// The check parses with the browser's WHATWG `URL`, which a vm context does not provide — and
// without it every URL would throw, be caught, and read as "not local".
function loadSettings(): Surface {
  return loadDashboardModule<Surface>("dashboard-env-settings.js", [], {
    document: { getElementById: () => stubEl(), addEventListener: () => {}, querySelectorAll: () => [] },
    fetch: () => Promise.reject(new Error("no network in this test")),
    URL,
  });
}

const LOCAL = [
  "",
  "   ",
  "http://localhost:5002",
  "http://LOCALHOST:5002/",
  "http://127.0.0.1:5002",
  "http://[::1]:5002",
  "http://0.0.0.0:5002",
  "https://localhost",
  "http://presidio-analyzer:3000",
  "http://presidio-analyzer:3000/",
];

// A loopback name and port in the USERINFO slot, in front of a remote host. Assembled at runtime
// because the literal reads as a user:password URL to the CI secret scanner (trufflehog).
const inUserinfo = (name: string, port: number) => `http://${name}:${port}` + "@remote.example";

const NOT_LOCAL = [
  "http://192.168.1.20:5002",
  "https://presidio.example.com",
  "http://presidio-analyzer.example.com:3000",
  "http://presidio-analyzerx:3000",
  "http://user@remote.example:5002",
  // Loopback names smuggled outside the hostname — each of these used to read as local.
  "http://remote.example/path//localhost:5002",
  "http://remote.example/path//presidio-analyzer:3000",
  "http://remote.example/?next=http://localhost:5002",
  inUserinfo("localhost", 5002),
  inUserinfo("presidio-analyzer", 3000),
  // Not a URL the client can use at all: warn rather than stay quiet.
  "localhost:5002",
  "not a url",
  "ftp://localhost/",
];

describe("isLocalPresidioUrl (#2197)", () => {
  const { isLocalPresidioUrl } = loadSettings();

  it("is published for the setup wizard to share", () => {
    expect(typeof isLocalPresidioUrl).toBe("function");
  });

  it.each(LOCAL)("treats %j as local", (url) => {
    expect(isLocalPresidioUrl?.(url)).toBe(true);
  });

  it.each(NOT_LOCAL)("warns for %j", (url) => {
    expect(isLocalPresidioUrl?.(url)).toBe(false);
  });
});

describe("both Presidio URL warnings use the shared check (#2197)", () => {
  it("has no whole-URL loopback regex left in either script", async () => {
    const { readFileSync } = await import("node:fs");
    for (const file of ["dashboard-env-settings.js", "dashboard-setup-wizard.js"]) {
      const src = readFileSync(new URL(`../../../public/js/${file}`, import.meta.url), "utf8");
      expect(src, file).not.toMatch(/localhost\|127\\\.0\\\.0\\\.1/);
    }
    const wizard = readFileSync(
      new URL("../../../public/js/dashboard-setup-wizard.js", import.meta.url),
      "utf8",
    );
    expect(wizard).toMatch(/isLocalPresidioUrl\(/);
  });
});
