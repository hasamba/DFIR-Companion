import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// POST /cases/:id/sigma/compile (#798): parse + compile a Sigma rule, never launch. It needs no AI
// provider and no Velociraptor API — createApp() here has neither — because the compile step is
// offline; only the Run button in the dashboard needs the API.

let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-sigma-compile-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases);
});

const RULE = `
title: Certutil download
id: 2f0d4b8e-7d2a-4d4d-9c26-0a5d2b4c9e11
level: high
tags:
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains: 'urlcache'
  condition: sel
`;

const compile = (yaml: unknown, caseId = "c1") =>
  request(app).post(`/cases/${caseId}/sigma/compile`).send({ yaml });

describe("POST /cases/:id/sigma/compile", () => {
  it("compiles a rule to VQL with the coverage line and the rule's metadata, without any Velociraptor API", async () => {
    const res = await compile(RULE);
    expect(res.status, res.text).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.vql).toContain("FROM pslist()");
    expect(res.body.vql).toContain('Image =~ "(?i)\\\\\\\\certutil\\\\.exe$"');
    expect(res.body.coverage).toBe("pslist(): running processes only, not process history");
    expect(res.body.title).toBe("Certutil download");
    expect(res.body.id).toBe("2f0d4b8e-7d2a-4d4d-9c26-0a5d2b4c9e11");
    expect(res.body.level).toBe("high");
    expect(res.body.mitreTechniques).toEqual(["T1105"]);
  });

  it("answers a refused rule with 200 and the refusal list — a refusal is an answer, not a server error", async () => {
    const res = await compile(RULE.replace("process_creation", "image_load"));
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
    expect(res.body.refusals).toEqual([
      { path: "logsource.category", message: expect.stringContaining("image_load") },
    ]);
    expect(res.body.vql).toBeUndefined();
  });

  it("answers malformed YAML with 400 and the YAML refusal", async () => {
    const res = await compile("title: [unclosed\n");
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
    expect(res.body.refusals[0].path).toBe("yaml");
  });

  it("answers an anchor/alias expansion bomb with 400 and the YAML refusal, never 500 (#805)", async () => {
    let bomb = 'k1: &a1 ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]\n';
    for (let i = 2; i <= 9; i++)
      bomb += `k${i}: &a${i} [${Array(9)
        .fill(`*a${i - 1}`)
        .join(",")}]\n`;
    const res = await compile(bomb);
    expect(res.status, res.text).toBe(400);
    expect(res.body.ok).toBe(false);
    expect(res.body.refusals).toEqual([{ path: "yaml", message: expect.stringContaining("too complex") }]);
  });

  it("answers a cyclic alias with 400 and the YAML refusal, never 500", async () => {
    const res = await compile(
      "title: T\nlogsource:\n  category: process_creation\ndetection:\n  sel: &a [*a]\n  condition: sel\n",
    );
    expect(res.status, res.text).toBe(400);
    expect(res.body.refusals).toEqual([
      { path: "yaml", message: expect.stringContaining("refers to itself") },
    ]);
  });

  it("answers a missing or non-string yaml with 400", async () => {
    expect((await request(app).post("/cases/c1/sigma/compile").send({})).status).toBe(400);
    expect((await compile(42)).status).toBe(400);
    expect((await compile("")).status).toBe(400);
  });

  it("caps the body at the parser's rule size, with 400 rather than a parse attempt", async () => {
    const res = await compile("title: T\n" + "#".repeat(70_000));
    expect(res.status).toBe(400);
    expect(res.body.refusals[0].path).toBe("yaml");
  });

  it("reads no case state, so it answers for a case id that does not exist (like hunt-query/validate)", async () => {
    const res = await compile(RULE, "nope");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });
});
