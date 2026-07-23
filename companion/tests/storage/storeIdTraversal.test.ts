import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, readFile, mkdir, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TemplateStore } from "../../src/analysis/templateStore.js";
import { ReportTemplateStore } from "../../src/reports/reportTemplateStore.js";
import { DashboardViewStore } from "../../src/analysis/dashboardViewStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { UnsafeStoreIdError } from "../../src/storage/safeStoreId.js";

// Layout: <sandbox>/store is the store root; <sandbox>/secret.json is a neighbour file that a
// traversal id would reach. Every assertion below is "the neighbour is untouched".
let sandbox: string;
let root: string;
const SECRET = JSON.stringify({ apiKey: "do-not-touch" });

beforeEach(async () => {
  sandbox = await mkdtemp(join(tmpdir(), "dfir-traversal-"));
  root = join(sandbox, "store");
  await mkdir(root, { recursive: true });
  await writeFile(join(sandbox, "secret.json"), SECRET, "utf8");
});

const secretIntact = async (): Promise<boolean> =>
  (await readFile(join(sandbox, "secret.json"), "utf8")) === SECRET;

describe("store id traversal (#213)", () => {
  it("TemplateStore.save cannot overwrite a file outside its root", async () => {
    const store = new TemplateStore(root);
    await expect(store.save({ id: "../secret", name: "pwn" } as never)).rejects.toThrow(UnsafeStoreIdError);
    expect(await secretIntact()).toBe(true);
  });

  it("ReportTemplateStore.save cannot overwrite a file outside its root", async () => {
    const store = new ReportTemplateStore(root);
    await expect(store.save({ id: "../secret", name: "pwn" })).rejects.toThrow(UnsafeStoreIdError);
    expect(await secretIntact()).toBe(true);
  });

  it("DashboardViewStore.save cannot overwrite a file outside its root", async () => {
    const store = new DashboardViewStore(root);
    await expect(store.save({ id: "../secret", name: "pwn" })).rejects.toThrow(UnsafeStoreIdError);
    expect(await secretIntact()).toBe(true);
  });

  it("ArtifactBundleStore.save cannot overwrite a file outside its root", async () => {
    const store = new ArtifactBundleStore(root);
    await expect(store.save({ id: "../secret", name: "pwn", artifacts: [] } as never)).rejects.toThrow(UnsafeStoreIdError);
    expect(await secretIntact()).toBe(true);
  });

  it("get cannot read a file outside the root", async () => {
    // The read path matters as much as the write path: with a wildcard CORS policy this was an
    // arbitrary-JSON exfiltration primitive, not just a clobber.
    await expect(new TemplateStore(root).get("../secret")).rejects.toThrow(UnsafeStoreIdError);
    await expect(new ReportTemplateStore(root).get("../secret")).rejects.toThrow(UnsafeStoreIdError);
    await expect(new DashboardViewStore(root).get("../secret")).rejects.toThrow(UnsafeStoreIdError);
    await expect(new ArtifactBundleStore(root).get("../secret")).rejects.toThrow(UnsafeStoreIdError);
  });

  it("delete cannot unlink a file outside the root", async () => {
    await expect(new TemplateStore(root).delete("../secret")).rejects.toThrow(UnsafeStoreIdError);
    await expect(new ReportTemplateStore(root).delete("../secret")).rejects.toThrow(UnsafeStoreIdError);
    await expect(new DashboardViewStore(root).delete("../secret")).rejects.toThrow(UnsafeStoreIdError);
    await expect(new ArtifactBundleStore(root).delete("../secret")).rejects.toThrow(UnsafeStoreIdError);
    expect(await secretIntact()).toBe(true);
  });

  it("still saves and reads back a legitimate custom record", async () => {
    // The guard must not break the normal path it is protecting.
    const store = new TemplateStore(root);
    const saved = await store.save({ id: "my-playbook", name: "Mine" } as never);
    expect(saved.id).toBe("my-playbook");
    expect((await store.get("my-playbook"))?.name).toBe("Mine");
    expect(await readdir(root)).toContain("my-playbook.json");
  });

  it("still mints a UUID id when none is supplied", async () => {
    const saved = await new TemplateStore(root).save({ name: "Auto" } as never);
    expect(saved.id).toMatch(/^[0-9a-f-]{36}$/);
  });
});
