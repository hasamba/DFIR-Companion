import { describe, it, expect } from "vitest";
import { parseBplist, type BplistValue } from "../../src/analysis/bplistReader.js";
import { resolveKeyedArchive } from "../../src/analysis/nsKeyedArchiver.js";

// Fixtures hand-built via Python's stdlib `plistlib.dumps({...}, fmt=plistlib.FMT_BINARY)` using
// real `plistlib.UID` objects for cross-references — real bplist00 bytes, round-tripped through
// `plistlib.loads()` before capture. See RECOMMENDATION-12.md for the full research trail.

function buf(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

// A real NSKeyedArchiver-wrapped NSMutableDictionary: root -> {name: "payload.exe", hidden: True}
const NSDICT_HEX =
  "62706c6973743030d40102030405061e215924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572a707081314151c1d55246e756c6cd3090a0b0c0d105624636c617373574e532e6b6579735a4e532e6f626a656374738004a20e0f80028003a2111280058006546e616d655668696464656ed2161718195824636c61737365735a24636c6173736e616d65a3191a1b5f10134e534d757461626c6544696374696f6e6172795c4e5344696374696f6e617279584e534f626a6563745b7061796c6f61642e65786509d11f2054726f6f74800112000186a008111b242932444c525960687375787a7c7f8183888f949da8acc2cfd8e4e5e8edef00000000000001010000000000000022000000000000000000000000000000f4";

// A real NSKeyedArchiver-wrapped NSData: root -> raw bytes "hello-bookmark-bytes"
const NSDATA_HEX =
  "62706c6973743030d401020304050613165924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572a307080d55246e756c6cd2090a0b0c5624636c617373574e532e6461746180024f101468656c6c6f2d626f6f6b6d61726b2d6279746573d20e0f10115824636c61737365735a24636c6173736e616d65a21112564e5344617461584e534f626a656374d1141554726f6f74800112000186a008111b24293244484e535a62647b808994979ea7aaafb100000000000001010000000000000017000000000000000000000000000000b6";

// A real cyclic reference: root -> {a: {b: <cycle back to root>}}
const CYCLE_HEX =
  "62706c6973743030d40102030405060e115924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572a307080b55246e756c6cd1090a51618002d10c0d51628001d10f1054726f6f74800112000186a008111b24293244484e515355585a5c5f6466000000000000010100000000000000120000000000000000000000000000006b";

describe("resolveKeyedArchive — real NSKeyedArchiver fixtures", () => {
  it("returns null for a plain (non-keyed-archive) bplist", () => {
    const plain = new Map<BplistValue, BplistValue>([["hello", "world"]]);
    expect(resolveKeyedArchive(plain)).toBeNull();
  });

  it("resolves UID references and unwraps a real NSMutableDictionary via NS.keys/NS.objects", () => {
    const root = parseBplist(buf(NSDICT_HEX));
    const result = resolveKeyedArchive(root);
    expect(result).not.toBeNull();
    const resolved = result!.roots.get("root") as Map<string, unknown>;
    expect(resolved).toBeInstanceOf(Map);
    expect(resolved.get("name")).toBe("payload.exe");
    expect(resolved.get("hidden")).toBe(true);
  });

  it("unwraps a real NSData object to a raw Buffer via NS.data", () => {
    const root = parseBplist(buf(NSDATA_HEX));
    const result = resolveKeyedArchive(root);
    const resolved = result!.roots.get("root");
    expect(Buffer.isBuffer(resolved)).toBe(true);
    expect((resolved as Buffer).toString("utf8")).toBe("hello-bookmark-bytes");
  });

  it("breaks a genuine reference cycle instead of recursing forever, disclosing a cycle marker", () => {
    const root = parseBplist(buf(CYCLE_HEX));
    const result = resolveKeyedArchive(root);
    const resolved = result!.roots.get("root") as Map<string, unknown>;
    const a = resolved.get("a") as Map<string, unknown>;
    const b = a.get("b") as { cycle: true; uid: number };
    expect(b.cycle).toBe(true);
    expect(typeof b.uid).toBe("number");
  });

  it("enforces the resolve-depth budget on a genuine 80-deep UID indirection chain", () => {
    // A real archive where object 1 -> UID(2) -> UID(3) -> ... -> a plain string 80 levels down —
    // never revisiting an index (not a cycle), but deep enough to exceed MAX_RESOLVE_DEPTH (64).
    const deepChainHex =
      "62706c6973743030d4010203040506595c5924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572af10520708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50515253545556575855246e756c6c80028003800480058006800780088009800a800b800c800d800e800f8010801180128013801480158016801780188019801a801b801c801d801e801f8020802180228023802480258026802780288029802a802b802c802d802e802f8030803180328033803480358036803780388039803a803b803c803d803e803f8040804180428043804480458046804780488049804a804b804c804d804e804f8050805159646565702d6c656166d15a5b54726f6f74800112000186a000080011001b00240029003200440099009f00a100a300a500a700a900ab00ad00af00b100b300b500b700b900bb00bd00bf00c100c300c500c700c900cb00cd00cf00d100d300d500d700d900db00dd00df00e100e300e500e700e900eb00ed00ef00f100f300f500f700f900fb00fd00ff01010103010501070109010b010d010f01110113011501170119011b011d011f01210123012501270129012b012d012f01310133013501370139013b013d013f0149014c015101530000000000000201000000000000005d00000000000000000000000000000158";
    const root = parseBplist(buf(deepChainHex));
    expect(() => resolveKeyedArchive(root)).toThrow();
  });
});
