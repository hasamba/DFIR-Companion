import { describe, it, expect } from "vitest";
import { parseMacLoginItemBtm, MAX_ITEMS_SCANNED } from "../../src/analysis/macLoginItemImport.js";

// Both fixtures below combine a REAL CFURL bookmark blob (encoded via michaeldiazlutz/mac_alias's
// own bidirectional Bookmark.to_bytes(), fetched live from PyPI) inside a hand-built
// NSKeyedArchiver bplist matching the exact container shapes mnrkbys/bgiparser's own parse_btm()
// confirms (cloned and read live): legacy `version === 2` with
// backgroundItems.allContainers[*].internalItems[0].bookmark.data, and modern (`version >= 3`) as
// a 2-element root array with element[1].store.itemsByUserIdentifier[uuid][*]. See
// RECOMMENDATION-12.md for the full research trail.

const LEGACY_BTM_HEX =
  "62706c6973743030d4010203040506282b5924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572aa07080d101215171a1d2255246e756c6cd2090a0b0c5f100f6261636b67726f756e644974656d735776657273696f6e80021002d10e0f5d616c6c436f6e7461696e6572738003a1118004d113145d696e7465726e616c4974656d738005a1168006d1181958626f6f6b6d61726b8007d11b1c54646174618008d21e1f20215624636c617373574e532e6461746180094f110184626f6f6b84010000000004103000000000000000000000000000000000000000000000000000000000000000000000000401000010000000010600001c0000002c000000380000004c000000050000000101000055736572730000000300000001010000626f62000c000000010100004170706c69636174696f6e730d000000010100004c65676163794170702e61707000000010000000010600007c0000008800000094000000a000000004000000030300000200000004000000030300003200000004000000030300003c0000000400000003030000460000000c000000010100004d6163696e746f7368204844240000000101000041414141414141412d313131312d323232322d333333332d3434343434343434343434340d000000010100004c65676163794170702e61707000000034000000feffffff01000000000000000500000004100000040000000000000005100000640000000000000010200000ac0000000000000011200000c00000000000000017f00000ec00000000000000d2232425265824636c61737365735a24636c6173736e616d65a22627564e5344617461584e534f626a656374d1292a54726f6f74800112000186a000080011001b0024002900320044004f0055005a006c007400760078007b0089008b008d008f009200a000a200a400a600a900b200b400b700bc00be00c300ca00d200d4025c0261026a02750278027f0288028b029002920000000000000201000000000000002c00000000000000000000000000000297";

const MODERN_BTM_HEX =
  "62706c6973743030d40102030405063e415924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572ae07080b0e11141719262b2e32353b55246e756c6ca2090a80028003d10c0d5776657273696f6e100dd10f105573746f72658004d112135f10156974656d734279557365724964656e7469666965728005d115165f102431313131323232322d333333332d343434342d353535352d3636363637373737383838388006a1188007d61a1b1c1d1e1f20212223242558626f6f6b6d61726b5f101062756e646c654964656e7469666965725f101a65786563757461626c654d6f64696669636174696f6e446174655f10106d6f64696669636174696f6e44617465567368613235365474797065800b5f1015636f6d2e6578616d706c652e6d6f6465726e61707080098008800a1001d22728292a5624636c617373574e532e74696d65800c23c1c1e1a300000000d227282c2d800c23c1c1e1a332000000d2272f3031574e532e64617461800d4f1020ababababababababababababababababababababababababababababababababd2272f3334800d4f110140626f6f6b4001000000000410300000000000000000000000000000000000000000000000000000000000000000000000c0000000080000000106000014000000280000000c000000010100004170706c69636174696f6e730d000000010100004d6f6465726e4170702e6170700000000800000001060000500000005c0000000400000003030000020000000400000003030000e70300000c000000010100004d6163696e746f7368204844240000000101000042424242424242422d313131312d323232322d333333332d3434343434343434343434340d000000010100004d6f6465726e4170702e61707000000034000000feffffff010000000000000005000000041000000400000000000000051000004000000000000000102000006800000000000000112000007c0000000000000017f00000a800000000000000d2363738395824636c61737365735a24636c6173736e616d65a2393a564e5344617465584e534f626a656374d236373c3da23d3a564e5344617461d13f4054726f6f74800112000186a000080011001b002400290032004400530059005c005e00600063006b006d007000760078007b00930095009800bf00c100c300c500d200db00ee010b011e0125012a012c014401460148014a014c0151015801600162016b01700172017b01800188018a01ad01b201b402f802fd030603110314031b03240329032c03330336033b033d0000000000000201000000000000004200000000000000000000000000000342";

function buf(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

describe("parseMacLoginItemBtm — legacy (macOS <= 12) generation", () => {
  it("recognizes the real legacy container shape and decodes the real bookmark target", () => {
    const r = parseMacLoginItemBtm(buf(LEGACY_BTM_HEX));
    expect(r).not.toBeNull();
    expect(r!.sourceFormat).toBe("btm-legacy");
    expect(r!.kept).toBe(1);
    const block = r!.events[0].canonical!.macLoginItem!;
    expect(block.sourceFormat).toBe("btm-legacy");
    expect(block.targetPathComponents).toEqual(["Users", "bob", "Applications", "LegacyApp.app"]);
    expect(block.targetCnidPath).toEqual(["2", "50", "60", "70"]);
    expect(block.volumeName).toBe("Macintosh HD");
    expect(block.volumeUuid).toBe("AAAAAAAA-1111-2222-3333-444444444444");
    expect(block.displayName).toBe("LegacyApp.app");
    expect(block.bookmarkDecodeStatus).toBe("decoded");
    expect(block.targetEvidence).toBe("stored-bookmark-metadata");
  });

  it("stays Info severity and never claims execution in the description", () => {
    const r = parseMacLoginItemBtm(buf(LEGACY_BTM_HEX))!;
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].description).toContain("never evidence of execution");
  });
});

describe("parseMacLoginItemBtm — modern (macOS 13+) generation", () => {
  it("recognizes the real modern container shape (2-element root array) and decodes the real bookmark target", () => {
    const r = parseMacLoginItemBtm(buf(MODERN_BTM_HEX));
    expect(r).not.toBeNull();
    expect(r!.sourceFormat).toBe("btm-modern");
    expect(r!.kept).toBe(1);
    const block = r!.events[0].canonical!.macLoginItem!;
    expect(block.sourceFormat).toBe("btm-modern");
    expect(block.userUuid).toBe("11112222-3333-4444-5555-666677778888");
    expect(block.targetPathComponents).toEqual(["Applications", "ModernApp.app"]);
    expect(block.volumeUuid).toBe("BBBBBBBB-1111-2222-3333-444444444444");
  });

  it("decodes the four confirmed per-item fields (type, both dates, sha256) with their own real types", () => {
    const r = parseMacLoginItemBtm(buf(MODERN_BTM_HEX))!;
    const block = r.events[0].canonical!.macLoginItem!;
    expect(block.itemType).toBe(1);
    expect(block.modificationDate).toBeTruthy();
    expect(block.executableModificationDate).toBeTruthy();
    expect(block.sha256).toBe("ab".repeat(32));
  });

  it("carries every other present key through as disclosed, unconfirmed rawFields", () => {
    const r = parseMacLoginItemBtm(buf(MODERN_BTM_HEX))!;
    const block = r.events[0].canonical!.macLoginItem!;
    expect(block.rawFields?.bundleIdentifier).toBe("com.example.modernapp");
  });
});

describe("parseMacLoginItemBtm — neither confirmed shape, never a blind fallback", () => {
  it("returns null for a plain (non-keyed-archive) bplist", () => {
    expect(parseMacLoginItemBtm(Buffer.from("not a bplist at all"))).toBeNull();
  });

  it("returns null for a real keyed archive that matches neither legacy nor modern shape", () => {
    const unrelatedHex =
      "62706c6973743030d40102030405060b0e5924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572a2070855246e756c6cd1090a5568656c6c6f55776f726c64d10c0d54726f6f74800112000186a008111b24293244474d50565c5f64660000000000000101000000000000000f0000000000000000000000000000006b";
    expect(parseMacLoginItemBtm(Buffer.from(unrelatedHex, "hex"))).toBeNull();
  });

  it("never throws on a short, malformed buffer -- returns null instead", () => {
    expect(() => parseMacLoginItemBtm(Buffer.from("short"))).not.toThrow();
    expect(parseMacLoginItemBtm(Buffer.from("short"))).toBeNull();
  });
});

describe("parseMacLoginItemBtm — malformed bookmark inside an otherwise-recognized BTM structure", () => {
  it("keeps the item (never drops it) but discloses the malformed bookmark via bookmarkDecodeStatus and malformedBookmarks", () => {
    const malformedBookmarkHex =
      "62706c6973743030d4010203040506282b5924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572aa07080d101215171a1d2255246e756c6cd2090a0b0c5f100f6261636b67726f756e644974656d735776657273696f6e80021002d10e0f5d616c6c436f6e7461696e6572738003a1118004d113145d696e7465726e616c4974656d738005a1168006d1181958626f6f6b6d61726b8007d11b1c54646174618008d21e1f20215624636c617373574e532e6461746180094f101f6e6f742d612d7265616c2d626f6f6b6d61726b2d626c6f622d61742d616c6cd2232425265824636c61737365735a24636c6173736e616d65a22627564e5344617461584e534f626a656374d1292a54726f6f74800112000186a000080011001b0024002900320044004f0055005a006c007400760078007b0089008b008d008f009200a000a200a400a600a900b200b400b700bc00be00c300ca00d200d400f600fb0104010f0112011901220125012a012c0000000000000201000000000000002c00000000000000000000000000000131";
    const r = parseMacLoginItemBtm(buf(malformedBookmarkHex))!;
    expect(r.kept).toBe(1);
    expect(r.malformedBookmarks).toBe(1);
    expect(r.events[0].canonical!.macLoginItem?.bookmarkDecodeStatus).toBe("malformed");
  });
});

describe("parseMacLoginItemBtm — a genuine parse failure propagates, never silently becomes null", () => {
  it("throws (does not return null) for a real bplist00 file whose trailer declares an object count past the budget", () => {
    // The real legacy BTM fixture with its trailer's numObjects field overwritten to 100,001 --
    // past bplistReader.ts's own MAX_OBJECTS budget. Before the fix, ANY exception here (including
    // a genuine budget-exceeded error on a real bplist00 file) was swallowed into a misleading
    // null ("not a recognized format"), indistinguishable from a file that was never a bplist at
    // all (Ollama code review finding).
    const budgetExceededHex =
      "62706c6973743030d4010203040506282b5924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572aa07080d101215171a1d2255246e756c6cd2090a0b0c5f100f6261636b67726f756e644974656d735776657273696f6e80021002d10e0f5d616c6c436f6e7461696e6572738003a1118004d113145d696e7465726e616c4974656d738005a1168006d1181958626f6f6b6d61726b8007d11b1c54646174618008d21e1f20215624636c617373574e532e6461746180094f110184626f6f6b84010000000004103000000000000000000000000000000000000000000000000000000000000000000000000401000010000000010600001c0000002c000000380000004c000000050000000101000055736572730000000300000001010000626f62000c000000010100004170706c69636174696f6e730d000000010100004c65676163794170702e61707000000010000000010600007c0000008800000094000000a000000004000000030300000200000004000000030300003200000004000000030300003c0000000400000003030000460000000c000000010100004d6163696e746f7368204844240000000101000041414141414141412d313131312d323232322d333333332d3434343434343434343434340d000000010100004c65676163794170702e61707000000034000000feffffff01000000000000000500000004100000040000000000000005100000640000000000000010200000ac0000000000000011200000c00000000000000017f00000ec00000000000000d2232425265824636c61737365735a24636c6173736e616d65a22627564e5344617461584e534f626a656374d1292a54726f6f74800112000186a000080011001b0024002900320044004f0055005a006c007400760078007b0089008b008d008f009200a000a200a400a600a900b200b400b700bc00be00c300ca00d200d4025c0261026a02750278027f0288028b02900292000000000000020100000000000186a100000000000000000000000000000297";
    expect(() => parseMacLoginItemBtm(buf(budgetExceededHex))).toThrow(/numObjects/);
  });
});

describe("parseMacLoginItemBtm — scan bound", () => {
  it("MAX_ITEMS_SCANNED is a real, positive, finite bound", () => {
    expect(MAX_ITEMS_SCANNED).toBeGreaterThan(0);
    expect(Number.isFinite(MAX_ITEMS_SCANNED)).toBe(true);
  });
});

// ── #1301: the two pre-BTM containers ─────────────────────────────────────────────────────────
// Fixtures built by a scratch script from dmgbuild/mac_alias 2.2.3 (Alias.to_bytes(),
// Bookmark.to_bytes()) and plistlib (containers). The sfl2 keyed archive follows the shape both
// ydkhatri/mac_apt ReadSFL2Plist and mac4n6/macMRU-Parser ParseSFL2 read; the classic plist follows
// mac_apt autostart.py process_loginitems_plist. See RECOMMENDATION-1301.md.

// Plain bplist: SessionItems.CustomListItems = [EvilAgent (v2 alias, appinfo 0), Payloads (v3
// alias, appinfo "alis"), Bookmarked (a real CFURL "book" bookmark under the Alias key), Broken
// (garbage after a plausible header), NoAlias (no Alias key)].
const LOGINITEMS_PLIST_HEX =
  "62706c6973743030d2010203185c53657373696f6e4974656d735f101353657373696f6e4974656d7356657273696f6ed104055f100f437573746f6d4c6973744974656d73a5060d101316d30708090a0b0c55416c6961735f1014437573746f6d4974656d50726f70657274696573544e616d654f110162000000000162000200000c4d6163696e746f7368204844000000000000000000000000000000d11c433f482b0000000004d20d4576696c4167656e742e61707000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000162ed3a51e730000000000000000ffffffff000000000000000000000000000000000000000c4170706c69636174696f6e73001000080000d11c433f0000001100080000d3a51e7300000001000c00000002000004d20000162e000200274d6163696e746f73682048443a4170706c69636174696f6e733a4576696c4167656e742e61707000000e001c000d004500760069006c004100670065006e0074002e006100700070000f001a000c004d006100630069006e0074006f007300680020004800440012001b2f4170706c69636174696f6e732f4576696c4167656e742e61707000001300012f00ffff0000d0594576696c4167656e74d207090e0f4f10ba616c697300ba000300010000d11c433f0000482b0000000000000063000010920000d3a51e730000000000000000000000000000000000000000001000080000d11c433f0000001100080000d3a51e7300000001000c000000020000006300001092000e00120008005000610079006c006f006100640073000f000a00040044006100740061001200132f55736572732f626f622f5061796c6f61647300001300142f53797374656d2f566f6c756d65732f44617461ffff0000585061796c6f616473d2070911124f110148626f6f6b4801000000000410300000000000000000000000000000000000000000000000000000000000000000000000c8000000080000000106000014000000280000000c000000010100004170706c69636174696f6e731100000001010000426f6f6b6d61726b65644170702e6170700000000800000001060000540000006000000004000000030300000200000004000000030300004d0000000c000000010100004d6163696e746f7368204844240000000101000043434343434343432d313131312d323232322d333333332d3434343434343434343434341100000001010000426f6f6b6d61726b65644170702e61707000000034000000feffffff010000000000000005000000041000000400000000000000051000004400000000000000102000006c0000000000000011200000800000000000000017f00000ac000000000000005a426f6f6b6d61726b6564d2070914154f101c0000000000c8000299999999999999999999999999999999999999995642726f6b656ed10917574e6f416c69617310010008000d001a003000330045004b00520058006f007401da01db01e501ea02a702b002b50401040c041104300437043a04420000000000000201000000000000001900000000000000000000000000000444";

// Keyed archive: root {items: [EvilAgent (raw NSData bookmark, visibility 0, CustomItemProperties
// with DateLastSeen), Helper (Bookmark as an NSMutableData wrapper dict → exercises the NS.data
// unwrap), NoBookmark], properties: {MaxAmount: 10}}.
const SFL2_HEX =
  "62706c6973743030d401020304050674775924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572af102907080f13171a1f2028292a2b2c2d2e2f30313e4228292a2b2c4546474828295556575e6465666b6c6d55246e756c6cd2090a0b0c5824636c61737365735a24636c6173736e616d65a30c0d0e5f10134e534d757461626c6544696374696f6e6172795c4e5344696374696f6e617279584e534f626a656374d2090a1011a311120e5e4e534d757461626c654172726179574e534172726179d2090a1415a315160e5d4e534d757461626c6544617461564e5344617461d2090a1819a2190e564e5344617465d21b1c1d1e5624636c617373574e532e74696d6580042341bdcd65000000005f1027636f6d2e6170706c652e4c5353686172656446696c654c6973742e446174654c6173745365656ed31b2122232426574e532e6b6579735a4e532e6f626a656374738001a1258006a1278005544e616d6554757569645a7669736962696c69747958426f6f6b6d61726b5f1014437573746f6d4974656d50726f70657274696573594576696c4167656e745f102441414141414141412d303030302d303030302d303030302d30303030303030303030303110004f110148626f6f6b4801000000000410300000000000000000000000000000000000000000000000000000000000000000000000c8000000080000000106000014000000280000000c000000010100004170706c69636174696f6e731100000001010000426f6f6b6d61726b65644170702e6170700000000800000001060000540000006000000004000000030300000200000004000000030300004d0000000c000000010100004d6163696e746f7368204844240000000101000043434343434343432d313131312d323232322d333333332d3434343434343434343434341100000001010000426f6f6b6d61726b65644170702e61707000000034000000feffffff010000000000000005000000041000000400000000000000051000004400000000000000102000006c0000000000000011200000800000000000000017f00000ac00000000000000d31b2122233238a5333435363780088009800a800b800ca5393a3b3c3d800d800e800f80108007d21b3f4041574e532e6461746180034f110140626f6f6b4001000000000410300000000000000000000000000000000000000000000000000000000000000000000000cc00000010000000010600001c0000002c0000003800000048000000050000000101000055736572730000000300000001010000626f620007000000010100004c696272617279000a0000000101000048656c7065722e6170700000100000000106000074000000800000008c000000980000000400000003030000020000000400000003030000030000000400000003030000040000000400000003030000050000000c000000010100004d6163696e746f73682048440a0000000101000048656c7065722e617070000028000000feffffff010000000000000004000000041000000400000000000000051000005c0000000000000010200000a40000000000000017f00000b800000000000000d31b2122234344a0a05648656c7065725f102441414141414141412d303030302d303030302d303030302d3030303030303030303030321001d31b212223494fa54a4b4c4d4e80148015801680178018a550515253548019801a801b801280135a4e6f426f6f6b6d61726b5f102441414141414141412d303030302d303030302d303030302d303030303030303030303033d31b212223585ba2595a801d801ea25c5d801f8020d21b225f608002a36162638011801c80215f1024636f6d2e6170706c652e4c5353686172656446696c654c6973742e4d6178416d6f756e74100ad31b2122236769a1688023a16a8024556974656d735a70726f70657274696573d31b2122236e71a26f7080268027a2727380228025d1757654726f6f74802812000186a000080011001b002400290032004400700076007b0084008f009300a900b600bf00c400c800d700df00e400e800f600fd01020105010c0111011801200122012b0155015c0164016f01710173017501770179017e0183018e019701ae01b801df01e1032d0334033a033c033e034003420344034a034c034e03500352035403590361036304a704ae04af04b004b704de04e004e704ed04ef04f104f304f504f704fd04ff0501050305050507051205390540054305450547054a054c054e055305550559055b055d055f05860588058f0591059305950597059d05a805af05b205b405b605b905bb05bd05c005c505c700000000000002010000000000000078000000000000000000000000000005cc";

// An sfl2 root that ALSO carries `version: 2` — must not be claimed by the legacy-BTM guard.
const SFL2_WITH_VERSION2_HEX =
  "62706c6973743030d401020304050630335924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572ad07080f1314151617222627282955246e756c6cd2090a0b0c5824636c61737365735a24636c6173736e616d65a30c0d0e5f10134e534d757461626c6544696374696f6e6172795c4e5344696374696f6e617279584e534f626a656374d2090a1011a311120e5e4e534d757461626c654172726179574e534172726179544e616d6558426f6f6b6d61726b565632526f6f744f110148626f6f6b4801000000000410300000000000000000000000000000000000000000000000000000000000000000000000c8000000080000000106000014000000280000000c000000010100004170706c69636174696f6e731100000001010000426f6f6b6d61726b65644170702e6170700000000800000001060000540000006000000004000000030300000200000004000000030300004d0000000c000000010100004d6163696e746f7368204844240000000101000043434343434343432d313131312d323232322d333333332d3434343434343434343434341100000001010000426f6f6b6d61726b65644170702e61707000000034000000feffffff010000000000000005000000041000000400000000000000051000004400000000000000102000006c0000000000000011200000800000000000000017f00000ac00000000000000d318191a1b1c1f5624636c617373574e532e6b6579735a4e532e6f626a656374738001a21d1e80038004a2202180058006d2181a23248002a1258007556974656d735776657273696f6e1002d318191a1b2a2da22b2c8009800aa22e2f8008800bd1313254726f6f74800c12000186a000080011001b002400290032004400520058005d006600710075008b009800a100a600aa00b900c100c600cf00d60222022902300238024302450248024a024c024f025102530258025a025c025e0264026c026e02750278027a027c027f028102830286028b028d0000000000000201000000000000003400000000000000000000000000000292";

describe("parseMacLoginItemBtm — classic com.apple.loginitems.plist (Alias records)", () => {
  it("recognizes the plain-plist container and decodes a v2 Alias record", () => {
    const r = parseMacLoginItemBtm(buf(LOGINITEMS_PLIST_HEX));
    expect(r).not.toBeNull();
    expect(r!.sourceFormat).toBe("loginitems-plist");
    expect(r!.format).toBe("MacLoginItemsPlist");
    expect(r!.total).toBe(5);
    expect(r!.kept).toBe(5);
    const evil = r!.events.find((e) => e.canonical!.macLoginItem!.itemName === "EvilAgent")!;
    const b = evil.canonical!.macLoginItem!;
    expect(b.targetRecordKind).toBe("alias-record");
    expect(b.aliasVersion).toBe(2);
    expect(b.aliasKind).toBe(0);
    expect(b.targetPathComponents).toEqual(["Applications", "EvilAgent.app"]);
    expect(b.targetCnidPath).toEqual(["2", "1234", "5678"]);
    expect(b.targetCnid).toBe("5678");
    expect(b.folderCnid).toBe("1234");
    expect(b.volumeName).toBe("Macintosh HD");
    expect(b.volumeCreationDate).toBe("2015-03-04T05:06:07.000Z");
    expect(b.fileCreationDate).toBe("2016-07-08T09:10:11.000Z");
    expect(b.displayName).toBe("EvilAgent.app");
    expect(b.posixMountPoint).toBe("/");
    expect(b.bookmarkDecodeStatus).toBe("decoded");
    expect(b.targetEvidence).toBe("stored-alias-metadata");
    expect(b.mappingVersion).toBe("mac-login-item-target-v2");
    expect(evil.description).toContain("/Applications/EvilAgent.app");
    expect(evil.description).toContain("never evidence of execution");
    expect(evil.severity).toBe("Info");
  });

  it("routes a v3 record whose appinfo is 'alis' to the ALIAS decoder, never the bookmark one", () => {
    const r = parseMacLoginItemBtm(buf(LOGINITEMS_PLIST_HEX))!;
    const b = r.events.find((e) => e.canonical!.macLoginItem!.itemName === "Payloads")!.canonical!
      .macLoginItem!;
    expect(b.targetRecordKind).toBe("alias-record");
    expect(b.aliasVersion).toBe(3);
    expect(b.aliasKind).toBe(1);
    expect(b.targetPathComponents).toEqual(["Users", "bob", "Payloads"]);
    expect(b.bookmarkDecodeStatus).toBe("decoded");
    expect(b.rawFields?.aliasAppinfo).toBe("alis");
  });

  it("routes a real CFURL bookmark stored under the Alias key to the bookmark decoder", () => {
    const r = parseMacLoginItemBtm(buf(LOGINITEMS_PLIST_HEX))!;
    const b = r.events.find((e) => e.canonical!.macLoginItem!.itemName === "Bookmarked")!.canonical!
      .macLoginItem!;
    expect(b.targetRecordKind).toBe("cfurl-bookmark");
    expect(b.targetPathComponents).toEqual(["Applications", "BookmarkedApp.app"]);
    expect(b.volumeUuid).toBe("CCCCCCCC-1111-2222-3333-444444444444");
    expect(b.targetEvidence).toBe("stored-bookmark-metadata");
  });

  it("keeps a malformed Alias and an item with no Alias, disclosing each", () => {
    const r = parseMacLoginItemBtm(buf(LOGINITEMS_PLIST_HEX))!;
    const broken = r.events.find((e) => e.canonical!.macLoginItem!.itemName === "Broken")!.canonical!
      .macLoginItem!;
    expect(broken.bookmarkDecodeStatus).toBe("malformed");
    expect(broken.targetRecordKind).toBe("alias-record");
    const none = r.events.find((e) => e.canonical!.macLoginItem!.itemName === "NoAlias")!.canonical!
      .macLoginItem!;
    expect(none.bookmarkDecodeStatus).toBe("absent");
    expect(r.malformedBookmarks).toBe(1);
  });

  it("returns null for a plain bplist that is not a loginitems plist", () => {
    // plistlib.dumps({"hello": "world"}, FMT_BINARY)
    const plain =
      "62706c6973743030d101025568656c6c6f55776f726c64080b110000000000000101000000000000000300000000000000000000000000000017";
    expect(parseMacLoginItemBtm(buf(plain))).toBeNull();
  });
});

describe("parseMacLoginItemBtm — SessionLoginItems.sfl2 (keyed archive)", () => {
  it("recognizes the sfl2 container and decodes each item's bookmark", () => {
    const r = parseMacLoginItemBtm(buf(SFL2_HEX));
    expect(r).not.toBeNull();
    expect(r!.sourceFormat).toBe("sfl2");
    expect(r!.format).toBe("MacSfl2");
    expect(r!.total).toBe(3);
    const evil = r!.events.find((e) => e.canonical!.macLoginItem!.itemName === "EvilAgent")!.canonical!
      .macLoginItem!;
    expect(evil.targetRecordKind).toBe("cfurl-bookmark");
    expect(evil.targetPathComponents).toEqual(["Applications", "BookmarkedApp.app"]);
    expect(evil.rawFields?.uuid).toBe("AAAAAAAA-0000-0000-0000-000000000001");
    expect(evil.rawFields?.visibility).toBe("0");
    expect(evil.rawFields?.["CustomItemProperties.com.apple.LSSharedFileList.DateLastSeen"]).toMatch(
      /^2016-11-05T/,
    );
    expect(evil.mappingVersion).toBe("mac-login-item-target-v2");
  });

  it("unwraps a Bookmark stored as an NSMutableData wrapper dict (NS.data)", () => {
    const r = parseMacLoginItemBtm(buf(SFL2_HEX))!;
    const helper = r.events.find((e) => e.canonical!.macLoginItem!.itemName === "Helper")!.canonical!
      .macLoginItem!;
    expect(helper.bookmarkDecodeStatus).toBe("decoded");
    expect(helper.targetPathComponents).toEqual(["Users", "bob", "Library", "Helper.app"]);
  });

  it("keeps an item with no Bookmark as absent", () => {
    const r = parseMacLoginItemBtm(buf(SFL2_HEX))!;
    const none = r.events.find((e) => e.canonical!.macLoginItem!.itemName === "NoBookmark")!.canonical!
      .macLoginItem!;
    expect(none.bookmarkDecodeStatus).toBe("absent");
  });

  it("is not claimed by the legacy-BTM guard when the root also carries version: 2", () => {
    const r = parseMacLoginItemBtm(buf(SFL2_WITH_VERSION2_HEX));
    expect(r).not.toBeNull();
    expect(r!.sourceFormat).toBe("sfl2");
    expect(r!.kept).toBe(1);
  });

  it("still parses both BTM generations exactly as before", () => {
    expect(parseMacLoginItemBtm(buf(LEGACY_BTM_HEX))!.sourceFormat).toBe("btm-legacy");
    expect(parseMacLoginItemBtm(buf(MODERN_BTM_HEX))!.sourceFormat).toBe("btm-modern");
    expect(parseMacLoginItemBtm(buf(LEGACY_BTM_HEX))!.events[0].canonical!.macLoginItem!.mappingVersion).toBe(
      "mac-login-item-target-v1",
    );
  });
});

describe("parseMacLoginItemBtm — code-review regressions (#1301)", () => {
  // A classic plist built from parts: SessionItems.CustomListItems with the given items.
  // Hand-assembled bplist00 is impractical here, so these reuse LOGINITEMS_PLIST_HEX's real
  // records and exercise the collector/mapper seams through the parser's own public surface.
  it("bounds merged rawFields at MAX_RAW_FIELDS with the alias reader's own facts first", () => {
    const r = parseMacLoginItemBtm(buf(LOGINITEMS_PLIST_HEX))!;
    for (const e of r.events) {
      const rf = e.canonical!.macLoginItem!.rawFields ?? {};
      expect(Object.keys(rf).length).toBeLessThanOrEqual(32);
    }
    const evil = r.events.find((e) => e.canonical!.macLoginItem!.itemName === "EvilAgent")!.canonical!
      .macLoginItem!;
    expect(evil.rawFields?.aliasRecsize).toBe(String(354));
    expect(evil.rawFields?.aliasFsType).toBe("H+");
  });

  it("a keyed archive whose `items` carry none of the sfl2 keys is not claimed as an sfl2", () => {
    // plistlib-built keyed archive: root NSDictionary {items: NSArray[1, 2, 3]} — an `items`
    // array, but no item carries Name/Bookmark/uuid. Before the positive signature this minted
    // three empty "login items" under a matching filename (code review finding 12).
    const notSfl2 =
      "62706c6973743030d401020304050621245924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572a607081112181e55246e756c6cd3090a0b0c0d0f5624636c617373574e532e6b6579735a4e532e6f626a656374738004a10e8002a1108003556974656d73d2090b13148005a3151617100110021003d2191a1b1c5824636c61737365735a24636c6173736e616d65a21c1d5c4e5344696374696f6e617279584e534f626a656374d2191a1f20a2201d574e534172726179d1222354726f6f74800112000186a008111b242932444b51585f67727476787a7c8287898d8f919398a1acafbcc5cacdd5d8dddf00000000000001010000000000000025000000000000000000000000000000e4";
    expect(parseMacLoginItemBtm(buf(notSfl2))).toBeNull();
  });

  it("a decoded alias with no stored name or path is labelled as such, not '(no bookmark)'", () => {
    // plistlib.dumps({"SessionItems": {"CustomListItems": [{"Name": "Nameless-v2", "Alias": <152-byte
    // v2 alias record: empty Pascal filename, no tags>}]}}, FMT_BINARY). The reader decodes it
    // cleanly (decodeStatus "decoded"), yet it carries no path, no carbon path and no display
    // name. "(no bookmark)" is the label for an ABSENT record, so a present-but-empty one must
    // say so instead (#1364).
    const namelessV2 =
      "62706c6973743030d101025c53657373696f6e4974656d73d103045f100f437573746f6d4c6973744974656d73a105d20607080955416c696173544e616d654f1098000000000098000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff5b4e616d656c6573732d7632080b181b2d2f343a3fda0000000000000101000000000000000a000000000000000000000000000000e6";
    const r = parseMacLoginItemBtm(buf(namelessV2))!;
    expect(r.events).toHaveLength(1);
    const nameless = r.events[0];
    const c = nameless.canonical!.macLoginItem!;
    expect(c.bookmarkDecodeStatus).toBe("decoded");
    expect(c.targetRecordKind).toBe("alias-record");
    expect(c.targetPathComponents).toBeUndefined();
    expect(nameless.description).toContain("(alias record stores no name or path)");
    expect(nameless.description).not.toContain("(no bookmark)");

    // The absent state keeps its own label — an item with no Alias key at all.
    const fixture = parseMacLoginItemBtm(buf(LOGINITEMS_PLIST_HEX))!;
    const none = fixture.events.find((e) => e.canonical!.macLoginItem!.itemName === "NoAlias")!;
    expect(none.description).toContain("(no bookmark)");
    expect(none.description).not.toContain("stores no name or path");
  });
});
