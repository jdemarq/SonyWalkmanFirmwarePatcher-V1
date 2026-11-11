// V1 regression test against packages whose bytes are known independently.
// Usage: ts-node test/v1.ts <dir>   (dir holds the files listed below)
import * as fs from "fs";
import * as path from "path";
import { Upg } from "../src/upg";
import { findModel } from "../src/upg/utils";

const dir = process.argv[2];
let failed = 0;
const check = (name: string, ok: boolean) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); if (!ok) failed++; };
const rd = (f: string) => fs.readFileSync(path.join(dir, f));
const has = (f: string) => fs.existsSync(path.join(dir, f));

// 1. Japanese-key packages open with nw-a16-jp, and are rejected with nwz-a10
for (const f of ["NW_WM_FW-install-bootmenu-JPKAS.UPG", "NW_WM_FW-uninstall-bootmenu-JPKAS.UPG"]) {
  const u = Upg.fromBinary(rd(f), findModel("nw-a16-jp"));
  check(`${f}: opens with nw-a16-jp (v${u.getVersion()}, ${u.getFileCount()} files)`, u.getVersion() === 1);
  let rejected = false;
  try { Upg.fromBinary(rd(f), findModel("nwz-a10")); } catch (e) { rejected = /Signature/.test(String(e)); }
  check(`${f}: rejected with nwz-a10 (signature mismatch)`, rejected);
  // 2. unpack + repack unchanged = byte-identical
  check(`${f}: repack unchanged is byte-identical`, Upg.fromBinary(rd(f), findModel("nw-a16-jp")).toBinary().equals(rd(f)));
}

// 3. series-key package opens with nwz-a10
{
  const f = "NW_WM_FW-install-bootmenu.UPG";
  check(`${f}: opens with nwz-a10`, Upg.fromBinary(rd(f), findModel("nwz-a10")).getVersion() === 1);
}

// 4. setFile: replace file 1 (payload, real size not a multiple of 8 is allowed)
//    and compare with fix2, built independently by pack_upg.py
if (has("payload-fix2.tar")) {
  const u = Upg.fromBinary(rd("NW_WM_FW-install-bootmenu-JPKAS.UPG"), findModel("nw-a16-jp"));
  u.setFile(1, rd("payload-fix2.tar"));
  check("setFile(1, fix2 payload) == NW_WM_FW-install-bootmenu-fix2-JPKAS.UPG byte for byte",
        u.toBinary().equals(rd("NW_WM_FW-install-bootmenu-fix2-JPKAS.UPG")));
}

// 5. setFile with a size that is NOT a multiple of 8, on a non-last file
{
  const u = Upg.fromBinary(rd("NW_WM_FW-install-bootmenu-JPKAS.UPG"), findModel("nw-a16-jp"));
  const script = Buffer.concat([u.getFile(0, false).slice(0, 4040), Buffer.from("\n# x\n")]); // 4045 B
  u.setFile(0, script);
  const r = Upg.fromBinary(u.toBinary(), findModel("nw-a16-jp"));
  const f0 = r.getFile(0, false).slice(0, 4045), f1 = r.getFile(1, false);
  const orig1 = Upg.fromBinary(rd("NW_WM_FW-install-bootmenu-JPKAS.UPG"), findModel("nw-a16-jp")).getFile(1, false);
  check("setFile(0, 4045 B) round-trips and file 1 is intact", f0.equals(script) && f1.equals(orig1));
}

// 6. createV1 reproduces known packages; lint accepts ours, flags Sony's, refuses a bad script
{
  const { lintInstallerScript } = require("../src/upg/utils");
  const src = Upg.fromBinary(rd("NW_WM_FW-install-bootmenu-JPKAS.UPG"), findModel("nw-a16-jp"));
  const files = [0, 1].map(i => src.getFile(i, false).slice(0, src.getFileSize(i)));
  check("createV1(nw-a16-jp, files) == install-JPKAS byte for byte",
        Upg.createV1(findModel("nw-a16-jp"), files).toBinary().equals(rd("NW_WM_FW-install-bootmenu-JPKAS.UPG")));
  check("lint: our installer passes", lintInstallerScript(files[0]).ok);
  check("lint: a script not clearing fup first is flagged", !lintInstallerScript(Buffer.from("#!/bin/sh\necho hi\nnvpflag fup 0xFFFFFFFF\n")).ok);
}

if (failed) { console.log(`${failed} FAILED`); process.exit(1); }
console.log("all V1 checks passed");
