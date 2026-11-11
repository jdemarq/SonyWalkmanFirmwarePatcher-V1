import { findModel } from "./src/upg/utils";
import * as cp from "child_process"
import { Upg } from "./src/upg";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { runCli } from "./src/cli";

// Usage: ts-node index info|extract|pack|rekey ...   (see src/cli.ts)
//    or: ts-node index <model> [file.UPG]   (interactive, original behaviour)
//   model: a name from src/upg/constants.ts, e.g. nw-zx300, nwz-a10, nw-a16-jp
//   file : defaults to ./FW.UPG
// Unpacks every file into ./bins/<n>.bin, waits for you to edit them, then
// repacks the changed ones into ./FW_MOD.UPG.
// The NW-ZX300 specifics (compressed sector 6, its hash in sector 1, the
// Windows injector) only run for nw-zx300. For V1 players (NWZ-A10 & co.),
// start the update with Rockbox's scsitool (do_fw_upgrade), not the injector.

const keypress = async () => {
  process.stdin.setRawMode(true)
  return new Promise<void>(resolve =>
    process.stdin.once('data', () => {
      process.stdin.setRawMode(false)
      resolve()
    })
  )
}

(async () => {
  // Non-interactive commands first: info / extract / pack / rekey (see src/cli.ts)
  try {
    if (runCli(process.argv.slice(2))) process.exit(0);
  } catch (e) {
    console.error("error: " + (e as Error).message);
    process.exit(1);
  }

  const modelName = process.argv[2] || "nw-zx300";
  const fwFile = process.argv[3] || "./FW.UPG";
  const zx300 = modelName.toLowerCase() === "nw-zx300";

  const upg = Upg.fromFile(fwFile, findModel(modelName));
  console.log(`${fwFile}: model ${modelName}, UPG v${upg.getVersion()}, ${upg.getFileCount()} files`);

  fs.mkdirSync("./bins", { recursive: true });
  const hashes: Buffer[] = [];
  const md5 = (b: Buffer) => crypto.createHash("md5").update(b).digest();

  for (let i = 0; i < upg.getFileCount(); i++) {
    const element = upg.getFile(i, zx300 && i == 6);

    console.log("Writing: " + i);
    fs.writeFileSync("./bins/" + i + ".bin", element);
    hashes[i] = md5(element);
  }

  console.log("Modify the files, hit enter when done");

  await keypress();

  if (zx300) {
    // Buffers must be compared with equals(), not == (always false upstream).
    const six = fs.readFileSync("./bins/6.bin");
    const sixUpdated = !md5(six).equals(hashes[6]);
    const oneUpdated = !md5(fs.readFileSync("./bins/1.bin")).equals(hashes[1]);

    if (sixUpdated && !oneUpdated) {
      const fileName = fs.readFileSync("./bins/1.bin", "utf-8").split(" ")[2];
      fs.writeFileSync("./bins/1.bin", `${six.length} ${md5(six).toString("hex")} ${fileName}`);
    }
  }

  for (let i = 0; i < upg.getFileCount(); i++) {
    const file = fs.readFileSync("./bins/" + i + ".bin");

    if (!md5(file).equals(hashes[i])) {
      console.log("File " + i + " changed. Updating...");
      upg.setFile(i, file, zx300 && i == 6);
    }
  }

  fs.writeFileSync("./FW_MOD.UPG", upg.toBinary());
  console.log("Wrote ./FW_MOD.UPG");

  if (zx300) {
    fs.writeFileSync("./inject/Data/Device/NW_WM_FW.UPG", upg.toBinary());
    cp.execFileSync(path.join(__dirname, "inject", "SoftwareUpdateTool.exe"), { cwd: path.join(__dirname, "inject") })
  }

  process.exit();
})()
