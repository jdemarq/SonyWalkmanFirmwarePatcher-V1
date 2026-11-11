// Non-interactive commands. Usage (ts-node index <command> ...):
//   info    <file.UPG>                        read-only: key/region, files, types, sha256
//   extract <file.UPG> <dir> [--model m]      write <dir>/<n>.bin + manifest.json
//   pack    <dir> <out.UPG> [--model m] [--force]   V1: rebuild from <dir> (anti-brick lint)
//   rekey   <file.UPG> <model> <out.UPG> [--force]  V1: re-sign for another region's key
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { Upg } from "./upg";
import { detectModels, findModel, lintInstallerScript } from "./upg/utils";
import { Model } from "./upg/constants";

const sha256 = (b: Buffer) => crypto.createHash("sha256").update(b).digest("hex");

function kind(b: Buffer): string {
  if (b.slice(0, 2).toString() === "#!") return "shell script";
  if (b[0] === 0x1f && b[1] === 0x8b) return "gzip";
  if (b.slice(257, 262).toString() === "ustar") return "tar";
  if (b.slice(0, 4).toString("hex") === "7f454c46") return "ELF";
  return "binary";
}

function open(file: string, modelName?: string): { upg: Upg, model: Model, others: Model[] } {
  const blob = fs.readFileSync(file);
  if (modelName) {
    const model = findModel(modelName);
    return { upg: Upg.fromBinary(blob, model), model, others: [] };
  }
  const found = detectModels(blob);
  if (!found.length)
    throw new Error(`${file}: no known key matches (MD5 ok?) — unknown model/region, pass --model or add its KAS`);
  return { upg: Upg.fromBinary(blob, found[0]), model: found[0], others: found.slice(1) };
}

function guard(script: Buffer, force: boolean) {
  const r = lintInstallerScript(script);
  if (r.ok) { console.log("anti-brick check: OK (sector 0 clears fup first)"); return; }
  r.problems.forEach(p => console.log("anti-brick check: " + p));
  if (!force) throw new Error("refusing to write this package (use --force if you really mean it)");
  console.log("--force given: writing anyway");
}

export function runCli(argv: string[]): boolean {
  const flag = (n: string) => argv.includes(n);
  const opt = (n: string) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  const pos = argv.filter((a, i) => !a.startsWith("--") && !(i > 0 && argv[i - 1] === "--model"));
  const [cmd, a1, a2, a3] = pos;

  switch (cmd) {
    case "info": {
      const { upg, model, others } = open(a1, opt("--model"));
      console.log(`${a1}: UPG v${upg.getVersion()}, key "${model.name}"` +
        (others.length ? ` (same key as: ${others.map(m => m.name).join(", ")})` : "") +
        `, ${upg.getFileCount()} files`);
      for (let i = 0; i < upg.getFileCount(); i++) {
        const f = upg.getFile(i, false).slice(0, upg.getFileSize(i));
        console.log(`  [${i}] ${String(f.length).padStart(9)} B  ${kind(f).padEnd(12)} sha256 ${sha256(f)}`);
      }
      if (upg.getVersion() === 1) {
        const r = lintInstallerScript(upg.getFile(0, false).slice(0, upg.getFileSize(0)));
        console.log(r.ok ? "anti-brick check: OK (sector 0 clears fup first)" : r.problems.map(p => "anti-brick check: " + p).join("\n"));
      }
      return true;
    }
    case "extract": {
      const { upg, model } = open(a1, opt("--model"));
      fs.mkdirSync(a2, { recursive: true });
      const files = [];
      for (let i = 0; i < upg.getFileCount(); i++) {
        const f = upg.getFile(i, false).slice(0, upg.getFileSize(i));
        fs.writeFileSync(path.join(a2, `${i}.bin`), f);
        files.push({ index: i, size: f.length, sha256: sha256(f) });
      }
      fs.writeFileSync(path.join(a2, "manifest.json"),
        JSON.stringify({ source: path.basename(a1), model: model.name, version: upg.getVersion(), files }, null, 2) + "\n");
      console.log(`extracted ${files.length} files to ${a2} (key "${model.name}")`);
      return true;
    }
    case "pack": {
      const manifest = JSON.parse(fs.readFileSync(path.join(a1, "manifest.json"), "utf-8"));
      const model = findModel(opt("--model") || manifest.model);
      if (manifest.version !== 1) throw new Error("pack from a directory is V1-only; for V2 use the interactive mode");
      const files = manifest.files.map((f: any) => fs.readFileSync(path.join(a1, `${f.index}.bin`)));
      manifest.files.forEach((f: any, i: number) => {
        if (sha256(files[i]) !== f.sha256) console.log(`file ${i} changed (${f.size} -> ${files[i].length} B)`);
      });
      guard(files[0], flag("--force"));
      const out = Upg.createV1(model, files).toBinary();
      fs.writeFileSync(a2, out);
      Upg.fromBinary(out, model); // re-open as a self-check
      console.log(`wrote ${a2} (${out.length} B, key "${model.name}", sha256 ${sha256(out)})`);
      return true;
    }
    case "rekey": {
      const { upg, model: from } = open(a1, opt("--model"));
      const to = findModel(a2);
      if (upg.getVersion() !== 1) throw new Error("rekey is V1-only");
      const files = [];
      for (let i = 0; i < upg.getFileCount(); i++) files.push(upg.getFile(i, false).slice(0, upg.getFileSize(i)));
      guard(files[0], flag("--force"));
      const out = Upg.createV1(to, files).toBinary();
      // checks: opens with the new key, refused by the old one (unless they share a KAS), same content
      const re = Upg.fromBinary(out, to);
      for (let i = 0; i < files.length; i++)
        if (!re.getFile(i, false).slice(0, re.getFileSize(i)).equals(files[i])) throw new Error(`rekey: file ${i} differs after re-signing`);
      if (from.kas !== to.kas) {
        let refused = false;
        try { Upg.fromBinary(out, from); } catch (e) { refused = true; }
        if (!refused) throw new Error("rekey: output still opens with the old key");
      }
      fs.writeFileSync(a3, out);
      console.log(`re-signed ${a1} ("${from.name}") -> ${a3} ("${to.name}"), ${files.length} files, sha256 ${sha256(out)}`);
      return true;
    }
  }
  return false;
}
