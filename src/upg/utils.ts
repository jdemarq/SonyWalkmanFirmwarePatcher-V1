import { DES_IV, DES_PASSKEY, MODEL_LIST, Model, AES_PASSKEY, AES_IV } from "./constants";
import * as crypto from "crypto";
import { Kas } from "./kas";

export enum CryptMode {
  Decrypt,
  Encrypt,
}

export function getKeyAndSignatureFromModel({ name, confirmed, kas: kasStr }: Model) {
  const kas = Buffer.from(kasStr, "hex");

  if (kas.length != 16 && kas.length != 32)
    throw new Error(`The KAS for model ${name} has the wrong length (expected 16 or 32 bytes, found ${kas.length} bytes)`);

  return Kas.fromBinary(kas);
}

export function findModel(name: string): Model {
  for (const model of MODEL_LIST) {
    if (model.name.toLowerCase() === name.toLowerCase())
      return model;
  }

  throw new Error(`Couldn't find model with name ${name}`)
}

export function roundUp(val: number, to: number): number {
  const base = Math.floor(val / to) * to;

  if (val % to !== 0) return base + to;

  return base;
}

export function chunkBuffer(buffer: Buffer, chunkSize: number): Buffer[] {
  var result: Buffer[] = [];
  var len = buffer.length;
  var i = 0;

  while (i < len) {
    result.push(buffer.slice(i, i += chunkSize));
  }

  return result;
}

/**
 * Try every known KAS on a package and return the models whose signature
 * matches (several models can share one KAS). Read-only.
 */
export function detectModels(blob: Buffer): Model[] {
  // imported lazily to avoid a circular import at module load
  const { Upg } = require("./index");
  const found: Model[] = [];
  for (const m of MODEL_LIST) {
    try { Upg.fromBinary(blob, m); found.push(m); } catch (e) { /* not this key */ }
  }
  return found;
}

export type LintResult = { ok: boolean, problems: string[] };

/**
 * Anti-brick check of a V1 installer script (sector 0). Every Sony and Rockbox
 * V1 update script clears the update flag first: if the script fails after
 * that, the player boots normally instead of looping into update mode.
 */
export function lintInstallerScript(script: Buffer): LintResult {
  const problems: string[] = [];
  const text = script.toString("latin1");
  if (!text.startsWith("#!")) problems.push("sector 0 is not a shell script (no #! line)");
  const commands = text.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  const first = commands[0] || "";
  if (!/^nvpflag\s+fup\s+0x[fF]{8}\b/.test(first)) {
    if (/fwpup/.test(text))
      problems.push(`this is a Sony full-system installer (it calls fwpup): it clears fup only on success, at the end — normal for official packages, but if it fails the player may loop into update mode. Only flash official packages of your region`);
    else
      problems.push(`first command is "${first.slice(0, 60)}", not "nvpflag fup 0xFFFFFFFF" — a failing script could leave the player looping into update mode`);
  }
  return { ok: problems.length === 0, problems };
}
