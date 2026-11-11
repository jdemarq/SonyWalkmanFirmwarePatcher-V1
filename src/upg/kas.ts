import * as crypto from "crypto";
import { DES_PASSKEY, DES_IV, AES_PASSKEY, AES_IV } from "./constants";
import * as aesJs from "aes-js";
// Node's OpenSSL 3 refuses des-ecb; des.js is a pure-JS DES that passes the
// FIPS known-answer test (key 0123456789abcdef, "Now is t" -> 3fa40e8a984d4815).
const desJs = require("des.js");

/** Raw DES-ECB with no padding (input length must be a multiple of 8). */
function desEcb(key: Buffer, data: Buffer, encrypt: boolean): Buffer {
  if (data.length % 8 !== 0) throw new Error("DES-ECB input must be a multiple of 8 bytes");
  const c = desJs.DES.create({ type: encrypt ? "encrypt" : "decrypt", key, padding: false });
  // update() may hold back the last block (it does when decrypting): always final()
  return Buffer.concat([Buffer.from(c.update(data)), Buffer.from(c.final())]);
}

export class Kas {
  static fromBinary(kas: Buffer): Kas {
    switch (kas.length) {
      // device before WM1/NW-A30 use DES
      case 16: {
        // V1 (NWZ-A10 generation and older): DES-ECB-decrypt the KAS with the
        // "ed295076" passkey -> first 8 bytes = key, next 8 = signature
        // (same as Rockbox utils/nwztools/upgtools/upg.c).
        const ks = desEcb(DES_PASSKEY, kas, false);
        return new Kas(ks.slice(0, 8), ks.slice(8, 16));
      }

      // device after WM1/NW-A30 use AES
      case 32: {
        const crypt = new aesJs.ModeOfOperation.cbc(AES_PASSKEY, AES_IV);
        const buf = crypt.decrypt(kas);
        return new Kas(Buffer.from(buf.slice(0, 16)), Buffer.from(buf.slice(16)))
      }
    }
  }

  protected cipher: any;

  constructor(protected readonly key: Buffer, protected readonly sig: Buffer) {
    // V1 keys are 8 bytes (DES), V2 keys 16 (AES)
    if (key.length !== 8) this.cipher = new aesJs.ModeOfOperation.ecb(key);
  }

  isV1(): boolean { return this.key.length === 8; }

  decrypt(buffer: Buffer): Buffer {
    if (this.isV1()) return desEcb(this.key, buffer, false);
    return Buffer.from(this.cipher.decrypt(buffer) as Uint8Array);
  }

  encrypt(buffer: Buffer): Buffer {
    if (this.isV1()) return desEcb(this.key, buffer, true);
    return Buffer.from(this.cipher.encrypt(buffer) as Uint8Array);
  }

  // V1 is DES-ECB everywhere: mode switches are no-ops
  resetToCbc() {
    if (this.isV1()) return;
    this.cipher = new aesJs.ModeOfOperation.cbc(this.key, AES_IV);
  }

  resetToEcb() {
    if (this.isV1()) return;
    this.cipher = new aesJs.ModeOfOperation.ecb(this.key);
  }

  getKey() { return this.key }
  getSignature() { return this.sig }
}
