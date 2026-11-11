import * as crypto from "crypto";
import * as fs from "fs";
import { Model } from "./constants";
import { Kas } from "./kas";
import * as zlib from "zlib";
import { chunkBuffer, getKeyAndSignatureFromModel, roundUp } from "./utils";

enum CryptMode {
  Encrypt,
  Decrypt,
}

export type Header = {
  signature: Buffer,
  fileCount: number,
  version: number,
}

export class Upg {
  static fromFile(file: string, model: Model) {
    return this.fromBinary(fs.readFileSync(file), model);
  }

  static fromBinary(blob: Buffer, model: Model) {
    const fileMd5 = blob.slice(0, 16);
    const computedMd5 = crypto.createHash("md5").update(blob.slice(16)).digest();

    if (!fileMd5.equals(computedMd5))
      throw new Error("MD5 Mismatch");

    const kas = getKeyAndSignatureFromModel(model);
    // V1 keys are 8 bytes (DES), V2 keys 16 bytes (AES)
    const version = kas.getKey().length == 8 ? 1 : 2;
    const headerSize = version === 1 ? 16 : 32;
    const headerBinary = kas.decrypt(blob.slice(16, 16 + headerSize));
    const header: Header = {
      signature: headerBinary.slice(0, kas.getSignature().length),
      fileCount: headerBinary.readUInt32LE(kas.getSignature().length),
      version,
    }

    if (!header.signature.equals(kas.getSignature()))
      throw new Error("Signature Mismatch");

    const fileTable: { offset: number, size: number }[] = [];

    let index = 16 + headerSize;

    for (let i = 0; i < header.fileCount; i++) {
      const buffer = kas.decrypt(blob.slice(index, index += version == 1 ? 8 : 16));

      fileTable.push({
        offset: buffer.readUInt32LE(0),
        size: buffer.readUInt32LE(4),
      })
    }

    return new Upg(blob, fileTable, header, kas);
  }

  /**
   * Build a V1 package from scratch (same layout as Sony's and Rockbox's):
   * MD5 | DES(sig[8] count[4] pad[4] | table count*{offset,size} | blobs padded to 8).
   * Table offsets are absolute file offsets; sizes are the real sizes.
   */
  static createV1(model: Model, files: Buffer[]): Upg {
    const kas = getKeyAndSignatureFromModel(model);
    if (kas.getKey().length !== 8) throw new Error(`createV1: ${model.name} is not a V1 model`);
    const n = files.length;
    const header = Buffer.alloc(16);
    kas.getSignature().copy(header, 0);
    header.writeUInt32LE(n, 8);
    let offset = 16 + 16 + 8 * n;
    const table = Buffer.alloc(8 * n);
    const blobs: Buffer[] = [];
    files.forEach((f, i) => {
      table.writeUInt32LE(offset, 8 * i);
      table.writeUInt32LE(f.length, 8 * i + 4);
      const padded = Buffer.alloc(roundUp(f.length, 8));
      f.copy(padded);
      blobs.push(padded);
      offset += padded.length;
    });
    const enc = kas.encrypt(Buffer.concat([header, table, ...blobs]));
    const md5 = crypto.createHash("md5").update(enc).digest();
    return Upg.fromBinary(Buffer.concat([md5, enc]), model);
  }

  private constructor(
    protected blob: Buffer,
    protected fileTable: { offset: number, size: number }[],
    protected header: Header,
    protected kas: Kas,
  ) {}

  getFileCount(): number {
    return this.header.fileCount;
  }

  /** Real (unpadded) size of file i, from the table. */
  getFileSize(i: number): number { return this.fileTable[i].size; }

  getVersion(): number {
    return this.header.version;
  }

  decompress(buffer: Buffer): Buffer {
    const MAX_CHUNK_SIZE = 4096;
    let pos = 0;

    const decompressed: Buffer[] = [];

    while(pos + 4 < buffer.length) {
      const compressedChunkSize = buffer.readUInt32LE(pos);

      if (compressedChunkSize === 0)
        break;

      decompressed.push(zlib.inflateSync(buffer.slice(pos + 4, pos + 4 + compressedChunkSize)));

      pos += 4 + compressedChunkSize;
    }

    return Buffer.concat(decompressed);
  }

  compress(buffer: Buffer): Buffer {
    return Buffer.concat(chunkBuffer(buffer, 4096).map(el => {
      const compresed = zlib.deflateSync(el);
      const size = Buffer.alloc(4);
      size.writeUInt32LE(compresed.length);
      return Buffer.concat([size, compresed]);
    }));
  }

  getFile(index: number, decompress: boolean): Buffer {
    const { offset, size } = this.fileTable[index]
    if (this.getVersion() == 2) this.kas.resetToCbc()
    const file =  this.kas.decrypt(this.blob.slice(offset, offset + roundUp(size, this.getVersion() == 1 ? 8 : 16)));

    if (decompress) return this.decompress(file);

    return file;
  }

  setFile(index: number, binary: Buffer, compress: boolean = false): void {
    if (this.getVersion() == 2) this.kas.resetToCbc();

    if (compress)
      binary = this.compress(binary);

    // The table stores the REAL size; the blob is padded to the cipher block.
    // (Upstream stored the padded size and laid out later files with it, which
    // corrupts V1 packages, whose sizes are not multiples of 8.)
    const block = this.getVersion() === 1 ? 8 : 16;
    const realSize = binary.length;
    const padded = Buffer.alloc(roundUp(realSize, block));
    binary.copy(padded);
    const encrypt = this.kas.encrypt(padded);

    const { offset: oldOffset, size: oldSize } = this.fileTable[index];
    const oldPadded = roundUp(oldSize, block);

    this.blob = Buffer.concat([
      this.blob.slice(0, oldOffset),
      encrypt,
      this.blob.slice(oldOffset + oldPadded),
    ]);

    const delta = encrypt.length - oldPadded;
    this.fileTable[index] = { offset: oldOffset, size: realSize };
    for (let i = 0; i < this.fileTable.length; i++) {
      if (i !== index && this.fileTable[i].offset > oldOffset)
        this.fileTable[i] = { offset: this.fileTable[i].offset + delta, size: this.fileTable[i].size };
    }
  }

  toBinary() {
    const headerSize = this.getVersion() == 1 ? 16 : 32;
    const fileEntrySize = this.getVersion() == 1 ? 8 : 16;
    let fileTableOffset = 16 + headerSize;

    const headerBuffer = Buffer.alloc(headerSize);
    this.header.signature.copy(headerBuffer);
    headerBuffer.writeUInt32LE(this.header.fileCount, this.header.signature.length);

    this.kas.resetToEcb();

    this.kas.encrypt(headerBuffer).copy(this.blob, 16);

    const blobBeforeFileTable = this.blob.slice(0, fileTableOffset);
    const blobAfterFileTable = this.blob.slice(fileTableOffset + (this.fileTable.length * fileEntrySize));
    const fileTableEntries: Buffer[] = [];

    for (let i = 0; i < this.fileTable.length; i++) {
      const entry = Buffer.alloc(fileEntrySize);

      entry.writeUInt32LE(this.fileTable[i].offset, 0);
      entry.writeUInt32LE(this.fileTable[i].size, 4);

      fileTableEntries.push(this.kas.encrypt(entry));
    }

    this.blob = Buffer.concat([blobBeforeFileTable, ...fileTableEntries, blobAfterFileTable]);

    const computedMd5 = crypto.createHash("md5").update(this.blob.slice(16)).digest();

    computedMd5.copy(this.blob);

    return this.blob;
  }
}
