# UPG file format documentation
*NOTE: This has all been learned from reverse engineering the file, and from previous work done by [Amaury Pouly](https://github.com/pamaury) and [Marcin Bukat](https://github.com/wodz) on the [Rockbox UPGTool](https://github.com/wangyu-/rockbox-modified/blob/master/utils/nwztools/upgtools/upgtool.c). Big credit to them.*

*NOTE 2: This documentation was written after I completed the source code. My names for things here will likely differ from how they are reffered to in source. I was still writing the source while learning the format. I want to do a rewrite eventually.*

## The file "sectors"

UPG files consist of 4 major sectors. I'm going to refer to them as "Verification" "Metadata" "Data Table" and "Data", with "Metadata" and "Data Table" being reffered to as a whole as the "Header"

### Verification

The verifcation sector is the first 16 bytes of the file. It's just a MD5 hash of the remaining file, before decryption.

It's reccomended you check and update this file when decrypting and encrypting this file respectively. 

### Metadata

The metadata sector is 16 bytes in V1 and 32 bytes in V2 (to account for the difference in encryption)

Both V1 and V2 metadata sectors contain a `signature` (more info about that in the encryption section) and a `UInt32LE FileCount`

The signature is 8 bytes in V1, and 16 bytes in V2. The file count is always a UInt32, and thus is 4 bytes in both versions.

The remaining data (4 Bytes in V1, 12 Bytes in V2) is padding and can be thrown away.

### Data Table

The data table is an array of "Data Table Records".

The entry is 8 bytes on V1 and 16 bytes on V2.

Despite the difference in size (the reason for which will be expanded on in the encryption section) both entry versions contain a `UInt32LE Offset` and a `UInt32LE Size`, totaling 8 bytes.

The remaining 8 bytes in V2 can be thrown away.

The number of records is equivalent to the `FileCount` field in the Metadata sector. Requiring that to be parsed first.

### Data 

The data sector is the remainder of the file. It is split up into chunks as described by the data table. The `Offset` and `Size` fields for each data table record defines the start and length of the data.

You can use this to slice the data out of the file.

It should be noted the Offset and Size fields define the start and length of the data *before decryption*. Though normally this wouldn't matter due to the 1:1 size nature of the encryption formats used, it's critical to understanding how to decrypt the data.

## The encryption

There are 2 encryption "versions" reffered here as "v1" and "v2". V2 is documented from the NW-ZX300; **V1 was added in this fork from the NWZ-A10 series (Japanese NW-A16)** — see "V1 Encryption" below.

### V1 Encryption (NWZ-A10 generation and older) — added in this fork

Measured on Sony's NWZ-A10 1.21 packages (international and Japanese), on a Japanese
NW-A16, and cross-checked on a Sony NWZ-E580 1.02 package. Same algorithm as
Rockbox's `utils/nwztools/upgtools/upg.c`.

- **Cipher: single DES, ECB, everywhere** — header, data table and data blobs
  alike. No CBC, no IV, so a V1 package can be decrypted in one pass from byte 16.
- **KAS → key + signature.** The KAS is the 16-byte (32 hex char) per-device secret.
  Decrypt it with single DES-ECB under the constant passkey `ed295076`:
  `DES-ECB-decrypt(key = "ed295076", KAS)` → 16 bytes = **8-byte key** ∥ **8-byte
  signature**. Unlike V2, there is no CBC and no IV in this step. Both results are
  8 printable-ASCII characters. Keep the three values distinct: the **KAS** is what
  is stored / recovered and what a player reports in its `kas` NVP node; the **key**
  decrypts the package; the **signature** is what must appear at file offset 16.

  | model | KAS (stored, 32 hex) | key (8 B ASCII) | signature (8 B ASCII) |
  |---|---|---|---|
  | NWZ-A10 international | `2572f4a7b8c1a08aeb5142ce9cb834d6` | `ec2889e3` | `f62ced8a` |
  | NW-A16 / A17 Japanese | `18a8b9bf121554408c60d2e67338a6d4` | `88d26023` | `f132af27` |
  | NWZ-E580 | `6e25f79812eca7ceed04819d833e80af` | `a70807da` | `97e8ce46` |

- **Verifying the key.** A tool knows it has the right KAS when the 8 bytes it
  decrypts at file offset 16 equal the derived signature. A player makes the same
  check and **rejects a package signed for another device before running its
  script**, so a wrong key is caught safely, not by a brick.
- **Layout** (offsets in the file, the encrypted region starts at 16):

  | offset | size | content |
  |---|---|---|
  | 0 | 16 | MD5 of bytes 16..end (i.e. of the *encrypted* payload) |
  | 16 | 8 | signature |
  | 24 | 4 | `UInt32LE` file count |
  | 28 | 4 | padding |
  | 32 | 8 × count | table: `UInt32LE offset`, `UInt32LE size` |
  | … | | blobs, each zero-padded to a multiple of 8 |

  Table **offsets are absolute file offsets**; **sizes are the real, unpadded
  sizes** (e.g. 2 120 and 54 209 509 bytes in Sony's A10 package). A tool that
  stores padded sizes, or lays out later blobs using real sizes instead of the
  padded length, corrupts V1 packages. The MD5 at offset 0 is computed over the
  encrypted bytes, so it is updated *after* re-encrypting, not before.

- **Keys are per model/region, not only per series.** The three examples above are
  three different keys for the same V1 format. Sony's international NWZ-A10 package
  opens only with the A10-international key; its **Japanese** NW-A16/A17 package only
  with the Japanese key (the value a Japanese NW-A16 reports in its `kas` NVP node);
  the NWZ-E580 only with its own. The container format itself is identical across all
  of them (verified byte-for-byte on A10 and E580 packages).
- **Sectors of an NWZ-A10 package**: 0 = installer shell script (`/bin/sh`),
  1 = kernel (4 259 840 B), 2 = gzip'd tar of the root filesystem. (An NWZ-E580
  package has the same three-sector shape: script, kernel, gzip'd rootfs tar.)
- **Update-flag rule (anti-brick)**: the update is triggered by the `fup` NVP flag.
  Sony's installer clears it only on success (`nvpflag fup 0` at the end);
  Rockbox-style scripts clear it first (`nvpflag fup 0xFFFFFFFF`), so a failing
  script cannot leave the player looping into update mode. This fork's `pack` and
  `rekey` refuse to write a custom script that does not clear it first.

### V2 Encryption

Before starting on how exactly to decrypt the sectors, first some background is needed on the type of encryption the UPG file uses, and how those encryption formats work.

V2 encryption uses 2 encryption standards. `AES-128-CBC` (CBC) and `AES-128-ECB` (ECB).

Different parts of the file use different standards. Generally, CBC is used for the header and ECB is used for the data.

Both CBC and ECB chunk data into 16 byte chunks before handling it.

CBC (Cipher Block Chaining) is *stateful*, that is to say that the last chunk of 16 bytes decoded or encoded will effect the next 16 bytes. When decoding the first 16 bytes of data, it uses the Initialization Vector (IV) instead of the non-existant last 16 bytes.

Thus, to encrypt or decrypt a chunk of data, you must:
 1. Initialize a encrypter/decrypter with the KAS Key and the IV constant
 2. Encrypt/Decrypt each 16 byte chunk of the data in order.

ECB (Electronic CodeBook) is not stateful, each chunk of 16 bytes can be decoded in any order. It is only initialized with the KAS Key.

Thus, to encrypt or decrypt the header, you must:
 1. Initialize a encrypter/decrypter with the KAS Key
 2. In any order:
    - Encrypt/Decrypt the Metadata sector
    - Encrypt/Decrypt each data table record.

### The Key And Signature (KAS)

For each device, a KAS has been recovered or brute forced.

The KAS contains an encrypted Key & Signature unique to each device.

Both the Key and Signature are 16 bytes in V2, and 8 bytes in V1.

The method for obtanining the Key and Signature from a KAS depends on the encryption version. V1 is described in "V1 Encryption" above; V2 below.

 1. Initialize a CBC decrypter with the Passkey constant and IV constant.
 2. Decrypt the first 16 bytes of the KAS, as the Key
 3. Decrypt the second 16 bytes of the KAS, as the Signature
 4. Discard this instance of the CBC decrypter.

## Data Sector Details

The data sector contains a number of unnamed binary blobs. This tool spits out each blob with the name of the index it was found in the data table sector.

From here on each sector will be reffered to by it's 0-indexed ID

It's also important to understand that this information is only based on my experience with my personal UPG (V2.02 for the NW-ZX300). There is nothing in the file format of the UPG that specifies the purpose of each sector.

Sector 0:
 - A bash script. Seemingly the entrypoint for the updater

Sector 1:
 - A plaintext file that seems to handle decompression (more on that later)

Sector 2:
 - (? not much research done here) An android bootimg

Sector 3:
 - Very little idea. binwalk claims it has multiple boot sections, but no research has been done here

Sector 4:
 - A set of gz compressed RGB565 images used by (what i assume) is the bootloader. Seems to have headers above the compressed data, more research is needed.

Sector 5:
 - Very little idea. No research has been done

Sector 6:
 - A compressed ext4 filesystem reffered to as "system.img" in sector 1.

Sector 7:
 - Very little idea. No research has been done

Sector 8:
 - tar.gz of a 480x800 RGB32 "fwup_bg.rgb" file
