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

Measured on Sony's NWZ-A10 1.21 packages (international and Japanese) and on a
Japanese NW-A16. Same algorithm as Rockbox's `utils/nwztools/upgtools/upg.c`.

- **Cipher: single DES, ECB, everywhere** — header, data table and data blobs
  alike. No CBC, no IV, so a V1 package can be decrypted in one pass from byte 16.
- **Key and signature from the KAS**: the KAS is 16 bytes (32 hex chars).
  `DES-ECB-decrypt(KAS, key = "ed295076")` gives 16 bytes: the first 8 are the
  **key**, the next 8 the **signature**. Both are printable ASCII
  (e.g. `ec2889e3` / `f62ced8a` for the NWZ-A10 international key).
- **Layout** (offsets in the file, the encrypted region starts at 16):

  | offset | size | content |
  |---|---|---|
  | 0 | 16 | MD5 of bytes 16..end (encrypted) |
  | 16 | 8 | signature |
  | 24 | 4 | `UInt32LE` file count |
  | 28 | 4 | padding |
  | 32 | 8 × count | table: `UInt32LE offset`, `UInt32LE size` |
  | … | | blobs, each padded with zeros to a multiple of 8 |

  Table **offsets are absolute file offsets**; **sizes are the real, unpadded
  sizes** (e.g. 2 120 and 54 209 509 bytes in Sony's package). A tool that stores
  padded sizes, or lays out later blobs with real sizes, corrupts V1 packages.
- **Keys are per region, not only per series.** Sony's international NWZ-A10
  package opens only with `2572f4a7…` (sig `f62ced8a`); its **Japanese** NW-A16/A17
  package only with `18a8b9bf…` (sig `f132af27`) — the value a Japanese NW-A16
  reports for its `kas` NVP node. A player rejects a package signed for the other
  region **before** running its script.
- **Sectors of an NWZ-A10 package**: 0 = installer shell script (`/bin/sh`),
  1 = kernel (4 259 840 B), 2 = gzip'd tar of the root filesystem.
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
