# Sony Walkman Firmware Patcher — fork with V1 (NWZ-A10 / NW-A16) support

> **This fork** adds **V1 (DES) update packages** to roobscoob's patcher, so it
> works on the NWZ-A10 generation and older — tested on a **Japanese NW-A16**.
> Upstream only handled V2 (AES) devices. Companion project:
> [jdemarq/NW-A16-Firmware-Mod](https://github.com/jdemarq/NW-A16-Firmware-Mod).

## What the fork changes

| | upstream | this fork |
|---|---|---|
| V1 decryption | `"V1 encryption not supported"` | DES-ECB via `des.js` (pure JS; Node's OpenSSL 3 refuses `des-ecb`), KAS → key/sig exactly as Rockbox's `upg.c` |
| version detection | key length `== 4` → V1 (never true: V1 keys are 8 bytes) | key length `== 8` → V1 |
| `setFile()` | V1: throws; stored the **padded** size and laid out later files with it | table keeps the **real** size, blob padded to the block (8/16), later offsets shifted by the exact delta — required for V1, whose sizes are not multiples of 8 |
| keys | `nwz-a10` (international) | + **`nw-a16-jp`** — the A10 package key is **per region**: Japanese units/packages use `18a8b9bf…`, read from a NW-A16 and confirmed on Sony's Japanese 1.21 package (sig `f132af27`) |
| `index.ts` | hard-wired to NW-ZX300, compared Buffers with `==` (always false) | `ts-node index <model> [file.UPG]`; ZX300 steps (compressed sector 6, its hash in sector 1, Windows injector) only for `nw-zx300`; `.equals()` |
| build | README says `tsc -p .` but no `tsconfig.json` | `tsconfig.json` added |

## Usage (V1 players)

```sh
npm i
npx ts-node index nw-a16-jp NW_WM_FW.UPG     # Japanese NW-A16/A17
npx ts-node index nwz-a10   NW_WM_FW.UPG     # international NWZ-A10 series
```

Files are unpacked to `./bins/<n>.bin`; edit, press Enter, get `./FW_MOD.UPG`.
On a V1 package, sector 0 is the installer shell script, 1 the kernel, 2 the
gzip'd root filesystem tar. **Use the key of your unit's region**: a package
signed with the other region's key is rejected by the player before its script
runs. To start the update, use Rockbox's `scsitool <drive> do_fw_upgrade`
(the bundled Windows injector is ZX300-only). Flashing modified firmware can
brick a player — keep an official package of your region at hand.

## Tests

`npm test -- <dir>` (`test/v1.ts`) checks, on packages whose bytes are known
independently:
- Japanese-key packages open with `nw-a16-jp` and are **rejected** with `nwz-a10`;
- unpack + repack unchanged is **byte-identical**;
- `setFile()` on the payload reproduces, **byte for byte**, a package built by a
  separate Python packer; a non-multiple-of-8 replacement round-trips and leaves
  the next file intact.

Also checked: Sony's official international NWZ-A10 1.21 package (58 MB) opens
with `nwz-a10` and repacks byte-identical (≈3 s).

---

*Original README below.*

# Sony Walkman Firmware Patcher

This tool is a utility for patching firmware updates for sony walkman devices.

It has only been tested on my personal device (NW-ZX300) but should™ work* on all devices with V2 update encryption, listed below:

 - NW-WM1A
 - NW-WM1Z
 - NW-ZX300
 - NW-A30
 - NW-A40
 - NW-A50
 - DMP-Z1

*\* With the exception of the injector, which will only work on the NW-ZX300.*

I welcome PRs, or working with people with the following devices to add support for V1 update encryption:

 - NWZ-A10
 - NW-A20
 - NWZ-E350
 - NWZ-E450
 - NWZ-E460
 - NWZ-A860
 - NWZ-A850
 - NWZ-A840
 - NWZ-E470
 - NWZ-E580
 - NWZ-S750
 - NWZ-X1000
 - NW-ZX100
 - NW-A820
 - NW-S10
 - NWZ-S610

I'd also love help from anyone with devices other than the NW-ZX300 to add injector support for your device.

## How to use

first, you'll need to install all packages with:
`npm i`

then you'll need to grab your update UPG and place it in the root project directory with the name `FW.UPG`

you can then run the script with `ts-node index` (if you have ts-node), or you can compile the typescript and run with `tsc -p .` followed by `node index`

the script will then unpack all the files in the update into a directory called `./bins`

once you finish modifying the files, you can then hit enter in the script. It will detect modified files and repack them into a UPG called `FW_MOD.UPG`

it will also attempt to run the injector on this modified binary, by copying the file into `inject/Data/Device/NW_WM_FM.UPG` and running `inject/SoftwareUpdateTool.exe`

## Assumptions made by the script

1. You are running windows
2. The connected device is an NW-ZX300
3. The 7th data sector in the UPG is compressed
4. The 2nd data sector in the UPG contains a hash for the 7th data sector

While this script was orignally made for my use, i'd love to work with people to reduce and modularize these assumptions.

## [Documentation on the UPG files](./upgDocs.md)
