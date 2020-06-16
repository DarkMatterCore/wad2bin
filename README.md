# wad2bin

Converts installable Wii WAD packages to backup WAD packages (*.bin files) using console-specific keydata. These files can be stored on a SD card and used to launch channels via System Menu 4.0+, or used with games that save/read data in this format.

Usage:
--------------

```
wad2bin <keys file> <device.cert> <input WAD> <output dir> [parent title ID]

Paths must not exceed 1023 characters. Relative paths are supported.
The required directory tree for the *.bin file(s) will be created at the output directory.
You can set your SD card root directory as the output directory.
Parent title ID is only required if the input WAD is a DLC. A 16 character long hex string is expected.
```

Guidelines:
--------------

* Console-specific data is required to perform the conversion. Dump it from the target console using [xyzzy-mod](https://github.com/DarkMatterCore/xyzzy-mod).
    * The program expects two different files with console specific data: a text file with keydata (check `keys.txt.template` for actual format) and `device.cert`.
* Both ticket and TMD for each converted WAD package must be installed on the target Wii console in order for this to work.
    * For this matter, the program generates a bogus WAD package at the provided output directory. It can be used with regular WAD Managers to install both ticket and TMD if needed.
* If the WAD ticket wasn't issued for the target console, or if the WAD isn't legit (e.g. homebrew WAD), the IOS used by the System Menu must be patched to enable the [signing bug](https://wiibrew.org/wiki/Signing_bug) on it.
* If a DLC WAD is provided, it doesn't matter if it's an uncomplete WAD with missing contents, a WAD with a tampered TMD that only references the packaged contents or a full WAD with all contents: all cases are supported by wad2bin. There's no need to provide any content indexes.

Differences between `content.bin` files and `<index>.bin` files:
--------------

* `content.bin` files are used to store data from `00010001` (downloadable channels) and `00010004` (disc-based channels) titles, and get saved to `sd:/private/wii/title/<ascii_lower_tid>/content.bin`. Whilst `<index>.bin` files are used to store data from `00010005` (DLC) titles, and get saved to `sd:/private/wii/data/<ascii_lower_tid>/<index>.bin` - where `<index>` represents a specific content index from its TMD (000 - 511).
* Both `content.bin` and `<index>.bin` files are backup WAD packages with a "Bk" header block, a TMD data block and encrypted contents using AES-128-CBC with the console-specific PRNG key and the content index as their IV (followed by 14 zeroes).
* However, `content.bin` files hold two leading blocks before the "Bk" header that are both encrypted using the SD key and the SD IV (which are not console specific):
    * A 0x640 byte-long title info header, which holds data such as title ID and a copy of the IMET header from the channel's `opening.bnr` (`00000000.app`).
    * A copy of the `/meta/icon.bin` file entry from the `opening.bnr` U8 archive, with a variable size.
* `content.bin` files also hold a trailing certificate area placed after the encrypted contents, which contains:
    * An ECSDA signature calculated over the whole backup WAD package area (using the console-specific ECC private key).
    * A copy of the console-specific ECC-B233 device certificate (also known as "NG" cert).
    * A title-issued ECC-B233 certificate (also known as "AP" cert), signed using the console-specific ECC private key. Its ECC public key is an ECDH shared secret generated with a custom ECC private key. The issuer title is always the System Menu (00000001-00000002).
* On the other hand, while `<index>.bin` files don't include any of the leading and trailing blocks from `content.bin` files, they are only allowed to hold a single encrypted content at a time, which index is used as part of the filename expressed in base 10 notation (e.g. `000.bin`).

Dependencies:
--------------

* [ninty-233](https://github.com/jbop1626/ninty-233) (licensed under GPLv3 or later) is used for ECDH data generation and ECSDA signing/verification.
* [mbedtls](https://tls.mbed.org) (licensed under Apache 2.0) is used for hash calculation and AES-CBC crypto operations.
* Keydata parsing based on code from [hactool](https://github.com/SciresM/hactool) (licensed under ISC).

License:
--------------

wad2bin is licensed under GPLv3 or (at your option) any later version.

Changelog:
--------------

**v0.5:**

Implemented bogus installable WAD package generation (header + certificate chain + ticket + TMD), saved at the provided output directory using the `<title_id>_bogus.wad` naming convention.

These bogus WAD packages can be used to install both ticket and TMD if needed, using regular WAD Managers. Errors such as -1022 can be safely ignored (e.g. content data isn't available in these WADs).

**v0.4:**

Fixed seeking after a missing content is detected while unpacking a DLC WAD.

**v0.3:**

Force the user to provide the full parent title ID for DLC WADs.

**v0.2:**

Added proper support for DLC WADs, even if they're incomplete (e.g. full TMD with missing content files).

**v0.1:**

Initial release.
