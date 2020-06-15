# wad2bin

Converts installable Wii WAD packages to content.bin files using console-specific keydata, which can be stored on a SD card and used to launch channels via System Menu 4.0+ or used with games that save/read data in this format.

Guidelines:

* Console-specific data is required to perform the conversion. Dump it from the target console using [xyzzy-mod](https://github.com/DarkMatterCore/xyzzy-mod).
    * The program expects two different files with console specific data: keys.txt (check template for actual format) and device.cert.
* Both ticket + TMD for each converted WAD package must be installed on the target Wii console in order for this to work.
    * A homebrew-based solution to install both ticket and TMD after the WAD package has been converted is being looked into.
* If the WAD ticket wasn't issued for the target console, or if the WAD isn't legit (e.g. homebrew WAD), the IOS used by the System Menu must be patched to enable the [signing bug](https://wiibrew.org/wiki/Signing_bug) on it.

Usage:

```
wad2bin <keys file> <device.cert> <input WAD> <output dir>

Paths must not exceed 1023 characters. Relative paths are supported.
The required directory tree for the content.bin file will be created at the output directory.
You can set your SD card root directory as the output directory.
```

Dependencies:

* [ninty-233](https://github.com/jbop1626/ninty-233) (licensed under GPLv3 or later) is used for ECDH data generation and ECSDA signing/verification.
* [mbedtls](https://tls.mbed.org) (licensed under Apache 2.0) is used for hash calculation and AES-CBC crypto operations.
* Keydata parsing based on code from [hactool](https://github.com/SciresM/hactool) (licensed under ISC).

wad2bin is licensed under GPLv3 or (at your option) any later version.
