# wad2cntbin

Converts installable Wii WAD packages to content.bin files using console-specific keydata, which can be stored on a SD card and used to launch channels via System Menu 4.0+ or used by games (e.g. DLCs in music titles).

A ticket for each converted WAD package must be installed on the target Wii console in order for this to work.

[ninty-233](https://github.com/jbop1626/ninty-233) is used for ECSDA signing/verification, and [mbedtls](https://tls.mbed.org) is used for hash calculation and AES-CBC crypto operations.

wad2cntbin is licensed under GPLv3 or (at your option) any later version.
