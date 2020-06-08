### ninty-233

ninty-233 is a C99 library for [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) operations using sect233r1 / NIST B-233, the curve used in the [iQue Player](https://en.wikipedia.org/wiki/IQue_Player) and [Nintendo Wii](https://en.wikipedia.org/wiki/Wii).  

It can be used for [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) (used to create some encryption keys on the iQue Player) and [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) signing/verification (used to sign game saves on both consoles and to sign recrypt.sys on the iQue Player).  

ninty-233 should **NOT** be expected to be secure; it is intended to be used as a tool for working with keys and/or data that are **already known** (made obvious by the fact that there is no function provided for generating keys). In its current state, I expect it to be vulnerable to various attacks (e.g. the GF(2^m) element and elliptic curve point arithmetic operations are not resistant to timing analysis). The ``generate_k()`` function in particular is not cryptographically secure, and is simply a trivial implementation that will allow, for example, signing homebrew apps.  

ninty-233 currently requires an architecture with unsigned integer types of exactly 8 and 32 bits - that is, both ``uint8_t`` and ``uint32_t`` must be defined. This likely isn't a problem for literally anyone, but it's probably good to know before compiling for a calculator or something.

Arbitrary-precision arithmetic is done using the [GNU MP library](https://gmplib.org/) in the form of mini-gmp, a standalone subset of GMP.  

The SHA1 implementation is a slightly modified version of the public domain [WjCryptLib](https://github.com/WaterJuice/WjCryptLib) implementation from [WaterJuice](https://github.com/WaterJuice) et al.

ninty-233 is licensed under the GPLv3 or (at your option) any later version (and I've opted to use GMP under the same license).  
