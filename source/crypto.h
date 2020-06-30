/*
 * crypto.h
 *
 * Copyright (c) 2020, DarkMatterCore <pabloacurielz@gmail.com>.
 *
 * This file is part of wad2bin (https://github.com/DarkMatterCore/wad2bin).
 *
 * wad2bin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * wad2bin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <mbedtls/aes.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md5.h>
#include <mbedtls/rsa.h>

#ifndef SHA1_HASH_SIZE
#define SHA1_HASH_SIZE      20
#endif

#ifndef SHA256_HASH_SIZE
#define SHA256_HASH_SIZE    32
#endif

#ifndef MD5_HASH_SIZE
#define MD5_HASH_SIZE       16
#endif

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE      16
#endif

#ifndef AES_BLOCK_SIZE_BITS
#define AES_BLOCK_SIZE_BITS (AES_BLOCK_SIZE * 8)
#endif

#define ECC_PRIV_KEY_SIZE   32
#define ECC_PUB_KEY_SIZE    64
#define ECDSA_SIG_SIZE      64

#define RSA2048_SIG_SIZE    0x100
#define RSA4096_SIG_SIZE    0x200

/// Used to hold AES-128-CBC crypto status.
typedef struct {
    u8 iv[AES_BLOCK_SIZE];
    mbedtls_aes_context aes_ctx;
} CryptoAes128CbcContext;

/// AES-128-CBC crypto functions.
bool cryptoAes128CbcContextInit(CryptoAes128CbcContext *ctx, const void *key, const void *iv, bool is_encryptor);
void cryptoAes128CbcContextFree(CryptoAes128CbcContext *ctx);
void cryptoAes128CbcContextResetIv(CryptoAes128CbcContext *ctx, const void *iv);
bool cryptoAes128CbcContextCrypt(CryptoAes128CbcContext *ctx, void *dst, const void *src, u64 size, bool encrypt);

/// Simple all-in-one AES-128-CBC crypto function.
bool cryptoAes128CbcCrypt(const void *key, const void *iv, void *dst, const void *src, u64 size, bool encrypt);

/// Generates an ECDSA signature using the provided ECC private key and a variable length hash.
/// Takes care of padding the input private key.
/// If padded_sig is true, the output signature will be padded with leading zeroes before each coordinate.
void cryptoGenerateEcdsaSignature(const void *private_key, void *dst, bool padded_sig, const void *data_hash, u64 data_hash_size);

/// Verifies an ECDSA signature using the provided ECC public key and a variable length hash.
/// Takes care of padding the input public key.
/// If padded_sig is false, the input signature will be padded with leading zeroes before each coordinate.
bool cryptoVerifyEcdsaSignature(const void *public_key, const void *signature, bool padded_sig, const void *data_hash, u64 data_hash_size);

/// Generates an ECC shared secret using an input ECC private key.
/// Takes care of padding the input private key.
/// Output public key will always be trimmed/unpadded.
void cryptoGenerateEccPublicKey(const void *private_key, void *dst);

/// Verifies a RSA-2048 or RSA-4906 signature using the provided RSA public key (modulus) and public exponent, as well as a variable length hash.
/// public_key_size must be set to either RSA2048_SIG_SIZE or RSA4096_SIG_SIZE, and signature must point to a buffer with a size of at least public_key_size.
bool cryptoVerifyRsaSignature(const void *public_key, u64 public_key_size, u64 public_exponent, const void *signature, const void *data_hash, u64 data_hash_size);

#endif /* __CRYPTO_H__ */
