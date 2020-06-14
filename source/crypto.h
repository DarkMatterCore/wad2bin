/*
 * crypto.h
 *
 * Copyright (c) 2020, DarkMatterCore <pabloacurielz@gmail.com>.
 *
 * This file is part of wad2cntbin (https://github.com/DarkMatterCore/wad2cntbin).
 *
 * wad2cntbin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * wad2cntbin is distributed in the hope that it will be useful,
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
#include <mbedtls/md5.h>

#ifndef SHA1_HASH_SIZE
#define SHA1_HASH_SIZE      20
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
#define ECSDA_SIG_SIZE      64

/// Used to hold AES-128-CBC crypto status.
typedef struct {
    u8 iv[AES_BLOCK_SIZE];
    mbedtls_aes_context aes_ctx;
} CryptoAes128CbcContext;

/// AES-128-CBC crypto functions.
bool cryptoAes128CbcContextInit(CryptoAes128CbcContext *ctx, const void *key, const void *iv, bool is_encryptor);
void cryptoAes128CbcContextFree(CryptoAes128CbcContext *ctx);
void cryptoAes128CbcContextResetIv(CryptoAes128CbcContext *ctx, const void *iv);
bool cryptoAes128CbcContextCrypt(CryptoAes128CbcContext *ctx, void *dst, const void *src, size_t size, bool encrypt);

/// Simple all-in-one AES-128-CBC crypto function.
bool cryptoAes128CbcCrypt(const void *key, const void *iv, void *dst, const void *src, size_t size, bool encrypt);

/// Generates an ECSDA signature using the provided ECC private key.
/// Takes care of handling key/signature padding when needed. If padded_sig is true, the output signature will include the two extra bytes before each coordinate.
void cryptoGenerateEcsdaSignatureWithData(const void *private_key, void *dst, const void *src, size_t size, bool padded_sig);

/// Same as cryptoGenerateEcsdaSignatureWithData, but takes an input SHA-1 hash instead of calculating it on its own over a provided memory block.
void cryptoGenerateEcsdaSignatureWithHash(const void *private_key, void *dst, const u8 data_hash[SHA1_HASH_SIZE], bool padded_sig);

/// Generates an ECC public key using the provided ECC private key.
/// Takes care of handling key padding when needed. The generated key can be used in AP certificates.
void cryptoGenerateEccPublicKey(const void *private_key, void *dst);

#endif /* __CRYPTO_H__ */
