/*
 * crypto.c
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

#include <ninty-233.h>

#include "utils.h"
#include "crypto.h"

bool cryptoAes128CbcCreateContext(CryptoAes128CbcContext *ctx, const void *key, const void *iv, bool is_encryptor)
{
    if (!ctx || !key || !iv)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    int ret = 0;
    
    /* Initialize AES context. */
    mbedtls_aes_init(&(ctx->aes_ctx));
    
    /* Set AES key. */
    ret = (is_encryptor ? mbedtls_aes_setkey_enc(&(ctx->aes_ctx), (const u8*)key, AES_BLOCK_SIZE_BITS) : mbedtls_aes_setkey_dec(&(ctx->aes_ctx), (const u8*)key, AES_BLOCK_SIZE_BITS));
    if (ret != 0)
    {
        ERROR_MSG("Failed to set AES key! (%d).", ret);
        goto out;
    }
    
    /* Copy IV. */
    memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    
out:
    if (ret != 0) mbedtls_aes_free(&(ctx->aes_ctx));
    
    return (ret == 0);
}

void cryptoAes128CbcFreeContext(CryptoAes128CbcContext *ctx)
{
    if (!ctx) return;
    mbedtls_aes_free(&(ctx->aes_ctx));
    memset(ctx, 0, sizeof(CryptoAes128CbcContext));
}

void cryptoAes128CbcResetContextIv(CryptoAes128CbcContext *ctx, const void *iv)
{
    if (!ctx || !iv) return;
    
    /* Copy IV. */
    memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
}

bool cryptoAes128CbcCrypt(CryptoAes128CbcContext *ctx, void *dst, const void *src, size_t size, bool encrypt)
{
    if (!ctx || !dst || !src || (size % AES_BLOCK_SIZE) > 0)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    int ret = 0;
    
    /* Perform AES-CBC crypto. */
    ret = mbedtls_aes_crypt_cbc(&(ctx->aes_ctx), (encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT), size, ctx->iv, (const u8*)src, (u8*)dst);
    if (ret != 0) ERROR_MSG("AES %s failed! (%d).", (encrypt ? "encryption" : "decryption"), ret);
    
    return (ret == 0);
}

void cryptoGenerateEcsdaSignature(const void *private_key, void *dst, const void *src, size_t size, bool padded_sig)
{
    if (!private_key || !dst || !src || !size) return;
    
    element priv_key = {0}, r = {0}, s = {0};
    u8 padded_priv_key[ECC_PRIV_KEY_SIZE] = {0};
    
    u8 full_sig[ECSDA_SIG_SIZE] = {0};
    
    mpz_t hash = {0};
    u8 *dst_u8 = (u8*)dst;
    
    /* Generate padded ECC private key. */
    /* Wii ECC private keys are 30 bytes long. */
    memcpy(padded_priv_key + 2, private_key, ECC_PRIV_KEY_SIZE - 2);
    
    /* Convert private key to a GF(2^m) element. */
    os_to_elem(padded_priv_key, priv_key);
    
    /* Calculate SHA-1 hash over source data. */
    mpz_init(hash);
    sha1((const u8*)src, size, NOT_IQUE_HASH, hash);
    
    /* Generate ECSDA signature. */
    ecdsa_sign(hash, priv_key, r, s);
    mpz_clear(hash);
    
    /* Convert ECSDA signature to a byte stream. */
    elem_to_os(r, full_sig);
    elem_to_os(s, full_sig + 32);
    
    if (padded_sig)
    {
        /* Copy ECSDA signature as-is. */
        memcpy(dst_u8, full_sig, ECSDA_SIG_SIZE);
    } else {
        /* Generate unpadded ECSDA signature. */
        /* Wii ECSDA signatures are normally 60 bytes long. */
        memcpy(dst_u8, full_sig + 2, 30);
        memcpy(dst_u8 + 30, full_sig + 34, 30);
    }
}

void cryptoGenerateEccPublicKey(const void *private_key, void *dst)
{
    if (!private_key || !dst) return;
    
    element priv_key = {0};
    u8 padded_priv_key[ECC_PRIV_KEY_SIZE] = {0};
    
    ec_point G = {0}, shared_secret = {0};
    u8 full_pub_key[ECC_PUB_KEY_SIZE] = {0};
    
    u8 *dst_u8 = (u8*)dst;
    
    /* Generate padded ECC private key. */
    /* Wii ECC private keys are 30 bytes long. */
    memcpy(padded_priv_key + 2, private_key, ECC_PRIV_KEY_SIZE - 2);
    
    /* Convert private key to a GF(2^m) element. */
    os_to_elem(padded_priv_key, priv_key);
    
    /* Copy ECC-B233 base point. */
    gf2m_copy(G_X, G.x);
    gf2m_copy(G_Y, G.y);
    
    /* Generate ECDH shared secret. This will serve as our ECC public key. */
    ec_point_mul(priv_key, &G, &shared_secret);
    
    /* Convert ECC public key to a byte stream. */
    point_to_os(&shared_secret, full_pub_key);
    
    /* Generate unpadded ECC public key. */
    /* Wii ECC public keys are normally 60 bytes long. */
    memcpy(dst_u8, full_pub_key + 2, 30);
    memcpy(dst_u8 + 30, full_pub_key + 34, 30);
}
