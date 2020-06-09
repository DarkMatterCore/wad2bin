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
