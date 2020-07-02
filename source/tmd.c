/*
 * tmd.c
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

#include "utils.h"
#include "tmd.h"

static bool tmdGetTitleMetadataTypeAndSize(void *buf, u64 buf_size, u8 *out_type, u64 *out_size);

bool tmdReadTitleMetadataFromFile(FILE *fd, u64 tmd_size, TitleMetadata *out_tmd, CertificateChain *chain)
{
    if (!fd || tmd_size < SIGNED_TMD_MIN_SIZE || tmd_size > SIGNED_TMD_MAX_SIZE || !out_tmd || !chain)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u64 res = 0;
    bool success = false;
    
    /* Cleanup output TMD. */
    memset(out_tmd, 0, sizeof(TitleMetadata));
    
    /* Allocate memory for the output TMD. */
    out_tmd->data = (u8*)calloc(ALIGN_UP(tmd_size, WAD_BLOCK_SIZE), sizeof(u8));
    if (!out_tmd->data)
    {
        ERROR_MSG("Error allocating memory for the TMD!");
        return false;
    }
    
    /* Read TMD. */
    res = fread(out_tmd->data, 1, tmd_size, fd);
    if (res != tmd_size)
    {
        ERROR_MSG("Failed to read 0x%" PRIx64 " bytes long TMD!", tmd_size);
        goto out;
    }
    
    /* Check if the TMD size is valid. */
    if (!tmdGetTitleMetadataTypeAndSize(out_tmd->data, tmd_size, &(out_tmd->type), &(out_tmd->size))) goto out;
    
    if (tmd_size != out_tmd->size)
    {
        printf("\n");
        ERROR_MSG("Calculated TMD size doesn't match input size! (0x%" PRIx64 " != 0x%" PRIx64 ").", tmd_size, out_tmd->size);
        goto out;
    }
    
    /* Verify TMD signature. */
    if (!certVerifySignatureFromSignedPayload(chain, out_tmd->data, out_tmd->size, &(out_tmd->valid_sig)))
    {
        ERROR_MSG("Failed to verify TMD signature!");
        goto out;
    }
    
    success = true;
    
out:
    if (!success) tmdFreeTitleMetadata(out_tmd);
    
    return success;
}

void tmdFakesignTitleMetadata(TitleMetadata *tmd)
{
    TmdCommonBlock *tmd_common_block = NULL;
    
    u32 sig_type = 0;
    u8 *signature = NULL;
    u64 signature_size = 0;
    
    u8 hash[SHA256_HASH_SIZE] = {0};
    u16 *padding = NULL;
    u64 tmd_hash_area_size = 0;
    
    if (!tmd || tmd->type == TmdType_None || tmd->type > TmdType_SigHmac160 || tmd->size < SIGNED_TMD_MIN_SIZE || tmd->size > SIGNED_TMD_MAX_SIZE || !tmdIsValidTitleMetadata(tmd->data)) return;
    
    /* Wipe signature. */
    sig_type = signatureGetSigType(tmd->data);
    signature = signatureGetSig(tmd->data);
    signature_size = signatureGetSigSize(sig_type);
    memset(signature, 0, signature_size);
    
    /* Modify TMD until we get a hash that starts with 0x00. */
    /* Return right away if we're dealing with a HMAC signature. */
    if (sig_type == SignatureType_Hmac160Sha1) return;
    
    tmd_common_block = tmdGetCommonBlock(tmd->data);
    padding = (u16*)tmd_common_block->reserved_4;
    tmd_hash_area_size = tmdGetSignedTitleMetadataHashAreaSize(tmd->data);
    
    for(u16 i = 0; i < 65535; i++)
    {
        *padding = bswap_16(i);
        
        switch(sig_type)
        {
            case SignatureType_Rsa4096Sha1:
            case SignatureType_Rsa4096Sha256:
            case SignatureType_Rsa2048Sha1:
            case SignatureType_Rsa2048Sha256:
                mbedtls_sha1((u8*)tmd_common_block, tmd_hash_area_size, hash);
                break;
            case SignatureType_Ecc480Sha1:
            case SignatureType_Ecc480Sha256:
                mbedtls_sha256((u8*)tmd_common_block, tmd_hash_area_size, hash, 0);
                break;
            default:
                break;
        }
        
        if (hash[0] == 0) break;
    }
    
    /* Update signature validity. */
    tmd->valid_sig = false;
}

static bool tmdGetTitleMetadataTypeAndSize(void *buf, u64 buf_size, u8 *out_type, u64 *out_size)
{
    TmdCommonBlock *tmd_common_block = NULL;
    u32 sig_type = 0;
    u64 signed_tmd_size = 0;
    u8 type = TmdType_None;
    
    if (!buf || buf_size < SIGNED_TMD_MIN_SIZE || (!out_type && !out_size))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    if (!(tmd_common_block = tmdGetCommonBlock(buf)) || !(signed_tmd_size = tmdGetSignedTitleMetadataSize(buf)))
    {
        printf("\n");
        ERROR_MSG("Input buffer doesn't hold a valid signed TMD!");
        return false;
    }
    
    if (signed_tmd_size > buf_size)
    {
        printf("\n");
        ERROR_MSG("Calculated signed TMD size exceeds input buffer size! (0x%" PRIx64 " > 0x%" PRIx64 ").", signed_tmd_size, buf_size);
        return false;
    }
    
    sig_type = signatureGetSigType(buf);
    
    printf("  Signature type:         0x%08" PRIx32, sig_type);
    switch(sig_type)
    {
        case SignatureType_Rsa4096Sha1:
        case SignatureType_Rsa4096Sha256:
            type = TmdType_SigRsa4096;
            printf(" (RSA-4096 + %s)", (sig_type == SignatureType_Rsa4096Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Rsa2048Sha1:
        case SignatureType_Rsa2048Sha256:
            type = TmdType_SigRsa2048;
            printf(" (RSA-2048 + %s)", (sig_type == SignatureType_Rsa2048Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Ecc480Sha1:
        case SignatureType_Ecc480Sha256:
            type = TmdType_SigEcc480;
            printf(" (ECDSA + %s)", (sig_type == SignatureType_Ecc480Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Hmac160Sha1:
            type = TmdType_SigHmac160;
            printf(" (HMAC + SHA-1)");
            break;
        default:
            break;
    }
    printf(".\n");
    
    printf("  Signature issuer:       %.*s.\n", (int)sizeof(tmd_common_block->issuer), tmd_common_block->issuer);
    
    if (out_type) *out_type = type;
    if (out_size) *out_size = signed_tmd_size;
    
    return true;
}
