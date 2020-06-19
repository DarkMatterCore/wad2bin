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

bool tmdGetTitleMetadataTypeAndSize(const void *buf, u64 buf_size, u8 *out_type, u64 *out_size, bool verbose);

u8 *tmdReadTitleMetadataFromFile(FILE *fd, u64 tmd_size)
{
    if (!fd || tmd_size < TMD_MIN_SIZE)
    {
        ERROR_MSG("Invalid parameters!");
        return NULL;
    }
    
    u8 *tmd = NULL;
    u64 res = 0;
    
    u8 tmd_type = 0;
    u64 tmd_detected_size = 0;
    
    bool success = false;
    
    /* Allocate memory for the TMD. */
    tmd = calloc(ALIGN_UP(tmd_size, WAD_BLOCK_SIZE), sizeof(u8));
    if (!tmd)
    {
        ERROR_MSG("Unable to allocate 0x%" PRIx64 " bytes TMD buffer!", tmd_size);
        return NULL;
    }
    
    /* Read TMD. */
    res = fread(tmd, 1, tmd_size, fd);
    if (res != tmd_size)
    {
        ERROR_MSG("Failed to read 0x%" PRIx64 " bytes long TMD!", tmd_size);
        goto out;
    }
    
    /* Check if the TMD size is valid. */
    if (!tmdGetTitleMetadataTypeAndSize(tmd, tmd_size, &tmd_type, &tmd_detected_size, true)) goto out;
    
    if (tmd_size != tmd_detected_size)
    {
        ERROR_MSG("\nCalculated TMD size doesn't match input size! (0x%" PRIx64 " != 0x%" PRIx64 ").", tmd_size, tmd_detected_size);
        goto out;
    }
    
    success = true;
    
out:
    if (!success && tmd)
    {
        free(tmd);
        tmd = NULL;
    }
    
    return tmd;
}

TmdCommonBlock *tmdGetCommonBlockFromBuffer(void *buf, u64 buf_size, u8 *out_tmd_type)
{
    if (!buf || buf_size < TMD_MIN_SIZE)
    {
        ERROR_MSG("Invalid parameters!");
        return NULL;
    }
    
    u8 tmd_type = 0;
    u8 *buf_u8 = (u8*)buf;
    TmdCommonBlock *tmd_common_block = NULL;
    
    if (!tmdGetTitleMetadataTypeAndSize(buf, buf_size, &tmd_type, NULL, false))
    {
        ERROR_MSG("Invalid TMD!");
        return NULL;
    }
    
    switch(tmd_type)
    {
        case TmdType_SigRsa4096:
            tmd_common_block = (TmdCommonBlock*)(buf_u8 + sizeof(SignatureBlockRsa4096));
            break;
        case TmdType_SigRsa2048:
            tmd_common_block = (TmdCommonBlock*)(buf_u8 + sizeof(SignatureBlockRsa2048));
            break;
        case TmdType_SigEcc480:
            tmd_common_block = (TmdCommonBlock*)(buf_u8 + sizeof(SignatureBlockEcc480));
            break;
        case TmdType_SigHmac160:
            tmd_common_block = (TmdCommonBlock*)(buf_u8 + sizeof(SignatureBlockHmac160));
            break;
        default:
            ERROR_MSG("Invalid TMD type value!");
            break;
    }
    
    if (tmd_common_block && out_tmd_type) *out_tmd_type = tmd_type;
    
    return tmd_common_block;
}

bool tmdIsSystemVersionValid(TmdCommonBlock *tmd_common_block)
{
    if (!tmd_common_block)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u64 title_id = bswap_64(tmd_common_block->system_version);
    u32 tid_upper = TITLE_UPPER(title_id);
    
    if (tid_upper != TITLE_TYPE_SYSTEM)
    {
        ERROR_MSG("TMD system version doesn't reference an IOS version!");
        return false;
    }
    
    return true;
}

void tmdFakesignTitleMetadata(void *buf, u64 buf_size)
{
    if (!buf || buf_size < TMD_MIN_SIZE) return;
    
    u8 tmd_type = 0;
    TmdCommonBlock *tmd_common_block = NULL;
    
    tmd_common_block = tmdGetCommonBlockFromBuffer(buf, buf_size, &tmd_type);
    if (!tmd_common_block) return;
    
    /* Wipe signature. */
    switch(tmd_type)
    {
        case TmdType_SigRsa4096:
        {
            SignatureBlockRsa4096 *sig_rsa_4096 = (SignatureBlockRsa4096*)buf;
            memset(sig_rsa_4096->signature, 0, sizeof(sig_rsa_4096->signature));
            break;
        }
        case TmdType_SigRsa2048:
        {
            SignatureBlockRsa2048 *sig_rsa_2048 = (SignatureBlockRsa2048*)buf;
            memset(sig_rsa_2048->signature, 0, sizeof(sig_rsa_2048->signature));
            break;
        }
        case TmdType_SigEcc480:
        {
            SignatureBlockEcc480 *sig_ecc_480 = (SignatureBlockEcc480*)buf;
            memset(sig_ecc_480->signature, 0, sizeof(sig_ecc_480->signature));
            break;
        }
        case TmdType_SigHmac160:
        {
            SignatureBlockHmac160 *sig_hmac_160 = (SignatureBlockHmac160*)buf;
            memset(sig_hmac_160->signature, 0, sizeof(sig_hmac_160->signature));
            break;
        }
        default:
            break;
    }
    
    /* Modify TMD until we get a hash that starts with 0x00. */
    u8 hash[SHA1_HASH_SIZE] = {0};
    u16 *padding = (u16*)tmd_common_block->reserved_4;
    u64 tmd_size = TMD_COMMON_BLOCK_SIZE(tmd_common_block);
    
    for(u16 i = 0; i < 65535; i++)
    {
        *padding = bswap_16(i);
        mbedtls_sha1((u8*)tmd_common_block, tmd_size, hash);
        if (hash[0] == 0) break;
    }
}

bool tmdGetTitleMetadataTypeAndSize(const void *buf, u64 buf_size, u8 *out_type, u64 *out_size, bool verbose)
{
    if (!buf || buf_size < TMD_MIN_SIZE || (!out_type && !out_size))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u32 sig_type = 0;
    u64 offset = 0;
    u8 type = TmdType_None;
    const u8 *buf_u8 = (const u8*)buf;
    const TmdCommonBlock *tmd_common_block = NULL;
    
    memcpy(&sig_type, buf_u8, sizeof(u32));
    sig_type = bswap_32(sig_type);
    
    switch(sig_type)
    {
        case SignatureType_Rsa4096Sha1:
        case SignatureType_Rsa4096Sha256:
            type = TmdType_SigRsa4096;
            offset += sizeof(SignatureBlockRsa4096);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (RSA-4096 + %s).\n", sig_type, (sig_type == SignatureType_Rsa4096Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Rsa2048Sha1:
        case SignatureType_Rsa2048Sha256:
            type = TmdType_SigRsa2048;
            offset += sizeof(SignatureBlockRsa2048);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (RSA-2048 + %s).\n", sig_type, (sig_type == SignatureType_Rsa2048Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Ecc480Sha1:
        case SignatureType_Ecc480Sha256:
            type = TmdType_SigEcc480;
            offset += sizeof(SignatureBlockEcc480);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (ECSDA + %s).\n", sig_type, (sig_type == SignatureType_Ecc480Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Hmac160Sha1:
            type = TmdType_SigHmac160;
            offset += sizeof(SignatureBlockHmac160);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (HMAC + SHA-1).\n", sig_type);
            break;
        default:
            ERROR_MSG("Invalid signature type value! (0x%08" PRIx32 ").", sig_type);
            return false;
    }
    
    if (verbose) printf("  Signature issuer:       %.*s.\n", (int)MEMBER_SIZE(SignatureBlockRsa4096, issuer), (const char*)(buf_u8 + (offset - MEMBER_SIZE(SignatureBlockRsa4096, issuer))));
    
    tmd_common_block = (const TmdCommonBlock*)(buf_u8 + offset);
    offset += sizeof(TmdCommonBlock);
    
    /* Retrieve content count. */
    u16 content_count = bswap_16(tmd_common_block->content_count);
    if (!content_count || content_count > TMD_MAX_CONTENT_COUNT)
    {
        ERROR_MSG("\nInvalid TMD content count!");
        return false;
    }
    
    offset += (content_count * sizeof(TmdContentRecord));
    if (offset > buf_size)
    {
        ERROR_MSG("\nCalculated end offset exceeds TMD buffer size! (0x%" PRIx64 " > 0x%" PRIx64 ").", offset, buf_size);
        return false;
    }
    
    if (out_type) *out_type = type;
    if (out_size) *out_size = offset;
    
    return true;
}
