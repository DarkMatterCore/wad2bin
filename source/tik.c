/*
 * tik.c
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
#include "tik.h"
#include "crypto.h"

static bool tikGetTicketTypeAndSize(const void *buf, u64 buf_size, u8 *out_type, u64 *out_size, bool verbose);

u8 *tikReadTicketFromFile(FILE *fd, u64 ticket_size)
{
    if (!fd || ticket_size < TIK_MIN_SIZE)
    {
        ERROR_MSG("Invalid parameters!");
        return NULL;
    }
    
    u8 *ticket = NULL;
    u64 res = 0;
    
    u8 ticket_type = 0;
    u64 ticket_detected_size = 0;
    
    bool success = false;
    
    /* Allocate memory for the ticket. */
    ticket = calloc(ALIGN_UP(ticket_size, WAD_BLOCK_SIZE), sizeof(u8));
    if (!ticket)
    {
        ERROR_MSG("Unable to allocate 0x%" PRIx64 " bytes ticket buffer!", ticket_size);
        return NULL;
    }
    
    /* Read ticket. */
    res = fread(ticket, 1, ticket_size, fd);
    if (res != ticket_size)
    {
        ERROR_MSG("Failed to read 0x%" PRIx64 " bytes long ticket!", ticket_size);
        goto out;
    }
    
    /* Check if the ticket size is valid. */
    if (!tikGetTicketTypeAndSize(ticket, ticket_size, &ticket_type, &ticket_detected_size, true)) goto out;
    
    if (ticket_size != ticket_detected_size)
    {
        ERROR_MSG("\nCalculated ticket size doesn't match input size! (0x%" PRIx64 " != 0x%" PRIx64 ").", ticket_size, ticket_detected_size);
        goto out;
    }
    
    success = true;
    
out:
    if (!success && ticket)
    {
        free(ticket);
        ticket = NULL;
    }
    
    return ticket;
}

TikCommonBlock *tikGetCommonBlockFromBuffer(void *buf, u64 buf_size, u8 *out_ticket_type)
{
    if (!buf || buf_size < TIK_MIN_SIZE)
    {
        ERROR_MSG("Invalid parameters!");
        return NULL;
    }
    
    u8 ticket_type = 0;
    u8 *buf_u8 = (u8*)buf;
    TikCommonBlock *tik_common_block = NULL;
    
    if (!tikGetTicketTypeAndSize(buf, buf_size, &ticket_type, NULL, false))
    {
        ERROR_MSG("Invalid ticket!");
        return NULL;
    }
    
    switch(ticket_type)
    {
        case TikType_SigRsa4096:
            tik_common_block = (TikCommonBlock*)(buf_u8 + sizeof(SignatureBlockRsa4096));
            break;
        case TikType_SigRsa2048:
            tik_common_block = (TikCommonBlock*)(buf_u8 + sizeof(SignatureBlockRsa2048));
            break;
        case TikType_SigEcc480:
            tik_common_block = (TikCommonBlock*)(buf_u8 + sizeof(SignatureBlockEcc480));
            break;
        case TikType_SigHmac160:
            tik_common_block = (TikCommonBlock*)(buf_u8 + sizeof(SignatureBlockHmac160));
            break;
        default:
            ERROR_MSG("Invalid ticket type value!");
            break;
    }
    
    if (tik_common_block && out_ticket_type) *out_ticket_type = ticket_type;
    
    return tik_common_block;
}

bool tikIsTitleExportable(TikCommonBlock *tik_common_block)
{
    if (!tik_common_block)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u64 title_id = bswap_64(tik_common_block->title_id);
    u32 tid_upper = TITLE_UPPER(title_id);
    
    return (tid_upper == TITLE_TYPE_DOWNLOADABLE_CHANNEL || tid_upper == TITLE_TYPE_DISC_BASED_CHANNEL || tid_upper == TITLE_TYPE_DLC);
}

//bool tikVerifySignature







void tikFakesignTicket(void *buf, u64 buf_size)
{
    if (!buf || buf_size < TIK_MIN_SIZE) return;
    
    u8 ticket_type = 0;
    TikCommonBlock *tik_common_block = NULL;
    
    tik_common_block = tikGetCommonBlockFromBuffer(buf, buf_size, &ticket_type);
    if (!tik_common_block) return;
    
    /* Wipe signature. */
    switch(ticket_type)
    {
        case TikType_SigRsa4096:
        {
            SignatureBlockRsa4096 *sig_rsa_4096 = (SignatureBlockRsa4096*)buf;
            memset(sig_rsa_4096->signature, 0, sizeof(sig_rsa_4096->signature));
            break;
        }
        case TikType_SigRsa2048:
        {
            SignatureBlockRsa2048 *sig_rsa_2048 = (SignatureBlockRsa2048*)buf;
            memset(sig_rsa_2048->signature, 0, sizeof(sig_rsa_2048->signature));
            break;
        }
        case TikType_SigEcc480:
        {
            SignatureBlockEcc480 *sig_ecc_480 = (SignatureBlockEcc480*)buf;
            memset(sig_ecc_480->signature, 0, sizeof(sig_ecc_480->signature));
            break;
        }
        case TikType_SigHmac160:
        {
            SignatureBlockHmac160 *sig_hmac_160 = (SignatureBlockHmac160*)buf;
            memset(sig_hmac_160->signature, 0, sizeof(sig_hmac_160->signature));
            break;
        }
        default:
            break;
    }
    
    /* Wipe ECDH data and console ID. */
    memset(tik_common_block->ecdh_data, 0, sizeof(tik_common_block->ecdh_data));
    tik_common_block->console_id = 0;
    
    /* Modify ticket until we get a hash that starts with 0x00. */
    u8 hash[SHA256_HASH_SIZE] = {0};
    u16 *padding = (u16*)tik_common_block->reserved_3;
    u32 sig_type = signatureGetSigType(buf);
    
    for(u16 i = 0; i < 65535; i++)
    {
        *padding = bswap_16(i);
        
        if (sig_type == SignatureType_Rsa4096Sha1 || sig_type == SignatureType_Rsa2048Sha1 || sig_type == SignatureType_Ecc480Sha1 || sig_type == SignatureType_Hmac160Sha1)
        {
            mbedtls_sha1((u8*)tik_common_block, sizeof(TikCommonBlock), hash);
        } else
        if (sig_type == SignatureType_Rsa4096Sha256 || sig_type == SignatureType_Rsa2048Sha256 || sig_type == SignatureType_Ecc480Sha256)
        {
            mbedtls_sha256((u8*)tik_common_block, sizeof(TikCommonBlock), hash, 0);
        }
        
        if (hash[0] == 0) break;
    }
}

static bool tikGetTicketTypeAndSize(const void *buf, u64 buf_size, u8 *out_type, u64 *out_size, bool verbose)
{
    if (!buf || buf_size < TIK_MIN_SIZE || (!out_type && !out_size))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u32 sig_type = 0;
    u64 offset = 0;
    u8 type = TikType_None;
    const u8 *buf_u8 = (const u8*)buf;
    
    memcpy(&sig_type, buf_u8, sizeof(u32));
    sig_type = bswap_32(sig_type);
    
    switch(sig_type)
    {
        case SignatureType_Rsa4096Sha1:
        case SignatureType_Rsa4096Sha256:
            type = TikType_SigRsa4096;
            offset += sizeof(SignatureBlockRsa4096);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (RSA-4096 + %s).\n", sig_type, (sig_type == SignatureType_Rsa4096Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Rsa2048Sha1:
        case SignatureType_Rsa2048Sha256:
            type = TikType_SigRsa2048;
            offset += sizeof(SignatureBlockRsa2048);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (RSA-2048 + %s).\n", sig_type, (sig_type == SignatureType_Rsa2048Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Ecc480Sha1:
        case SignatureType_Ecc480Sha256:
            type = TikType_SigEcc480;
            offset += sizeof(SignatureBlockEcc480);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (ECDSA + %s).\n", sig_type, (sig_type == SignatureType_Ecc480Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Hmac160Sha1:
            type = TikType_SigHmac160;
            offset += sizeof(SignatureBlockHmac160);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (HMAC + SHA-1).\n", sig_type);
            break;
        default:
            ERROR_MSG("Invalid signature type value! (0x%08" PRIx32 ").", sig_type);
            return false;
    }
    
    if (verbose) printf("  Signature issuer:       %.*s.\n", (int)MEMBER_SIZE(TikCommonBlock, issuer), ((TikCommonBlock*)(buf_u8 + offset))->issuer);
    offset += sizeof(TikCommonBlock);
    
    if (offset > buf_size)
    {
        ERROR_MSG("\nCalculated end offset exceeds certificate buffer size! (0x%" PRIx64 " > 0x%" PRIx64 ").", offset, buf_size);
        return false;
    }
    
    if (out_type) *out_type = type;
    if (out_size) *out_size = offset;
    
    return true;
}
