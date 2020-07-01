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

static bool tikGetTicketTypeAndSize(void *buf, u64 buf_size, u8 *out_type, u64 *out_size);

bool tikReadTicketFromFile(FILE *fd, u64 ticket_size, Ticket *out_ticket, CertificateChain *chain)
{
    if (!fd || ticket_size < SIGNED_TIK_MIN_SIZE || ticket_size > SIGNED_TIK_MAX_SIZE || !out_ticket || !chain)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u64 res = 0;
    
    /* Cleanup output ticket. */
    memset(out_ticket, 0, sizeof(Ticket));
    
    /* Read ticket. */
    res = fread(out_ticket->data, 1, ticket_size, fd);
    if (res != ticket_size)
    {
        ERROR_MSG("Failed to read 0x%" PRIx64 " bytes long ticket!", ticket_size);
        return false;
    }
    
    /* Check if the ticket size is valid. */
    if (!tikGetTicketTypeAndSize(out_ticket->data, ticket_size, &(out_ticket->type), &(out_ticket->size))) return false;
    
    if (ticket_size != out_ticket->size)
    {
        ERROR_MSG("\nCalculated ticket size doesn't match input size! (0x%" PRIx64 " != 0x%" PRIx64 ").", out_ticket->size, ticket_size);
        return false;
    }
    
    /* Verify ticket signature. */
    if (!certVerifySignatureFromSignedPayload(chain, out_ticket->data, out_ticket->size, &(out_ticket->valid_sig)))
    {
        ERROR_MSG("Failed to verify ticket signature!");
        return false;
    }
    
    return true;
}

bool tikIsTitleExportable(TikCommonBlock *tik_common_block)
{
    if (!tik_common_block) return false;
    u64 title_id = bswap_64(tik_common_block->title_id);
    u32 tid_upper = TITLE_UPPER(title_id);
    return (tid_upper == TITLE_TYPE_DOWNLOADABLE_CHANNEL || tid_upper == TITLE_TYPE_DISC_BASED_CHANNEL || tid_upper == TITLE_TYPE_DLC);
}

void tikFakesignTicket(Ticket *ticket)
{
    TikCommonBlock *tik_common_block = NULL;
    
    u32 sig_type = 0;
    u8 *signature = NULL;
    u64 signature_size = 0;
    
    u8 hash[SHA256_HASH_SIZE] = {0};
    u16 *padding = NULL;
    
    if (!ticket || ticket->type == TikType_None || ticket->type > TikType_SigHmac160 || ticket->size < SIGNED_TIK_MIN_SIZE || ticket->size > SIGNED_TIK_MAX_SIZE || \
        !(tik_common_block = tikGetCommonBlock(ticket->data))) return;
    
    /* Wipe signature. */
    sig_type = signatureGetSigType(ticket->data);
    signature = signatureGetSig(ticket->data);
    signature_size = signatureGetSigSize(signatureGetSigType(ticket->data));
    memset(signature, 0, signature_size);
    
    /* Wipe ECDH data and console ID. */
    memset(tik_common_block->ecdh_data, 0, sizeof(tik_common_block->ecdh_data));
    tik_common_block->console_id = 0;
    
    /* Modify ticket until we get a hash that starts with 0x00. */
    /* Return right away if we're dealing with a HMAC signature. */
    if (sig_type == SignatureType_Hmac160Sha1) return;
    
    padding = (u16*)tik_common_block->reserved_3;
    for(u16 i = 0; i < 65535; i++)
    {
        *padding = bswap_16(i);
        
        switch(sig_type)
        {
            case SignatureType_Rsa4096Sha1:
            case SignatureType_Rsa4096Sha256:
            case SignatureType_Rsa2048Sha1:
            case SignatureType_Rsa2048Sha256:
                mbedtls_sha1((u8*)tik_common_block, sizeof(TikCommonBlock), hash);
                break;
            case SignatureType_Ecc480Sha1:
            case SignatureType_Ecc480Sha256:
                mbedtls_sha256((u8*)tik_common_block, sizeof(TikCommonBlock), hash, 0);
                break;
            default:
                break;
        }
        
        if (hash[0] == 0) break;
    }
}

static bool tikGetTicketTypeAndSize(void *buf, u64 buf_size, u8 *out_type, u64 *out_size)
{
    TikCommonBlock *tik_common_block = NULL;
    u32 sig_type = 0;
    u64 signed_ticket_size = 0;
    u8 type = TikType_None;
    
    if (!buf || buf_size < SIGNED_TIK_MIN_SIZE || (!out_type && !out_size))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    if (!(tik_common_block = tikGetCommonBlock(buf)) || !(signed_ticket_size = tikGetSignedTicketSize(buf)))
    {
        ERROR_MSG("\nInput buffer doesn't hold a valid signed ticket!");
        return false;
    }
    
    if (signed_ticket_size > buf_size)
    {
        ERROR_MSG("\nCalculated signed ticket size exceeds input buffer size! (0x%" PRIx64 " > 0x%" PRIx64 ").", signed_ticket_size, buf_size);
        return false;
    }
    
    sig_type = signatureGetSigType(buf);
    
    printf("  Signature type:         0x%08" PRIx32, sig_type);
    switch(sig_type)
    {
        case SignatureType_Rsa4096Sha1:
        case SignatureType_Rsa4096Sha256:
            type = TikType_SigRsa4096;
            printf(" (RSA-4096 + %s)", (sig_type == SignatureType_Rsa4096Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Rsa2048Sha1:
        case SignatureType_Rsa2048Sha256:
            type = TikType_SigRsa2048;
            printf(" (RSA-2048 + %s)", (sig_type == SignatureType_Rsa2048Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Ecc480Sha1:
        case SignatureType_Ecc480Sha256:
            type = TikType_SigEcc480;
            printf(" (ECDSA + %s)", (sig_type == SignatureType_Ecc480Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Hmac160Sha1:
            type = TikType_SigHmac160;
            printf(" (HMAC + SHA-1)");
            break;
        default:
            break;
    }
    printf(".\n");
    
    printf("  Signature issuer:       %.*s.\n", (int)sizeof(tik_common_block->issuer), tik_common_block->issuer);
    
    if (out_type) *out_type = type;
    if (out_size) *out_size = signed_ticket_size;
    
    return true;
}
