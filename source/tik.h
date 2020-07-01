/*
 * tik.h
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

#ifndef __TIK_H__
#define __TIK_H__

#include "cert.h"
#include "crypto.h"

#define SIGNED_TIK_MAX_SIZE         (u64)sizeof(TikSigRsa4096)
#define SIGNED_TIK_MIN_SIZE         (u64)sizeof(TikSigHmac160)

#define TIK_COMMON_KEY_INDEX_STR(x) ((x) == TikCommonKeyIndex_Korean ? "Korean" : ((x) == TikCommonKeyIndex_vWii ? "vWii" : "Normal"))

typedef enum {
    TikType_None        = 0,
    TikType_SigRsa4096  = 1,
    TikType_SigRsa2048  = 2,
    TikType_SigEcc480   = 3,
    TikType_SigHmac160  = 4
} TikType;

typedef enum {
    TikTitleExport_NotAllowed = 0,
    TikTitleExport_Allowed    = 1
} TikTitleExport;

typedef enum {
    TikCommonKeyIndex_Normal = 0,
    TikCommonKeyIndex_Korean = 1,
    TikCommonKeyIndex_vWii   = 2
} TikCommonKeyIndex;

typedef struct {
    u32 enabled;    ///< 0 = Disabled, 1 = Enabled.
    u32 seconds;    ///< Time limit expressed in seconds.
} TikTimeLimit;

/// Placed after the ticket signature block.
typedef struct {
    char issuer[0x40];
    u8 ecdh_data[0x3C];             ///< ECDH data. Used to generate one-time key during install of console specific titles.
    u8 reserved_1[0x03];
    u8 titlekey[AES_BLOCK_SIZE];    ///< Encrypted titlekey. Its decrypted form is used to encrypt all content files from a title.
    u8 reserved_2;
    u64 ticket_id;                  ///< Ticket ID. Used as the IV for titlekey decryption of console specific titles.
    u32 console_id;                 ///< Console ID.
    u64 title_id;                   ///< Title ID. Used as the IV for titlekey decryption using the common key (the last 8 bytes of the IV should be zero).
    u16 access_mask;                ///< Access mask (always 0xFFFF).
    u16 title_version;              ///< Title version.
    u32 permitted_titles_mask;      ///< Permitted Titles Mask.
    u32 permit_mask;                ///< Permit mask. The title ID is ANDed with the inverse of this mask to see if the result matches the Permitted Titles Mask.
    u8 title_export;                ///< TikTitleExport. Not entirely sure about this one, I have seen exportable titles with this field set to zero.
    u8 common_key_index;            ///< TikCommonKeyIndex. Out of range values can be found in some titles, though...
    u8 unknown[0x30];               ///< Unknown. It's usually all zeroes except for VC and system titles, in which the last byte is set to 1.
    u8 access_permissions[0x40];    ///< Content access permissions (one bit for each content). The first 0x20 bytes are usually set to 0xFF.
    u8 reserved_3[0x02];
    TikTimeLimit time_limits[8];    ///< Time limits (used in SSBB VC titles).
} PACKED TikCommonBlock;

typedef struct {
    SignatureBlockRsa4096 sig_block;    ///< sig_type field is stored using big endian byte order.
    TikCommonBlock tik_common_block;
} TikSigRsa4096;

typedef struct {
    SignatureBlockRsa2048 sig_block;    ///< sig_type field is stored using big endian byte order.
    TikCommonBlock tik_common_block;
} TikSigRsa2048;

typedef struct {
    SignatureBlockEcc480 sig_block;    ///< sig_type field is stored using big endian byte order.
    TikCommonBlock tik_common_block;
} TikSigEcc480;

typedef struct {
    SignatureBlockHmac160 sig_block;    ///< sig_type field is stored using big endian byte order.
    TikCommonBlock tik_common_block;
} TikSigHmac160;

/// Used to store ticket type, size and raw data.
typedef struct {
    u8 type;                        ///< TikType.
    u64 size;                       ///< Raw ticket size.
    bool valid_sig;                 ///< Determines if the ticket signature is valid or not.
    u8 *data;                       ///< Raw ticket data.
} Ticket;

/// Reads a ticket from a file and validates its signature.
bool tikReadTicketFromFile(FILE *fd, u64 ticket_size, Ticket *out_ticket, CertificateChain *chain);

/// Fakesigns a ticket.
void tikFakesignTicket(Ticket *ticket);

/// Helper inline functions.

ALWAYS_INLINE void tikFreeTicket(Ticket *ticket)
{
    if (!ticket) return;
    if (ticket->data) free(ticket->data);
    memset(ticket, 0, sizeof(Ticket));
}

ALWAYS_INLINE TikCommonBlock *tikGetCommonBlock(void *buf)
{
    return (TikCommonBlock*)signatureGetPayload(buf);
}

ALWAYS_INLINE u64 tikGetSignedTicketSize(void *buf)
{
    TikCommonBlock *tik_common_block = tikGetCommonBlock(buf);
    return (u64)(tik_common_block != NULL ? (signatureGetBlockSize(signatureGetSigType(buf)) + sizeof(TikCommonBlock)) : 0);
}

#endif /* __TIK_H__ */
