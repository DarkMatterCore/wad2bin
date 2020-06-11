/*
 * tik.h
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

#ifndef __TIK_H__
#define __TIK_H__

#include "signature.h"
#include "crypto.h"

#define TIK_MIN_SIZE    0x1A4   /* Equivalent to sizeof(TikSigHmac160) */

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
    u8 cnt_access_permissions;      ///< Content access permissions (one bit for each content). The first 0x20 bytes are usually set to 0xFF.
    u8 reserved_3[0x02];
    TikTimeLimit time_limits[8];    ///< Time limits (used in SSBB VC titles).
} TikCommonBlock;

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

/// Determines if a buffer holds a valid ticket and saves its type and size to the input pointers.
/// out_type and out_size can be NULL, but at least one of them must be a valid pointer.
/// Returns false if an error occurs.
bool tikGetTicketTypeAndSize(const void *buf, size_t buf_size, u8 *out_type, size_t *out_size);

/// Reads a ticket from a file and validates its signature size.
u8 *tikReadTicketFromFile(FILE *fd, size_t ticket_size);

/// Returns a pointer to the common ticket block from a ticket stored in a memory buffer.
/// Optionally, it also saves the ticket type to an input pointer if provided.
TikCommonBlock *tikGetCommonBlockFromBuffer(void *buf, size_t buf_size, u8 *out_ticket_type);

/// Checks the Title ID from a common ticket block to determine if the title is exportable.
bool tikIsTitleExportable(TikCommonBlock *tik_common_block);

/// Fakesigns a ticket stored in a buffer.
void tikFakesignTicket(void *buf, size_t buf_size);

#endif /* __TIK_H__ */
