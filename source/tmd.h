/*
 * tmd.h
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

#ifndef __TMD_H__
#define __TMD_H__

#include "signature.h"

#define TMD_MAX_SIZE    0x   /* Equivalent to sizeof(TmdSigRsa2048) */
#define TMD_MIN_SIZE    0x   /* Equivalent to sizeof(TmdSigHmac160) */

typedef enum {
    TmdType_None        = 0,
    TmdType_SigRsa4096  = 1,
    TmdType_SigRsa2048  = 2,
    TmdType_SigEcc480   = 3,
    TmdType_SigHmac160  = 4
} TmdType;








typedef enum {
    TmdTargetSystem_Normal = 0,
    TmdTargetSystem_vWii   = 1
} TmdTargetSystem;

typedef enum {
    TmdTitleType_Default      = 0x01,
    TmdTitleType_Unknown_0x04 = 0x04,
    TmdTitleType_Data         = 0x08,
    TmdTitleType_Unknown_0x10 = 0x10,
    TmdTitleType_WFS          = 0x20,
    TmdTitleType_CT           = 0x40
} TmdTitleType;



/// Placed after the ticket signature block.
typedef struct {
    u8 tmd_version;
    u8 ca_crl_version;
    u8 signer_crl_version;
    u8 target_system;       ///< TmdTargetSystem.
    u64 system_version;     ///< Required IOS version. Set to 0 for IOS. Set to boot2 version for boot2.
    u64 title_id;           ///< Title ID.
    u32 title_type;         ///< TmdTitleType.
    char group_id[0x02];    ///< Publisher.
    u8 reserved[0x02];
    
} TmdCommonBlock;






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
bool tikGetTicketTypeAndSize(const void *buf, size_t buf_size, u8 *out_type, u64 *out_size);

/// Reads a ticket from a file and verifies its signature size.
u8 *tikReadTicketFromFile(FILE *fd, size_t ticket_size);

/// Returns a pointer to the common ticket block from a ticket stored in a memory buffer.
/// Optionally, it also saves the ticket type to an input pointer if provided.
TikCommonBlock *tikGetCommonBlockFromBuffer(void *buf, size_t buf_size, u8 *out_ticket_type);

/// Checks the Title ID from a common ticket block to determine if the title is exportable.
bool tikIsTitleExportable(TikCommonBlock *tik_common_block);

/// Fakesigns a ticket stored in a buffer.
void tikFakesignTicket(void *buf, size_t buf_size);

#endif /* __TIK_H__ */
