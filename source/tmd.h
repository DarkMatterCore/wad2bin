/*
 * tmd.h
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

#ifndef __TMD_H__
#define __TMD_H__

#include "signature.h"
#include "crypto.h"

#define TMD_MIN_SIZE                0x108   /* Equivalent to sizeof(TmdSigHmac160) + sizeof(TmdContentRecord) */
#define TMD_MAX_CONTENT_COUNT       512
#define TMD_COMMON_BLOCK_SIZE(x)    (sizeof(TmdCommonBlock) + ((x)->content_count * sizeof(TmdContentRecord)))
#define TMD_CONTENTS(x)             ((TmdContentRecord*)(((u8*)(x)) + sizeof(TmdCommonBlock)))

#define TMD_TARGET_SYSTEM_STR(x)    ((x) == TmdTargetSystem_Wii ? "Wii" : ((x) == TmdTargetSystem_vWii ? "vWii" : "Unknown"))
#define TMD_CONTENT_REC_TYPE_STR(x) ((x) == TmdContentRecordType_Normal ? "Normal" : ((x) == TmdContentRecordType_DLC ? "DLC" : ((x) == TmdContentRecordType_Shared ? "Shared" : "Unknown")))

typedef enum {
    TmdType_None        = 0,
    TmdType_SigRsa4096  = 1,
    TmdType_SigRsa2048  = 2,
    TmdType_SigEcc480   = 3,
    TmdType_SigHmac160  = 4
} TmdType;

typedef enum {
    TmdTargetSystem_Wii    = 0,
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

typedef enum {
    TmdAccessRights_FullHardware   = BIT(0),
    TmdAccessRights_DriveInterface = BIT(1)
} TmdAccessRights;

typedef enum {
    TmdContentRecordType_Normal = 0x0001,
    TmdContentRecordType_DLC    = 0x4001,
    TmdContentRecordType_Shared = 0x8001
} TmdContentRecordType;

typedef struct {
    u32 content_id;
    u16 index;
    u16 type;                   ///< TmdContentRecordType.
    u64 size;
    u8 hash[SHA1_HASH_SIZE];    ///< SHA-1 hash.
} PACKED TmdContentRecord;

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
    u8 reserved_1[0x02];
    u16 region;
    u8 ratings[0x10];
    u8 reserved_2[0x0C];
    u8 ipc_mask[0x0C];
    u8 reserved_3[0x12];
    u32 access_rights;      ///< TmdAccessRights.
    u16 title_version;
    u16 content_count;
    u16 boot_index;
    u8 reserved_4[0x02];
} PACKED TmdCommonBlock;

typedef struct {
    SignatureBlockRsa4096 sig_block;    ///< sig_type field is stored using big endian byte order.
    TmdCommonBlock tmd_common_block;
} TmdSigRsa4096;

typedef struct {
    SignatureBlockRsa2048 sig_block;    ///< sig_type field is stored using big endian byte order.
    TmdCommonBlock tmd_common_block;
} TmdSigRsa2048;

typedef struct {
    SignatureBlockEcc480 sig_block;    ///< sig_type field is stored using big endian byte order.
    TmdCommonBlock tmd_common_block;
} TmdSigEcc480;

typedef struct {
    SignatureBlockHmac160 sig_block;    ///< sig_type field is stored using big endian byte order.
    TmdCommonBlock tmd_common_block;
} TmdSigHmac160;

/// Reads a TMD from a file and validates its signature size.
u8 *tmdReadTitleMetadataFromFile(FILE *fd, u64 tmd_size);

/// Returns a pointer to the common TMD block from a TMD stored in a memory buffer.
/// Optionally, it also saves the TMD type to an input pointer if provided.
TmdCommonBlock *tmdGetCommonBlockFromBuffer(void *buf, u64 buf_size, u8 *out_tmd_type);

/// Check the system version field from a common TMD block to determine if it references an IOS version.
bool tmdIsSystemVersionValid(TmdCommonBlock *tmd_common_block);

/// Fakesigns a TMD stored in a buffer.
void tmdFakesignTitleMetadata(void *buf, u64 buf_size);

/// Byteswaps fields from a TMD content record.
ALWAYS_INLINE void tmdByteswapTitleMetadataContentRecordFields(TmdContentRecord *content_record)
{
    if (!content_record || IS_BIG_ENDIAN) return;
    content_record->content_id = __builtin_bswap32(content_record->content_id);
    content_record->index = __builtin_bswap16(content_record->index);
    content_record->type = __builtin_bswap16(content_record->type);
    content_record->size = __builtin_bswap64(content_record->size);
}

#endif /* __TMD_H__ */
