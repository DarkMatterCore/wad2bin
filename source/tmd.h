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

#include "cert.h"
#include "crypto.h"

#define TMD_MAX_CONTENT_COUNT       512

#define SIGNED_TMD_MAX_SIZE         (u64)(sizeof(TmdSigRsa4096) + (TMD_MAX_CONTENT_COUNT * sizeof(TmdContentRecord)))
#define SIGNED_TMD_MIN_SIZE         (u64)(sizeof(TmdSigHmac160) + sizeof(TmdContentRecord))

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

/// Placed after the TMD signature block.
typedef struct {
    char issuer[0x40];
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

typedef enum {
    TmdContentRecordType_Normal = 0x0001,
    TmdContentRecordType_DLC    = 0x4001,
    TmdContentRecordType_Shared = 0x8001
} TmdContentRecordType;

/// Placed after the TMD common block.
typedef struct {
    u32 content_id;
    u16 index;
    u16 type;                   ///< TmdContentRecordType.
    u64 size;
    u8 hash[SHA1_HASH_SIZE];    ///< SHA-1 hash.
} PACKED TmdContentRecord;

typedef struct {
    SignatureBlockRsa4096 sig_block;    ///< sig_type field is stored using big endian byte order.
    TmdCommonBlock tmd_common_block;
    TmdContentRecord tmd_contents[];    ///< C99 flexible array.
} TmdSigRsa4096;

typedef struct {
    SignatureBlockRsa2048 sig_block;    ///< sig_type field is stored using big endian byte order.
    TmdCommonBlock tmd_common_block;
} TmdSigRsa2048;

typedef struct {
    SignatureBlockEcc480 sig_block;    ///< sig_type field is stored using big endian byte order.
    TmdCommonBlock tmd_common_block;
    TmdContentRecord tmd_contents[];    ///< C99 flexible array.
} TmdSigEcc480;

typedef struct {
    SignatureBlockHmac160 sig_block;    ///< sig_type field is stored using big endian byte order.
    TmdCommonBlock tmd_common_block;
    TmdContentRecord tmd_contents[];    ///< C99 flexible array.
} TmdSigHmac160;

/// Used to store TMD type, size and raw data.
typedef struct {
    u8 type;        ///< TmdType.
    u64 size;       ///< Raw TMD size.
    bool valid_sig; ///< Determines if the TMD signature is valid or not.
    u8 *data;       ///< Raw TMD data.
} TitleMetadata;

/// Reads a TMD from a file and validates its signature size.
bool tmdReadTitleMetadataFromFile(FILE *fd, u64 tmd_size, TitleMetadata *out_tmd, CertificateChain *chain);

/// Fakesigns a TMD.
void tmdFakesignTitleMetadata(TitleMetadata *tmd);

/// Helper inline functions.

ALWAYS_INLINE void tmdFreeTitleMetadata(TitleMetadata *tmd)
{
    if (!tmd) return;
    if (tmd->data) free(tmd->data);
    memset(tmd, 0, sizeof(TitleMetadata));
}

ALWAYS_INLINE TmdCommonBlock *tmdGetCommonBlock(void *buf)
{
    return (TmdCommonBlock*)signatureGetPayload(buf);
}

ALWAYS_INLINE TmdContentRecord *tmdGetTitleMetadataContentRecords(TmdCommonBlock *tmd_common_block)
{
    return (tmd_common_block != NULL ? (TmdContentRecord*)((u8*)tmd_common_block + sizeof(TmdCommonBlock)) : NULL);
}

ALWAYS_INLINE bool tmdIsValidTitleMetadata(void *buf)
{
    TmdCommonBlock *tmd_common_block = tmdGetCommonBlock(buf);
    u16 content_count = bswap_16(tmd_common_block->content_count);
    return (tmd_common_block != NULL && content_count <= TMD_MAX_CONTENT_COUNT);
}

ALWAYS_INLINE u64 tmdGetTitleMetadataContentRecordsBlockSize(TmdCommonBlock *tmd_common_block)
{
    return (u64)(tmd_common_block != NULL ? (bswap_16(tmd_common_block->content_count) * sizeof(TmdContentRecord)) : 0);
}

ALWAYS_INLINE u64 tmdGetSignedTitleMetadataSize(void *buf)
{
    return (tmdIsValidTitleMetadata(buf) ? (signatureGetBlockSize(signatureGetSigType(buf)) + (u64)sizeof(TmdCommonBlock) + tmdGetTitleMetadataContentRecordsBlockSize(tmdGetCommonBlock(buf))) : 0);
}

ALWAYS_INLINE u64 tmdGetSignedTitleMetadataHashAreaSize(void *buf)
{
    return (tmdIsValidTitleMetadata(buf) ? ((u64)sizeof(TmdCommonBlock) + tmdGetTitleMetadataContentRecordsBlockSize(tmdGetCommonBlock(buf))) : 0);
}

ALWAYS_INLINE void tmdByteswapTitleMetadataContentRecordFields(TmdContentRecord *content_record)
{
    if (!content_record || IS_BIG_ENDIAN) return;
    content_record->content_id = __builtin_bswap32(content_record->content_id);
    content_record->index = __builtin_bswap16(content_record->index);
    content_record->type = __builtin_bswap16(content_record->type);
    content_record->size = __builtin_bswap64(content_record->size);
}

#endif /* __TMD_H__ */
