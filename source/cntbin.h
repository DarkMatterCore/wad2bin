/*
 * cntbin.h
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

#ifndef __CNTBIN_H__
#define __CNTBIN_H__

#include "wad.h"
#include "crypto.h"
#include "cert.h"

#define IMET_MAGIC              (u32)0x494D4554         /* "IMET". */
#define IMET_HASHED_AREA_SIZE   (u32)0x600
#define IMET_FILE_COUNT         (u32)3
#define IMET_NAME_LENGTH        42

#define IMD5_MAGIC              (u32)0x494D4435         /* "IMD5". */

/// Used in the encrypted content.bin header (Part A).
typedef struct {
    u8 padding_1[0x40];
    u32 magic;                          ///< IMET_MAGIC.
    u32 hash_size;                      ///< Hashed area size. Always set to IMET_HASHED_AREA_SIZE.
    u32 file_count;                     ///< Always set to IMET_FILE_COUNT (icon.bin, banner.bin, sound.bin).
    u32 icon_bin_size;                  ///< icon.bin size (decompressed).
    u32 banner_bin_size;                ///< banner.bin size (decompressed).
    u32 sound_bin_size;                 ///< sound.bin size (decompressed).
    u8 reserved[0x04];
    u16 names[10][IMET_NAME_LENGTH];    ///< Title names in different languages (Japanese, English, German, French, Spanish, Italian, Dutch, unknown, unknown, Korean). Encoded using UTF-16BE.
    u8 padding_2[0x24C];
    u8 hash[MD5_HASH_SIZE];             ///< MD5 hash from the magic word to hash_size. This field must be set to zeroes when calculating the hash.
} CntBinImetHeader;

/// Used in the encrypted icon.bin copy in content.bin (Part B).
typedef struct {
    u32 magic;              ///< IMD5_MAGIC.
    u32 data_size;          ///< Data size after this header.
    u8 reserved[0x08];
    u8 hash[MD5_HASH_SIZE]; ///< MD5 hash calculated over IMD5 data after this header.
} CntBinImd5Header;

/// content.bin encrypted header (Part A).
/// This is followed by an encrypted copy of the icon.bin portion from the title's opening.bnr, which is known as Part B and has a variable size.
/// Then, a WAD backup package header (WadBackupPackageHeader) follows, also known as "Bk" header or Part C.
/// A cleartext TMD area follows, also known as Part D.
/// Part E is nothing more than the encrypted content files, using console specific keydata.
/// Finally, Part F is a plaintext certificate area used to verify the backup package validity, using an ECC signature that's calculated from Part C onwards (check CntBinCertArea).
/// Each part from a content.bin file must be aligned to a 64-byte boundary, using zeroes to pad data if necessary.
typedef struct {
    u64 title_id;                       ///< Title ID.
    u32 icon_bin_size;                  ///< Decrypted icon.bin size. Align to AES_BLOCK_SIZE to get the Part B size.
    u8 header_hash[MD5_HASH_SIZE];      ///< MD5 hash of the header with this field set to the MD5 blanker.
    u8 icon_bin_hash[MD5_HASH_SIZE];    ///< MD5 hash of the decrypted icon.bin (with WAD block alignment padding).
    u32 unknown_tid_lower;              ///< Title ID lower u32 from another title (unknown purpose).
    u64 ref_tid_1;                      ///< Full Title ID from another title (unknown purpose).
    u64 ref_tid_2;                      ///< Full Title ID from another title (unknown purpose).
    CntBinImetHeader imet_header;       ///< IMET header.
} CntBinHeader;

/// Plaintext certificate area (Part F).
typedef struct {
    u8 signature[ECSDA_SIG_SIZE];
    CertSigEcc480PubKeyEcc480 device_cert;
    CertSigEcc480PubKeyEcc480 ap_cert;
} CntBinCertArea;

/// Generates a content.bin file using an unpacked WAD data directory and TMD data loaded into memory.
bool cntbinGenerateFromUnpackedInstallableWadPackage(os_char_t *unpacked_wad_path, os_char_t *out_path, u8 **tmd, size_t *tmd_size);

#endif /* __CNTBIN_H__ */
