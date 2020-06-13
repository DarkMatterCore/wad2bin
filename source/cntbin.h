/*
 * cntbin.h
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

#ifndef __CNTBIN_H__
#define __CNTBIN_H__

#include "wad.h"
#include "crypto.h"

#define IMET_MAGIC              (u32)0x494D4554 /* "IMET". */
#define IMET_HASHED_AREA_SIZE   (u32)0x600
#define IMET_FILE_COUNT         (u32)3
#define IMET_NAME_LENGTH        42

#define IMD5_MAGIC              (u32)0x494D4435 /* "IMD5". */

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

typedef struct {
    u32 magic;              ///< IMD5_MAGIC.
    u32 data_size;          ///< Data size after this header.
    u8 reserved[0x08];
    u8 hash[MD5_HASH_SIZE]; ///< MD5 hash calculated over IMD5 data after this header.
} CntBinImd5Header;

/// content.bin encrypted header, also known as Part A.
/// This is followed by an encrypted copy of the icon.bin portion from the title's opening.bnr, which is known as Part B and has a variable size.
/// Then, a WAD backup package header (WadBackupPackageHeader) follows, also known as "Bk" header or Part C.
/// A cleartext TMD area follows, also known as Part D.
/// Part E is nothing more than the encrypted content files, using console specific keydata.
/// Finally, Part F is cleartext certificate area used to verify the package validity, using an ECC signature that's calculated from Part C onwards.
/// Each part from a content.bin file must be aligned to a 64-byte boundary, using zeroes to pad data if necessary (except for the end of Part D and the start of Part E).
typedef struct {
    u64 title_id;                       ///< Title ID.
    u32 icon_area_size;                 ///< Encrypted icon.bin area size.
    u8 header_hash[MD5_HASH_SIZE];      ///< MD5 hash of the header with this field set to zeroes.
    u8 icon_area_hash[MD5_HASH_SIZE];   ///< MD5 hash of the decrypted icon.bin area.
    u32 unknown_lower_tid;              ///< Lower ID from another title (unknown purpose).
    u64 ref_title_id_1;                 ///< Full ID from another title (unknown purpose).
    u64 ref_title_id_2;                 ///< Full ID from another title (unknown purpose).
    CntBinImetHeader imet_header;       ///< IMET header.
} CntBinHeader;

bool cntbinConvertInstallableWadPackageToBackupPackage(const os_char_t *keys_file_path, const os_char_t *device_cert_path, const os_char_t *wad_path, const os_char_t *out_path, os_char_t *tmp_path, size_t tmp_path_len);

#endif /* __CNTBIN_H__ */
