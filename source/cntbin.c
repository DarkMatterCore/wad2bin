/*
 * cntbin.c
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

#include "utils.h"
#include "keys.h"
#include "u8.h"
#include "tik.h"
#include "tmd.h"
#include "cntbin.h"

bool cntbinConvertInstallableWadPackageToBackupPackage(const os_char_t *keys_file_path, const os_char_t *device_cert_path, const os_char_t *wad_path, os_char_t *out_path, os_char_t *tmp_path)
{
    size_t out_path_len = os_strlen(out_path), new_out_path_len = 0;
    size_t tmp_path_len = os_strlen(tmp_path);
    
    u8 *ticket = NULL;
    size_t ticket_size = 0;
    TikCommonBlock *tik_common_block = NULL;
    
    u8 *tmd = NULL;
    size_t tmd_size = 0;
    TmdCommonBlock *tmd_common_block = NULL;
    
    u64 title_id = 0;
    u32 low_tid = 0;
    char low_tid_ascii[5] = {0};
    
    FILE *opening_bnr = NULL;
    u8 *icon_bin = NULL;
    size_t res = 0, imet_icon_bin_size = 0, icon_bin_size = 0;
    
    CntBinHeader cntbin_header = {0};
    u8 imet_hash[MD5_HASH_SIZE] = {0}, calc_imet_hash[MD5_HASH_SIZE] = {0};
    
    CntBinImd5Header *imd5_header = NULL;
    u8 imd5_hash[MD5_HASH_SIZE] = {0};
    

    
    
    
    
    
    
    
    bool success = false;
    
    /* Load keydata and device certificate. */
    if (!keysLoadKeyDataAndDeviceCert(keys_file_path, device_cert_path)) return false;
    printf("Keydata and device certificate successfully loaded.\n\n");
    
    /* Unpack input WAD package. */
    if (!wadUnpackInstallablePackage(wad_path, tmp_path, NULL, NULL, &ticket, &ticket_size, &tmd, &tmd_size)) return false;
    printf("WAD package \"" OS_PRINT_STR "\" successfully unpacked.\n\n", wad_path);
    
    /* Retrieve ticket and TMD common blocks. */
    tik_common_block = tikGetCommonBlockFromBuffer(ticket, ticket_size, NULL);
    tmd_common_block = tmdGetCommonBlockFromBuffer(tmd, tmd_size, NULL);
    
    /* Get title ID and convert its lower u32 to ASCII. */
    title_id = bswap_64(tmd_common_block->title_id);
    low_tid = TITLE_LOWER(title_id);
    
    for(u8 i = 0; i < 4; i++)
    {
        low_tid_ascii[i] = (char)((u8)(low_tid >> (24 - (i * 8))) & 0xFF);
        if (low_tid_ascii[i] < 0x20 || low_tid_ascii[i] > 0x7E) low_tid_ascii[i] = '.';
    }
    
    /* Open 00000000.app content file (opening.bnr). */
    os_snprintf(tmp_path + tmp_path_len, MAX_PATH - tmp_path_len, OS_PATH_SEPARATOR "00000000.app");
    opening_bnr = os_fopen(tmp_path, OS_MODE_READ);
    if (!opening_bnr)
    {
        ERROR_MSG("Failed to open \"" OS_PRINT_STR "\" in read mode!", tmp_path);
        return false;
    }
    
    /* Read full IMET header. */
    res = fread(&cntbin_header, 1, sizeof(CntBinHeader), opening_bnr);
    if (res != sizeof(CntBinHeader))
    {
        ERROR_MSG("Failed to read IMET header from \"" OS_PRINT_STR "\"!", tmp_path);
        goto out;
    }
    
    /* Copy IMET hash and wipe it from the IMET header. */
    memcpy(imet_hash, cntbin_header.imet_header.hash, MD5_HASH_SIZE);
    memset(cntbin_header.imet_header.hash, 0, MD5_HASH_SIZE);
    
    /* Calculate IMET hash. */
    mbedtls_md5((u8*)&cntbin_header.imet_header, sizeof(CntBinImetHeader), calc_imet_hash);
    
    /* Check IMET header fields. */
    if (cntbin_header.imet_header.magic != bswap_32(IMET_MAGIC) || cntbin_header.imet_header.hash_size != bswap_32(IMET_HASHED_AREA_SIZE) || \
        cntbin_header.imet_header.file_count != bswap_32(IMET_FILE_COUNT) || !(imet_icon_bin_size = bswap_32(cntbin_header.imet_header.icon_bin_size)) || !cntbin_header.imet_header.banner_bin_size || \
        !cntbin_header.imet_header.sound_bin_size || memcmp(imet_hash, calc_imet_hash, MD5_HASH_SIZE) != 0)
    {
        ERROR_MSG("Invalid IMET header in \"" OS_PRINT_STR "\"!", tmp_path);
        goto out;
    }
    
    /* Print IMET information. */
    printf("IMET header:\n");
    printf("  icon.bin size:          0x%" PRIx64 " (decompressed).\n", imet_icon_bin_size);
    printf("  banner.bin size:        0x%" PRIx32 " (decompressed).\n", bswap_32(cntbin_header.imet_header.banner_bin_size));
    printf("  sound.bin size:         0x%" PRIx32 " (decompressed).\n", bswap_32(cntbin_header.imet_header.sound_bin_size));
    utilsPrintHexData("  Hash:                   ", imet_hash, MD5_HASH_SIZE);
    utilsPrintUTF16BEString("  Title name:             ", cntbin_header.imet_header.names[1], IMET_NAME_LENGTH);
    printf("  Build name:             %.*s.\n", 0x30, (char*)&(cntbin_header));
    printf("  Builder:                %.*s.\n\n", 0x10, (char*)&(cntbin_header) + 0x30);
    
    /* Load icon.bin file from 00000000.app U8 archive. */
    icon_bin = u8LoadFileDataFromU8ArchiveByPath(opening_bnr, "/meta/icon.bin", &icon_bin_size);
    if (!icon_bin) goto out;
    
    /* Check size. */
    if (icon_bin_size <= sizeof(CntBinImd5Header))
    {
        ERROR_MSG("Invalid icon.bin size!");
        goto out;
    }
    
    /* Calculate IMD5 hash. */
    imd5_header = (CntBinImd5Header*)icon_bin;
    mbedtls_md5(icon_bin + sizeof(CntBinImd5Header), icon_bin_size - sizeof(CntBinImd5Header), imd5_hash);
    
    /* Check IMD5 header fields. */
    if (imd5_header->magic != bswap_32(IMD5_MAGIC) || imd5_header->data_size != bswap_32((u32)(icon_bin_size - sizeof(CntBinImd5Header))) || memcmp(imd5_header->hash, imd5_hash, MD5_HASH_SIZE) != 0)
    {
        ERROR_MSG("Invalid icon.bin IMD5 header!");
        goto out;
    }
    
    /* Print IMD5 information. */
    printf("IMD5 (icon.bin):\n");
    printf("  Data size:              0x%" PRIx32 ".\n", bswap_32(imd5_header->data_size));
    utilsPrintHexData("  Hash:                   ", imd5_header->hash, MD5_HASH_SIZE);
    printf("\n");
    
    /* Generate output path. */
    os_snprintf(out_path + out_path_len, MAX_PATH - out_path_len, CONTENT_PRIVATE_PATH, low_tid_ascii);
    utilsCreateDirectoryTree(out_path);
    
    new_out_path_len = os_strlen(out_path);
    os_snprintf(out_path + new_out_path_len, MAX_PATH - new_out_path_len, OS_PATH_SEPARATOR CONTENT_NAME);
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
out:
    if (icon_bin) free(icon_bin);
    
    if (opening_bnr) fclose(opening_bnr);
    
    if (tmd) free(tmd);
    
    if (ticket) free(ticket);
    
    tmp_path[tmp_path_len] = (os_char_t)0;
    //utilsRemoveDirectoryRecursively(tmp_path);
    
    if (!success)
    {
        os_snprintf(out_path + out_path_len, MAX_PATH - out_path_len, OS_PATH_SEPARATOR "private");
        //utilsRemoveDirectoryRecursively(out_path);
    }
    
    out_path[out_path_len] = (os_char_t)0;
    
    return success;
}
