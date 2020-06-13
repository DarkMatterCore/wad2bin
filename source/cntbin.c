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
#include "cntbin.h"

bool cntbinConvertInstallableWadPackageToBackupPackage(const os_char_t *keys_file_path, const os_char_t *device_cert_path, const os_char_t *wad_path, const os_char_t *out_path, os_char_t *tmp_path, size_t tmp_path_len)
{
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
    if (!wadUnpackInstallablePackage(wad_path, tmp_path)) return false;
    printf("WAD package \"" OS_PRINT_STR "\" successfully unpacked.\n\n", wad_path);
    
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
    
    
    
    
    
    
    
    
    
    
    
    
    
out:
    
    if (icon_bin) free(icon_bin);
    
    if (opening_bnr) fclose(opening_bnr);
    
    return success;
}


