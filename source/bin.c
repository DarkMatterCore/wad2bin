/*
 * bin.c
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
#include "keys.h"
#include "u8.h"
#include "bin.h"

#define CONTENT_NAME            "content.bin"

#define UNKNOWN_TID_LOWER       (u32)0x57444645         /* "WDFE". Used by BannerBomb. */
#define REF_TID_1               (u64)0x0001000157424D45 /* 10001-WBME. Used by BannerBomb. */
#define REF_TID_2               (u64)0x000100014E414A4E /* 10001-NAJN. Used by BannerBomb. */

bool binGenerateContentBinFromUnpackedInstallableWadPackage(os_char_t *unpacked_wad_path, os_char_t *out_path, u8 *tmd, u64 tmd_size)
{
    size_t unpacked_wad_path_len = 0;
    size_t out_path_len = 0, new_out_path_len = 0;
    
    if (!unpacked_wad_path || !(unpacked_wad_path_len = os_strlen(unpacked_wad_path)) || !out_path || !(out_path_len = os_strlen(out_path)) || !tmd || !tmd_size)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u64 aligned_tmd_size = ALIGN_UP(tmd_size, WAD_BLOCK_SIZE);
    TmdCommonBlock *tmd_common_block = NULL;
    TmdContentRecord *tmd_contents = NULL;
    
    u16 content_count = 0;
    u8 cnt_iv[AES_BLOCK_SIZE] = {0};
    
    u32 console_id = 0;
    u8 *sd_key = NULL, *sd_iv = NULL, *md5_blanker = NULL, *ecc_private_key = NULL, *prng_key = NULL;
    CertSigEcc480PubKeyEcc480 *device_cert = NULL;
    
    char tid_lower_ascii[5] = {0};
    
    FILE *opening_bnr = NULL;
    u8 *icon_bin = NULL;
    u64 res = 0, icon_bin_size = 0;
    
    BinContentHeader cntbin_header = {0};
    u8 imet_hash[MD5_HASH_SIZE] = {0}, calc_imet_hash[MD5_HASH_SIZE] = {0}, cntbin_header_hash[MD5_HASH_SIZE] = {0};
    
    BinContentImd5Header *imd5_header = NULL;
    u8 imd5_hash[MD5_HASH_SIZE] = {0};
    
    WadBackupPackageHeader bk_header = {0};
    u64 content_data_size = 0, backup_area_size = 0;
    
    mbedtls_sha1_context sha1_ctx = {0};
    u8 backup_area_hash[SHA1_HASH_SIZE] = {0};
    
    BinContentCertArea cert_area = {0};
    u8 ap_private_key[ECC_PRIV_KEY_SIZE - 2] = {0};
    ap_private_key[ECC_PRIV_KEY_SIZE - 3] = 1; /* Keep it simple, don't generate a random value for the key. */
    
    FILE *content_bin = NULL;
    
    bool success = false;
    
    /* Retrieve TMD common block, contents and content count. */
    tmd_common_block = tmdGetCommonBlockFromBuffer(tmd, tmd_size, NULL);
    tmd_contents = TMD_CONTENTS(tmd_common_block);
    content_count = bswap_16(tmd_common_block->content_count);
    
    /* Retrieve required keydata. */
    console_id = keysGetConsoleId();
    sd_key = keysGetSdKey();
    sd_iv = keysGetSdIv();
    md5_blanker = keysGetMd5Blanker();
    ecc_private_key = keysGetEccPrivateKey();
    prng_key = keysGetPrngKey();
    device_cert = keysGetDeviceCertificate();
    
    /* Initialize SHA-1 context used to calculate a checksum over the backup area. */
    /* Needed to generate the ECSDA signature at the start of Part F. */
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts(&sha1_ctx);
    
    /* Convert the Title ID lower u32 to ASCII. */
    utilsGenerateAsciiStringFromTitleIdLower(bswap_64(tmd_common_block->title_id), tid_lower_ascii);
    
    /* Open 00000000.app content file (opening.bnr). */
    os_snprintf(unpacked_wad_path + unpacked_wad_path_len, MAX_PATH - unpacked_wad_path_len, OS_PATH_SEPARATOR "00000000.app");
    opening_bnr = os_fopen(unpacked_wad_path, OS_MODE_READ);
    if (!opening_bnr)
    {
        ERROR_MSG("Failed to open \"" OS_PRINT_STR "\" in read mode!", unpacked_wad_path);
        return false;
    }
    
    /* Read full IMET header. */
    res = fread(&cntbin_header, 1, sizeof(BinContentHeader), opening_bnr);
    if (res != sizeof(BinContentHeader))
    {
        ERROR_MSG("Failed to read IMET header from \"" OS_PRINT_STR "\"!", unpacked_wad_path);
        goto out;
    }
    
    /* Copy IMET hash and wipe it from the IMET header. */
    /* The IMET header from content.bin files doesn't have this hash. */
    memcpy(imet_hash, cntbin_header.imet_header.hash, MD5_HASH_SIZE);
    memset(cntbin_header.imet_header.hash, 0, MD5_HASH_SIZE);
    
    /* Calculate IMET hash. */
    mbedtls_md5((u8*)&cntbin_header.imet_header, sizeof(BinContentImetHeader), calc_imet_hash);
    
    /* Check IMET header fields. */
    if (cntbin_header.imet_header.magic != bswap_32(IMET_MAGIC) || cntbin_header.imet_header.hash_size != bswap_32(IMET_HASHED_AREA_SIZE) || \
        cntbin_header.imet_header.file_count != bswap_32(IMET_FILE_COUNT) || !cntbin_header.imet_header.icon_bin_size || !cntbin_header.imet_header.banner_bin_size || \
        !cntbin_header.imet_header.sound_bin_size || memcmp(imet_hash, calc_imet_hash, MD5_HASH_SIZE) != 0)
    {
        ERROR_MSG("Invalid IMET header in \"" OS_PRINT_STR "\"!", unpacked_wad_path);
        goto out;
    }
    
    /* Print IMET information. */
    printf("IMET header:\n");
    printf("  icon.bin size:          0x%" PRIx32 " (decompressed).\n", bswap_32(cntbin_header.imet_header.icon_bin_size));
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
    if (icon_bin_size <= sizeof(BinContentImd5Header))
    {
        ERROR_MSG("Invalid icon.bin size!");
        goto out;
    }
    
    /* Calculate IMD5 hash. */
    imd5_header = (BinContentImd5Header*)icon_bin;
    mbedtls_md5(icon_bin + sizeof(BinContentImd5Header), icon_bin_size - sizeof(BinContentImd5Header), imd5_hash);
    
    /* Check IMD5 header fields. */
    if (imd5_header->magic != bswap_32(IMD5_MAGIC) || imd5_header->data_size != bswap_32((u32)(icon_bin_size - sizeof(BinContentImd5Header))) || memcmp(imd5_header->hash, imd5_hash, MD5_HASH_SIZE) != 0)
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
    os_snprintf(out_path + out_path_len, MAX_PATH - out_path_len, PRIVATE_PATH("title"), tid_lower_ascii);
    utilsCreateDirectoryTree(out_path);
    
    new_out_path_len = os_strlen(out_path);
    os_snprintf(out_path + new_out_path_len, MAX_PATH - new_out_path_len, OS_PATH_SEPARATOR CONTENT_NAME);
    
    /* Open content.bin file. */
    content_bin = os_fopen(out_path, OS_MODE_WRITE);
    if (!content_bin)
    {
        ERROR_MSG("Failed to open \"" OS_PRINT_STR "\" in write mode!", out_path);
        goto out;
    }
    
    /* Update content.bin header (Part A). */
    cntbin_header.title_id = tmd_common_block->title_id;
    cntbin_header.icon_bin_size = bswap_32((u32)icon_bin_size);
    memcpy(cntbin_header.header_hash, md5_blanker, MD5_HASH_SIZE);
    cntbin_header.unknown_tid_lower = bswap_32(UNKNOWN_TID_LOWER);
    cntbin_header.ref_tid_1 = bswap_64(REF_TID_1);
    cntbin_header.ref_tid_2 = bswap_64(REF_TID_2);
    
    /* Reallocate icon.bin buffer (if necessary). */
    /* We need to do this if the icon.bin size isn't aligned to the WAD block size. */
    if (!utilsAlignBuffer((void**)&icon_bin, &icon_bin_size, WAD_BLOCK_SIZE))
    {
        ERROR_MSG("Failed to align icon.bin buffer to WAD block size!");
        goto out;
    }
    
    /* Calculate decrypted icon.bin MD5 hash. */
    /* Hash is calculated over the WAD block size padding as well. */
    mbedtls_md5(icon_bin, icon_bin_size, cntbin_header.icon_bin_hash);
    
    /* Calculate header hash. */
    mbedtls_md5((u8*)&cntbin_header, sizeof(BinContentHeader), cntbin_header_hash);
    memcpy(cntbin_header.header_hash, cntbin_header_hash, MD5_HASH_SIZE);
    
    /* Print content.bin header (Part A) information. */
    printf("content.bin header (Part A):\n");
    printf("  Title ID:               %016" PRIx64 ".\n", bswap_64(cntbin_header.title_id));
    printf("  icon.bin size:          0x%" PRIx32 ".\n", bswap_32(cntbin_header.icon_bin_size));
    utilsPrintHexData("  Hash:                   ", cntbin_header.header_hash, MD5_HASH_SIZE);
    utilsPrintHexData("  icon.bin hash:          ", cntbin_header.icon_bin_hash, MD5_HASH_SIZE);
    printf("\n");
    
    /* Encrypt header (Part A) in-place. */
    if (!cryptoAes128CbcCrypt(sd_key, sd_iv, &cntbin_header, &cntbin_header, sizeof(BinContentHeader), true))
    {
        ERROR_MSG("Failed to encrypt header (Part A) for \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    /* Write encrypted content.bin header (Part A). */
    res = fwrite(&cntbin_header, 1, sizeof(BinContentHeader), content_bin);
    if (res != sizeof(BinContentHeader))
    {
        ERROR_MSG("Failed to write encrypted header (Part A) to \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    /* Encrypt icon.bin (Part B) in-place. */
    if (!cryptoAes128CbcCrypt(sd_key, sd_iv, icon_bin, icon_bin, icon_bin_size, true))
    {
        ERROR_MSG("Failed to encrypt icon.bin (Part B) for \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    /* Write encrypted icon.bin (Part B). */
    res = fwrite(icon_bin, 1, icon_bin_size, content_bin);
    if (res != icon_bin_size)
    {
        ERROR_MSG("Failed to write encrypted icon.bin (Part B) to \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    /* Prepare backup WAD header (Part C). */
    bk_header.header_size = (u32)WadHeaderSize_BackupPackage;
    bk_header.type = (u16)WadType_BackupPackage;
    bk_header.version = (u16)WadVersion_BackupPackage;
    bk_header.console_id = console_id;
    bk_header.content_tmd_size = (u32)tmd_size;
    
    /* Calculate content data size and generate the included contents bitfield. */
    for(u16 i = 0; i < content_count; i++)
    {
        /* TODO: check if shared content inclusion actually works. */
        /* If not, they must be discarded here. */
        //if (bswap_16(tmd_contents[i].type) != TmdContentRecordType_Normal) continue;
        content_data_size += ALIGN_UP(bswap_64(tmd_contents[i].size), WAD_BLOCK_SIZE);
        wadUpdateBackupPackageHeaderIncludedContents(&bk_header, i);
    }
    
    bk_header.content_data_size = (u32)content_data_size;
    
    /* Calculate backup area size. */
    backup_area_size = (sizeof(WadBackupPackageHeader) + aligned_tmd_size + content_data_size + sizeof(BinContentCertArea));
    bk_header.backup_area_size = (u32)backup_area_size;
    
    /* Print content.bin backup WAD header (Part C) information. */
    char wad_type[3] = { (u8)(bk_header.type >> 8), (u8)bk_header.type, 0 };
    printf("content.bin backup WAD header (Part C):\n");
    printf("  Header size:            0x%" PRIx32 " (%s).\n", bk_header.header_size, WAD_HEADER_SIZE_STR(bk_header.header_size));
    printf("  Type:                   \"%s\" (%s).\n", wad_type, WAD_TYPE_STR(bk_header.type));
    printf("  Version:                %u (%s).\n", bk_header.version, WAD_VERSION_STR(bk_header.version));
    printf("  Console ID:             %08" PRIx32 ".\n", bk_header.console_id);
    printf("  TMD size:               0x%" PRIx32 ".\n", bk_header.content_tmd_size);
    printf("  Content data size:      0x%" PRIx32 ".\n", bk_header.content_data_size);
    printf("  Backup area size:       0x%" PRIx32 ".\n\n", bk_header.backup_area_size);
    
    /* Byteswap backup WAD header (Part C) fields. */
    wadByteswapBackupPackageHeaderFields(&bk_header);
    
    /* Write plaintext "Bk" header (Part C). */
    res = fwrite(&bk_header, 1, sizeof(WadBackupPackageHeader), content_bin);
    if (res != sizeof(WadBackupPackageHeader))
    {
        ERROR_MSG("Failed to write plaintext \"Bk\" header (Part C) to \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    /* Update SHA-1 hash calculation. */
    mbedtls_sha1_update(&sha1_ctx, (u8*)&bk_header, sizeof(WadBackupPackageHeader));
    
    /* Write plaintext TMD (Part D). */
    res = fwrite(tmd, 1, aligned_tmd_size, content_bin);
    if (res != aligned_tmd_size)
    {
        ERROR_MSG("Failed to write plaintext TMD (Part D) to \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    /* Update SHA-1 hash calculation. */
    mbedtls_sha1_update(&sha1_ctx, tmd, aligned_tmd_size);
    
    /* Process content files (Part E). */
    printf("content.bin content data (Part E):\n");
    for(u16 i = 0; i < content_count; i++)
    {
        FILE *cnt_fd = NULL;
        u16 cnt_idx = bswap_16(tmd_contents[i].index);
        u64 cnt_size = bswap_64(tmd_contents[i].size);
        u64 aligned_cnt_size = 0;
        bool write_res = false;
        
        /* TODO: check if shared content inclusion actually works. */
        /* If not, they must be discarded here. */
        //if (bswap_16(tmd_contents[i].type) != TmdContentRecordType_Normal) continue;
        
        /* Generate content IV. */
        memset(cnt_iv, 0, AES_BLOCK_SIZE);
        memcpy(cnt_iv, &(tmd_contents[i].index), sizeof(u16));
        
        /* Generate input path for the current content. */
        os_snprintf(unpacked_wad_path + unpacked_wad_path_len, MAX_PATH - unpacked_wad_path_len, OS_PATH_SEPARATOR "%08" PRIx16 ".app", cnt_idx);
        
        /* Open content file. */
        cnt_fd = os_fopen(unpacked_wad_path, OS_MODE_READ);
        if (!cnt_fd)
        {
            ERROR_MSG("Failed to open unpacked content \"" OS_PRINT_STR "\" in read mode!", unpacked_wad_path);
            goto out;
        }
        
        /* Write encrypted content file. */
        write_res = wadWriteUnpackedContentToPackage(content_bin, prng_key, cnt_iv, &sha1_ctx, cnt_fd, cnt_idx, cnt_size, &aligned_cnt_size);
        if (!write_res) ERROR_MSG("Failed to write content file \"" OS_PRINT_STR "\" to \"" OS_PRINT_STR "\"!", unpacked_wad_path, out_path);
        
        /* Close content file. */
        fclose(cnt_fd);
        
        /* Stop process if there was an error. */
        if (!write_res) goto out;
        
        /* Print content information. */
        printf("  Content #%u:\n", cnt_idx + 1);
        printf("    Offset:               0x%" PRIx64 ".\n", os_ftell(content_bin));
        printf("    Size (unpacked):      0x%" PRIx64 ".\n", cnt_size);
        printf("    Size (encrypted):     0x%" PRIx64 ".\n", ALIGN_UP(cnt_size, AES_BLOCK_SIZE));
        printf("    Size (padded):        0x%" PRIx64 ".\n\n", aligned_cnt_size);
    }
    
    /* Retrieve backup area hash. */
    mbedtls_sha1_finish(&sha1_ctx, backup_area_hash);
    
    /* Print hash. */
    utilsPrintHexData("Backup area hash:         ", backup_area_hash, SHA1_HASH_SIZE);
    printf("\n");
    
    /* Prepare certificate area (Part F). */
    
    /* Generate backup area ECSDA signature using the AP private key and the SHA-1 we calculated. */
    cryptoGenerateEcsdaSignatureWithHash(ap_private_key, cert_area.signature, backup_area_hash, true);
    
    /* Copy device certificate. */
    memcpy(&(cert_area.device_cert), device_cert, sizeof(CertSigEcc480PubKeyEcc480));
    
    /* Set AP certificate signature type to ECSDA + SHA-1. */
    cert_area.ap_cert.sig_block.sig_type = bswap_32((u32)SignatureType_Ecc480Sha1);
    
    /* Set AP certificate signature issuer. */
    snprintf(cert_area.ap_cert.sig_block.issuer, sizeof(cert_area.ap_cert.sig_block.issuer), "Root-CA00000001-MS00000002-NG%08" PRIx32, console_id);
    
    /* Set AP certificate public key type to ECC-B233. */
    cert_area.ap_cert.cert_common_block.pub_key_type = bswap_32((u32)CertPubKeyType_Ecc480);
    
    /* Set AP certificate name. */
    snprintf(cert_area.ap_cert.cert_common_block.name, sizeof(cert_area.ap_cert.cert_common_block.name), "AP%016" PRIx64, SYSTEM_MENU_TID);
    
    /* Generate AP certificate public key using the AP private key. */
    cryptoGenerateEccPublicKey(ap_private_key, cert_area.ap_cert.pub_key_block.public_key);
    
    /* Generate AP certificate ECSDA signature using the ECC private key. */
    cryptoGenerateEcsdaSignatureWithData(ecc_private_key, cert_area.ap_cert.sig_block.signature, &(cert_area.ap_cert.sig_block.issuer), sizeof(cert_area.ap_cert.sig_block.issuer) + \
                                       sizeof(CertCommonBlock) + sizeof(CertPublicKeyBlockEcc480), false);
    
    /* Write plaintext certificate area (Part F). */
    res = fwrite(&cert_area, 1, sizeof(BinContentCertArea), content_bin);
    if (res != sizeof(BinContentCertArea))
    {
        ERROR_MSG("Failed to write plaintext certificate area (Part F) to \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    printf("Successfully saved converted WAD package to \"" OS_PRINT_STR "\".\n\n", out_path);
    
    success = true;
    
out:
    if (content_bin) fclose(content_bin);
    
    if (icon_bin) free(icon_bin);
    
    if (opening_bnr) fclose(opening_bnr);
    
    mbedtls_sha1_free(&sha1_ctx);
    
    if (!success && new_out_path_len > 0)
    {
        /* Remove only the last subdirectory from the directory tree we created. */
        out_path[new_out_path_len] = (os_char_t)0;
        utilsRemoveDirectoryRecursively(out_path);
    }
    
    out_path[out_path_len] = (os_char_t)0;
    unpacked_wad_path[unpacked_wad_path_len] = (os_char_t)0;
    
    return success;
}

bool binGenerateIndexedPackagesFromUnpackedInstallableWadPackage(os_char_t *unpacked_wad_path, os_char_t *out_path, u8 *tmd, u64 tmd_size, u64 parent_tid)
{
    size_t unpacked_wad_path_len = 0;
    size_t out_path_len = 0, new_out_path_len = 0;
    
    if (!unpacked_wad_path || !(unpacked_wad_path_len = os_strlen(unpacked_wad_path)) || !out_path || !(out_path_len = os_strlen(out_path)) || !tmd || !tmd_size)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u64 aligned_tmd_size = ALIGN_UP(tmd_size, WAD_BLOCK_SIZE);
    TmdCommonBlock *tmd_common_block = NULL;
    TmdContentRecord *tmd_contents = NULL;
    
    u16 content_count = 0;
    u8 cnt_iv[AES_BLOCK_SIZE] = {0};
    
    u32 console_id = 0;
    u8 *prng_key = NULL;
    
    u64 title_id = 0;
    char tid_lower_ascii[5] = {0};
    
    WadBackupPackageHeader bk_header = {0};
    u64 res = 0;
    
    bool success = false;
    
    /* Retrieve TMD common block, contents and content count. */
    tmd_common_block = tmdGetCommonBlockFromBuffer(tmd, tmd_size, NULL);
    tmd_contents = TMD_CONTENTS(tmd_common_block);
    content_count = bswap_16(tmd_common_block->content_count);
    
    /* Retrieve required keydata. */
    console_id = keysGetConsoleId();
    prng_key = keysGetPrngKey();
    
    /* Convert the Title ID lower u32 to ASCII. */
    title_id = bswap_64(tmd_common_block->title_id);
    utilsGenerateAsciiStringFromTitleIdLower(title_id, tid_lower_ascii);
    
    /* Create directory tree. */
    os_snprintf(out_path + out_path_len, MAX_PATH - out_path_len, PRIVATE_PATH("data"), tid_lower_ascii);
    utilsCreateDirectoryTree(out_path);
    new_out_path_len = os_strlen(out_path);
    
    /* Process each content individually. */
    for(u16 i = 0; i < content_count; i++)
    {
        FILE *cnt_fd = NULL, *indexed_bin = NULL;
        u16 cnt_idx = bswap_16(tmd_contents[i].index);
        u64 cnt_size = bswap_64(tmd_contents[i].size);
        u64 aligned_cnt_size = 0;
        bool write_res = false;
        
        /* Generate content IV. */
        memset(cnt_iv, 0, AES_BLOCK_SIZE);
        memcpy(cnt_iv, &(tmd_contents[i].index), sizeof(u16));
        
        /* Generate input path for the current content. */
        os_snprintf(unpacked_wad_path + unpacked_wad_path_len, MAX_PATH - unpacked_wad_path_len, OS_PATH_SEPARATOR "%08" PRIx16 ".app", cnt_idx);
        
        /* Generate output path. */
        os_snprintf(out_path + new_out_path_len, MAX_PATH - new_out_path_len, OS_PATH_SEPARATOR "%03u.bin", cnt_idx);
        
        /* Open content file. */
        cnt_fd = os_fopen(unpacked_wad_path, OS_MODE_READ);
        if (!cnt_fd)
        {
            printf("Content \"" OS_PRINT_STR "\" not found. Skipping...\n\n", unpacked_wad_path);
            continue;
        }
        
        /* Open output file. */
        indexed_bin = os_fopen(out_path, OS_MODE_WRITE);
        if (!indexed_bin)
        {
            fclose(cnt_fd);
            ERROR_MSG("Failed to open \"" OS_PRINT_STR "\" in write mode!", out_path);
            goto out;
        }
        
        /* Prepare backup WAD header. */
        bk_header.header_size = (u32)WadHeaderSize_BackupPackage;
        bk_header.type = (u16)WadType_BackupPackage;
        bk_header.version = (u16)WadVersion_BackupPackage;
        bk_header.console_id = console_id;
        bk_header.content_tmd_size = (u32)tmd_size;
        bk_header.content_data_size = (u32)ALIGN_UP(cnt_size, WAD_BLOCK_SIZE);
        bk_header.backup_area_size = (u32)(sizeof(WadBackupPackageHeader) + aligned_tmd_size + bk_header.content_data_size);
        memset(bk_header.included_contents, 0, sizeof(bk_header.included_contents));
        wadUpdateBackupPackageHeaderIncludedContents(&bk_header, cnt_idx);
        bk_header.title_id = parent_tid;
        
        /* Print backup WAD header information. */
        char wad_type[3] = { (u8)(bk_header.type >> 8), (u8)bk_header.type, 0 };
        printf("Content #%u backup WAD header:\n", cnt_idx + 1);
        printf("  Header size:            0x%" PRIx32 " (%s).\n", bk_header.header_size, WAD_HEADER_SIZE_STR(bk_header.header_size));
        printf("  Type:                   \"%s\" (%s).\n", wad_type, WAD_TYPE_STR(bk_header.type));
        printf("  Version:                %u (%s).\n", bk_header.version, WAD_VERSION_STR(bk_header.version));
        printf("  Console ID:             %08" PRIx32 ".\n", bk_header.console_id);
        printf("  TMD size:               0x%" PRIx32 ".\n", bk_header.content_tmd_size);
        printf("  Content data size:      0x%" PRIx32 ".\n", bk_header.content_data_size);
        printf("  Backup area size:       0x%" PRIx32 ".\n", bk_header.backup_area_size);
        printf("  Title ID:               %016" PRIx64 ".\n\n", bk_header.title_id);
        
        /* Byteswap backup WAD header fields. */
        wadByteswapBackupPackageHeaderFields(&bk_header);
        
        /* Write plaintext "Bk" header. */
        res = fwrite(&bk_header, 1, sizeof(WadBackupPackageHeader), indexed_bin);
        if (res != sizeof(WadBackupPackageHeader))
        {
            fclose(indexed_bin);
            fclose(cnt_fd);
            ERROR_MSG("Failed to write plaintext \"Bk\" header to \"" OS_PRINT_STR "\"!", out_path);
            goto out;
        }
        
        /* Write plaintext TMD. */
        res = fwrite(tmd, 1, aligned_tmd_size, indexed_bin);
        if (res != aligned_tmd_size)
        {
            fclose(indexed_bin);
            fclose(cnt_fd);
            ERROR_MSG("Failed to write plaintext TMD to \"" OS_PRINT_STR "\"!", out_path);
            goto out;
        }
        
        /* Write encrypted content file. */
        write_res = wadWriteUnpackedContentToPackage(indexed_bin, prng_key, cnt_iv, NULL, cnt_fd, cnt_idx, cnt_size, &aligned_cnt_size);
        if (!write_res) ERROR_MSG("Failed to write content file \"" OS_PRINT_STR "\" to \"" OS_PRINT_STR "\"!", unpacked_wad_path, out_path);
        
        /* Close files. */
        fclose(indexed_bin);
        fclose(cnt_fd);
        
        /* Stop process if there was an error. */
        if (!write_res) goto out;
        
        printf("Successfully saved converted DLC content #%u to \"" OS_PRINT_STR "\".\n\n", cnt_idx + 1, out_path);
    }
    
    success = true;
    
out:
    if (!success && new_out_path_len > 0)
    {
        /* Remove only the last subdirectory from the directory tree we created. */
        out_path[new_out_path_len] = (os_char_t)0;
        utilsRemoveDirectoryRecursively(out_path);
    }
    
    out_path[out_path_len] = (os_char_t)0;
    unpacked_wad_path[unpacked_wad_path_len] = (os_char_t)0;
    
    return success;
}
