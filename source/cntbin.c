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
#include "cntbin.h"

#define CONTENT_PRIVATE_PATH    OS_PATH_SEPARATOR "private" OS_PATH_SEPARATOR "wii" OS_PATH_SEPARATOR "title" OS_PATH_SEPARATOR "%s" /* "%s" gets replaced by the ASCII conversion of the TID lower u32 */
#define CONTENT_NAME            "content.bin"

#define UNKNOWN_LOW_TID         (u32)0x57444645         /* "WDFE". Used by BannerBomb. */
#define REF_TID_1               (u64)0x0001000157424D45 /* 10001-WBME. Used by BannerBomb. */
#define REF_TID_2               (u64)0x000100014E414A4E /* 10001-NAJN. Used by BannerBomb. */

static bool cntbinWriteContent(FILE *content_bin, const u8 *key, const u8 *iv, mbedtls_sha1_context *sha1_ctx, const os_char_t *cnt_path, size_t cnt_size);

bool cntbinConvertInstallableWadPackageToBackupPackage(const os_char_t *keys_file_path, const os_char_t *device_cert_path, const os_char_t *wad_path, os_char_t *out_path, os_char_t *tmp_path)
{
    size_t out_path_len = os_strlen(out_path), new_out_path_len = 0;
    size_t tmp_path_len = os_strlen(tmp_path);
    
    u32 console_id = 0;
    u8 *sd_key = NULL, *sd_iv = NULL, *md5_blanker = NULL, *ecc_private_key = NULL, *prng_key = NULL;
    CertSigEcc480PubKeyEcc480 *device_cert = NULL;
    
    u8 *ticket = NULL;
    size_t ticket_size = 0;
    //TikCommonBlock *tik_common_block = NULL;
    
    u8 *tmd = NULL;
    size_t tmd_size = 0;
    TmdCommonBlock *tmd_common_block = NULL;
    TmdContentRecord *tmd_contents = NULL;
    u16 content_count = 0;
    u8 content_iv[AES_BLOCK_SIZE] = {0};
    
    u64 title_id = 0;
    u32 low_tid = 0;
    char low_tid_ascii[5] = {0};
    
    FILE *opening_bnr = NULL;
    u8 *icon_bin = NULL;
    size_t res = 0, icon_bin_size = 0;
    
    CntBinHeader cntbin_header = {0};
    u8 imet_hash[MD5_HASH_SIZE] = {0}, calc_imet_hash[MD5_HASH_SIZE] = {0}, cntbin_header_hash[MD5_HASH_SIZE] = {0};
    
    CntBinImd5Header *imd5_header = NULL;
    u8 imd5_hash[MD5_HASH_SIZE] = {0};
    
    WadBackupPackageHeader bk_header = {0};
    size_t content_data_size = 0, backup_area_size = 0;
    
    /* SHA-1 context used to calculate a checksum over the backup area. */
    /* Needed to generate the ECSDA signature at the start of Part F. */
    mbedtls_sha1_context sha1_ctx = {0};
    u8 backup_area_hash[SHA1_HASH_SIZE] = {0};
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts(&sha1_ctx);
    
    CntBinCertArea cert_area = {0};
    u8 ap_private_key[ECC_PRIV_KEY_SIZE - 2] = {0};
    ap_private_key[ECC_PRIV_KEY_SIZE - 3] = 1; /* Keep it simple, don't generate a random value for the key. */
    
    FILE *content_bin = NULL;
    size_t content_bin_offset = 0;
    
    bool success = false;
    
    /* Load keydata and device certificate. */
    if (!keysLoadKeyDataAndDeviceCert(keys_file_path, device_cert_path)) return false;
    printf("Keydata and device certificate successfully loaded.\n\n");
    
    /* Retrieve required keydata */
    console_id = keysGetConsoleId();
    sd_key = keysGetSdKey();
    sd_iv = keysGetSdIv();
    md5_blanker = keysGetMd5Blanker();
    ecc_private_key = keysGetEccPrivateKey();
    prng_key = keysGetPrngKey();
    device_cert = keysGetDeviceCertificate();
    
    /* Unpack input WAD package. */
    if (!wadUnpackInstallablePackage(wad_path, tmp_path, NULL, NULL, &ticket, &ticket_size, &tmd, &tmd_size)) return false;
    printf("WAD package \"" OS_PRINT_STR "\" successfully unpacked.\n\n", wad_path);
    
    /* Retrieve ticket common block, TMD common block and TMD contents. */
    tik_common_block = tikGetCommonBlockFromBuffer(ticket, ticket_size, NULL);
    tmd_common_block = tmdGetCommonBlockFromBuffer(tmd, tmd_size, NULL);
    tmd_contents = TMD_CONTENTS(tmd_common_block);
    content_count = bswap_16(tmd_common_block->content_count);
    
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
    /* The IMET header from content.bin files doesn't have this hash. */
    memcpy(imet_hash, cntbin_header.imet_header.hash, MD5_HASH_SIZE);
    memset(cntbin_header.imet_header.hash, 0, MD5_HASH_SIZE);
    
    /* Calculate IMET hash. */
    mbedtls_md5((u8*)&cntbin_header.imet_header, sizeof(CntBinImetHeader), calc_imet_hash);
    
    /* Check IMET header fields. */
    if (cntbin_header.imet_header.magic != bswap_32(IMET_MAGIC) || cntbin_header.imet_header.hash_size != bswap_32(IMET_HASHED_AREA_SIZE) || \
        cntbin_header.imet_header.file_count != bswap_32(IMET_FILE_COUNT) || !cntbin_header.imet_header.icon_bin_size || !cntbin_header.imet_header.banner_bin_size || \
        !cntbin_header.imet_header.sound_bin_size || memcmp(imet_hash, calc_imet_hash, MD5_HASH_SIZE) != 0)
    {
        ERROR_MSG("Invalid IMET header in \"" OS_PRINT_STR "\"!", tmp_path);
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
    cntbin_header.unknown_low_tid = bswap_32(UNKNOWN_LOW_TID);
    cntbin_header.ref_title_id_1 = bswap_64(REF_TID_1);
    cntbin_header.ref_title_id_2 = bswap_64(REF_TID_2);
    
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
    mbedtls_md5((u8*)&cntbin_header, sizeof(CntBinHeader), cntbin_header_hash);
    memcpy(cntbin_header.header_hash, cntbin_header_hash, MD5_HASH_SIZE);
    
    /* Print content.bin header (Part A) information. */
    printf("content.bin header (Part A):\n");
    printf("  Title ID:               %016" PRIx64 ".\n", bswap_64(cntbin_header.title_id));
    printf("  icon.bin size:          0x%" PRIx32 ".\n", bswap_32(cntbin_header.icon_bin_size));
    utilsPrintHexData("  Hash:                   ", cntbin_header.header_hash, MD5_HASH_SIZE);
    utilsPrintHexData("  icon.bin hash:          ", cntbin_header.icon_bin_hash, MD5_HASH_SIZE);
    printf("\n");
    
    /* Encrypt header (Part A) in-place. */
    if (!cryptoAes128CbcCrypt(sd_key, sd_iv, &cntbin_header, &cntbin_header, sizeof(CntBinHeader), true))
    {
        ERROR_MSG("Failed to encrypt header (Part A) for \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    /* Write encrypted content.bin header (Part A). */
    res = fwrite(&cntbin_header, 1, sizeof(CntBinHeader), content_bin);
    if (res != sizeof(CntBinHeader))
    {
        ERROR_MSG("Failed to write encrypted header (Part A) to \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    /* Update content.bin offset. */
    content_bin_offset += sizeof(CntBinHeader);
    
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
    
    /* Update content.bin offset. */
    content_bin_offset += icon_bin_size;
    
    /* Prepare backup WAD header (Part C). */
    bk_header.header_size = (u32)WadHeaderSize_BackupPackage;
    bk_header.type = (u16)WadType_BackupPackage;
    bk_header.version = (u16)WadVersion_BackupPackage;
    bk_header.console_id = console_id;
    bk_header.content_tmd_size = (u32)tmd_size;
    
    /* Calculate content data size and generate the included contents bitfield. */
    for(u16 i = 0; i < content_count; i++)
    {
        /* TODO: check if shared/DLC content inclusion actually works. */
        /* If not, they must be discarded here. */
        //if (bswap_16(tmd_contents[i].type) != TmdContentRecordType_Normal) continue;
        content_data_size += ALIGN_UP(bswap_64(tmd_contents[i].size), WAD_BLOCK_SIZE);
        wadUpdateBackupPackageHeaderIncludedContents(&bk_header, i);
    }
    
    bk_header.content_data_size = (u32)content_data_size;
    
    /* Calculate backup area size. */
    backup_area_size = (sizeof(WadBackupPackageHeader) + ALIGN_UP(tmd_size, WAD_BLOCK_SIZE) + content_data_size + sizeof(CntBinCertArea));
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
    
    /* Update content.bin offset. */
    content_bin_offset += sizeof(WadBackupPackageHeader);
    
    /* Update SHA-1 hash calculation. */
    mbedtls_sha1_update(&sha1_ctx, (u8*)&bk_header, sizeof(WadBackupPackageHeader));
    
    /* Reallocate TMD buffer (if necessary). */
    /* We need to do this if the TMD size isn't aligned to the WAD block size. */
    if (!utilsAlignBuffer((void**)&tmd, &tmd_size, WAD_BLOCK_SIZE))
    {
        ERROR_MSG("Failed to align TMD buffer to WAD block size!");
        goto out;
    }
    
    /* Write plaintext TMD (Part D). */
    res = fwrite(tmd, 1, tmd_size, content_bin);
    if (res != tmd_size)
    {
        ERROR_MSG("Failed to write plaintext TMD (Part D) to \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    /* Update content.bin offset. */
    content_bin_offset += tmd_size;
    
    /* Update SHA-1 hash calculation. */
    mbedtls_sha1_update(&sha1_ctx, tmd, tmd_size);
    
    /* Process content files (Part E). */
    printf("content.bin content data (Part E):\n");
    for(u16 i = 0; i < content_count; i++)
    {
        u16 content_index = bswap_16(tmd_contents[i].index);
        size_t content_size = bswap_64(tmd_contents[i].size);
        
        /* TODO: check if shared/DLC content inclusion actually works. */
        /* If not, they must be discarded here. */
        //u16 content_type = bswap_16(tmd_contents[i].type);
        //if (content_type != TmdContentRecordType_Normal) continue;
        
        /* Generate content IV. */
        memset(content_iv, 0, AES_BLOCK_SIZE);
        memcpy(content_iv, &(tmd_contents[i].index), sizeof(u16));
        
        /* Generate input path for the current content. */
        os_snprintf(tmp_path + tmp_path_len, MAX_PATH - tmp_path_len, OS_PATH_SEPARATOR "%08" PRIx16 ".app", content_index);
        
        /* Print content information. */
        printf("  Content #%u:\n", content_index + 1);
        printf("    Offset:               0x%" PRIx64 ".\n", os_ftell(content_bin));
        printf("    Size (unpacked):      0x%" PRIx64 ".\n", content_size);
        printf("    Size (encrypted):     0x%" PRIx64 ".\n", ALIGN_UP(content_size, AES_BLOCK_SIZE));
        printf("    Size (padded):        0x%" PRIx64 ".\n\n", ALIGN_UP(content_size, WAD_BLOCK_SIZE));
        
        /* Write encrypted content file. */
        if (!cntbinWriteContent(content_bin, prng_key, content_iv, &sha1_ctx, tmp_path, content_size))
        {
            ERROR_MSG("Failed to write encrypted content file \"%08" PRIx16 ".app\"!", content_index);
            goto out;
        }
        
        /* Update content.bin offset. */
        content_bin_offset += ALIGN_UP(content_size, WAD_BLOCK_SIZE);
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
    snprintf(cert_area.ap_cert.sig_block.issuer, sizeof(cert_area.ap_cert.sig_block.issuer), "%s-%s", cert_area.device_cert.sig_block.issuer, cert_area.device_cert.cert_common_block.name);
    
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
    res = fwrite(&cert_area, 1, sizeof(CntBinCertArea), content_bin);
    if (res != sizeof(CntBinCertArea))
    {
        ERROR_MSG("Failed to write plaintext certificate area (Part F) to \"" OS_PRINT_STR "\"!", out_path);
        goto out;
    }
    
    printf("Successfully saved converted WAD package to \"" OS_PRINT_STR "\".\n", out_path);
    
    success = true;
    
out:
    if (content_bin) fclose(content_bin);
    
    if (icon_bin) free(icon_bin);
    
    if (opening_bnr) fclose(opening_bnr);
    
    if (tmd) free(tmd);
    
    if (ticket) free(ticket);
    
    mbedtls_sha1_free(&sha1_ctx);
    
    tmp_path[tmp_path_len] = (os_char_t)0;
    //utilsRemoveDirectoryRecursively(tmp_path);
    
    if (!success)
    {
        os_snprintf(out_path + out_path_len, MAX_PATH - out_path_len, OS_PATH_SEPARATOR "private");
        utilsRemoveDirectoryRecursively(out_path);
    }
    
    out_path[out_path_len] = (os_char_t)0;
    
    return success;
}

static bool cntbinWriteContent(FILE *content_bin, const u8 *key, const u8 *iv, mbedtls_sha1_context *sha1_ctx, const os_char_t *cnt_path, size_t cnt_size)
{
    if (!content_bin || !key || !iv || !sha1_ctx || !cnt_path || !os_strlen(cnt_path) || !cnt_size)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u8 *buf = NULL;
    size_t blksize = CONTENT_BLOCKSIZE;
    size_t res = 0, write_size = 0;
    
    CryptoAes128CbcContext aes_ctx = {0};
    
    FILE *cnt_fd = NULL;
    
    bool success = false, aes_ctx_init = false;
    
    /* Allocate memory for the process. */
    buf = malloc(blksize);
    if (!buf)
    {
        ERROR_MSG("Failed to allocate memory for the write procedure!");
        return false;
    }
    
    /* Initialize AES-128-CBC context. */
    aes_ctx_init = cryptoAes128CbcContextInit(&aes_ctx, key, iv, true);
    if (!aes_ctx_init)
    {
        ERROR_MSG("Failed to initialize AES-128-CBC context!");
        goto out;
    }
    
    /* Open input content file. */
    cnt_fd = os_fopen(cnt_path, OS_MODE_READ);
    if (!cnt_fd)
    {
        ERROR_MSG("Failed to open content file \"" OS_PRINT_STR "\"in read mode!", cnt_path);
        goto out;
    }
    
    /* Copy content data. */
    for(size_t offset = 0; offset < cnt_size; offset += blksize)
    {
        /* Handle last plaintext chunk size. */
        if (blksize > (cnt_size - offset)) blksize = (cnt_size - offset);
        
        /* Read plaintext chunk. */
        res = fread(buf, 1, blksize, cnt_fd);
        if (res != blksize)
        {
            ERROR_MSG("Failed to read 0x%" PRIx64 " bytes plaintext chunk at offset 0x%" PRIx64 " from content \"" OS_PRINT_STR "\"!", blksize, offset, cnt_path);
            goto out;
        }
        
        /* Check if the current chunk isn't aligned to the AES block size. */
        write_size = ALIGN_UP(blksize, AES_BLOCK_SIZE);
        if (write_size > blksize) memset(buf + blksize, 0, write_size - blksize);
        
        /* Encrypt chunk. */
        if (!cryptoAes128CbcContextCrypt(&aes_ctx, buf, buf, write_size, true))
        {
            ERROR_MSG("Failed to encrypt 0x%" PRIx64 " bytes chunk at offset 0x%" PRIx64 " from content \"" OS_PRINT_STR "\"!", write_size, offset, cnt_path);
            goto out;
        }
        
        /* Update SHA-1 hash calculation. */
        mbedtls_sha1_update(sha1_ctx, buf, write_size);
        
        /* Write encrypted chunk. */
        res = fwrite(buf, 1, write_size, content_bin);
        if (res != write_size)
        {
            ERROR_MSG("Failed to write 0x%" PRIx64 " bytes encrypted chunk at offset 0x%" PRIx64 " from content \"" OS_PRINT_STR "\"!", write_size, offset, cnt_path);
            goto out;
        }
        
        /* Flush data. */
        fflush(content_bin);
    }
    
    /* Write padding if necessary. */
    cnt_size = ALIGN_UP(cnt_size, AES_BLOCK_SIZE);
    if (!IS_ALIGNED(cnt_size, WAD_BLOCK_SIZE))
    {
        size_t new_cnt_size = cnt_size;
        if (!utilsWritePadding(content_bin, &new_cnt_size, WAD_BLOCK_SIZE))
        {
            ERROR_MSG("Failed to write pad block for content \"" OS_PRINT_STR "\"!", cnt_path);
            goto out;
        }
        
        /* Update SHA-1 hash calculation. */
        u8 padding[WAD_BLOCK_SIZE] = {0};
        mbedtls_sha1_update(sha1_ctx, padding, new_cnt_size - cnt_size);
    }
    
    success = true;
    
out:
    if (cnt_fd) fclose(cnt_fd);
    
    if (aes_ctx_init) cryptoAes128CbcContextFree(&aes_ctx);
    
    if (buf) free(buf);
    
    return success;
}
