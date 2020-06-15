/*
 * wad.c
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
#include "tik.h"
#include "wad.h"

#define WAD_CONTENT_BLOCKSIZE   0x800000    /* 8 MiB. */

static bool wadUnpackContentFromInstallablePackage(FILE *wad_fd, const u8 *titlekey, const u8 *iv, size_t cnt_size, const u8 *cnt_hash, const os_char_t *out_path, size_t *out_aligned_cnt_size);

bool wadUnpackInstallablePackage(const os_char_t *wad_path, os_char_t *out_path, u8 **out_cert_chain, size_t *out_cert_chain_size, u8 **out_tik, size_t *out_tik_size, u8 **out_tmd, \
                                 size_t *out_tmd_size, u8 *out_dec_titlekey, u32 *out_tid_upper)
{
    size_t out_path_len = 0;
    
    if (!wad_path || !os_strlen(wad_path) || !out_path || !(out_path_len = os_strlen(out_path)) || (!out_cert_chain && out_cert_chain_size) || (out_cert_chain && !out_cert_chain_size) || \
        (!out_tik && out_tik_size) || (out_tik && !out_tik_size) || (!out_tmd && out_tmd_size) || (out_tmd && !out_tmd_size))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    bool save_cert_chain = (out_cert_chain && out_cert_chain_size);
    bool save_ticket = (out_tik && out_tik_size);
    bool save_tmd = (out_tmd && out_tmd_size);
    
    FILE *wad_fd = NULL;
    size_t wad_offset = 0, wad_size = 0, calc_wad_size = 0, res = 0;
    
    WadInstallablePackageHeader wad_header = {0};
    
    u8 *common_key = NULL;
    u32 console_id = keysGetConsoleId();
    
    u8 *cert_chain = NULL;
    
    u8 *ticket = NULL;
    TikCommonBlock *tik_common_block = NULL;
    TmdContentRecord *tmd_contents = NULL;
    u64 tik_tid = 0;
    
    u8 *tmd = NULL;
    TmdCommonBlock *tmd_common_block = NULL;
    u16 content_count = 0;
    u64 tmd_tid = 0;
    
    u32 tid_upper = 0;
    u8 titlekey_iv[AES_BLOCK_SIZE] = {0};
    u8 dec_titlekey[AES_BLOCK_SIZE] = {0};
    u8 cnt_iv[AES_BLOCK_SIZE] = {0};
    
    bool success = false;
    
    /* Open WAD package. */
    wad_fd = os_fopen(wad_path, OS_MODE_READ);
    if (!wad_fd)
    {
        ERROR_MSG("Unable to open \"" OS_PRINT_STR "\" for reading!", wad_path);
        goto out;
    }
    
    /* Retrieve WAD package size. */
    os_fseek(wad_fd, 0, SEEK_END);
    wad_size = os_ftell(wad_fd);
    rewind(wad_fd);
    
    if (wad_size < sizeof(WadInstallablePackageHeader))
    {
        ERROR_MSG("Invalid size for \"" OS_PRINT_STR "\"! (0x%" PRIx64 ").", wad_path, wad_size);
        goto out;
    }
    
    /* Read WAD package header. */
    res = fread(&wad_header, 1, sizeof(WadInstallablePackageHeader), wad_fd);
    if (res != sizeof(WadInstallablePackageHeader))
    {
        ERROR_MSG("Failed to read WAD header from \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Byteswap WAD package header fields. */
    wadByteswapInstallablePackageHeaderFields(&wad_header);
    
    /* Print header info. */
    char wad_type[3] = { (u8)(wad_header.type >> 8), (u8)wad_header.type, 0 };
    printf("WAD header:\n");
    printf("  Header size:            0x%" PRIx32 " (%s).\n", wad_header.header_size, WAD_HEADER_SIZE_STR(wad_header.header_size));
    printf("  Type:                   \"%s\" (%s).\n", wad_type, WAD_TYPE_STR(wad_header.type));
    printf("  Version:                %u (%s).\n", wad_header.version, WAD_VERSION_STR(wad_header.version));
    printf("  Certificate chain size: 0x%" PRIx32 ".\n", wad_header.cert_chain_size);
    printf("  Ticket size:            0x%" PRIx32 ".\n", wad_header.ticket_size);
    printf("  TMD size:               0x%" PRIx32 ".\n", wad_header.tmd_size);
    printf("  Content data size:      0x%" PRIx32 ".\n\n", wad_header.data_size);
    
    /* Check header fields. */
    /* Discard WadType_Boot2Package while we're at it. */
    calc_wad_size = (sizeof(WadInstallablePackageHeader) + ALIGN_UP(wad_header.cert_chain_size, WAD_BLOCK_SIZE) + ALIGN_UP(wad_header.ticket_size, WAD_BLOCK_SIZE) + \
                     ALIGN_UP(wad_header.tmd_size, WAD_BLOCK_SIZE) + ALIGN_UP(wad_header.data_size, WAD_BLOCK_SIZE));
    
    if (wad_header.header_size != WadHeaderSize_InstallablePackage || wad_header.type != WadType_NormalPackage || wad_header.version != WadVersion_InstallablePackage || \
        !wad_header.cert_chain_size || wad_header.ticket_size < TIK_MIN_SIZE || wad_header.tmd_size < TMD_MIN_SIZE || !wad_header.data_size || wad_size < calc_wad_size)
    {
        ERROR_MSG("Invalid WAD header in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Update WAD offset. */
    wad_offset += sizeof(WadInstallablePackageHeader);
    
    /* Read certificate chain. */
    cert_chain = certReadRawCertificateChainFromFile(wad_fd, wad_header.cert_chain_size);
    if (!cert_chain)
    {
        ERROR_MSG("Invalid certificate chain in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Save certificate chain. */
    os_snprintf(out_path + out_path_len, MAX_PATH - out_path_len, OS_PATH_SEPARATOR "cert.bin");
    if (!utilsWriteDataToFile(out_path, cert_chain, wad_header.cert_chain_size))
    {
        ERROR_MSG("Failed to save certificate chain from \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Update file stream position. */
    wad_offset += ALIGN_UP(wad_header.cert_chain_size, WAD_BLOCK_SIZE);
    os_fseek(wad_fd, wad_offset, SEEK_SET);
    
    /* Read ticket. */
    printf("Ticket:\n");
    ticket = tikReadTicketFromFile(wad_fd, wad_header.ticket_size);
    if (!ticket)
    {
        ERROR_MSG("Invalid ticket in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Retrieve ticket common block. */
    tik_common_block = tikGetCommonBlockFromBuffer(ticket, wad_header.ticket_size, NULL);
    
    /* Generate decrypted titlekey. */
    memcpy(titlekey_iv, (u8*)(&(tik_common_block->title_id)), sizeof(u64));
    common_key = (tik_common_block->common_key_index == TikCommonKeyIndex_Korean ? keysGetWiiKoreanKey() : \
                 (tik_common_block->common_key_index == TikCommonKeyIndex_vWii ? keysGetVirtualWiiCommonKey() : keysGetWiiCommonKey()));
    
    if (!common_key || !cryptoAes128CbcCrypt(common_key, titlekey_iv, dec_titlekey, tik_common_block->titlekey, AES_BLOCK_SIZE, false))
    {
        ERROR_MSG("Failed to generate decrypted titlekey!");
        goto out;
    }
    
    /* Print ticket information */
    utilsPrintHexData("  Encrypted Titlekey:     ", tik_common_block->titlekey, AES_BLOCK_SIZE);
    printf("  ID:                     %016" PRIx64 ".\n", bswap_64(tik_common_block->ticket_id));
    printf("  Console ID:             %08" PRIx32 ".\n", bswap_32(tik_common_block->console_id));
    printf("  Title ID:               %016" PRIx64 ".\n", bswap_64(tik_common_block->title_id));
    printf("  Title Version:          %u.\n", bswap_16(tik_common_block->title_version));
    utilsPrintHexData("  Titlekey IV:            ", titlekey_iv, AES_BLOCK_SIZE);
    utilsPrintHexData("  Decrypted titlekey:     ", dec_titlekey, AES_BLOCK_SIZE);
    printf("\n");
    
    /* Check if the title we're dealing with is exportable. */
    if (!tikIsTitleExportable(tik_common_block))
    {
        ERROR_MSG("Invalid Title ID type!\nOnly downloadable channels, disc-based game channels and DLCs are exportable!");
        goto out;
    }
    
    /* Check if the ticket was issued for the target console. */
    /* If not, then we'll need to fakesign it. */
    if (bswap_32(tik_common_block->console_id) != console_id)
    {
        tikFakesignTicket(ticket, wad_header.ticket_size);
        printf("Ticket fakesigned (not issued for target console).\n\n");
    }
    
    /* Save ticket. */
    os_snprintf(out_path + out_path_len, MAX_PATH - out_path_len, OS_PATH_SEPARATOR "tik.bin");
    if (!utilsWriteDataToFile(out_path, ticket, wad_header.ticket_size))
    {
        ERROR_MSG("Failed to save ticket from \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Update file stream position. */
    wad_offset += ALIGN_UP(wad_header.ticket_size, WAD_BLOCK_SIZE);
    os_fseek(wad_fd, wad_offset, SEEK_SET);
    
    /* Read TMD. */
    printf("Title Metadata (TMD):\n");
    tmd = tmdReadTitleMetadataFromFile(wad_fd, wad_header.tmd_size);
    if (!tmd)
    {
        ERROR_MSG("Invalid TMD in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Retrieve TMD common block. */
    tmd_common_block = tmdGetCommonBlockFromBuffer(tmd, wad_header.tmd_size, NULL);
    
    /* Print TMD information. */
    printf("  Version:                %u.\n", tmd_common_block->tmd_version);
    printf("  Target System:          0x%02" PRIx8 " (%s).\n", tmd_common_block->target_system, TMD_TARGET_SYSTEM_STR(tmd_common_block->target_system));
    printf("  System Version:         %016" PRIx64 ".\n", bswap_64(tmd_common_block->system_version));
    printf("  Title ID:               %016" PRIx64 ".\n", bswap_64(tmd_common_block->title_id));
    printf("  Title Type:             0x%08" PRIx32 ".\n", bswap_32(tmd_common_block->title_type));
    printf("  Publisher:              %.*s.\n", (int)sizeof(tmd_common_block->group_id), tmd_common_block->group_id);
    printf("  Region:                 0x%04" PRIx16 ".\n", bswap_16(tmd_common_block->region));
    printf("  Title Version:          %u.\n", bswap_16(tmd_common_block->title_version));
    printf("  Content Count:          %u.\n", bswap_16(tmd_common_block->content_count));
    printf("  Boot Index:             %u.\n\n", bswap_16(tmd_common_block->boot_index));
    
    /* Check if the TMD system version field is valid. */
    if (!tmdIsSystemVersionValid(tmd_common_block))
    {
        ERROR_MSG("Invalid TMD system version field!\nThis is probably an IOS / boot2 WAD package!");
        goto out;
    }
    
    /* Compare ticket and TMD title IDs. */
    tik_tid = bswap_64(tik_common_block->title_id);
    tmd_tid = bswap_64(tmd_common_block->title_id);
    if (tik_tid != tmd_tid)
    {
        ERROR_MSG("Ticket/TMD Title ID mismatch! (%08" PRIx32 "-%08" PRIx32 " [Ticket] != %08" PRIx32 "-%08" PRIx32 " [TMD]).", TITLE_UPPER(tik_tid), TITLE_LOWER(tik_tid), TITLE_UPPER(tmd_tid), \
                  TITLE_LOWER(tmd_tid));
        goto out;
    }
    
    /* Retrieve TID upper u32. */
    tid_upper = TITLE_UPPER(tik_tid);
    
    /* Save TMD. */
    os_snprintf(out_path + out_path_len, MAX_PATH - out_path_len, OS_PATH_SEPARATOR "tmd.bin");
    if (!utilsWriteDataToFile(out_path, tmd, wad_header.tmd_size))
    {
        ERROR_MSG("Failed to save TMD from \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Update file stream position. */
    wad_offset += ALIGN_UP(wad_header.tmd_size, WAD_BLOCK_SIZE);
    os_fseek(wad_fd, wad_offset, SEEK_SET);
    
    /* Process content files. */
    content_count = bswap_16(tmd_common_block->content_count);
    tmd_contents = TMD_CONTENTS(tmd_common_block);
    
    for(u16 i = 0; i < content_count && wad_offset < calc_wad_size; i++)
    {
        /* Generate content IV. */
        memset(cnt_iv, 0, AES_BLOCK_SIZE);
        memcpy(cnt_iv, &(tmd_contents[i].index), sizeof(u16));
        
        /* Temporarily byteswap content record fields. */
        tmdByteswapTitleMetadataContentRecordFields(&(tmd_contents[i]));
        
        /* Check if we're dealing with an unknown content type. */
        if (tmd_contents[i].type != TmdContentRecordType_Normal && tmd_contents[i].type != TmdContentRecordType_DLC && tmd_contents[i].type != TmdContentRecordType_Shared)
        {
            ERROR_MSG("Invalid content type!");
            goto out;
        }
        
        /* Generate output path for the current content. */
        os_snprintf(out_path + out_path_len, MAX_PATH - out_path_len, OS_PATH_SEPARATOR "%08" PRIx16 ".app", tmd_contents[i].index);
        
        /* Unpack content. */
        size_t aligned_cnt_size = 0;
        if (!wadUnpackContentFromInstallablePackage(wad_fd, dec_titlekey, cnt_iv, tmd_contents[i].size, tmd_contents[i].hash, out_path, &aligned_cnt_size))
        {
            os_remove(out_path);
            
            if (tid_upper == TITLE_TYPE_DLC && i < (content_count - 1))
            {
                printf("Data at WAD offset 0x%zx doesn't match content index %04" PRIx16 ".\n\n", wad_offset, tmd_contents[i].index);
                
                /* Seek back to the start of the current content file. We'll retry again with the next content record. */
                os_fseek(wad_fd, wad_offset, SEEK_SET);
            } else {
                ERROR_MSG("Failed to save decrypted content file \"%08" PRIx16 ".app\" from \"" OS_PRINT_STR "\"!", tmd_contents[i].index, wad_path);
                goto out;
            }
        }
        
        /* Update WAD offset. */
        wad_offset += aligned_cnt_size;
        
        /* Print unpacked content info. */
        printf("  TMD content #%u:\n", i + 1);
        printf("    Content ID:           %08" PRIx32 ".\n", tmd_contents[i].content_id);
        printf("    Content index:        %04" PRIx16 ".\n", tmd_contents[i].index);
        printf("    Content type:         %04" PRIx16 " (%s).\n", tmd_contents[i].type, TMD_CONTENT_REC_TYPE_STR(tmd_contents[i].type));
        printf("    Content size:         0x%" PRIx64 ".\n", tmd_contents[i].size);
        utilsPrintHexData("    Content SHA-1 hash:   ", tmd_contents[i].hash, SHA1_HASH_SIZE);
        utilsPrintHexData("    Content IV:           ", cnt_iv, AES_BLOCK_SIZE);
        printf("\n");
        
        /* Restore byteswapped content record fields. */
        tmdByteswapTitleMetadataContentRecordFields(&(tmd_contents[i]));
    }
    
    if (save_cert_chain)
    {
        *out_cert_chain = cert_chain;
        *out_cert_chain_size = wad_header.cert_chain_size;
    }
    
    if (save_ticket)
    {
        *out_tik = ticket;
        *out_tik_size = wad_header.ticket_size;
    }
    
    if (save_tmd)
    {
        *out_tmd = tmd;
        *out_tmd_size = wad_header.tmd_size;
    }
    
    if (out_dec_titlekey) memcpy(out_dec_titlekey, dec_titlekey, AES_BLOCK_SIZE);
    
    if (out_tid_upper) *out_tid_upper = tid_upper;
    
    success = true;
    
out:
    if (tmd && (!success || (success && !save_tmd))) free(tmd);
    
    if (ticket && (!success || (success && !save_ticket))) free(ticket);
    
    if (cert_chain && (!success || (success && !save_cert_chain))) free(cert_chain);
    
    if (wad_fd) fclose(wad_fd);
    
    out_path[out_path_len] = (os_char_t)0;
    
    return success;
}

bool wadWriteUnpackedContentToPackage(FILE *wad_fd, const u8 *titlekey, const u8 *iv, mbedtls_sha1_context *sha1_ctx, FILE *cnt_fd, u16 cnt_idx, size_t cnt_size, size_t *out_aligned_cnt_size)
{
    if (!wad_fd || !titlekey || !iv || !cnt_fd || cnt_idx >= TMD_MAX_CONTENT_COUNT || !cnt_size || !out_aligned_cnt_size)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u8 *buf = NULL;
    size_t blksize = WAD_CONTENT_BLOCKSIZE;
    size_t res = 0, write_size = 0;
    
    CryptoAes128CbcContext aes_ctx = {0};
    
    bool success = false, aes_ctx_init = false;
    
    /* Allocate memory for the process. */
    buf = malloc(blksize);
    if (!buf)
    {
        ERROR_MSG("Failed to allocate memory for the write procedure!");
        return false;
    }
    
    /* Initialize AES-128-CBC context. */
    aes_ctx_init = cryptoAes128CbcContextInit(&aes_ctx, titlekey, iv, true);
    if (!aes_ctx_init)
    {
        ERROR_MSG("Failed to initialize AES-128-CBC context!");
        goto out;
    }
    
    /* Process content data. */
    for(size_t offset = 0; offset < cnt_size; offset += blksize)
    {
        /* Handle last plaintext chunk size. */
        if (blksize > (cnt_size - offset)) blksize = (cnt_size - offset);
        
        /* Read plaintext chunk. */
        res = fread(buf, 1, blksize, cnt_fd);
        if (res != blksize)
        {
            ERROR_MSG("Failed to read 0x%" PRIx64 " bytes plaintext chunk at offset 0x%" PRIx64 " from content \"%08" PRIx16 ".app\"!", blksize, offset, cnt_idx);
            goto out;
        }
        
        /* Check if the current chunk isn't aligned to the AES block size. */
        write_size = ALIGN_UP(blksize, AES_BLOCK_SIZE);
        if (write_size > blksize) memset(buf + blksize, 0, write_size - blksize);
        
        /* Encrypt chunk. */
        if (!cryptoAes128CbcContextCrypt(&aes_ctx, buf, buf, write_size, true))
        {
            ERROR_MSG("Failed to encrypt 0x%" PRIx64 " bytes chunk at offset 0x%" PRIx64 " from content \"%08" PRIx16 ".app\"!", write_size, offset, cnt_idx);
            goto out;
        }
        
        if (sha1_ctx)
        {
            /* Update SHA-1 hash calculation. */
            mbedtls_sha1_update(sha1_ctx, buf, write_size);
        }
        
        /* Write encrypted chunk. */
        res = fwrite(buf, 1, write_size, wad_fd);
        if (res != write_size)
        {
            ERROR_MSG("Failed to write 0x%" PRIx64 " bytes encrypted chunk at offset 0x%" PRIx64 " from content \"%08" PRIx16 ".app\"!", write_size, offset, cnt_idx);
            goto out;
        }
        
        /* Flush data. */
        fflush(wad_fd);
    }
    
    /* Write padding if necessary. */
    size_t aligned_cnt_size = ALIGN_UP(cnt_size, AES_BLOCK_SIZE);
    if (!IS_ALIGNED(aligned_cnt_size, WAD_BLOCK_SIZE))
    {
        size_t new_aligned_cnt_size = aligned_cnt_size;
        
        if (!utilsWritePadding(wad_fd, &new_aligned_cnt_size, WAD_BLOCK_SIZE))
        {
            ERROR_MSG("Failed to write pad block for content \"%08" PRIx16 ".app\"!", cnt_idx);
            goto out;
        }
        
        if (sha1_ctx)
        {
            /* Update SHA-1 hash calculation. */
            u8 padding[WAD_BLOCK_SIZE] = {0};
            mbedtls_sha1_update(sha1_ctx, padding, new_aligned_cnt_size - aligned_cnt_size);
        }
        
        aligned_cnt_size = new_aligned_cnt_size;
    }
    
    *out_aligned_cnt_size = aligned_cnt_size;
    
    success = true;
    
out:
    if (aes_ctx_init) cryptoAes128CbcContextFree(&aes_ctx);
    
    if (buf) free(buf);
    
    return success;
}

static bool wadUnpackContentFromInstallablePackage(FILE *wad_fd, const u8 *titlekey, const u8 *iv, size_t cnt_size, const u8 *cnt_hash, const os_char_t *out_path, size_t *out_aligned_cnt_size)
{
    if (!wad_fd || !titlekey || !iv || !cnt_size || !cnt_hash || !out_path || !os_strlen(out_path) || !out_aligned_cnt_size)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u8 *buf = NULL;
    size_t blksize = WAD_CONTENT_BLOCKSIZE;
    size_t res = 0, read_size = 0;
    
    CryptoAes128CbcContext aes_ctx = {0};
    
    u8 hash[SHA1_HASH_SIZE] = {0};
    mbedtls_sha1_context sha1_ctx = {0};
    
    FILE *cnt_fd = NULL;
    
    bool success = false, aes_ctx_init = false, sha1_ctx_init = false;
    
    /* Allocate memory for the process. */
    buf = malloc(blksize);
    if (!buf)
    {
        ERROR_MSG("Failed to allocate memory for the unpacking procedure!");
        return false;
    }
    
    /* Initialize AES-128-CBC context. */
    aes_ctx_init = cryptoAes128CbcContextInit(&aes_ctx, titlekey, iv, false);
    if (!aes_ctx_init)
    {
        ERROR_MSG("Failed to initialize AES-128-CBC context!");
        goto out;
    }
    
    /* Initialize SHA-1 context. */
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts(&sha1_ctx);
    sha1_ctx_init = true;
    
    /* Open output content file. */
    cnt_fd = os_fopen(out_path, OS_MODE_WRITE);
    if (!cnt_fd)
    {
        ERROR_MSG("Failed to open content file in write mode!");
        goto out;
    }
    
    /* Process content data. */
    for(size_t offset = 0; offset < cnt_size; offset += blksize)
    {
        /* Handle last encrypted chunk size. */
        if (blksize > (cnt_size - offset)) blksize = (cnt_size - offset);
        
        /* Read encrypted chunk. */
        read_size = ALIGN_UP(blksize, AES_BLOCK_SIZE);
        res = fread(buf, 1, read_size, wad_fd);
        if (res != read_size)
        {
            ERROR_MSG("Failed to read 0x%" PRIx64 " bytes encrypted chunk from content offset 0x%" PRIx64 "!", read_size, offset);
            goto out;
        }
        
        /* Decrypt chunk. */
        if (!cryptoAes128CbcContextCrypt(&aes_ctx, buf, buf, read_size, false))
        {
            ERROR_MSG("Failed to decrypt 0x%" PRIx64 " bytes chunk from content offset 0x%" PRIx64 "!", read_size, offset);
            goto out;
        }
        
        /* Update SHA-1 hash calculation. */
        mbedtls_sha1_update(&sha1_ctx, buf, blksize);
        
        /* Write decrypted chunk. */
        res = fwrite(buf, 1, blksize, cnt_fd);
        if (res != blksize)
        {
            ERROR_MSG("Failed to write 0x%" PRIx64 " bytes decrypted chunk from content offset 0x%" PRIx64 "!", blksize, offset);
            goto out;
        }
        
        /* Flush data. */
        fflush(cnt_fd);
    }
    
    /* Retrieve calculated SHA-1 checksum. */
    mbedtls_sha1_finish(&sha1_ctx, hash);
    
    /* Compare checksums. */
    if (memcmp(hash, cnt_hash, SHA1_HASH_SIZE) != 0)
    {
        ERROR_MSG("SHA-1 checksum mismatch!");
        goto out;
    }
    
    /* Update file stream position if necessary. */
    size_t aligned_cnt_size = ALIGN_UP(cnt_size, AES_BLOCK_SIZE);
    if (!IS_ALIGNED(aligned_cnt_size, WAD_BLOCK_SIZE))
    {
        size_t new_aligned_cnt_size = ALIGN_UP(aligned_cnt_size, WAD_BLOCK_SIZE);
        os_fseek(wad_fd, new_aligned_cnt_size - aligned_cnt_size, SEEK_CUR);
        aligned_cnt_size = new_aligned_cnt_size;
    }
    
    *out_aligned_cnt_size = aligned_cnt_size;
    
    success = true;
    
out:
    if (cnt_fd) fclose(cnt_fd);
    
    if (sha1_ctx_init) mbedtls_sha1_free(&sha1_ctx);
    
    if (aes_ctx_init) cryptoAes128CbcContextFree(&aes_ctx);
    
    if (buf) free(buf);
    
    return success;
}
