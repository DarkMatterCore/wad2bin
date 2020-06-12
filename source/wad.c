/*
 * wad.c
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
#include "tik.h"
#include "tmd.h"
#include "wad.h"

#define WAD_CONTENT_BLOCKSIZE   0x800000    /* 8 MiB. */

static bool wadSaveContentFileFromInstallablePackage(FILE *wad_file, const u8 titlekey[AES_BLOCK_SIZE], const u8 iv[AES_BLOCK_SIZE], const TmdContentRecord *content_record, const os_char_t *out_path);

bool wadUnpackInstallablePackage(const os_char_t *wad_path, const os_char_t *out_dir)
{
    if (!wad_path || !os_strlen(wad_path) || !out_dir || !os_strlen(out_dir))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    FILE *wad_fd = NULL;
    size_t wad_offset = 0, wad_size = 0, res = 0;
    
    WadInstallablePackageHeader wad_header = {0};
    
    u8 *common_key = NULL;
    u32 console_id = keysGetConsoleId();
    
    u8 *cert_chain = NULL;
    
    u8 *ticket = NULL;
    TikCommonBlock *tik_common_block = NULL;
    TmdContentRecord *tmd_contents = NULL;
    
    u8 *tmd = NULL;
    TmdCommonBlock *tmd_common_block = NULL;
    
    u64 tik_tid = 0, tmd_tid = 0;
    u16 content_count = 0;
    
    os_char_t entry_path[MAX_PATH] = {0};
    
    u8 titlekey_iv[AES_BLOCK_SIZE] = {0};
    u8 dec_titlekey[AES_BLOCK_SIZE] = {0};
    u8 content_iv[AES_BLOCK_SIZE] = {0};
    
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
    printf("WAD package size: 0x%" PRIx64 ".\n", wad_size);
    printf("WAD header size: 0x%" PRIx32 " (%s).\n", wad_header.header_size, WAD_HEADER_SIZE_STR(wad_header.header_size));
    printf("WAD type: \"%s\" (%s).\n", wad_type, WAD_TYPE_STR(wad_header.type));
    printf("WAD version: %u (%s).\n", wad_header.version, WAD_VERSION_STR(wad_header.version));
    printf("WAD certificate chain size: 0x%" PRIx32 ".\n", wad_header.cert_chain_size);
    printf("WAD ticket size: 0x%" PRIx32 ".\n", wad_header.ticket_size);
    printf("WAD TMD size: 0x%" PRIx32 ".\n", wad_header.tmd_size);
    printf("WAD content data size: 0x%" PRIx32 ".\n\n", wad_header.data_size);
    
    /* Check header fields. */
    /* Discard WadType_Boot2Package while we're at it. */
    if (wad_header.header_size != WadHeaderSize_InstallablePackage || wad_header.type != WadType_NormalPackage || wad_header.version != WadVersion_InstallablePackage || \
        !wad_header.cert_chain_size || wad_header.ticket_size < TIK_MIN_SIZE || wad_header.tmd_size < TMD_MIN_SIZE || !wad_header.data_size || \
        wad_size < (ALIGN_UP(wad_header.header_size, WAD_BLOCK_ALIGNMENT) + ALIGN_UP(wad_header.cert_chain_size, WAD_BLOCK_ALIGNMENT) + ALIGN_UP(wad_header.ticket_size, WAD_BLOCK_ALIGNMENT) + \
        ALIGN_UP(wad_header.tmd_size, WAD_BLOCK_ALIGNMENT) + ALIGN_UP(wad_header.data_size, WAD_BLOCK_ALIGNMENT)))
    {
        ERROR_MSG("Invalid WAD header in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Update file stream position. */
    wad_offset = ALIGN_UP(wad_header.header_size, WAD_BLOCK_ALIGNMENT);
    os_fseek(wad_fd, wad_offset, SEEK_SET);
    
    /* Read certificate chain. */
    cert_chain = certReadRawCertificateChainFromFile(wad_fd, wad_header.cert_chain_size);
    if (!cert_chain)
    {
        ERROR_MSG("Invalid certificate chain in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Save certificate chain. */
    os_snprintf(entry_path, MAX_ELEMENTS(entry_path), OS_PRINT_STR OS_PATH_SEPARATOR "cert.bin", out_dir);
    if (!utilsWriteDataToFile(entry_path, cert_chain, wad_header.cert_chain_size))
    {
        ERROR_MSG("Failed to save certificate chain from \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Update file stream position. */
    wad_offset += ALIGN_UP(wad_header.cert_chain_size, WAD_BLOCK_ALIGNMENT);
    os_fseek(wad_fd, wad_offset, SEEK_SET);
    
    /* Read ticket. */
    ticket = tikReadTicketFromFile(wad_fd, wad_header.ticket_size);
    if (!ticket)
    {
        ERROR_MSG("Invalid ticket in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Retrieve ticket common block. */
    tik_common_block = tikGetCommonBlockFromBuffer(ticket, wad_header.ticket_size, NULL);
    
    /* Print ticket information */
    utilsPrintHexData("Ticket Encrypted Titlekey: ", tik_common_block->titlekey, AES_BLOCK_SIZE);
    printf("Ticket ID: %016" PRIx64 ".\n", bswap_64(tik_common_block->ticket_id));
    printf("Ticket Console ID: %08" PRIx32 ".\n", bswap_32(tik_common_block->console_id));
    printf("Ticket Title ID: %016" PRIx64 ".\n", bswap_64(tik_common_block->title_id));
    printf("Ticket Title Version: %u.\n\n", bswap_16(tik_common_block->title_version));
    
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
    os_snprintf(entry_path, MAX_ELEMENTS(entry_path), OS_PRINT_STR OS_PATH_SEPARATOR "tik.bin", out_dir);
    if (!utilsWriteDataToFile(entry_path, ticket, wad_header.ticket_size))
    {
        ERROR_MSG("Failed to save ticket from \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Update file stream position. */
    wad_offset += ALIGN_UP(wad_header.ticket_size, WAD_BLOCK_ALIGNMENT);
    os_fseek(wad_fd, wad_offset, SEEK_SET);
    
    /* Read TMD. */
    tmd = tmdReadTitleMetadataFromFile(wad_fd, wad_header.tmd_size);
    if (!tmd)
    {
        ERROR_MSG("Invalid TMD in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Retrieve TMD common block. */
    tmd_common_block = tmdGetCommonBlockFromBuffer(tmd, wad_header.tmd_size, NULL);
    
    /* Print TMD information. */
    printf("TMD Version: %u.\n", tmd_common_block->tmd_version);
    printf("TMD Target System: 0x%02" PRIx8 " (%s).\n", tmd_common_block->target_system, TMD_TARGET_SYSTEM_STR(tmd_common_block->target_system));
    printf("TMD System Version: %016" PRIx64 ".\n", bswap_64(tmd_common_block->system_version));
    printf("TMD Title ID: %016" PRIx64 ".\n", bswap_64(tmd_common_block->title_id));
    printf("TMD Title Type: 0x%08" PRIx32 ".\n", bswap_32(tmd_common_block->title_type));
    printf("TMD Publisher: %.*s.\n", (int)sizeof(tmd_common_block->group_id), tmd_common_block->group_id);
    printf("TMD Region: 0x%04" PRIx16 ".\n", bswap_16(tmd_common_block->region));
    printf("TMD Title Version: %u.\n", bswap_16(tmd_common_block->title_version));
    printf("TMD Content Count: %u.\n", bswap_16(tmd_common_block->content_count));
    printf("TMD Boot Index: %u.\n\n", bswap_16(tmd_common_block->boot_index));
    
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
        ERROR_MSG("Ticket/TMD Title ID mismatch! (%08" PRIx32 "-%08" PRIx32 " != %08" PRIx32 "-%08" PRIx32 ").", TITLE_UPPER(tik_tid), TITLE_LOWER(tik_tid), TITLE_UPPER(tmd_tid), TITLE_LOWER(tmd_tid));
        goto out;
    }
    
    /* Save TMD. */
    os_snprintf(entry_path, MAX_ELEMENTS(entry_path), OS_PRINT_STR OS_PATH_SEPARATOR "tmd.bin", out_dir);
    if (!utilsWriteDataToFile(entry_path, tmd, wad_header.tmd_size))
    {
        ERROR_MSG("Failed to save TMD from \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Update file stream position. */
    wad_offset += ALIGN_UP(wad_header.tmd_size, WAD_BLOCK_ALIGNMENT);
    os_fseek(wad_fd, wad_offset, SEEK_SET);
    
    /* Generate decrypted titlekey. */
    memcpy(titlekey_iv, (u8*)(&(tik_common_block->title_id)), sizeof(u64));
    utilsPrintHexData("Titlekey IV: ", titlekey_iv, AES_BLOCK_SIZE);
    
    common_key = (tik_common_block->common_key_index == TikCommonKeyIndex_Korean ? keysGetWiiKoreanKey() : \
                 (tik_common_block->common_key_index == TikCommonKeyIndex_vWii ? keysGetVirtualWiiCommonKey() : keysGetWiiCommonKey()));
    
    if (!common_key || !cryptoAes128CbcCrypt(common_key, titlekey_iv, dec_titlekey, tik_common_block->titlekey, AES_BLOCK_SIZE, false))
    {
        ERROR_MSG("Failed to generate decrypted titlekey!");
        goto out;
    }
    
    utilsPrintHexData("Decrypted titlekey: ", dec_titlekey, AES_BLOCK_SIZE);
    printf("\n");
    
    /* Process content files. */
    content_count = bswap_16(tmd_common_block->content_count);
    tmd_contents = TMD_CONTENTS(tmd_common_block);
    
    for(u16 i = 0; i < content_count; i++)
    {
        /* Generate content IV. */
        memset(content_iv, 0, AES_BLOCK_SIZE);
        memcpy(content_iv, &(tmd_contents[i].index), sizeof(u16));
        
        /* Byteswap content record fields. */
        tmdByteswapTitleMetadataContentRecordFields(&(tmd_contents[i]));
        
        /* Print content info. */
        printf("TMD content #%u:\n", i + 1);
        printf("Content ID: %08" PRIx32 ".\n", tmd_contents[i].content_id);
        printf("Content index: %04" PRIx16 ".\n", tmd_contents[i].index);
        printf("Content type: %04" PRIx16 " (%s).\n", tmd_contents[i].type, TMD_CONTENT_REC_TYPE_STR(tmd_contents[i].type));
        printf("Content size: 0x%" PRIx64 ".\n", tmd_contents[i].size);
        utilsPrintHexData("Content SHA-1 hash: ", tmd_contents[i].hash, SHA1_HASH_SIZE);
        utilsPrintHexData("Content IV: ", content_iv, AES_BLOCK_SIZE);
        printf("\n");
        
        if (tmd_contents[i].type != TmdContentRecordType_Normal && tmd_contents[i].type != TmdContentRecordType_DLC && tmd_contents[i].type != TmdContentRecordType_Shared)
        {
            ERROR_MSG("Invalid content type!");
            goto out;
        }
        
        /* Generate output path for the current content. */
        os_snprintf(entry_path, MAX_ELEMENTS(entry_path), OS_PRINT_STR OS_PATH_SEPARATOR "%08" PRIx16 ".app", out_dir, tmd_contents[i].index);
        
        /* Save decrypted content file. */
        if (!wadSaveContentFileFromInstallablePackage(wad_fd, dec_titlekey, content_iv, &(tmd_contents[i]), entry_path))
        {
            ERROR_MSG("Failed to save decrypted content file \"%08" PRIx16 ".app\" from \"" OS_PRINT_STR "\"!", tmd_contents[i].index, wad_path);
            goto out;
        }
    }
    
    success = true;
    
out:
    if (tmd) free(tmd);
    
    if (ticket) free(ticket);
    
    if (cert_chain) free(cert_chain);
    
    if (wad_fd) fclose(wad_fd);
    
    return success;
}

static bool wadSaveContentFileFromInstallablePackage(FILE *wad_file, const u8 titlekey[AES_BLOCK_SIZE], const u8 iv[AES_BLOCK_SIZE], const TmdContentRecord *content_record, const os_char_t *out_path)
{
    if (!wad_file || !titlekey || !iv || !content_record || !out_path || !os_strlen(out_path))
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
    
    /* Copy content data. */
    for(size_t offset = 0; offset < content_record->size; offset += blksize)
    {
        /* Handle last encrypted chunk size. */
        if (blksize > (content_record->size - offset)) blksize = (content_record->size - offset);
        
        /* Read encrypted chunk. */
        read_size = ALIGN_UP(blksize, AES_BLOCK_SIZE);
        res = fread(buf, 1, read_size, wad_file);
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
    }
    
    /* Retrieve calculated SHA-1 checksum. */
    mbedtls_sha1_finish(&sha1_ctx, hash);
    
    /* Compare checksums. */
    if (memcmp(hash, content_record->hash, SHA1_HASH_SIZE) != 0)
    {
        ERROR_MSG("SHA-1 checksum mismatch!");
        goto out;
    }
    
    /* Update file stream position if necessary. */
    if (!IS_ALIGNED(content_record->size, WAD_BLOCK_ALIGNMENT)) os_fseek(wad_file, ALIGN_UP(content_record->size, WAD_BLOCK_ALIGNMENT) - ALIGN_UP(content_record->size, AES_BLOCK_SIZE), SEEK_CUR);
    
    success = true;
    
out:
    if (cnt_fd) fclose(cnt_fd);
    
    if (sha1_ctx_init) mbedtls_sha1_free(&sha1_ctx);
    
    if (aes_ctx_init) cryptoAes128CbcContextFree(&aes_ctx);
    
    if (buf) free(buf);
    
    return success;
}
