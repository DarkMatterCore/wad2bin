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
#include "wad.h"
#include "cert.h"
#include "tik.h"
#include "tmd.h"

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
    
    u8 *cert_chain = NULL;
    
    u8 *ticket = NULL;
    TikCommonBlock *tik_common_block = NULL;
    
    u8 *tmd = NULL;
    
    
    
    
    
    
    FILE *cnt_fd = NULL;
    
    
    bool success = false;
    
    
    
    
    
    
    
    
    
    
    
    /* Create output directory. */
    if (os_mkdir(out_dir, 0777) < 0)
    {
        ERROR_MSG("Unable to create directory \"" OS_PRINT_STR "\"!", out_dir);
        return false;
    }
    
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
    
    /* Check header fields. */
    /* Ignore WadType_Boot2Package while we're at it. */
    if (wad_header.header_size != WadHeaderSize_InstallablePackage || wad_header.type != WadType_NormalPackage || wad_header.version != WadVersion_InstallablePackage || \
        !wad_header.cert_chain_size || !wad_header.ticket_size || !wad_header.tmd_size || !wad_header.data_size || wad_size < (ALIGN_UP(wad_header.header_size, 0x40) + \
        ALIGN_UP(wad_header.cert_chain_size, 0x40) + ALIGN_UP(wad_header.ticket_size, 0x40) + ALIGN_UP(wad_header.tmd_size, 0x40) + ALIGN_UP(wad_header.data_size, 0x40) + \
        ALIGN_UP(wad_header.footer_size, 0x40)))
    {
        ERROR_MSG("Invalid WAD header in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Update file stream position. */
    wad_offset = ALIGN_UP(wad_header.header_size, 0x40);
    os_fseek(wad_fd, wad_offset, SEEK_SET);
    
    /* Read certificate chain. */
    cert_chain = certReadRawCertificateChainFromFile(wad_fd, wad_header.cert_chain_size);
    if (!cert_chain)
    {
        ERROR_MSG("Invalid certificate chain in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Update file stream position. */
    wad_offset += ALIGN_UP(wad_header.cert_chain_size, 0x40);
    os_fseek(wad_fd, wad_offset, SEEK_SET);
    
    /* Read ticket. */
    ticket = tikReadTicketFromFile(wad_fd, wad_header.ticket_size);
    if (!ticket)
    {
        ERROR_MSG("Invalid ticket in \"" OS_PRINT_STR "\"!", wad_path);
        goto out;
    }
    
    /* Check if the title we're dealing with is exportable. */
    tik_common_block = tikGetCommonBlockFromBuffer(ticket, wad_header.ticket_size, NULL);
    if (!tikIsTitleExportable(tik_common_block))
    {
        ERROR_MSG("Invalid Title ID type!\nOnly downloadable channels, disc-based game channels and DLCs are exportable!");
        goto out;
    }
    
    /* Update file stream position. */
    wad_offset += ALIGN_UP(wad_header.ticket_size, 0x40);
    os_fseek(wad_fd, wad_offset, SEEK_SET);
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
out:
    if (tmd) free(tmd);
    if (ticket) free(ticket);
    if (cert_chain) free(cert_chain);
    
    if (wad_fd) fclose(wad_fd);
    
    if (!success) utilsRemoveDirectoryRecursively(out_dir);
    
    return success;
}





