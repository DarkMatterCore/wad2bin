/*
 * main.c
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
#include "bin.h"

#define ARG_COUNT   4

int main(int argc, char **argv)
{
    int ret = 0;
    
    /* Reserve memory for an extra temporary path. */
    os_char_t *paths[ARG_COUNT + 1] = {0};
    
    u8 *cert_chain = NULL;
    u64 cert_chain_size = 0;
    
    u8 *ticket = NULL;
    u64 ticket_size = 0;
    
    u8 *tmd = NULL;
    u64 tmd_size = 0;
    
    u64 title_id = 0, parent_tid = 0;
    u32 tid_upper = 0;
    
    printf("\nwad2bin v%s (c) DarkMatterCore.\n", VERSION);
    printf("Built: %s %s.\n\n", __TIME__, __DATE__);
    
    if (argc < (ARG_COUNT + 1) || argc > (ARG_COUNT + 2) || strlen(argv[1]) >= MAX_PATH || strlen(argv[2]) >= MAX_PATH || strlen(argv[3]) >= MAX_PATH || \
        (strlen(argv[4]) + SD_CONTENT_PATH_MAX_LENGTH) >= MAX_PATH || (argc == (ARG_COUNT + 2) && strlen(argv[5]) != 16))
    {
        printf("Usage: %s <keys file> <device.cert> <input WAD> <output dir> [parent title ID]\n\n", argv[0]);
        printf("Paths must not exceed %u characters. Relative paths are supported.\n", MAX_PATH - 1);
        printf("The required directory tree for the *.bin file(s) will be created at the output directory.\n");
        printf("You can set your SD card root directory as the output directory.\n");
        printf("Parent title ID is only required if the input WAD is a DLC. A 16 character long hex string is expected.\n\n");
        ret = -1;
        goto out;
    }
    
    /* Generate path buffers. */
    for(u32 i = 0; i <= ARG_COUNT; i++)
    {
        /* Allocate memory for the current path. */
        paths[i] = calloc(MAX_PATH, sizeof(os_char_t));
        if (!paths[i])
        {
            ERROR_MSG("Error allocating memory for path #%u!", i);
            ret = -2;
            goto out;
        }
        
        if (i == ARG_COUNT)
        {
            /* Save temporary path and create it. */
            os_snprintf(paths[i], MAX_PATH, "." OS_PATH_SEPARATOR "wad2bin_wad_data");
            os_mkdir(paths[i], 0777);
        } else {
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
            /* Convert current path string to UTF-16. */
            /* We'll only need to perform manual conversion at this point. */
            if (!utilsConvertUTF8ToUTF16(paths[i], argv[i + 1]))
            {
                ERROR_MSG("Failed to convert path from UTF-8 to UTF-16!");
                ret = -3;
                goto out;
            }
#else
            /* Copy path. */
            os_snprintf(paths[i], MAX_PATH, "%s", argv[i + 1]);
#endif
            
            /* Check if the output directory string ends with a path separator. */
            /* If so, remove it. */
            u64 path_len = strlen(argv[i + 1]);
            if (i == (ARG_COUNT - 1) && argv[i + 1][path_len - 1] == *((u8*)OS_PATH_SEPARATOR)) paths[i][path_len - 1] = (os_char_t)0;
        }
    }
    
    /* Check if the user provided a parent title ID. */
    if (argc == (ARG_COUNT + 2))
    {
        /* Parse parent title ID. */
        if (!keysParseHexKey((u8*)&parent_tid, NULL, argv[5], 8, false))
        {
            printf("Failed to parse parent title ID!\n");
            ret = -4;
            goto out;
        }
        
        /* Byteswap parent title ID. */
        parent_tid = bswap_64(parent_tid);
        
        /* Check if the TID upper u32 is valid. */
        u32 parent_tid_upper = TITLE_UPPER(parent_tid);
        if (parent_tid_upper != TITLE_TYPE_DISC_GAME && parent_tid_upper != TITLE_TYPE_DOWNLOADABLE_CHANNEL && parent_tid_upper != TITLE_TYPE_DISC_BASED_CHANNEL)
        {
            printf("Invalid parent title ID category!\nOnly disc-based game IDs, downloadable channel IDs and disc-based channel IDs are supported.\n");
            ret = -5;
            goto out;
        }
    }
    
    /* Load keydata and device certificate. */
    if (!keysLoadKeyDataAndDeviceCert(paths[0], paths[1]))
    {
        ret = -6;
        goto out;
    }
    
    printf("Keydata and device certificate successfully loaded.\n\n");
    
    /* Unpack input WAD package. */
    if (!wadUnpackInstallablePackage(paths[2], paths[4], &cert_chain, &cert_chain_size, &ticket, &ticket_size, &tmd, &tmd_size, &title_id))
    {
        ret = -7;
        goto out;
    }
    
    printf("WAD package \"" OS_PRINT_STR "\" successfully unpacked.\n\n", paths[2]);
    
    /* Start conversion process. */
    tid_upper = TITLE_UPPER(title_id);
    if (tid_upper == TITLE_TYPE_DLC)
    {
        /* Check if a parent title ID was provided. */
        if (argc != (ARG_COUNT + 2))
        {
            printf("Error: parent title ID not provided! This is required for DLC titles.\n");
            ret = -8;
            goto out;
        }
        
        /* Check if we're dealing with a DLC that can be converted. */
        if (!binIsDlcTitleConvertible(title_id))
        {
            printf("This DLC package belongs to a game that doesn't support the <index>.bin format!\nConversion process halted.\n");
            ret = -9;
            goto out;
        }
        
        /* Generate <index>.bin file(s). */
        if (!binGenerateIndexedPackagesFromUnpackedInstallableWadPackage(paths[4], paths[3], tmd, tmd_size, parent_tid))
        {
            ret = -10;
            goto out;
        }
    } else {
        /* Generate content.bin file. */
        if (!binGenerateContentBinFromUnpackedInstallableWadPackage(paths[4], paths[3], tmd, tmd_size))
        {
            ret = -11;
            goto out;
        }
    }
    
    /* Generate bogus installable WAD package. */
    if (!wadGenerateBogusInstallablePackage(paths[3], cert_chain, cert_chain_size, ticket, ticket_size, tmd, tmd_size))
    {
        ret = -12;
        goto out;
    }
    
    printf("Process finished!\n\n");
    
out:
    if (ret < 0 && ret != -1) printf("Process failed!\n\n");
    
    if (tmd) free(tmd);
    
    if (ticket) free(ticket);
    
    if (cert_chain) free(cert_chain);
    
    /* Remove unpacked WAD directory. */
    if (paths[4]) utilsRemoveDirectoryRecursively(paths[4]);
    
    for(u32 i = 0; i <= ARG_COUNT; i++)
    {
        if (paths[i]) free(paths[i]);
    }
    
    return ret;
}
