/*
 * main.c
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
#include "wad.h"

#define ARG_COUNT   4

int main(int argc, char **argv)
{
    int ret = 0;
    
    os_char_t *paths[ARG_COUNT] = {0};
    
    os_char_t wad_output_dir[0x20] = {0};
    os_snprintf(wad_output_dir, MAX_ELEMENTS(wad_output_dir), "." OS_PATH_SEPARATOR "wad2cntbin_unpacked_wad" OS_PATH_SEPARATOR);
    os_mkdir(wad_output_dir, 0777);
    
    printf("\nwad2cntbin v%s (c) DarkMatterCore.\n", VERSION);
    printf("Built: %s %s.\n\n", __TIME__, __DATE__);
    
    if (argc != (ARG_COUNT + 1) || strlen(argv[1]) >= MAX_PATH || strlen(argv[2]) >= MAX_PATH || strlen(argv[3]) >= MAX_PATH || (strlen(argv[4]) + 1 + SD_CONTENT_PATH_LENGTH) >= MAX_PATH)
    {
        printf("Usage: %s <keys file> <device.cert> <input WAD> <output dir>\n", argv[0]);
        printf("Paths must not exceed %u characters.\n", MAX_PATH - 1);
        ret = -1;
        goto out;
    }
    
    /* Generate path buffers. */
    for(u32 i = 0; i < ARG_COUNT; i++)
    {
        /* Allocate memory for the current path. */
        paths[i] = calloc(MAX_PATH, sizeof(os_char_t));
        if (!paths[i])
        {
            ERROR_MSG("Error allocating memory for path #%u!", i);
            ret = -2;
            goto out;
        }
        
        size_t path_len = strlen(argv[i + 1]);
        
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
        os_snprintf(paths[i], MAX_PATH, argv[i + 1]);
#endif
        
        /* Check if the output directory string doesn't end with a path separator. */
        /* If so, concatenate a path separator to the copied path. */
        if (i == (ARG_COUNT - 1) && argv[i + 1][path_len - 1] != *((u8*)OS_PATH_SEPARATOR)) os_snprintf(paths[i] + path_len, MAX_PATH - path_len, OS_PATH_SEPARATOR);
    }
    
    /* Load keydata and device certificate. */
    if (!keysLoadKeyDataAndDeviceCert(paths[0], paths[1]))
    {
        ret = -4;
        goto out;
    }
    
    /* Unpack input WAD package. */
    if (!wadUnpackInstallablePackage(paths[2], wad_output_dir))
    {
        ret = -5;
        goto out;
    }
    
    
    
    
    
    
    
    
    
out:
    //utilsRemoveDirectoryRecursively(wad_output_dir);
    
    for(u32 i = 0; i < ARG_COUNT; i++)
    {
        if (paths[i]) free(paths[i]);
    }
    
    return ret;
}
