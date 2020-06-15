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
#include "cntbin.h"

#define ARG_COUNT   4

int main(int argc, char **argv)
{
    int ret = 0;
    
    /* Reserve memory for an extra temporary path. */
    os_char_t *paths[ARG_COUNT + 1] = {0};
    bool res = false;
    
    printf("\nwad2bin v%s (c) DarkMatterCore.\n", VERSION);
    printf("Built: %s %s.\n\n", __TIME__, __DATE__);
    
    if (argc != (ARG_COUNT + 1) || strlen(argv[1]) >= MAX_PATH || strlen(argv[2]) >= MAX_PATH || strlen(argv[3]) >= MAX_PATH || (strlen(argv[4]) + SD_CONTENT_PATH_LENGTH) >= MAX_PATH)
    {
        printf("Usage: %s <keys file> <device.cert> <input WAD> <output dir>\n\n", argv[0]);
        printf("Paths must not exceed %u characters. Relative paths are supported.\n", MAX_PATH - 1);
        printf("The required directory tree for the content.bin file will be created at the output directory.\n");
        printf("You can set your SD card root directory as the output directory.\n");
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
            size_t path_len = strlen(argv[i + 1]);
            if (i == (ARG_COUNT - 1) && argv[i + 1][path_len - 1] == *((u8*)OS_PATH_SEPARATOR)) paths[i][path_len - 1] = (os_char_t)0;
        }
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    /* Start conversion procedure. */
    res = cntbinConvertInstallableWadPackageToBackupPackage(paths[0], paths[1], paths[2], paths[3], paths[4]);
    if (!res) ret = -4;
    
out:
    for(u32 i = 0; i <= ARG_COUNT; i++)
    {
        if (paths[i]) free(paths[i]);
    }
    
    return ret;
}
