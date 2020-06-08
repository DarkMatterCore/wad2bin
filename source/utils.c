/*
 * utils.c
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

void utilsPrintErrorMessage(const char *func_name, const char *fmt, ...)
{
    va_list args;
    
    printf("%s: ", func_name);
    
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    
    printf("\n");
}

bool utilsRemoveDirectoryRecursively(const os_char_t *dir_path)
{
    os_dir_t *dir = NULL;
    os_dirent_t *entry = NULL;
    os_char_t *name_buf = NULL;
    os_stat_t st = {0};
    
    size_t path_len = 0, entry_len = 0;
    bool success = true;
    
    if (!dir_path || !(path_len = os_strlen(dir_path)))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    /* Open directory. */
    if (!(dir = os_opendir(dir_path)))
    {
        ERROR_MSG("Error opening directory \"" OS_PRINT_STR "\"!", dir_path);
        return false;
    }
    
    while((entry = os_readdir(dir)) != NULL)
    {
        entry_len = os_strlen(entry->d_name);
        
        /* Skip "." and ".." directory entries. */
        if (!entry_len || (entry_len == 1 && !os_strcmp(entry->d_name, OS_CURRENT_DIR)) || (entry_len == 2 && !os_strcmp(entry->d_name, OS_PARENT_DIR))) continue;
        
        /* Allocate memory for the current entry name. */
        entry_len = (path_len + 1 + entry_len + 1);
        name_buf = calloc(entry_len, sizeof(os_char_t));
        if (!name_buf)
        {
            ERROR_MSG("Failed to allocate memory for entry name buffer!");
            success = false;
            break;
        }
        
        /* Generate entry path. */
        os_snprintf(name_buf, entry_len, OS_PRINT_STR OS_PATH_SEPARATOR OS_PRINT_STR, dir_path, entry->d_name);
        
        /* Get entry status */
        if (os_stat(name_buf, &st) < 0)
        {
            ERROR_MSG("Failed to get entry status for \"" OS_PRINT_STR "\"!", name_buf);
            success = false;
            break;
        }
        
        if (st.st_mode & S_IFDIR)
        {
            /* Delete directory entry. */
            if (!utilsRemoveDirectoryRecursively(name_buf)) success = false;
        } else
        if (st.st_mode & S_IFREG)
        {
            /* Delete file entry. */
            os_remove(name_buf);
        }
        
        free(name_buf);
        name_buf = NULL;
        
        if (!success) break;
    }
    
    /* Close directory. */
    os_closedir(dir);
    
    /* Remove directory. */
    if (success) os_rmdir(dir_path);
    
    return success;
}
