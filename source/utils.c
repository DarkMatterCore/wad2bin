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
#include "ConvertUTF.h"

void utilsPrintErrorMessage(const char *func_name, const char *fmt, ...)
{
    va_list args;
    
    printf("%s: ", func_name);
    
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    
    printf("\n");
}

bool utilsConvertUTF8ToUTF16(os_char_t *dst, const char *src)
{
    size_t src_len = 0, dst_len = 0;
    
    const UTF8 *src_start = (const UTF8*)src;
    UTF16 *dst_start = (UTF16*)dst;
    
    ConversionResult res = conversionOK;
    
    if (!dst || !src || !(src_len = strlen(src)))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    dst_len = (src_len + 1);
    
    const UTF8 *src_end = (const UTF8*)(src + src_len);
    UTF16 *dst_end = (UTF16*)(dst + dst_len);
    
    res = ConvertUTF8toUTF16(&src_start, src_end, &dst_start, dst_end, strictConversion);
    if (res != conversionOK)
    {
        ERROR_MSG("UTF-8 to UTF-16 conversion failed! (%d).", res);
        return false;
    }
    
    return true;
}

bool utilsReadDataFromFile(const os_char_t *file_path, void *buf, size_t expected_size)
{
    if (!file_path || !os_strlen(file_path) || !buf || !expected_size)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    FILE *fd = NULL;
    size_t file_size = 0, res = 0;
    bool success = false;
    
    /* Open file. */
    fd = os_fopen(file_path, OS_MODE_READ);
    if (!fd)
    {
        ERROR_MSG("Failed to open \"" OS_PRINT_STR "\" in read mode!", file_path);
        return false;
    }
    
    /* Get file size. */
    os_fseek(fd, 0, SEEK_END);
    file_size = os_ftell(fd);
    rewind(fd);
    
    /* Check file size. */
    if (file_size != expected_size)
    {
        ERROR_MSG("File size for \"" OS_PRINT_STR "\" doesn't match expected size! (0x%" PRIx64 " != 0x%" PRIx64 ").", file_path, file_size, expected_size);
        goto out;
    }
    
    /* Read file data. */
    res = fread(buf, 1, expected_size, fd);
    if (res != expected_size)
    {
        ERROR_MSG("Unable to read 0x%" PRIx64 " bytes block from \"" OS_PRINT_STR "\"!", expected_size, file_path);
        goto out;
    }
    
    success = true;
    
out:
    fclose(fd);
    
    return success;
}

bool utilsWriteDataToFile(const os_char_t *out_path, const void *buf, size_t size)
{
    if (!out_path || !os_strlen(out_path) || !buf || !size)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    FILE *fd = NULL;
    size_t res = 0;
    bool success = true;
    
    /* Open file. */
    fd = os_fopen(out_path, OS_MODE_WRITE);
    if (!fd)
    {
        ERROR_MSG("Failed to open \"" OS_PRINT_STR "\" in write mode!", out_path);
        return false;
    }
    
    /* Write data to file. */
    res = fwrite(buf, 1, size, fd);
    if (res != size)
    {
        ERROR_MSG("Failed to write 0x%" PRIx64 " bytes block to \"" OS_PRINT_STR "\"!", size, out_path);
        success = false;
    }
    
    /* Close file. */
    fclose(fd);
    
    /* Delete file if write failed. */
    if (!success) os_remove(out_path);
    
    return success;
}

void utilsPrintHexData(const char *msg, const void *data, size_t size)
{
    if (!data || !size) return;
    
    if (msg && strlen(msg)) printf(msg);
    
    const u8 *data_u8 = (const u8*)data;
    
    for(size_t i = 0; i < size; i++) printf("%02" PRIx8, data_u8[i]);
    
    printf(".\n");
}

void utilsPrintUTF16BEString(const char *msg, u16 *utf16be_str, size_t size)
{
    if (!utf16be_str || !size) return;
    
    if (msg && strlen(msg)) printf(msg);
    
    for(size_t i = 0; i < size && utf16be_str[i] != 0; i++) printf("%lc", bswap_16(utf16be_str[i]));
    
    printf(".\n");
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

void utilsCreateDirectoryTree(const os_char_t *path)
{
    if (!path || !os_strlen(path)) return;
    
    os_char_t tmp[MAX_PATH] = {0};
    os_char_t *ptr = NULL;
    
    ptr = os_strchr(path, *((u8*)OS_PATH_SEPARATOR));
    
    while(ptr)
    {
        os_snprintf(tmp, MAX_PATH, OS_PRINT_PRECISION_STR, (int)(ptr - path), path);
        os_mkdir(tmp, 0777);
        ptr++;
        ptr = os_strchr(ptr, *((u8*)OS_PATH_SEPARATOR));
    }
    
    os_mkdir(path, 0777);
}
