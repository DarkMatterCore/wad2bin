/*
 * os.h
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

#pragma once

#ifndef __OS_H__
#define __OS_H__

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#include <wchar.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAX_PATH
#define MAX_PATH    1024
#endif

#define IS_BIG_ENDIAN   (*((u16*)"\0\xff") < 0x100)

/* Conditional byteswap macros to achieve endianness-agnostic integer handling. */
#define bswap_16(val)   (IS_BIG_ENDIAN ? val : __builtin_bswap16(val))
#define bswap_32(val)   (IS_BIG_ENDIAN ? val : __builtin_bswap32(val))
#define bswap_64(val)   (IS_BIG_ENDIAN ? val : __builtin_bswap64(val))

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
typedef wchar_t os_char_t;   /// UTF-16.
typedef _WDIR os_dir_t;
typedef struct _wdirent os_dirent_t;
typedef struct _stat os_stat_t;

#define OS_MODE_READ                    L"rb"
#define OS_MODE_WRITE                   L"wb"
#define OS_MODE_EDIT                    L"rb+"
#define OS_PATH_SEPARATOR               "\\"
#define OS_CURRENT_DIR                  L"."
#define OS_PARENT_DIR                   L".."
#define OS_PRINT_STR                    "%ls"

#define os_fopen                        _wfopen
#define os_fseek                        _fseeki64   /// Point to the right function for large file support.
#define os_ftell                        _ftelli64   /// Point to the right function for large file support.
#define os_strlen                       wcslen
#define os_strcmp                       wcscmp
#define os_strncmp                      wcsncmp
#define os_strcat                       wcscat
#define os_mkdir(path, mode)            _wmkdir(path)
#define os_rmdir                        _wrmdir
#define os_opendir                      _wopendir
#define os_readdir                      _wreaddir
#define os_closedir                     _wclosedir
#define os_remove                       _wremove
#define os_stat                         _wstat

int os_snprintf(os_char_t *out, size_t len, const char *fmt, ...);
#else /* WIN32 || _WIN32 || __WIN32__ || __NT__ */
typedef char os_char_t;     /// UTF-8.
typedef DIR os_dir_t;
typedef struct dirent os_dirent_t;
typedef struct stat os_stat_t;

#define OS_MODE_READ                    "rb"
#define OS_MODE_WRITE                   "wb"
#define OS_MODE_EDIT                    "rb+"
#define OS_PATH_SEPARATOR               "/"
#define OS_CURRENT_DIR                  "."
#define OS_PARENT_DIR                   ".."
#define OS_PRINT_STR                    "%s"

#define os_fopen                        fopen
#define os_fseek                        fseek       /// Large file support already enabled.
#define os_ftell                        ftell       /// Large file support already enabled.
#define os_strlen                       strlen
#define os_strcmp                       strcmp
#define os_strncmp                      strncmp
#define os_snprintf                     snprintf
#define os_strcat                       strcat
#define os_mkdir                        mkdir
#define os_rmdir                        rmdir
#define os_opendir                      opendir
#define os_readdir                      readdir
#define os_closedir                     closedir
#define os_remove                       remove
#define os_stat                         stat
#endif /* WIN32 || _WIN32 || __WIN32__ || __NT__ */

#endif /* __OS_H__ */
