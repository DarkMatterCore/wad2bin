/*
 * utils.h
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

#pragma once

#ifndef __UTILS_H__
#define __UTILS_H__

#include "types.h"
#include "os.h"

#define VERSION                         "0.5"

/* Supress clang warnings about variadic macro arguments. */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif
#define ERROR_MSG(...)                  utilsPrintErrorMessage(__func__, ##__VA_ARGS__)
#ifdef __clang__
#pragma clang diagnostic pop
#endif

#define MEMBER_SIZE(type, member)       sizeof(((type*)NULL)->member)

#define MAX_ELEMENTS(x)                 ((sizeof((x))) / (sizeof((x)[0])))

#define ALIGN_DOWN(x, y)                ((x) & ~((y) - 1))
#define ALIGN_UP(x, y)                  ((((y) - 1) + (x)) & ~((y) - 1))
#define IS_ALIGNED(x, y)                (((x) & ((y) - 1)) == 0)

#define TITLE_UPPER(x)                  ((u32)((x) >> 32))
#define TITLE_LOWER(x)                  ((u32)(x))
#define TITLE_ID(x, y)                  (((u64)(x) << 32) | (y))

#define TITLE_TYPE_SYSTEM               (u32)0x00000001
#define TITLE_TYPE_DISC_GAME            (u32)0x00010000
#define TITLE_TYPE_DOWNLOADABLE_CHANNEL (u32)0x00010001
#define TITLE_TYPE_DISC_BASED_CHANNEL   (u32)0x00010004
#define TITLE_TYPE_DLC                  (u32)0x00010005

#define SYSTEM_MENU_TID                 TITLE_ID(1, 2)

#define SD_CONTENT_PATH_MAX_LENGTH      35

/* "dir" is a subdirectory name inside "/private/wii/". */
/* "%s" is replaced by the desired filename using *printf functions. */
#define PRIVATE_PATH(dir)               OS_PATH_SEPARATOR "private" OS_PATH_SEPARATOR "wii" OS_PATH_SEPARATOR dir OS_PATH_SEPARATOR "%s"

void utilsPrintErrorMessage(const char *func_name, const char *fmt, ...);

bool utilsConvertUTF8ToUTF16(os_char_t *dst, const char *src);

bool utilsReadDataFromFile(const os_char_t *file_path, void *buf, u64 expected_size);

bool utilsWriteDataToFile(const os_char_t *out_path, const void *buf, u64 size);

void utilsPrintHexData(const char *msg, const void *data, u64 size);

void utilsPrintUTF16BEString(const char *msg, u16 *utf16be_str, u64 size);

bool utilsRemoveDirectoryRecursively(const os_char_t *dir_path);

void utilsCreateDirectoryTree(const os_char_t *path);

bool utilsWritePadding(FILE *fd, u64 *size, u64 alignment);

bool utilsAlignBuffer(void **buf, u64 *size, u64 alignment);

void utilsGenerateAsciiStringFromTitleIdLower(u64 title_id, char *out);

#endif /* __UTILS_H__ */
