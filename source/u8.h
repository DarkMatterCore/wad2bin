/*
 * u8.h
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

#ifndef __U8_H__
#define __U8_H__

#define U8_MAGIC    (u32)0x55AA382D /* "U.8-". */

typedef struct {
    u32 magic;                  ///< U8_MAGIC.
    u32 root_node_offset;       ///< Root node offset, relative to the start of this header.
    u32 node_info_block_size;   ///< Node table size + string table size, starting from the root node offset.
    u32 data_offset;            ///< Root node offset + node info block size, aligned to 0x40. Relative to the start of this header.
} U8Header;

typedef enum {
    U8NodeType_File      = 0,
    U8NodeType_Directory = 1
} U8NodeType;

typedef struct {
    u32 type        : 8;    ///< U8NodeType.
    u32 name_offset : 24;   ///< Offset to node name. Relative to the start of the string table.
} U8NodeProperties;

typedef struct {
    U8NodeProperties properties;    ///< Using a bitfield because of the odd name_offset field size.
    u32 data_offset;                ///< Files: offset to file data (relative to the start of the U8 header). Directories: parent dir offset (relative to the start of the node table).
    u32 size;                       ///< Files: data size. Directories: node number from the last file inside this directory (root node is number 1).
} U8Node;

typedef struct {
    FILE *u8_fd;
    size_t header_offset;
    U8Header u8_header;
    u32 node_count;
    U8Node *nodes;
    char *str_table;
} U8Context;

bool u8ContextInit(FILE *u8_fd, U8Context *ctx);

ALWAYS_INLINE void u8ContextFree(U8Context *ctx)
{
    if (!ctx) return;
    if (ctx->nodes) free(ctx->nodes);
    if (ctx->str_table) free(ctx->str_table);
    memset(ctx, 0, sizeof(U8Context));
}

ALWAYS_INLINE void u8ByteswapHeaderFields(U8Header *u8_header)
{
    if (!u8_header || IS_BIG_ENDIAN) return;
    u8_header->magic = __builtin_bswap32(u8_header->magic);
    u8_header->root_node_offset = __builtin_bswap32(u8_header->root_node_offset);
    u8_header->node_info_block_size = __builtin_bswap32(u8_header->node_info_block_size);
    u8_header->data_offset = __builtin_bswap32(u8_header->data_offset);
}

ALWAYS_INLINE void u8ByteswapNodeFields(U8Node *u8_node)
{
    if (!u8_node || IS_BIG_ENDIAN) return;
    /* Perform a bitshift to the left to make the byteswap return the desired result. */
    u8_node->properties.name_offset = __builtin_bswap32(u8_node->properties.name_offset << 8);
    u8_node->data_offset = __builtin_bswap32(u8_node->data_offset);
    u8_node->size = __builtin_bswap32(u8_node->size);
}

#endif /* __U8_H__ */
