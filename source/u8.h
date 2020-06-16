/*
 * u8.h
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
    u64 header_offset;
    U8Header u8_header;
    u32 node_count;
    U8Node *nodes;
    char *str_table;
} U8Context;

/// Initializes an U8 context.
bool u8ContextInit(FILE *u8_fd, U8Context *ctx);

/// Frees an U8 context.
void u8ContextFree(U8Context *ctx);

/// Retrieves an U8 directory node by its path.
/// Its index is saved to the out_node_idx pointer.
U8Node *u8GetDirectoryNodeByPath(U8Context *ctx, const char *path, u32 *out_node_idx);

/// Retrieves an U8 file node by its path.
/// Its index is saved to the out_node_idx pointer.
U8Node *u8GetFileNodeByPath(U8Context *ctx, const char *path, u32 *out_node_idx);

/// Loads file data from an U8 file node into memory.
/// The returned pointer must be freed by the user.
u8 *u8LoadFileData(U8Context *ctx, U8Node *file_node, u64 *out_size);

/// Simple all-in-one function to load file data from an U8 archive by its internal path.
u8 *u8LoadFileDataFromU8ArchiveByPath(FILE *u8_fd, const char *file_path, u64 *out_size);

/// Byteswaps fields from an U8 header.
ALWAYS_INLINE void u8ByteswapHeaderFields(U8Header *u8_header)
{
    if (!u8_header || IS_BIG_ENDIAN) return;
    u8_header->magic = __builtin_bswap32(u8_header->magic);
    u8_header->root_node_offset = __builtin_bswap32(u8_header->root_node_offset);
    u8_header->node_info_block_size = __builtin_bswap32(u8_header->node_info_block_size);
    u8_header->data_offset = __builtin_bswap32(u8_header->data_offset);
}

/// Byteswaps fields from an U8 node.
ALWAYS_INLINE void u8ByteswapNodeFields(U8Node *u8_node)
{
    if (!u8_node || IS_BIG_ENDIAN) return;
    /* Perform a bitwise left shift to make the byteswap return the desired result. */
    u8_node->properties.name_offset = __builtin_bswap32(u8_node->properties.name_offset << 8);
    u8_node->data_offset = __builtin_bswap32(u8_node->data_offset);
    u8_node->size = __builtin_bswap32(u8_node->size);
}

/// Retrieves an U8 node by its offset.
ALWAYS_INLINE U8Node *u8GetNodeByOffset(U8Context *ctx, u32 offset)
{
    u32 node_idx = 0;
    if (!ctx || !ctx->nodes || !IS_ALIGNED(offset, sizeof(U8Node)) || (node_idx = (u32)(offset / sizeof(U8Node))) >= ctx->node_count) return NULL;
    return &(ctx->nodes[node_idx]);
}

#endif /* __U8_H__ */
