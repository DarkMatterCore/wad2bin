/*
 * u8.c
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
#include "u8.h"

#define U8_FILE_ALIGNMENT   0x20

bool u8ContextInit(FILE *u8_fd, U8Context *ctx)
{
    if (!u8_fd || !ctx)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    U8Header u8_header = {0};
    U8Node root_node = {0}, *nodes = NULL;
    u32 node_count = 0, node_section_size = 0, str_table_size = 0, cur_file_offset = 0;
    char *str_table = NULL;
    size_t header_offset = 0, res = 0;
    bool success = false;
    
    /* Save current offset. */
    header_offset = os_ftell(u8_fd);
    
    /* Read U8 header. */
    res = fread(&u8_header, 1, sizeof(U8Header), u8_fd);
    if (res != sizeof(U8Header))
    {
        ERROR_MSG("Failed to read U8 header!");
        return false;
    }
    
    /* Byteswap U8 header fields. */
    u8ByteswapHeaderFields(&u8_header);
    
    /* Check header fields. */
    if (u8_header.magic != U8_MAGIC || u8_header.root_node_offset <= (u32)sizeof(U8Header) || u8_header.node_info_block_size <= (u32)sizeof(U8Node) || \
        u8_header.data_offset != ALIGN_UP(u8_header.root_node_offset + u8_header.node_info_block_size, 0x40))
    {
        ERROR_MSG("Invalid U8 header!");
        return false;
    }
    
    /* Update file stream position. */
    os_fseek(u8_fd, header_offset + u8_header.root_node_offset, SEEK_SET);
    
    /* Read root U8 node. */
    res = fread(&root_node, 1, sizeof(U8Node), u8_fd);
    if (res != sizeof(U8Node))
    {
        ERROR_MSG("Failed to read root U8 node!");
        return false;
    }
    
    /* Byteswap root U8 node fields. */
    u8ByteswapNodeFields(&root_node);
    
    /* Check root U8 node. */
    if (root_node.properties.type != U8NodeType_Directory || root_node.properties.name_offset != 0 || root_node.data_offset != 0 || root_node.size <= 1)
    {
        ERROR_MSG("Invalid root U8 node!");
        return false;
    }
    
    /* Calculate node section size. */
    node_count = root_node.size;
    node_section_size = (u32)(sizeof(U8Node) * node_count);
    if (node_section_size >= u8_header.node_info_block_size)
    {
        ERROR_MSG("Node section size exceeds node info block size in U8 header!");
        return false;
    }
    
    /* Calculate U8 string table size. */
    str_table_size = (u8_header.node_info_block_size - node_section_size);
    if ((node_section_size + str_table_size) != u8_header.node_info_block_size)
    {
        ERROR_MSG("Node info block size in U8 header doesn't match calculated node section and string table sizes!");
        return false;
    }
    
    /* Allocate memory for the U8 nodes. */
    nodes = calloc(node_count, sizeof(U8Node));
    if (!nodes)
    {
        ERROR_MSG("Error allocating memory for U8 nodes!");
        return false;
    }
    
    /* Read all U8 nodes. */
    memcpy(nodes, &root_node, sizeof(U8Node));
    res = fread(nodes + 1, 1, sizeof(U8Node) * (node_count - 1), u8_fd);
    if (res != (sizeof(U8Node) * (node_count - 1)))
    {
        ERROR_MSG("Failed to read U8 nodes!");
        goto out;
    }
    
    /* Allocate memory for the U8 string table. */
    str_table = calloc(str_table_size, sizeof(char));
    if (!str_table)
    {
        ERROR_MSG("Error allocating memory for U8 string table!");
        goto out;
    }
    
    /* Read U8 string table. */
    res = fread(str_table, 1, str_table_size, u8_fd);
    if (res != str_table_size)
    {
        ERROR_MSG("Failed to read U8 string table!");
        goto out;
    }
    
    /* Check all U8 nodes. */
    cur_file_offset = u8_header.data_offset;
    for(u32 i = 1; i < node_count; i++)
    {
        /* Byteswap current U8 node. */
        u8ByteswapNodeFields(&(nodes[i]));
        
        u32 node_number = (i + 1);
        
        /* Check node type. */
        if (nodes[i].properties.type != U8NodeType_File && nodes[i].properties.type != U8NodeType_Directory)
        {
            ERROR_MSG("Invalid entry type for U8 node #%u! (0x%x).", node_number, nodes[i].properties.type);
            goto out;
        }
        
        /* Check name offset. */
        if (nodes[i].properties.name_offset >= str_table_size)
        {
            ERROR_MSG("Name offset for U8 node #%u exceeds string table size!", node_number);
            goto out;
        }
        
        /* Check name. */
        if (!strlen(str_table + nodes[i].properties.name_offset))
        {
            ERROR_MSG("Empty name for U8 node #%u!", node_number);
            goto out;
        }
        
        /* Check data offset. */
        /* Files: check if the data offset matches the current value for the calculated file offset. */
        /* Directories: check if the data offset isn't aligned to the U8 node size, if it exceeds the node section size or if the node it points to isn't a directory node. */
        if ((nodes[i].properties.type == U8NodeType_File && nodes[i].data_offset != cur_file_offset) || \
            (nodes[i].properties.type == U8NodeType_Directory && (!IS_ALIGNED(nodes[i].data_offset, sizeof(U8Node)) || nodes[i].data_offset >= node_section_size || \
            nodes[nodes[i].data_offset / sizeof(U8Node)].properties.type != U8NodeType_Directory)))
        {
            ERROR_MSG("Invalid data offset for U8 node #%u! (0x%x).", node_number);
            goto out;
        }
        
        if (nodes[i].properties.type == U8NodeType_File)
        {
            /* Update file offset calculation. */
            if (nodes[i].size > 0) cur_file_offset += ALIGN_UP(nodes[i].size, U8_FILE_ALIGNMENT);
        } else {
            /* Check if the size value points to a node number *lower* than this directory's node number, or if it exceeds the total node count. */
            /* We could be dealing with an empty directory, so don't check if the size value is equal to this directory's node number. */
            if (nodes[i].size < node_number || nodes[i].size > node_count)
            {
                ERROR_MSG("Invalid end node number value for U8 node #%u! (0x%x).", node_number);
                goto out;
            }
        }
    }
    
    /* Update output context. */
    ctx->u8_fd = u8_fd;
    ctx->header_offset = header_offset;
    memcpy(&(ctx->u8_header), &u8_header, sizeof(U8Header));
    ctx->node_count = node_count;
    ctx->nodes = nodes;
    ctx->str_table = str_table;
    
    success = true;
    
out:
    if (!success)
    {
        if (str_table) free(str_table);
        if (nodes) free(nodes);
    }
    
    return success;
}





u8 *u8LoadFileDataFromU8ArchiveByPath(U8Context *ctx, const char *file_path, size_t *out_size)
{
    if (!ctx || !file_path || !strlen(file_path) || !out_size)
    {
        ERROR_MSG("Invalid parameters!");
        return NULL;
    }
    
    
    
    
    return NULL;
    
    
}
