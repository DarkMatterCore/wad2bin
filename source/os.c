/*
 * os.c
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

#include "os.h"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)

int os_snprintf(os_char_t *out, size_t len, const char *fmt, ...)
{
    if (!out || !len || !fmt) return -1;
    
    va_list args;
    char tmp[MAX_PATH] = {0};
    
    va_start(args, fmt);
    vsnprintf(tmp, MAX_PATH, fmt, args);
    va_end(args);
    
    return snwprintf(out, len, L"%hs", tmp);
}

#endif /* WIN32 || _WIN32 || __WIN32__ || __NT__ */
