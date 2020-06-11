/*
 * keys.h
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

#ifndef __KEYS_H__
#define __KEYS_H__

#include "cert.h"

/// Loads keydata and device certificate data.
bool keysLoadKeyDataAndDeviceCert(const os_char_t *keys_file_path, const os_char_t *device_cert_path);

/// Functions to retrieve loaded data.
/// These return NULL if their respective data hasn't been loaded.
u8 *keysGetWiiCommonKey(void);
u8 *keysGetWiiKoreanKey(void);
u8 *keysGetVirtualWiiCommonKey(void);
u8 *keysGetSdKey(void);
u8 *keysGetSdIv(void);
u32 keysGetConsoleId(void);
u8 *keysGetPrngKey(void);
u8 *keysGetEccPrivateKey(void);
CertSigEcc480PubKeyEcc480 *keysGetDeviceCertificate(void);

#endif /* __KEYS_H__ */
