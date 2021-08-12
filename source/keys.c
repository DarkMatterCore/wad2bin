/*
 * keys.c
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
#include "crypto.h"
#include "keys.h"

#define KEYS_MAX_NAME_SIZE  0x20
#define KEYS_MAX_SIZE       0x40

typedef struct {
    char name[KEYS_MAX_NAME_SIZE];
    u8 key[KEYS_MAX_SIZE];
    u32 key_size;
    u8 hash[SHA1_HASH_SIZE];
    bool console_specific;
    bool mandatory;
    bool retrieved;
} KeysEntryInfo;

static KeysEntryInfo g_keyData[] = {
    {
        ///< Normal common key. Found in OTP dumps @ 0x14. Used for titlekey and content file crypto.
        .name = "wii_common_key",
        .key = {0},
        .key_size = AES_BLOCK_SIZE,
        .hash = { 0xEB, 0xEA, 0xE6, 0xD2, 0x76, 0x2D, 0x4D, 0x3E, 0xA1, 0x60, 0xA6, 0xD8, 0x32, 0x7F, 0xAC, 0x9A, 0x25, 0xF8, 0x06, 0x2B },
        .console_specific = false,
        .mandatory = true,
        .retrieved = false
    },
    {
        ///< Korean common key. Found in SEEPROM dumps from Korean consoles @ 0x74. Used for titlekey and content file crypto.
        .name = "wii_korean_key",
        .key = {0},
        .key_size = AES_BLOCK_SIZE,
        .hash = { 0x5B, 0xAC, 0xDB, 0x63, 0xDD, 0x28, 0xA1, 0xCC, 0x1B, 0x50, 0x9A, 0x93, 0x71, 0x20, 0x32, 0xBE, 0xFB, 0x9E, 0xAD, 0xB5 },
        .console_specific = false,
        .mandatory = false,
        .retrieved = false
    },
    {
        ///< vWii common key. Found in Wii U's Starbuck OTP. Used for titlekey and content file crypto.
        .name = "vwii_common_key",
        .key = {0},
        .key_size = AES_BLOCK_SIZE,
        .hash = { 0x2B, 0x30, 0xB7, 0x03, 0xC6, 0x67, 0x6C, 0x81, 0x24, 0xC7, 0x34, 0x7B, 0x30, 0xC7, 0x97, 0x2F, 0xFE, 0xAE, 0x2B, 0x39 },
        .console_specific = false,
        .mandatory = false,
        .retrieved = false
    },
    {
        ///< SD key. Found in ES modules from IOS. Used to generate encrypted sections from a content.bin file.
        .name = "sd_key",
        .key = {0},
        .key_size = AES_BLOCK_SIZE,
        .hash = { 0x10, 0x37, 0xD8, 0x80, 0x10, 0x2F, 0xF0, 0x21, 0xC2, 0x2B, 0xA8, 0xF5, 0xDF, 0x53, 0xD7, 0x98, 0xCF, 0x44, 0xDD, 0x0B },
        .console_specific = false,
        .mandatory = true,
        .retrieved = false
    },
    {
        ///< SD IV. Stored in the System Menu binary. Used to generate encrypted sections from a content.bin file.
        .name = "sd_iv",
        .key = {0},
        .key_size = AES_BLOCK_SIZE,
        .hash = { 0x25, 0xAE, 0xEF, 0x2E, 0x60, 0x1E, 0xDE, 0x3E, 0x16, 0x17, 0x54, 0x3B, 0xEB, 0x2E, 0xDE, 0xB0, 0x8A, 0xF8, 0x7D, 0xA8 },
        .console_specific = false,
        .mandatory = true,
        .retrieved = false
    },
    {
        ///< MD5 Blanker. Stored in the System Menu binary. Used as a placeholder for hash fields during MD5 hash calculations of SD card data.
        .name = "md5_blanker",
        .key = {0},
        .key_size = MD5_HASH_SIZE,
        .hash = { 0x3D, 0xAB, 0xA9, 0xEF, 0x67, 0xCA, 0x94, 0xBF, 0x08, 0x28, 0xEC, 0x04, 0x39, 0x4A, 0x53, 0x13, 0x4D, 0x33, 0x1C, 0x1F },
        .console_specific = false,
        .mandatory = true,
        .retrieved = false
    },
    {
        ///< Console ID. Console specific, found in OTP dumps @ 0x24. Used as part of the backup WAD package header in content.bin files.
        .name = "console_id",
        .key = {0},
        .key_size = 4,
        .hash = {0},
        .console_specific = true,
        .mandatory = true,
        .retrieved = false
    },
    {
        ///< PRNG key. Console specific, found in OTP dumps @ 0x68. Used to encrypt content data in a content.bin file.
        .name = "prng_key",
        .key = {0},
        .key_size = AES_BLOCK_SIZE,
        .hash = {0},
        .console_specific = true,
        .mandatory = true,
        .retrieved = false
    },
    {
        ///< ECC private key. Console specific, found in OTP dumps @ 0x28. Used to generate signatures in a content.bin file.
        .name = "ecc_private_key",
        .key = {0},
        .key_size = (ECC_PRIV_KEY_SIZE - 2),
        .hash = {0},
        .console_specific = true,
        .mandatory = true,
        .retrieved = false
    }
};

static const u32 g_keyDataCount = MAX_ELEMENTS(g_keyData);

/// Device certificate. Console specific, found at /sys/device.cert in the NAND filesystem. Used as part of the content.bin certificate chain.
static CertSigEcc480PubKeyEcc480 g_deviceCert = {0};

static bool g_keyDataLoaded = false, g_deviceCertRetrieved = false;

static int keysGetKeyAndValueFromFile(FILE *f, char **key, char **value);
static char keysConvertHexCharToBinary(char c);
static bool keysReadKeysFromFile(const os_char_t *keys_file_path);

static bool keysReadDeviceCertificateFromFile(const os_char_t *device_cert_path);

bool keysLoadKeyDataAndDeviceCert(const os_char_t *keys_file_path, const os_char_t *device_cert_path)
{
    if (g_keyDataLoaded && g_deviceCertRetrieved) return true;
    
    if (!keys_file_path || !os_strlen(keys_file_path) || !device_cert_path || !os_strlen(device_cert_path))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    /* Load keys from keys file. */
    if (!g_keyDataLoaded)
    {
        if (!keysReadKeysFromFile(keys_file_path)) return false;
        g_keyDataLoaded = true;
    }
    
    /* Load device certificate data from file. */
    if (!g_deviceCertRetrieved)
    {
        if (!keysReadDeviceCertificateFromFile(device_cert_path)) return false;
        g_deviceCertRetrieved = true;
    }
    
    return true;
}

u8 *keysGetWiiCommonKey(void)
{
    return (g_keyData[0].retrieved ? g_keyData[0].key : NULL);
}

u8 *keysGetWiiKoreanKey(void)
{
    return (g_keyData[1].retrieved ? g_keyData[1].key : NULL);
}

u8 *keysGetVirtualWiiCommonKey(void)
{
    return (g_keyData[2].retrieved ? g_keyData[2].key : NULL);
}

u8 *keysGetSdKey(void)
{
    return (g_keyData[3].retrieved ? g_keyData[3].key : NULL);
}

u8 *keysGetSdIv(void)
{
    return (g_keyData[4].retrieved ? g_keyData[4].key : NULL);
}

u8 *keysGetMd5Blanker(void)
{
    return (g_keyData[5].retrieved ? g_keyData[5].key : NULL);
}

u32 keysGetConsoleId(void)
{
    if (!g_keyData[6].retrieved) return 0;
    
    /* Byteswap console ID. */
    u32 console_id = 0;
    memcpy(&console_id, g_keyData[6].key, sizeof(u32));
    console_id = bswap_32(console_id);
    
    return console_id;
}

u8 *keysGetPrngKey(void)
{
    return (g_keyData[7].retrieved ? g_keyData[7].key : NULL);
}

u8 *keysGetEccPrivateKey(void)
{
    return (g_keyData[8].retrieved ? g_keyData[8].key : NULL);
}

CertSigEcc480PubKeyEcc480 *keysGetDeviceCertificate(void)
{
    return (g_deviceCertRetrieved ? &g_deviceCert : NULL);
}

bool keysParseHexKey(u8 *out, const char *key, const char *value, u32 size, bool verbose)
{
    u32 hex_str_len = (2 * size);
    u64 value_len = 0;
    
    if (!out || (verbose && (!key || !strlen(key))) || !value || !(value_len = strlen(value)) || !size)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    if (value_len != hex_str_len)
    {
        if (verbose) ERROR_MSG("Key \"%s\" must be %u hex digits long!", key, hex_str_len);
        return false;
    }
    
    memset(out, 0, size);
    
    for(u32 i = 0; i < hex_str_len; i++)
    {
        char val = keysConvertHexCharToBinary(value[i]);
        if (val == 'z')
        {
            if (verbose) ERROR_MSG("Invalid hex character in key \"%s\" at position %u!", key, i);
            return false;
        }
        
        if ((i & 1) == 0) val <<= 4;
        out[i >> 1] |= val;
    }
    
    return true;
}

/**
 * Reads a line from file f and parses out the key and value from it.
 * The format of a line must match /^ *[A-Za-z0-9_] *[,=] *.+$/.
 * If a line ends in \r, the final \r is stripped.
 * The input file is assumed to have been opened with the 'b' flag.
 * The input file is assumed to contain only ASCII.
 *
 * A line cannot exceed 512 bytes in length.
 * Lines that are excessively long will be silently truncated.
 *
 * On success, *key and *value will be set to point to the key and value in
 * the input line, respectively.
 * *key and *value may also be NULL in case of empty lines.
 * On failure, *key and *value will be set to NULL.
 * End of file is considered failure.
 *
 * Because *key and *value will point to a static buffer, their contents must be
 * copied before calling this function again.
 * For the same reason, this function is not thread-safe.
 *
 * The key will be converted to lowercase.
 * An empty key is considered a parse error, but an empty value is returned as
 * success.
 *
 * This function assumes that the file can be trusted not to contain any NUL in
 * the contents.
 *
 * Whitespace (' ', ASCII 0x20, as well as '\t', ASCII 0x09) at the beginning of
 * the line, at the end of the line as well as around = (or ,) will be ignored.
 *
 * @param f the file to read
 * @param key pointer to change to point to the key
 * @param value pointer to change to point to the value
 * @return 0 on success,
 *         1 on end of file,
 *         -1 on parse error (line too long, line malformed)
 *         -2 on I/O error
 */
static int keysGetKeyAndValueFromFile(FILE *f, char **key, char **value)
{
    if (!f || !key || !value)
    {
        ERROR_MSG("Invalid parameters!");
        return -2;
    }
    
#define SKIP_SPACE(p) do {\
    for (; (*p == ' ' || *p == '\t'); ++p);\
} while(0);
    
    static char line[512] = {0};
    char *k, *v, *p, *end;
    
    *key = *value = NULL;
    
    errno = 0;
    
    if (fgets(line, (int)sizeof(line), f) == NULL)
    {
        if (feof(f))
        {
            return 1;
        } else {
            return -2;
        }
    }
    
    if (errno != 0) return -2;
    
    if (*line == '\n' || *line == '\r' || *line == '\0') return 0;
    
    /* Not finding \r or \n is not a problem.
     * The line might just be exactly 512 characters long, we have no way to
     * tell.
     * Additionally, it's possible that the last line of a file is not actually
     * a line (i.e., does not end in '\n'); we do want to handle those.
     */
    if ((p = strchr(line, '\r')) != NULL || (p = strchr(line, '\n')) != NULL)
    {
        end = p;
        *p = '\0';
    } else {
        end = (line + strlen(line) + 1);
    }
    
    p = line;
    SKIP_SPACE(p);
    k = p;
    
    /* Validate key and convert to lower case. */
    for (; *p != ' ' && *p != ',' && *p != '\t' && *p != '='; ++p)
    {
        if (*p == '\0') return -1;
        
        if (*p >= 'A' && *p <= 'Z')
        {
            *p = 'a' + (*p - 'A');
            continue;
        }
        
        if (*p != '_' && (*p < '0' && *p > '9') && (*p < 'a' && *p > 'z')) return -1;
    }
    
    /* Bail if the final ++p put us at the end of string */
    if (*p == '\0') return -1;
    
    /* We should be at the end of key now and either whitespace or [,=]
     * follows.
     */
    if (*p == '=' || *p == ',')
    {
        *p++ = '\0';
    } else {
        *p++ = '\0';
        SKIP_SPACE(p);
        if (*p != '=' && *p != ',') return -1;
        *p++ = '\0';
    }
    
    /* Empty key is an error. */
    if (*k == '\0') return -1;
    
    SKIP_SPACE(p);
    v = p;
    
    /* Skip trailing whitespace */
    for (p = end - 1; *p == '\t' || *p == ' '; --p);
    
    *(p + 1) = '\0';
    
    *key = k;
    *value = v;
    
    return 0;
    
#undef SKIP_SPACE
}

static char keysConvertHexCharToBinary(char c)
{
    if ('a' <= c && c <= 'f') return (c - 'a' + 0xA);
    if ('A' <= c && c <= 'F') return (c - 'A' + 0xA);
    if ('0' <= c && c <= '9') return (c - '0');
    return 'z';
}

static bool keysReadKeysFromFile(const os_char_t *keys_file_path)
{
    if (!keys_file_path || !os_strlen(keys_file_path))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    int ret = 0;
    FILE *keys_file = NULL;
    char *key = NULL, *value = NULL;
    bool parse_fail = false;
    u8 hash[SHA1_HASH_SIZE] = {0};
    
    keys_file = os_fopen(keys_file_path, OS_MODE_READ);
    if (!keys_file)
    {
        ERROR_MSG("Unable to open \"" OS_PRINT_STR "\" to retrieve keys! (%d).", keys_file_path, errno);
        return false;
    }
    
    while(true)
    {
        ret = keysGetKeyAndValueFromFile(keys_file, &key, &value);
        if (ret == 1 || ret == -2) break; /* Break from the while loop if EOF is reached or if an I/O error occurs. */
        
        /* Ignore malformed lines. */
        if (ret != 0 || !key || !value) continue;
        
        for(u32 i = 0; i < g_keyDataCount; i++)
        {
            /* Skip current key if we have already retrieved it or if its name doesn't match the current key entry. */
            if (g_keyData[i].retrieved || strlen(key) != strlen(g_keyData[i].name) || strcmp(key, g_keyData[i].name) != 0) continue;
            
            /* Parse current key. */
            if ((parse_fail = !keysParseHexKey(g_keyData[i].key, key, value, g_keyData[i].key_size, true)))
            {
                /* Reset flag if we're not dealing with a mandatory key. */
                if (!g_keyData[i].mandatory) parse_fail = false;
                break;
            }
            
            /* Perform a hash check if the current key isn't console-specific. */
            if (!g_keyData[i].console_specific)
            {
                mbedtls_sha1(g_keyData[i].key, g_keyData[i].key_size, hash);
                if (memcmp(hash, g_keyData[i].hash, SHA1_HASH_SIZE) != 0)
                {
                    memset(g_keyData[i].key, 0, g_keyData[i].key_size);
                    ERROR_MSG("Hash check for key \"%s\" failed!", g_keyData[i].name);
                    if (g_keyData[i].mandatory) break;
                }
            }
            
            /* Set key retrieved status. */
            g_keyData[i].retrieved = true;
        }
        
        if (parse_fail) break;
    }
    
    fclose(keys_file);
    
    if (parse_fail) return false;
    
    /* Check if we retrieved all mandatory keys. */
    for(u32 i = 0; i < g_keyDataCount; i++)
    {
        if (g_keyData[i].mandatory && !g_keyData[i].retrieved)
        {
            ERROR_MSG("Missing mandatory key \"%s\"!", g_keyData[i].name);
            return false;
        }
    }
    
    return true;
}

static bool keysReadDeviceCertificateFromFile(const os_char_t *device_cert_path)
{
    if (!device_cert_path || !os_strlen(device_cert_path))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u32 sig_type = 0, pub_key_type = 0;
    u32 console_id = keysGetConsoleId();
    char cert_name[0x10] = {0};
    const char ms_issuer_retail[] = "Root-CA00000001-MS00000002";
    const char ms_issuer_debug[] = "Root-CA00000002-MS00000003";
    
    /* Read device certificate file. */
    if (!utilsReadDataFromFile(device_cert_path, &g_deviceCert, sizeof(CertSigEcc480PubKeyEcc480)))
    {
        ERROR_MSG("Failed to read device certificate file!");
        return false;
    }
    
    /* Verify device certificate signature and public key types. */
    sig_type = bswap_32(g_deviceCert.sig_block.sig_type);
    pub_key_type = bswap_32(g_deviceCert.cert_common_block.pub_key_type);
    if (sig_type != SignatureType_Ecc480Sha1 || pub_key_type != CertPubKeyType_Ecc480)
    {
        ERROR_MSG("Invalid device certificate signature/public key type!");
        return false;
    }
    
    /* Verify device certificate signature issuer. */
    if (strlen(g_deviceCert.cert_common_block.issuer) != strlen(ms_issuer_retail) || (strcmp(g_deviceCert.cert_common_block.issuer, ms_issuer_retail) != 0 && \
        strcmp(g_deviceCert.cert_common_block.issuer, ms_issuer_debug) != 0))
    {
        ERROR_MSG("Invalid device certificate signature issuer!");
        return false;
    }
    
    /* Verify device certificate name. */
    sprintf(cert_name, "NG%08" PRIx32, console_id);
    if (strlen(g_deviceCert.cert_common_block.name) != strlen(cert_name) || strcmp(g_deviceCert.cert_common_block.name, cert_name) != 0)
    {
        ERROR_MSG("Device certificate name mismatch! Expected \"%s\", got \"%s\".", cert_name, g_deviceCert.cert_common_block.name);
        return false;
    }
    
    return true;
}
