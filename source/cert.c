/*
 * cert.c
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
#include "cert.h"

#define CERT_TYPE(sig)  (pub_key_type == CertPubKeyType_Rsa4096 ? CertType_Sig##sig##_PubKeyRsa4096 : \
                        (pub_key_type == CertPubKeyType_Rsa2048 ? CertType_Sig##sig##_PubKeyRsa2048 : CertType_Sig##sig##_PubKeyEcc480))

static bool certGetCertificateTypeAndSize(const void *buf, u64 buf_size, u8 *out_type, u64 *out_size, bool verbose);

u8 *certReadRawCertificateChainFromFile(FILE *fd, u64 cert_chain_size)
{
    if (!fd || cert_chain_size < CERT_MIN_SIZE)
    {
        ERROR_MSG("Invalid parameters!");
        return NULL;
    }
    
    u8 *raw_chain = NULL;
    u64 res = 0, offset = 0;
    u32 cert_num = 0;
    
    bool success = false;
    
    /* Allocate memory for the raw certificate chain. */
    raw_chain = calloc(ALIGN_UP(cert_chain_size, WAD_BLOCK_SIZE), sizeof(u8));
    if (!raw_chain)
    {
        ERROR_MSG("Unable to allocate 0x%" PRIx64 " bytes raw certificate chain buffer!", cert_chain_size);
        return NULL;
    }
    
    /* Read raw certificate chain. */
    res = fread(raw_chain, 1, cert_chain_size, fd);
    if (res != cert_chain_size)
    {
        ERROR_MSG("Failed to read 0x%" PRIx64 " bytes long raw certificate chain!", cert_chain_size);
        goto out;
    }
    
    /* Check each certificate in the chain. */
    while(offset < cert_chain_size)
    {
        if ((cert_chain_size - offset) < CERT_MIN_SIZE) break;
        
        u8 cert_type = 0;
        u64 cert_size = 0;
        
        printf("Certificate #%u:\n", cert_num + 1);
        
        if (!certGetCertificateTypeAndSize(raw_chain + offset, cert_chain_size, &cert_type, &cert_size, true))
        {
            ERROR_MSG("Invalid certificate detected in chain!");
            goto out;
        }
        
        printf("\n");
        
        offset += cert_size;
        cert_num++;
    }
    
    if (offset != cert_chain_size)
    {
        ERROR_MSG("\nCalculated certificate chain size doesn't match input size! (0x%" PRIx64 " != 0x%" PRIx64 ").", offset, cert_chain_size);
        goto out;
    }
    
    success = true;
    
out:
    if (!success && raw_chain)
    {
        free(raw_chain);
        raw_chain = NULL;
    }
    
    return raw_chain;
}

CertCommonBlock *certGetCertificateCommonBlockFromBuffer(void *buf, u64 buf_size)
{
    if (!buf || buf_size < CERT_MIN_SIZE)
    {
        ERROR_MSG("Invalid parameters!");
        return NULL;
    }
    
    u8 cert_type = 0;
    CertCommonBlock *cert_common_block = NULL;
    
    if (!certGetCertificateTypeAndSize(buf, buf_size, &cert_type, NULL, false))
    {
        ERROR_MSG("Invalid certificate!");
        return NULL;
    }
    
    switch(cert_type)
    {
        case CertType_SigRsa4096_PubKeyRsa4096:
            cert_common_block = &(((CertSigRsa4096PubKeyRsa4096*)buf)->cert_common_block);
            break;
        case CertType_SigRsa4096_PubKeyRsa2048:
            cert_common_block = &(((CertSigRsa4096PubKeyRsa2048*)buf)->cert_common_block);
            break;
        case CertType_SigRsa4096_PubKeyEcc480:
            cert_common_block = &(((CertSigRsa4096PubKeyEcc480*)buf)->cert_common_block);
            break;
        case CertType_SigRsa2048_PubKeyRsa4096:
            cert_common_block = &(((CertSigRsa2048PubKeyRsa4096*)buf)->cert_common_block);
            break;
        case CertType_SigRsa2048_PubKeyRsa2048:
            cert_common_block = &(((CertSigRsa2048PubKeyRsa2048*)buf)->cert_common_block);
            break;
        case CertType_SigRsa2048_PubKeyEcc480:
            cert_common_block = &(((CertSigRsa2048PubKeyEcc480*)buf)->cert_common_block);
            break;
        case CertType_SigEcc480_PubKeyRsa4096:
            cert_common_block = &(((CertSigEcc480PubKeyRsa4096*)buf)->cert_common_block);
            break;
        case CertType_SigEcc480_PubKeyRsa2048:
            cert_common_block = &(((CertSigEcc480PubKeyRsa2048*)buf)->cert_common_block);
            break;
        case CertType_SigEcc480_PubKeyEcc480:
            cert_common_block = &(((CertSigEcc480PubKeyEcc480*)buf)->cert_common_block);
            break;
        case CertType_SigHmac160_PubKeyRsa4096:
            cert_common_block = &(((CertSigHmac160PubKeyRsa4096*)buf)->cert_common_block);
            break;
        case CertType_SigHmac160_PubKeyRsa2048:
            cert_common_block = &(((CertSigHmac160PubKeyRsa2048*)buf)->cert_common_block);
            break;
        case CertType_SigHmac160_PubKeyEcc480:
            cert_common_block = &(((CertSigHmac160PubKeyEcc480*)buf)->cert_common_block);
            break;
        default:
            break;
    }
    
    return cert_common_block;
}

static bool certGetCertificateTypeAndSize(const void *buf, u64 buf_size, u8 *out_type, u64 *out_size, bool verbose)
{
    if (!buf || buf_size < CERT_MIN_SIZE || (!out_type && !out_size))
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u64 offset = 0;
    u8 type = CertType_None;
    const u8 *buf_u8 = (const u8*)buf;
    u32 sig_type = 0, pub_key_type = 0, date = 0;
    
    memcpy(&sig_type, buf_u8, sizeof(u32));
    sig_type = bswap_32(sig_type);
    
    switch(sig_type)
    {
        case SignatureType_Rsa4096Sha1:
        case SignatureType_Rsa4096Sha256:
            offset += sizeof(SignatureBlockRsa4096);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (RSA-4096 + %s).\n", sig_type, (sig_type == SignatureType_Rsa4096Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Rsa2048Sha1:
        case SignatureType_Rsa2048Sha256:
            offset += sizeof(SignatureBlockRsa2048);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (RSA-2048 + %s).\n", sig_type, (sig_type == SignatureType_Rsa2048Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Ecc480Sha1:
        case SignatureType_Ecc480Sha256:
            offset += sizeof(SignatureBlockEcc480);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (ECSDA + %s).\n", sig_type, (sig_type == SignatureType_Ecc480Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Hmac160Sha1:
            offset += sizeof(SignatureBlockHmac160);
            if (verbose) printf("  Signature type:         0x%08" PRIx32 " (HMAC + SHA-1).\n", sig_type);
            break;
        default:
            ERROR_MSG("Invalid signature type value! (0x%08" PRIx32 ").", sig_type);
            return false;
    }
    
    if (verbose) printf("  Signature issuer:       %.*s.\n", (int)MEMBER_SIZE(SignatureBlockRsa4096, issuer), (const char*)(buf_u8 + (offset - MEMBER_SIZE(SignatureBlockRsa4096, issuer))));
    
    memcpy(&pub_key_type, buf_u8 + offset, sizeof(u32));
    pub_key_type = bswap_32(pub_key_type);
    offset += MEMBER_SIZE(CertCommonBlock, pub_key_type);
    
    if (verbose) printf("  Name:                   %.*s.\n", (int)MEMBER_SIZE(CertCommonBlock, name), (const char*)(buf_u8 + offset));
    offset += MEMBER_SIZE(CertCommonBlock, name);
    
    if (verbose)
    {
        memcpy(&date, buf_u8 + offset, sizeof(u32));
        date = bswap_32(date);
        printf("  Date:                   0x%08" PRIx32 ".\n", date);
    }
    
    offset += MEMBER_SIZE(CertCommonBlock, date);
    
    switch(pub_key_type)
    {
        case CertPubKeyType_Rsa4096:
            offset += sizeof(CertPublicKeyBlockRsa4096);
            if (verbose) printf("  Public key type:        0x%08" PRIx32 " (RSA-4096).\n", pub_key_type);
            break;
        case CertPubKeyType_Rsa2048:
            offset += sizeof(CertPublicKeyBlockRsa2048);
            if (verbose) printf("  Public key type:        0x%08" PRIx32 " (RSA-2048).\n", pub_key_type);
            break;
        case CertPubKeyType_Ecc480:
            offset += sizeof(CertPublicKeyBlockEcc480);
            if (verbose) printf("  Public key type:        0x%08" PRIx32 " (ECC-B233).\n", pub_key_type);
            break;
        default:
            ERROR_MSG("\nInvalid public key type value! (0x%08" PRIx32 ").", pub_key_type);
            return false;
    }
    
    if (offset > buf_size)
    {
        ERROR_MSG("\nCalculated end offset exceeds certificate buffer size! (0x%" PRIx64 " > 0x%" PRIx64 ").", offset, buf_size);
        return false;
    }
    
    if (sig_type == SignatureType_Rsa4096Sha1 || sig_type == SignatureType_Rsa4096Sha256)
    {
        type = CERT_TYPE(Rsa4096);
    } else
    if (sig_type == SignatureType_Rsa2048Sha1 || sig_type == SignatureType_Rsa2048Sha256)
    {
        type = CERT_TYPE(Rsa2048);
    } else
    if (sig_type == SignatureType_Ecc480Sha1 || sig_type == SignatureType_Ecc480Sha256)
    {
        type = CERT_TYPE(Ecc480);
    } else
    if (sig_type == SignatureType_Hmac160Sha1)
    {
        type = CERT_TYPE(Hmac160);
    }
    
    if (out_type) *out_type = type;
    if (out_size) *out_size = offset;
    
    return true;
}
