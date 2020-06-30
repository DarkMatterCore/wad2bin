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
#include "crypto.h"

#define CERT_TYPE(sig)  (pub_key_type == CertPubKeyType_Rsa4096 ? CertType_Sig##sig##_PubKeyRsa4096 : \
                        (pub_key_type == CertPubKeyType_Rsa2048 ? CertType_Sig##sig##_PubKeyRsa2048 : CertType_Sig##sig##_PubKeyEcc480))

static bool certGetCertificateTypeAndSize(void *buf, u64 buf_size, u8 *out_type, u64 *out_size);

bool certReadCertificateChainFromFile(FILE *fd, u64 cert_chain_size, CertificateChain *out_chain, u8 **out_raw_chain)
{
    if (!fd || cert_chain_size < SIGNED_CERT_MIN_SIZE || !out_chain)
    {
        ERROR_MSG("Invalid parameters!");
        return false;
    }
    
    u8 *raw_chain = NULL;
    u64 res = 0, offset = 0;
    Certificate *tmp_certs = NULL;
    
    bool success = false;
    
    /* Cleanup output certificate chain. */
    memset(out_chain, 0, sizeof(CertificateChain));
    
    /* Allocate memory for the raw certificate chain. */
    raw_chain = calloc(ALIGN_UP(cert_chain_size, WAD_BLOCK_SIZE), sizeof(u8));
    if (!raw_chain)
    {
        ERROR_MSG("Unable to allocate 0x%" PRIx64 " bytes raw certificate chain buffer!", cert_chain_size);
        return false;
    }
    
    /* Read raw certificate chain. */
    res = fread(raw_chain, 1, cert_chain_size, fd);
    if (res != cert_chain_size)
    {
        ERROR_MSG("Failed to read 0x%" PRIx64 " bytes long raw certificate chain!", cert_chain_size);
        goto out;
    }
    
    /* Check each certificate in the chain. */
    while(offset < cert_chain_size && (cert_chain_size - offset) >= SIGNED_CERT_MIN_SIZE)
    {
        /* Reallocate certificate buffer. */
        tmp_certs = (Certificate*)realloc(out_chain->certs, (out_chain->count + 1) * sizeof(Certificate));
        if (!tmp_certs)
        {
            ERROR_MSG("Failed to reallocate certificate chain struct buffer!");
            goto out;
        }
        
        out_chain->certs = tmp_certs;
        tmp_certs = NULL;
        
        memset(&(out_chain->certs[out_chain->count]), 0, sizeof(Certificate));
        
        /* Get certificate type and size. */
        printf("Certificate #%u:\n", out_chain->count + 1);
        
        if (!certGetCertificateTypeAndSize(raw_chain + offset, cert_chain_size, &(out_chain->certs[out_chain->count].type), &(out_chain->certs[out_chain->count].size)))
        {
            ERROR_MSG("Invalid certificate detected in chain!");
            goto out;
        }
        
        printf("\n");
        
        /* Update new certificate entry. */
        memcpy(out_chain->certs[out_chain->count].data, raw_chain + offset, out_chain->certs[out_chain->count].size);
        offset += out_chain->certs[out_chain->count].size;
        out_chain->count++;
    }
    
    if (offset != cert_chain_size)
    {
        ERROR_MSG("Calculated certificate chain size doesn't match input size! (0x%" PRIx64 " != 0x%" PRIx64 ").", offset, cert_chain_size);
        goto out;
    }
    
    if (out_chain->count < 3)
    {
        ERROR_MSG("Certificate chain holds less than 3 certificates!");
        goto out;
    }
    
    /* Verify certificate signatures. */
    for(u32 i = 0; i < out_chain->count; i++)
    {
        Certificate *cert = &(out_chain->certs[i]);
        
        u32 sig_type = 0;
        u8 *signature = NULL;
        
        CertCommonBlock *cert_common_block = NULL;
        u64 cert_hash_area_size = 0, cert_hash_size = 0;
        u8 cert_hash[SHA256_HASH_SIZE] = {0};
        
        u32 parent_pub_key_type = 0, parent_public_exponent = 0;
        char *parent_cert_name = NULL;
        u8 *parent_pub_key = NULL;
        u64 parent_cert_name_len = 0, parent_pub_key_size = 0;
        bool valid_sig = false;
        
        /* Retrieve signature type, signature, certificate common block and certificate hash area size. */
        sig_type = signatureGetSigType(cert->data);
        signature = signatureGetSig(cert->data);
        cert_common_block = certGetCommonBlock(cert->data);
        cert_hash_area_size = certGetSignedCertificateHashAreaSize(cert->data);
        
        /* Skip signature verification if we're dealing with a HMAC signature or a certificate issued by Root. */
        if (sig_type == SignatureType_Hmac160Sha1 || (strlen(cert_common_block->issuer) == 4 && !strcmp(cert_common_block->issuer, "Root"))) continue;
        
        /* Calculate certificate hash. */
        switch(sig_type)
        {
            case SignatureType_Rsa4096Sha1:
            case SignatureType_Rsa2048Sha1:
            case SignatureType_Ecc480Sha1:
                cert_hash_size = SHA1_HASH_SIZE;
                mbedtls_sha1((u8*)cert_common_block, cert_hash_area_size, cert_hash);
                break;
            case SignatureType_Rsa4096Sha256:
            case SignatureType_Rsa2048Sha256:
            case SignatureType_Ecc480Sha256:
                cert_hash_size = SHA256_HASH_SIZE;
                mbedtls_sha256((u8*)cert_common_block, cert_hash_area_size, cert_hash, 0);
                break;
            default:
                break;
        }
        
        /* Get pointer to the parent certificate name. */
        parent_cert_name = strrchr(cert_common_block->issuer, '-');
        if (!parent_cert_name || (parent_cert_name_len = strlen(parent_cert_name)) <= 1)
        {
            ERROR_MSG("Invalid signature issuer in certificate \"%s\"!", cert_common_block->name);
            goto out;
        }
        
        parent_cert_name++;
        parent_cert_name_len--;
        
        /* Look for the parent certificate. */
        for(u32 j = 0; j < out_chain->count; j++)
        {
            /* Skip current child certificate. */
            if (j == i) continue;
            
            /* Get certificate common block and check the certificate name. */
            CertCommonBlock *parent_cert_common_block = certGetCommonBlock(out_chain->certs[j].data);
            if (strlen(parent_cert_common_block->name) == parent_cert_name_len && !strcmp(parent_cert_common_block->name, parent_cert_name))
            {
                /* Check if the public key type from the parent certificate matches the signature type from the child certificate. */
                parent_pub_key_type = bswap_32(parent_cert_common_block->pub_key_type);
                if ((parent_pub_key_type == CertPubKeyType_Rsa4096 && sig_type != SignatureType_Rsa4096Sha1 && sig_type != SignatureType_Rsa4096Sha256) || \
                    (parent_pub_key_type == CertPubKeyType_Rsa2048 && sig_type != SignatureType_Rsa2048Sha1 && sig_type != SignatureType_Rsa2048Sha256) || \
                    (parent_pub_key_type == CertPubKeyType_Ecc480  && sig_type != SignatureType_Ecc480Sha1  && sig_type != SignatureType_Ecc480Sha256))
                {
                    ERROR_MSG("Found parent certificate \"%s\" for \"%s\", but public key and signature types don't match! (0x%08" PRIx32 ", 0x%08" PRIx32 ")", parent_cert_name, \
                              cert_common_block->name, parent_pub_key_type, sig_type);
                    goto out;
                }
                
                /* Update parent certificate variables. */
                parent_pub_key = certGetPublicKey(parent_cert_common_block);
                parent_public_exponent = certGetPublicExponent(parent_cert_common_block);
                parent_pub_key_size = certGetPublicKeySize(parent_pub_key_type);
                break;
            }
        }
        
        if (!parent_pub_key)
        {
            ERROR_MSG("Unable to find parent \"%s\" certificate for \"%s\"!", parent_cert_name, cert_common_block->name);
            goto out;
        }
        
        /* Verify child certificate signature. */
        switch(sig_type)
        {
            case SignatureType_Rsa4096Sha1:
            case SignatureType_Rsa4096Sha256:
            case SignatureType_Rsa2048Sha1:
            case SignatureType_Rsa2048Sha256:
                valid_sig = cryptoVerifyRsaSignature(parent_pub_key, parent_pub_key_size, parent_public_exponent, signature, cert_hash, cert_hash_size);
                break;
            case SignatureType_Ecc480Sha1:
            case SignatureType_Ecc480Sha256:
                valid_sig = cryptoVerifyEcdsaSignature(parent_pub_key, signature, false, cert_hash, cert_hash_size);
                break;
            default:
                break;
        }
        
        if (!valid_sig)
        {
            ERROR_MSG("Signature verification failed for certificate \"%s\"!", cert_common_block->name);
            goto out;
        }
    }
    
    success = true;
    
out:
    if (!success) certFreeCertificateChain(out_chain);
    
    if (raw_chain)
    {
        if (success && out_raw_chain)
        {
            *out_raw_chain = raw_chain;
        } else {
            free(raw_chain);
        }
    }
    
    return success;
}

static bool certGetCertificateTypeAndSize(void *buf, u64 buf_size, u8 *out_type, u64 *out_size)
{
    CertCommonBlock *cert_common_block = NULL;
    u32 sig_type = 0, pub_key_type = 0, date = 0;
    
    u64 signed_cert_size = 0;
    u8 type = CertType_None;
    
    if (!buf || buf_size < SIGNED_CERT_MIN_SIZE || (!out_type && !out_size))
    {
        ERROR_MSG("\nInvalid parameters!");
        return false;
    }
    
    if (!(cert_common_block = certGetCommonBlock(buf)) || !(signed_cert_size = certGetSignedCertificateSize(buf)))
    {
        ERROR_MSG("\nInput buffer doesn't hold a valid signed certificate!");
        return false;
    }
    
    if (signed_cert_size > buf_size)
    {
        ERROR_MSG("\nCalculated signed certificate size exceeds input buffer size! (0x%" PRIx64 " > 0x%" PRIx64 ").", signed_cert_size, buf_size);
        return false;
    }
    
    sig_type = signatureGetSigType(buf);
    pub_key_type = bswap_32(cert_common_block->pub_key_type);
    date = bswap_32(cert_common_block->date);
    
    printf("  Signature type:         0x%08" PRIx32, sig_type);
    switch(sig_type)
    {
        case SignatureType_Rsa4096Sha1:
        case SignatureType_Rsa4096Sha256:
            type = CERT_TYPE(Rsa4096);
            printf(" (RSA-4096 + %s)", (sig_type == SignatureType_Rsa4096Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Rsa2048Sha1:
        case SignatureType_Rsa2048Sha256:
            type = CERT_TYPE(Rsa2048);
            printf(" (RSA-2048 + %s)", (sig_type == SignatureType_Rsa2048Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Ecc480Sha1:
        case SignatureType_Ecc480Sha256:
            type = CERT_TYPE(Ecc480);
            printf(" (ECDSA + %s)", (sig_type == SignatureType_Ecc480Sha1 ? "SHA-1" : "SHA-256"));
            break;
        case SignatureType_Hmac160Sha1:
            type = CERT_TYPE(Hmac160);
            printf(" (HMAC + SHA-1)");
            break;
        default:
            break;
    }
    printf(".\n");
    
    printf("  Signature issuer:       %.*s.\n", (int)sizeof(cert_common_block->issuer), cert_common_block->issuer);
    
    printf("  Public key type:        0x%08" PRIx32, pub_key_type);
    switch(pub_key_type)
    {
        case CertPubKeyType_Rsa4096:
            printf(" (RSA-4096)");
            break;
        case CertPubKeyType_Rsa2048:
            printf(" (RSA-2048)");
            break;
        case CertPubKeyType_Ecc480:
            printf(" (ECC-B233)");
            break;
        default:
            break;
    }
    printf(".\n");
    
    printf("  Name:                   %.*s.\n", (int)sizeof(cert_common_block->name), cert_common_block->name);
    printf("  Date:                   0x%08" PRIx32 ".\n", date);
    
    if (out_type) *out_type = type;
    if (out_size) *out_size = signed_cert_size;
    
    return true;
}
