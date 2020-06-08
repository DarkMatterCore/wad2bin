/*
    example.c
    Simple example of how to use ninty-233

    Copyright © 2019 Jbop (https://github.com/jbop1626)

    This file is a part of ninty-233.

    ninty-233 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ninty-233 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdio.h>

#include "ninty-233.h"

int main(int argc, char * argv[]) {
    uint8_t private_key_A[32] = { 0x00, 0x00, 0x01, 0x5F, 0xC2, 0xC6, 0x53, 0xCD,
                                  0xBA, 0xDC, 0xD8, 0x24, 0x23, 0xFE, 0xA2, 0xE8,
                                  0xCC, 0x75, 0x7C, 0xC3, 0x5A, 0x27, 0x46, 0x73,
                                  0xF5, 0x70, 0xAE, 0x7A, 0xD2, 0xBB, 0x59, 0xB0 };
                                  
    uint8_t public_key_A[64] = {  0x00, 0x00, 0x00, 0x27, 0x64, 0xB9, 0x37, 0x21,
                                  0xDA, 0xA4, 0x33, 0xC1, 0xC4, 0x45, 0x0B, 0xFA,
                                  0x8E, 0x4D, 0x36, 0x9C, 0x41, 0x16, 0xD6, 0xED,
                                  0xBE, 0x03, 0x0D, 0x9F, 0x12, 0x3B, 0xB1, 0x18,
                                  0x00, 0x00, 0x01, 0x87, 0xBE, 0xC4, 0xF5, 0x1A,
                                  0x9F, 0x4B, 0x0B, 0x3F, 0xD3, 0x08, 0x01, 0xBC,
                                  0x6F, 0x11, 0xAC, 0x4C, 0x26, 0xDB, 0x3B, 0x6C,
                                  0x70, 0x5D, 0xC1, 0x7E, 0x9C, 0x00, 0x84, 0x27 };
    
    uint8_t private_key_B[32] = { 0x00, 0x00, 0x00, 0xE4, 0xC0, 0x89, 0x52, 0x2C,
                                  0xA3, 0x38, 0x6C, 0xC8, 0xF6, 0x29, 0x80, 0x1E,
                                  0x0F, 0xE9, 0xD0, 0x92, 0xA5, 0x61, 0x27, 0x48,
                                  0xC1, 0xE9, 0x51, 0x1D, 0x82, 0xDB, 0x93, 0xE0 };
                                  
    uint8_t public_key_B[64] = {  0x00, 0x00, 0x00, 0xDD, 0x56, 0x98, 0x2B, 0xED,
                                  0x1F, 0x91, 0x0C, 0x20, 0x2D, 0x91, 0x38, 0xE8,
                                  0x6B, 0xFC, 0x60, 0x77, 0x3F, 0x38, 0xF5, 0x4A,
                                  0x08, 0xEC, 0xB3, 0xD6, 0xEB, 0x40, 0x10, 0xD1,
                                  0x00, 0x00, 0x00, 0xBB, 0xFD, 0x3C, 0xA6, 0x76,
                                  0x6F, 0xB1, 0x19, 0xCE, 0xC4, 0xEB, 0x65, 0x74,
                                  0x8D, 0x54, 0x9B, 0xD6, 0x94, 0x0F, 0x70, 0x44,
                                  0x00, 0x0F, 0x8E, 0xA1, 0xD5, 0x1B, 0x47, 0x1A};
    
    uint8_t data[48] = { 0x6B, 0xFC, 0x60, 0x77, 0x3F, 0x38, 0xF5, 0x4A,
                         0x08, 0xEC, 0xB3, 0xD6, 0xEB, 0x40, 0x10, 0xD1,
                         0x00, 0x00, 0x00, 0xBB, 0xFD, 0x3C, 0xA6, 0x76,
                         0xA3, 0x38, 0x6C, 0xC8, 0xF6, 0x29, 0x80, 0x1E,
                         0x8E, 0x4D, 0x36, 0x9C, 0x41, 0x16, 0xD6, 0xED,
                         0xBE, 0x03, 0x0D, 0x9F, 0x12, 0x3B, 0xB1, 0x18 };
    
    // Convert bytes to GF(2^m) elements and elliptic curve points
    element priv_key_A, priv_key_B;
    ec_point pub_key_A, pub_key_B;
    os_to_elem(private_key_A, priv_key_A);
    os_to_elem(private_key_B, priv_key_B);
    os_to_point(public_key_A, &pub_key_A);
    os_to_point(public_key_B, &pub_key_B);
    
    /* ECDH */
    printf("ECDH with private key A and public key B:\n");
    ec_point shared_secret1;
    ecdh(priv_key_A, &pub_key_B, &shared_secret1);
    print_point(&shared_secret1);
    
    printf("ECDH with private key B and public key A:\n");
    ec_point shared_secret2;
    ecdh(priv_key_B, &pub_key_A, &shared_secret2);
    print_point(&shared_secret2);
    
    if (ec_point_is_equal(&shared_secret1, &shared_secret2)) {
        printf("Success! Shared secret outputs are equal.\n");
    }
    else {
        printf("Failure! Shared secret outputs are not equal.\n");
    }
    
    
    /* HASHING */
    printf("\n\nSign data with private key A:\n");
    mpz_t hash;
    mpz_init(hash);
    
    // If we wanted to hash in the way the iQue Player does it (by adding
    // certain magic data to the SHA1 state), we would pass in the aptly-named
    // IQUE_HASH flag instead of NOT_IQUE_HASH as the 3rd argument.
    sha1(data, 48, NOT_IQUE_HASH, hash);
    
    /* SIGNING */
    element r, s;
    ecdsa_sign(hash, priv_key_A, r, s);
    printf("Complete!\n");
    
    /* SIGNATURE VERIFICATION */
    int result1 = ecdsa_verify(hash, &pub_key_A, r, s);
    printf("Verify signature with public key A: %d\n", result1);
    
    int result2 = ecdsa_verify(hash, &pub_key_B, r, s);
    printf("Verify signature with public key B: %d\n", result2);
    mpz_clear(hash);
}
