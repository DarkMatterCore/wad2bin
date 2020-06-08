/*
    ninty-233.c

    Copyright © 2018, 2019 Jbop (https://github.com/jbop1626)

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

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>
#include <time.h>

#include "ninty-233.h"
#include "ecc/ecc.h"
#include "sha1/sha1.h"
#include "mini-gmp/mini-gmp.h"


static void init_mpz_list(size_t count, mpz_ptr x, ...) {
    va_list mpz_list;
    va_start(mpz_list, x);

    size_t i = 0;
    while (i < count) {
        mpz_init(x);
        x = va_arg(mpz_list, mpz_ptr);
        i++;
    }
    
    va_end(mpz_list);
}

static void clear_mpz_list(size_t count, mpz_ptr x, ...) {
    va_list mpz_list;
    va_start(mpz_list, x);
    
    size_t i = 0;
    while (i < count) {
        mpz_clear(x);
        x = va_arg(mpz_list, mpz_ptr);
        i++;
    }
    
    va_end(mpz_list);
}

static void generate_k(const mpz_t n, const mpz_t hash, mpz_t k_out) {
    // Do NOT use this implementation for generation of k
    // when creating a signature that must be secure!
    srand(time(NULL));

    mpz_t random_mpz;
    mpz_init(random_mpz);
    
    uint32_t buffer[8] = { 0 };
    for(int i = 0; i < 8; ++i) {
        buffer[i] = rand() % UINT32_MAX;
    }
    
    mpz_import(random_mpz, 8, 1, sizeof(buffer[0]), 0, 0, buffer);
    mpz_mul(k_out, random_mpz, hash);
    while (mpz_cmp(k_out, n) >= 0) {
        mpz_tdiv_q_ui(k_out, k_out, 7);
    }
    
    mpz_clear(random_mpz);
}



void mpz_to_gf2m(const mpz_t src, element dst) {
    uint32_t buffer[32] = { 0 };
    gf2m_set_zero(dst);
    
    size_t count = 0;
    mpz_export((void *)buffer, &count, 1, sizeof(dst[0]), 0, 0, src);
    if (count == 0 || count > INT_MAX) {
        fprintf(stderr, "mpz_to_gf2m error! Element argument is now zero.\n");
        return;
    }
    
    int i = 7;
    int j = count - 1;
    while(i >= 0 && j >= 0) { 
        dst[i] = buffer[j];
        i--;
        j--;
    }
}

void gf2m_to_mpz(const element src, mpz_t dst) {
    mpz_import(dst, 8, 1, sizeof(src[0]), 0, 0, src);
}

void sha1(const uint8_t * input, uint32_t input_length, unsigned ique_flag, mpz_t hash_out) {
    SHA1_HASH hash;
	Sha1Context context;
	
	Sha1Initialise(&context);
	Sha1Update(&context, input, input_length);
    if (ique_flag) {
        // When performing certain hashes, the iQue Player updates the
        // SHA1 state with the following magic data.
        uint8_t ique_magic[4] = { 0x06, 0x09, 0x19, 0x68 };
        Sha1Update(&context, &ique_magic, 4);
    }
	Sha1Finalise(&context, &hash);

    mpz_import(hash_out, 20, 1, sizeof(hash.bytes[0]), 0, 0, (void *)hash.bytes);
}

void ecdh(const element private_key, const ec_point * public_key, ec_point * shared_secret_output) {	
	ec_point_mul(private_key, public_key, shared_secret_output);
}

void ecdsa_sign(const mpz_t z, const element private_key, element r_out, element s_out) {
    mpz_t r, s, n, D, zero, k, x_p, k_inv, med;
    init_mpz_list(9, r, s, n, D, zero, k, x_p, k_inv, med);
    
	gf2m_to_mpz(G_ORDER, n);
	gf2m_to_mpz(private_key, D);
    gf2m_set_zero(r_out);
    gf2m_set_zero(s_out);
    
	while(!mpz_cmp(r, zero) || !mpz_cmp(s, zero)) {
		// Generate k in [1, n - 1]
        generate_k(n, z, k);
		element k_elem;
		mpz_to_gf2m(k, k_elem);
		
		// Calculate P = kG
		ec_point G, P;
		gf2m_copy(G_X, G.x);
		gf2m_copy(G_Y, G.y);
		ec_point_mul(k_elem, &G, &P);
		
		// Calculate r = x_p mod n
		gf2m_to_mpz(P.x, x_p);
        mpz_mod(r, x_p, n);
		
		// Calculate s = k^-1(z + rD) mod n
        if (mpz_invert(k_inv, k, n) == 0) {
            fprintf(stderr, "An error occurred while calculating the inverse of k mod n.\n");
            fprintf(stderr, "The resulting signature will be invalid!\n");
        }
        mpz_mul(med, r, D);
        mpz_add(med, z, med);
        mpz_mod(med, med, n);
        
        mpz_mul(s, k_inv, med);
        mpz_mod(s, s, n);
	}
	mpz_to_gf2m(r, r_out);
	mpz_to_gf2m(s, s_out);
    
    clear_mpz_list(9, r, s, n, D, zero, k, x_p, k_inv, med);
}

int ecdsa_verify(const mpz_t z, const ec_point * public_key, const element r_input, const element s_input) {
	ec_point Q, test;
	ec_point_copy(public_key, &Q);
	element zero = { 0 };

	// If Q is the identity, Q is invalid
	if (gf2m_is_equal(Q.x, zero) && gf2m_is_equal(Q.y, zero)) {
		return 0;
	}
	// If Q is not a point on the curve, Q is invalid
	if (!ec_point_on_curve(&Q)) {
		return 0;
	}
	// If nQ is not the identity, Q is invalid (or n is messed up)
	ec_point_mul(G_ORDER, &Q, &test);
	if (!(gf2m_is_equal(test.x, zero) && gf2m_is_equal(test.y, zero))) {
		return 0;
	}
    
	// Public key is valid, now verify signature...
    mpz_t r, s, n;
    init_mpz_list(3, r, s, n);
    gf2m_to_mpz(r_input, r);
    gf2m_to_mpz(s_input, s);
    gf2m_to_mpz(G_ORDER, n);

	// If r or s are not in [1, n - 1], sig is invalid
    if ( (mpz_cmp_ui(r, 1) < 0 || mpz_cmp(r, n) > 0 || mpz_cmp(r, n) == 0) ||
         (mpz_cmp_ui(s, 1) < 0 || mpz_cmp(s, n) > 0 || mpz_cmp(s, n) == 0) ) {
        clear_mpz_list(3, r, s, n);
		return 0;
	}

	// Calculate u_1 and u_2
    mpz_t s_inv, u_1, u_2;
    init_mpz_list(3, s_inv, u_1, u_2);
    
    if (mpz_invert(s_inv, s, n) == 0) {
        fprintf(stderr, "An error occurred while calculating the inverse of s mod n.\n");
        clear_mpz_list(6, r, s, n, s_inv, u_1, u_2);
        return 0;
    }
    mpz_mul(u_1, z, s_inv);
    mpz_mod(u_1, u_1, n);
    mpz_mul(u_2, r, s_inv);
    mpz_mod(u_2, u_2, n);

	// Calculate P3 = u_1G + u_2Q
	element u_1_elem, u_2_elem;
    mpz_to_gf2m(u_1, u_1_elem);
	mpz_to_gf2m(u_2, u_2_elem);
	ec_point G, P1, P2, P3;
	gf2m_copy(G_X, G.x);
	gf2m_copy(G_Y, G.y);

	ec_point_mul(u_1_elem, &G, &P1);
	ec_point_mul(u_2_elem, &Q, &P2);
	ec_point_add(&P1, &P2, &P3);

	// If P3 is the identity, sig is invalid
	if (gf2m_is_equal(P3.x, zero) && gf2m_is_equal(P3.y, zero)) {
        clear_mpz_list(6, r, s, n, s_inv, u_1, u_2);
		return 0;
	}
	
	// And finally, is r congruent to P3.x mod n?
    mpz_t x_p;
    mpz_init(x_p);
	gf2m_to_mpz(P3.x, x_p);   
    
    int is_congruent = mpz_congruent_p(r, x_p, n) != 0;
    clear_mpz_list(7, r, s, n, s_inv, u_1, u_2, x_p);
    return is_congruent;
}