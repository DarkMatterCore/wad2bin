/*
	ninty-233
	Library for ECC operations using keys defined with
	sect233r1 / NIST B-233 -- the curve/domain parameters
	used by Nintendo in the iQue Player and Wii.

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
#ifndef NINTY_233_H
#define NINTY_233_H

#include <stdint.h>

#include "ecc/ecc.h"
#include "mini-gmp/mini-gmp.h"

#if defined (__cplusplus)
extern "C" {
#endif
/*
	Multi-precision integer <--> GF(2^m) element conversions
*/
void mpz_to_gf2m(const mpz_t src, element dst);
void gf2m_to_mpz(const element src, mpz_t dst);

/*
	SHA-1 result as multi-precision integer
*/
#define NOT_IQUE_HASH 0
#define     IQUE_HASH 1
void sha1(const uint8_t * input, uint32_t input_length, unsigned ique_flag, mpz_t hash_out);

/*
	ECC algorithms
*/
void ecdh(const element private_key, const ec_point * public_key, ec_point * shared_secret_output);
void ecdsa_sign(const mpz_t hash, const element private_key, element r_out, element s_out);
int  ecdsa_verify(const mpz_t hash, const ec_point * public_key, const element r_input, const element s_input);

#if defined (__cplusplus)
}
#endif

#endif
