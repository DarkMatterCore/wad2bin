/*
    ecc.h - definitions required for ECC operations using keys
            defined with sect233r1 / NIST B-233
    
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
#ifndef NINTY_233_ECC_H
#define NINTY_233_ECC_H

#include <stdint.h>

#if defined (__cplusplus)
extern "C" {
#endif

typedef uint32_t element[8];

typedef struct {
    element x;
    element y;
} ec_point;

/*
    sect233r1 - domain parameters over GF(2^m).
    Defined in "Standards for Efficient Cryptography 2 (SEC 2)" v2.0, pp. 19-20
    Not all are currently used.
    (Actual definitions are in ecc.c)
*/
extern const element POLY_F;
extern const element POLY_R;
extern const element A_COEFF;
extern const element B_COEFF;
extern const element G_X;
extern const element G_Y;
extern const element G_ORDER; /*
extern const uint32_t COFACTOR; */

/*
    Printing
*/
void print_element(const element a);
void print_point(const ec_point * a);

/*
    Helper functions for working with elements in GF(2^m)
*/
int  gf2m_is_equal(const element a, const element b);
void gf2m_set_zero(element a);
void gf2m_copy(const element src, element dst);
int  gf2m_get_bit(const element a, int index);
void gf2m_left_shift(element a, int shift);
int  gf2m_is_one(const element a);
int  gf2m_degree(const element a);
void gf2m_swap(element a, element b);

/*
    Arithmetic operations on elements in GF(2^m)
*/
void gf2m_add(const element a, const element b, element result);
void gf2m_inv(const element a, element result);
void gf2m_mul(const element a, const element b, element result);
void gf2m_div(const element a, const element b, element result);

/*
    Operations on points on the elliptic curve
    y^2 + xy = x^3 + ax^2 + b over GF(2^m)
*/
void ec_point_copy(const ec_point * src, ec_point * dst);
int  ec_point_is_equal(const ec_point * a, const ec_point * b);
void ec_point_neg(const ec_point * a, ec_point * result);
void ec_point_double(const ec_point * a, ec_point * result);
void ec_point_add(const ec_point * a, const ec_point * b, ec_point * result);
void ec_point_mul(const element a, const ec_point * b, ec_point * result);
int  ec_point_on_curve(const ec_point * a);

/*
    I/O Helpers
*/
void os_to_elem(const uint8_t * src_os, element dst_elem);
void os_to_point(const uint8_t * src_os, ec_point * dst_point);
void elem_to_os(const element src_elem, uint8_t * dst_os);
void point_to_os(const ec_point * src_point, uint8_t * dst_os);

#if defined (__cplusplus)
}
#endif

#endif
