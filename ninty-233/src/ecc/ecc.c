/*
    ecc.c - inplementations of ECC operations using keys
            defined with sect233r1 / NIST B-233
            
    This is NOT intended to be used in an actual cryptographic
    scheme; as written, it is vulnerable to several attacks.
    This might or might not change in the future. It is intended
    to be used for doing operations on keys which are already known.

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

#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>

#include "ecc.h"

/*
    sect233r1 - domain parameters over GF(2^m).
    Defined in "Standards for Efficient Cryptography 2 (SEC 2)" v2.0, pp. 19-20
    Not all are currently used.
*/
const element POLY_F =      {0x0200, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000400, 0x00000000, 0x00000001};
const element POLY_R =      {0x0000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000400, 0x00000000, 0x00000001};
const element A_COEFF =     {0x0000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001};
const element B_COEFF =     {0x0066, 0x647EDE6C, 0x332C7F8C, 0x0923BB58, 0x213B333B, 0x20E9CE42, 0x81FE115F, 0x7D8F90AD};
const element G_X =         {0x00FA, 0xC9DFCBAC, 0x8313BB21, 0x39F1BB75, 0x5FEF65BC, 0x391F8B36, 0xF8F8EB73, 0x71FD558B};
const element G_Y =         {0x0100, 0x6A08A419, 0x03350678, 0xE58528BE, 0xBF8A0BEF, 0xF867A7CA, 0x36716F7E, 0x01F81052};
const element G_ORDER =     {0x0100, 0x00000000, 0x00000000, 0x00000000, 0x0013E974, 0xE72F8A69, 0x22031D26, 0x03CFE0D7}; /*
const uint32_t COFACTOR =   0x02; */


/*
    Printing
*/
void print_element(const element a) {
    for (int i = 0; i < 8; ++i) {
        printf("%08"PRIX32" ", a[i]);
    }
    printf("\n");
}

void print_point(const ec_point * a) {
    printf("x: ");
    print_element(a->x);
    printf("y: ");
    print_element(a->y);
    printf("\n");
}

/*
    Helper functions for working with elements in GF(2^m)
*/
int gf2m_is_equal(const element a, const element b) {
    for (int i = 0; i < 8; ++i) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

void gf2m_set_zero(element a) {
    for (int i = 0; i < 8; ++i) {
        a[i] = 0;
    }
}

void gf2m_copy(const element src, element dst) {
    for (int i = 0; i < 8; ++i) {
        dst[i] = src[i];
    }
}

int gf2m_get_bit(const element a, int index) {
    if (index >= 233 || index < 0) return -1;
    int word_index = ((index / 32) - 7) * -1;
    int shift = index - (32 * (7 - word_index));
    return (a[word_index] >> shift) & 1;
}

void gf2m_left_shift(element a, int shift) {
    if (shift <= 0) {
        a[0] &= 0x1FF;
        return;
    }
    for (int i = 0; i < 7; ++i) {
        a[i] <<= 1;
        if (a[i + 1] >= 0x80000000) {
            a[i] |= 1;
        }
    }
    a[7] <<= 1;
    gf2m_left_shift(a, shift - 1);
}

int gf2m_is_one(const element a) {
    if (a[7] != 1) {
        return 0;
    }
    else {
        for (int i = 0; i < 7; ++i) {
            if (a[i] != 0) {
                return 0;
            }
        }
    }
    return 1;
}

int gf2m_degree(const element a) {
    int degree = 0;
    int i = 0;
    while ((i < 7) && (a[i] == 0)) {
        i++;
    }
    degree = (7 - i) * 32;
    uint32_t most_significant_word = a[i];
    while (most_significant_word != 0) {
        most_significant_word >>= 1;
        degree += 1;
    }
    return degree - 1;
}

void gf2m_swap(element a, element b) {
    element temp;
    gf2m_copy(a, temp);
    gf2m_copy(b, a);
    gf2m_copy(temp, b);
}

/*
    Arithmetic operations on elements in GF(2^m)
*/
void gf2m_add(const element a, const element b, element result) {
    for (int i = 0; i < 8; ++i) {
        result[i] = a[i] ^ b[i];
    }
}

void gf2m_inv(const element a, element result) {
    element u, v, g_1, g_2, temp;
    gf2m_copy(a, u);
    gf2m_copy(POLY_F, v);
    gf2m_set_zero(g_1);
    g_1[7] |= 1;
    gf2m_set_zero(g_2);
    int j = gf2m_degree(u) - 233;
    while (!gf2m_is_one(u)) {
        if (j < 0) {
            gf2m_swap(u, v);
            gf2m_swap(g_1, g_2);
            j = -j;
        }
        gf2m_copy(v, temp);
        gf2m_left_shift(temp, j);
        gf2m_add(u, temp, u);
        gf2m_copy(g_2, temp);
        gf2m_left_shift(temp, j);
        gf2m_add(g_1, temp, g_1);

        u[0] &= 0x1FF;
        g_1[0] &= 0x1FF;

        j = gf2m_degree(u) - gf2m_degree(v);
    }
    gf2m_copy(g_1, result);
}

// basic implementation
void gf2m_mul(const element a, const element b, element result) {
    element t1, t2, t3;
    gf2m_copy(a, t1);
    gf2m_copy(b, t2);
    gf2m_set_zero(t3);
    for (int i = 0; i < 233; ++i) {
        if (gf2m_get_bit(t2, i)) {
            gf2m_add(t3, t1, t3);
        }
        int carry = gf2m_get_bit(t1, 232);
        gf2m_left_shift(t1, 1);
        if (carry == 1) {
            gf2m_add(POLY_R, t1, t1);
        }
    }
    gf2m_copy(t3, result);
}

void gf2m_div(const element a, const element b, element result) {
    element temp;
    gf2m_inv(b, temp);
    gf2m_mul(a, temp, result);
}

/*
    Operations on points on the elliptic curve
    y^2 + xy = x^3 + ax^2 + b over GF(2^m)
*/
void ec_point_copy(const ec_point * src, ec_point * dst) {
    gf2m_copy(src->x, dst->x);
    gf2m_copy(src->y, dst->y);
}

int ec_point_is_equal(const ec_point * a, const ec_point * b) {
    return gf2m_is_equal(a->x, b->x) && gf2m_is_equal(a->y, b->y);
}

void ec_point_neg(const ec_point * a, ec_point * result) {
    gf2m_copy(a->x, result->x);
    gf2m_add(a->x, a->y, result->y);
}

void ec_point_double(const ec_point * a, ec_point * result) {
    ec_point temp, zero;
    gf2m_set_zero(zero.x);
    gf2m_set_zero(zero.y);

    ec_point_neg(a, &temp);
    if (ec_point_is_equal(a, &temp) || ec_point_is_equal(a, &zero)) {
        ec_point_copy(&zero, result);
        return;
    }

    element lambda, x, y, t, t2;
    // Compute lambda (a.x + (a.y / a.x))
    gf2m_div(a->y, a->x, t);
    gf2m_add(a->x, t, lambda);
    // Compute X (lambda^2 + lambda + A_COEFF)
    gf2m_mul(lambda, lambda, t);
    gf2m_add(t, lambda, t);
    gf2m_add(t, A_COEFF, x);
    // Compute Y (a.x^2 + (lambda * X) + X)
    gf2m_mul(a->x, a->x, t);
    gf2m_mul(lambda, x, t2);
    gf2m_add(t, t2, t);
    gf2m_add(t, x, y);
    // Copy X,Y to output point result
    gf2m_copy(x, result->x);
    gf2m_copy(y, result->y);
}

void ec_point_add(const ec_point * a, const ec_point * b, ec_point * result) {
    if (!ec_point_is_equal(a, b)) {
        ec_point temp, zero;
        gf2m_set_zero(zero.x);
        gf2m_set_zero(zero.y);
        ec_point_neg(b, &temp);
        if (ec_point_is_equal(a, &temp)) {
            ec_point_copy(&zero, result);
            return;
        }
        else if (ec_point_is_equal(a, &zero)) {
            ec_point_copy(b, result);
            return;
        }
        else if (ec_point_is_equal(b, &zero)) {
            ec_point_copy(a, result);
            return;
        }
        else {
            element lambda, x, y, t, t2;
            // Compute lambda ((b.y + a.y) / (b.x + a.x))
            gf2m_add(b->y, a->y, t);
            gf2m_add(b->x, a->x, t2);
            gf2m_div(t, t2, lambda);
            // Compute X (lambda^2 + lambda + a.x + b.x + A_COEFF)
            gf2m_mul(lambda, lambda, t);
            gf2m_add(t, lambda, t2);
            gf2m_add(t2, a->x, t);
            gf2m_add(t, b->x, t2);
            gf2m_add(t2, A_COEFF, x);
            // Compute Y ((lambda * (a.x + X)) + X + a.y)
            gf2m_add(a->x, x, t);
            gf2m_mul(lambda, t, t2);
            gf2m_add(t2, x, t);
            gf2m_add(t, a->y, y);
            // Copy X,Y to output point result
            gf2m_copy(x, result->x);
            gf2m_copy(y, result->y);
            return;
        }
    }
    else {
        ec_point_double(a, result);
    }
}

void ec_point_mul(const element a, const ec_point * b, ec_point * result) {
    element k;
    ec_point P, Q;

    gf2m_copy(a, k);
    ec_point_copy(b, &P);
    gf2m_set_zero(Q.x);
    gf2m_set_zero(Q.y);
    for (int i = 0; i < 233; ++i) {
        if (gf2m_get_bit(k, i)) {
            ec_point_add(&Q, &P, &Q);
        }
        ec_point_double(&P, &P);
    }
    ec_point_copy(&Q, result);
}

int ec_point_on_curve(const ec_point * P) {
    // y^2 + xy = x^3 + ax^2 + b
    element xx, yy, xy, lhs, rhs;
    
    // lhs = y^2 + xy
    gf2m_mul(P->y, P->y, yy);
    gf2m_mul(P->x, P->y, xy);
    gf2m_add(yy, xy, lhs);
    
    // rhs = x^3 + ax^2 + b = (x^2)(x + a) + b
    gf2m_mul(P->x, P->x, xx);
    gf2m_add(P->x, A_COEFF, rhs);
    gf2m_mul(xx, rhs, rhs);
    gf2m_add(rhs, B_COEFF, rhs);
    
    return gf2m_is_equal(lhs, rhs);
}

/*
    I/O Helpers
        Private keys are expected to be 32 bytes; Public keys
        are expected to be 64 bytes and in uncompressed form.
        
        Wii keys will need to be padded - two 0 bytes at the
        start of the private key, and two 0 bytes before each
        coordinate in the public key. Keys on the iQue Player
        are already stored with padding and need no changes.
        
        These functions are mainly intended for reading/writing
        *keys* as byte arrays or octet streams, but they will
        work fine for any input with the correct length.
*/
// (32-byte) octet stream to GF(2^m) element
void os_to_elem(const uint8_t * src_os, element dst_elem) {
    int j = 0;
    for (int i = 0; i < 8; ++i) {
        uint32_t result = src_os[j];
        result = (result << 8) | src_os[j + 1];
        result = (result << 8) | src_os[j + 2];
        result = (result << 8) | src_os[j + 3];
        dst_elem[i] = result;
        j += 4;
    }
}

// (64-byte) octet stream to elliptic curve point
void os_to_point(const uint8_t * src_os, ec_point * dst_point) {
    os_to_elem(src_os, dst_point->x);
    os_to_elem(src_os + 32, dst_point->y);
}

// GF(2^m) element to (32-byte) octet stream
void elem_to_os(const element src_elem, uint8_t * dst_os) {
    int j = 0;
    for (int i = 0; i < 8; ++i) {
        dst_os[j] =     (src_elem[i] & 0xFF000000) >> 24;
        dst_os[j + 1] = (src_elem[i] & 0x00FF0000) >> 16;
        dst_os[j + 2] = (src_elem[i] & 0x0000FF00) >> 8;
        dst_os[j + 3] =  src_elem[i] & 0x000000FF;
        j += 4;
    }
}

// Elliptic curve point to (64-byte) octet stream
void point_to_os(const ec_point * src_point, uint8_t * dst_os) {
    elem_to_os(src_point->x, dst_os);
    elem_to_os(src_point->y, dst_os + 32);
}
