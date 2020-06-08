#pragma once

#ifndef __TYPES_H__
#define __TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdalign.h>
#include <sys/types.h>
#include <inttypes.h>

/// Creates a bitmask from a bit number.
#ifndef BIT
#define BIT(n)          (1U << (n))
#endif

/// Packs a struct so that it won't include padding bytes.
#ifndef PACKED
#define PACKED          __attribute__((packed))
#endif

/// Flags a function as (always) inline.
#ifndef ALWAYS_INLINE
#define ALWAYS_INLINE   __attribute__((always_inline)) static inline
#endif

typedef uint8_t u8;     ///<  8-bit unsigned integer.
typedef uint16_t u16;   ///< 16-bit unsigned integer.
typedef uint32_t u32;   ///< 32-bit unsigned integer.
typedef uint64_t u64;   ///< 64-bit unsigned integer.

typedef int8_t s8;      ///<  8-bit signed integer.
typedef int16_t s16;    ///< 16-bit signed integer.
typedef int32_t s32;    ///< 32-bit signed integer.
typedef int64_t s64;    ///< 64-bit signed integer.

#endif /* __TYPES_H__ */
