#ifndef _NTBOOT_H
#define _NTBOOT_H

/*
 *  ntloader  --  Microsoft Windows NT6+ loader
 *  Copyright (C) 2021  A1ive.
 *
 *  ntloader is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  ntloader is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ntloader.  If not, see <http://www.gnu.org/licenses/>.
 */

/** Debug switch */
#ifndef DEBUG
  #define DEBUG 1
#endif

/** Base segment address
 *
 * We place everything at 4000:0000.
 */
#define BASE_SEG 0x4000

/** Base linear address */
#define BASE_ADDRESS (BASE_SEG << 4)

/** 64 bit long mode code segment */
#define LM_CS 0x10

/** 32 bit protected mode flat code segment */
#define FLAT_CS 0x20

/** 32 bit protected mode flat data segment */
#define FLAT_DS 0x30

/** 16 bit real mode code segment */
#define REAL_CS 0x50

/** 16 bit real mode data segment */
#define REAL_DS 0x60

#ifndef ASSEMBLY

#include <stdint.h>
#include <bootapp.h>
#include <cmdline.h>

/** Construct wide-character version of a string constant */
#define L( x ) _L ( x )
#define _L( x ) L ## x

/** Page size */
#define PAGE_SIZE 4096

#define BYTES_TO_PAGES(bytes)   (((bytes) + 0xfff) >> 12)
#define BYTES_TO_PAGES_DOWN(bytes)  ((bytes) >> 12)
#define PAGES_TO_BYTES(pages)   ((pages) << 12)

#define ALIGN_UP(addr, align) \
    (((addr) + (typeof (addr)) (align) - 1) & ~((typeof (addr)) (align) - 1))
#define ALIGN_UP_OVERHEAD(addr, align) ((-(addr)) & ((typeof (addr)) (align) - 1))
#define ALIGN_DOWN(addr, align) \
    ((addr) & ~((typeof (addr)) (align) - 1))
#define ARRAY_SIZE(array) (sizeof (array) / sizeof (array[0]))

struct packed_guid
{
  uint32_t data1;
  uint16_t data2;
  uint16_t data3;
  uint8_t data4[8];
} __attribute__ ((packed));
typedef struct packed_guid packed_guid_t;

struct unaligned_uint16
{
  uint16_t val;
} __attribute__ ((packed));

struct unaligned_uint32
{
  uint32_t val;
} __attribute__ ((packed));

struct unaligned_uint64
{
  uint64_t val;
} __attribute__ ((packed));

static inline uint16_t get_unaligned16 (const void *ptr)
{
  const struct unaligned_uint16 *dd = (const struct unaligned_uint16 *) ptr;
  return dd->val;
}

static inline void set_unaligned16 (void *ptr, uint16_t val)
{
  struct unaligned_uint16 *dd = (struct unaligned_uint16 *) ptr;
  dd->val = val;
}

static inline uint32_t get_unaligned32 (const void *ptr)
{
  const struct unaligned_uint32 *dd = (const struct unaligned_uint32 *) ptr;
  return dd->val;
}

static inline void set_unaligned32 (void *ptr, uint32_t val)
{
  struct unaligned_uint32 *dd = (struct unaligned_uint32 *) ptr;
  dd->val = val;
}

static inline uint64_t get_unaligned64 (const void *ptr)
{
  const struct unaligned_uint64 *dd = (const struct unaligned_uint64 *) ptr;
  return dd->val;
}

static inline void set_unaligned64 (void *ptr, uint64_t val)
{
  struct unaligned_uint64 *dd = (struct unaligned_uint64 *) ptr;
  dd->val = val;
}

/**
 * Calculate start page number
 *
 * @v address   Address
 * @ret page    Start page number
 */
static inline unsigned int page_start (const void *address)
{
  return (((intptr_t) address) / PAGE_SIZE);
}

/**
 * Calculate end page number
 *
 * @v address   Address
 * @ret page    End page number
 */
static inline unsigned int page_end (const void *address)
{
  return ((((intptr_t) address) + PAGE_SIZE - 1) / PAGE_SIZE);
}

/**
 * Calculate page length
 *
 * @v start   Start address
 * @v end   End address
 * @ret num_pages Number of pages
 */
static inline unsigned int page_len (const void *start, const void *end)
{
  return (page_end (end) - page_start (start));
}

/** Debugging output */
#define DBG(...) do {           \
    if ( ( DEBUG & 1 ) && ( ! nt_cmdline->quiet ) ) { \
      printf ( __VA_ARGS__ );     \
    }           \
  } while ( 0 )

/** Verbose debugging output */
#define DBG2(...) do {            \
    if ( ( DEBUG & 2 ) && ( ! nt_cmdline->quiet ) ) { \
      printf ( __VA_ARGS__ );     \
    }           \
  } while ( 0 )

/* Branch prediction macros */
#define likely( x ) __builtin_expect ( !! (x), 1 )
#define unlikely( x ) __builtin_expect ( (x), 0 )

/* Mark parameter as unused */
#define __unused __attribute__ (( unused ))

#if __x86_64__
static inline void call_real (struct bootapp_callback_params *params)
{
  /* Not available in 64-bit mode */
  (void) params;
}
static inline void call_interrupt (struct bootapp_callback_params *params)
{
  /* Not available in 64-bit mode */
  (void) params;
}
static inline void reboot (void)
{
  /* Not available in 64-bit mode */
}
#else
extern void call_real (struct bootapp_callback_params *params);
extern void call_interrupt (struct bootapp_callback_params *params);
extern void __attribute__ ((noreturn)) reboot (void);
#endif

extern void __attribute__ ((noreturn, format (printf, 1, 2)))
die (const char *fmt, ...);
extern void pause_boot (void);
extern void print_banner (void);
extern void cls (void);

extern unsigned long __stack_chk_guard;
extern void init_cookie (void);

#endif /* ASSEMBLY */

#endif /* _WIMBOOT_H */
