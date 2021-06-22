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

#ifndef _STDLIB_H
#define _STDLIB_H 1

/* Magic words.  */
#define MM_FREE_MAGIC     0x2d3c2808
#define MM_ALLOC_MAGIC    0x6db08fa4

typedef struct mm_header
{
  struct mm_header *next;
  size_t size;
  size_t magic;
#if defined(__i386__)
  char padding[4];
#elif defined(__x86_64__)
  char padding[8];
#else
# error "unknown word size"
#endif
} *mm_header_t;

#if defined(__i386__)
# define MM_ALIGN_LOG2    4
#elif defined(__x86_64__)
# define MM_ALIGN_LOG2    5
#endif

#define MM_ALIGN          (1 << MM_ALIGN_LOG2)

typedef struct mm_region
{
  struct mm_header *first;
  struct mm_region *next;
  size_t pre_size;
  size_t size;
} *mm_region_t;

extern mm_region_t mm_base;

extern void mm_init_region (void *addr, size_t size);
extern void *malloc (size_t size);
extern void *zalloc (size_t size);
extern void free (void *ptr);
extern void *realloc (void *ptr, size_t size);
extern void *memalign (size_t align, size_t size);

extern unsigned long strtoul (const char *nptr, char **endptr, int base);

#endif /* _STDLIB_H */
