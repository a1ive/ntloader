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
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2021  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
  The design of this memory manager.

  This is a simple implementation of malloc with a few extensions. These are
  the extensions:

  - memalign is implemented efficiently.

  - multiple regions may be used as free space. They may not be
  contiguous.

  Regions are managed by a singly linked list, and the meta information is
  stored in the beginning of each region. Space after the meta information
  is used to allocate memory.

  The memory space is used as cells instead of bytes for simplicity. This
  is important for some CPUs which may not access multiple bytes at a time
  when the first byte is not aligned at a certain boundary (typically,
  4-byte or 8-byte). The size of each cell is equal to the size of struct
  mm_header, so the header of each allocated/free block fits into one
  cell precisely. One cell is 16 bytes on 32-bit platforms and 32 bytes
  on 64-bit platforms.

  There are two types of blocks: allocated blocks and free blocks.

  In allocated blocks, the header of each block has only its size. Note that
  this size is based on cells but not on bytes. The header is located right
  before the returned pointer, that is, the header resides at the previous
  cell.

  Free blocks constitutes a ring, using a singly linked list. The first free
  block is pointed to by the meta information of a region. The allocator
  attempts to pick up the second block instead of the first one. This is
  a typical optimization against defragmentation, and makes the
  implementation a bit easier.

  For safety, both allocated blocks and free ones are marked by magic
  numbers. Whenever anything unexpected is detected, GRUB aborts the
  operation.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ntboot.h>

mm_region_t mm_base;

/* Get a header from the pointer PTR, and set *P and *R to a pointer
   to the header and a pointer to its region, respectively. PTR must
   be allocated.  */
static void
get_header_from_pointer (void *ptr, mm_header_t *p, mm_region_t *r)
{
  if ((intptr_t) ptr & (MM_ALIGN - 1))
    die ("unaligned pointer %p\n", ptr);

  for (*r = mm_base; *r; *r = (*r)->next)
  {
    if ((intptr_t) ptr > (intptr_t) ((*r) + 1)
        && (intptr_t) ptr <= (intptr_t) ((*r) + 1) + (*r)->size)
      break;
  }

  if (! *r)
    die ("out of range pointer %p\n", ptr);

  *p = (mm_header_t) ptr - 1;
  if ((*p)->magic == MM_FREE_MAGIC)
    die ("double free at %p\n", *p);
  if ((*p)->magic != MM_ALLOC_MAGIC)
    die ("alloc magic is broken at %p: %lx\n", *p, (unsigned long) (*p)->magic);
}

/* Initialize a region starting from ADDR and whose size is SIZE,
   to use it as free space.  */
void
mm_init_region (void *addr, size_t size)
{
  mm_header_t h;
  mm_region_t r, *p, q;

  DBG ("Using memory for heap: start=%p, end=%p\n",
       addr, (uint8_t *) addr + (unsigned int) size);

  /* Exclude last 4K to avoid overflows. */
  /* If addr + 0x1000 overflows then whole region is in excluded zone.  */
  if ((intptr_t) addr > ~((intptr_t) 0x1000))
    return;

  /* If addr + 0x1000 + size overflows then decrease size.  */
  if (((intptr_t) addr + 0x1000) > ~(intptr_t) size)
    size = ((intptr_t) -0x1000) - (intptr_t) addr;

  for (p = &mm_base, q = *p; q; p = &(q->next), q = *p)
  {
    if ((uint8_t *) addr + size + q->pre_size == (uint8_t *) q)
    {
      r = (mm_region_t) ALIGN_UP ((intptr_t) addr, MM_ALIGN);
      *r = *q;
      r->pre_size += size;
      if (r->pre_size >> MM_ALIGN_LOG2)
      {
        h = (mm_header_t) (r + 1);
        h->size = (r->pre_size >> MM_ALIGN_LOG2);
        h->magic = MM_ALLOC_MAGIC;
        r->size += h->size << MM_ALIGN_LOG2;
        r->pre_size &= (MM_ALIGN - 1);
        *p = r;
        free (h + 1);
      }
      *p = r;
      return;
    }
  }

  /* Allocate a region from the head.  */
  r = (mm_region_t) ALIGN_UP ((intptr_t) addr, MM_ALIGN);

  /* If this region is too small, ignore it.  */
  if (size < MM_ALIGN + (char *) r - (char *) addr + sizeof (*r))
    return;

  size -= (char *) r - (char *) addr + sizeof (*r);

  h = (mm_header_t) (r + 1);
  h->next = h;
  h->magic = MM_FREE_MAGIC;
  h->size = (size >> MM_ALIGN_LOG2);

  r->first = h;
  r->pre_size = (intptr_t) r - (intptr_t) addr;
  r->size = (h->size << MM_ALIGN_LOG2);

  /* Find where to insert this region. Put a smaller one before bigger ones,
     to prevent fragmentation.  */
  for (p = &mm_base, q = *p; q; p = &(q->next), q = *p)
  {
    if (q->size > r->size)
      break;
  }

  *p = r;
  r->next = q;
}

/* Allocate the number of units N with the alignment ALIGN from the ring
   buffer starting from *FIRST.  ALIGN must be a power of two. Both N and
   ALIGN are in units of MM_ALIGN.  Return a non-NULL if successful,
   otherwise return NULL.  */
static void *
real_malloc (mm_header_t *first, size_t n, size_t align)
{
  mm_header_t p, q;

  /* When everything is allocated side effect is that *first will have alloc
     magic marked, meaning that there is no room in this region.  */
  if ((*first)->magic == MM_ALLOC_MAGIC)
    return 0;

  /* Try to search free slot for allocation in this memory region.  */
  for (q = *first, p = q->next; ; q = p, p = p->next)
  {
    uint64_t extra;

    extra = ((intptr_t) (p + 1) >> MM_ALIGN_LOG2) & (align - 1);
    if (extra)
      extra = align - extra;

    if (! p)
      die ("null in the ring\n");

    if (p->magic != MM_FREE_MAGIC)
      die ("free magic is broken at %p: 0x%lx\n", p, (unsigned long) p->magic);

    if (p->size >= n + extra)
    {
      extra += (p->size - extra - n) & (~(align - 1));
      if (extra == 0 && p->size == n)
      {
        /* There is no special alignment requirement and memory block
           is complete match.

           1. Just mark memory block as allocated and remove it from
              free list.

           Result:
           +---------------+ previous block's next
           | alloc, size=n |          |
           +---------------+          v
        */
        q->next = p->next;
      }
      else if (align == 1 || p->size == n + extra)
      {
        /* There might be alignment requirement, when taking it into
           account memory block fits in.

           1. Allocate new area at end of memory block.
           2. Reduce size of available blocks from original node.
           3. Mark new area as allocated and "remove" it from free
              list.

           Result:
           +---------------+
           | free, size-=n | next --+
           +---------------+        |
           | alloc, size=n |        |
           +---------------+        v
           */

        p->size -= n;
        p += p->size;
      }
      else if (extra == 0)
      {
        mm_header_t r;

        r = p + extra + n;
        r->magic = MM_FREE_MAGIC;
        r->size = p->size - extra - n;
        r->next = p->next;
        q->next = r;

        if (q == p)
        {
          q = r;
          r->next = r;
        }
      }
      else
      {
        /* There is alignment requirement and there is room in memory
           block.  Split memory block to three pieces.

           1. Create new memory block right after section being
              allocated.  Mark it as free.
           2. Add new memory block to free chain.
           3. Mark current memory block having only extra blocks.
           4. Advance to aligned block and mark that as allocated and
              "remove" it from free list.

           Result:
           +------------------------------+
           | free, size=extra             | next --+
           +------------------------------+        |
           | alloc, size=n                |        |
           +------------------------------+        |
           | free, size=orig.size-extra-n | <------+, next --+
           +------------------------------+                  v
           */
        mm_header_t r;

        r = p + extra + n;
        r->magic = MM_FREE_MAGIC;
        r->size = p->size - extra - n;
        r->next = p;

        p->size = extra;
        q->next = r;
        p += extra;
      }

      p->magic = MM_ALLOC_MAGIC;
      p->size = n;

      /* Mark find as a start marker for next allocation to fasten it.
         This will have side effect of fragmenting memory as small
         pieces before this will be un-used.  */
      /* So do it only for chunks under 64K.  */
      if (n < (0x8000 >> MM_ALIGN_LOG2) || *first == p)
        *first = q;

      return p + 1;
    }

    /* Search was completed without result.  */
    if (p == *first)
      break;
  }

  return 0;
}

/* Allocate SIZE bytes with the alignment ALIGN and return the pointer.  */
void *
memalign (size_t align, size_t size)
{
  mm_region_t r;
  size_t n = ((size + MM_ALIGN - 1) >> MM_ALIGN_LOG2) + 1;
  int count = 0;

  if (!mm_base)
    goto fail;

  if (size > ~(size_t) align)
    goto fail;

  /* We currently assume at least a 32-bit size_t,
     so limiting allocations to <adress space size> - 1MiB
     in name of sanity is beneficial. */
  if ((size + align) > ~(size_t) 0x100000)
    goto fail;

  align = (align >> MM_ALIGN_LOG2);
  if (align == 0)
    align = 1;

#if 0
again:
#endif

  for (r = mm_base; r; r = r->next)
  {
    void *p;

    p = real_malloc (&(r->first), n, align);
    if (p)
      return p;
  }

  /* If failed, increase free memory somehow.  */
  switch (count)
  {
#if 0
    case 0:
      /* Invalidate disk caches.  */
      bl_disk_cache_invalidate_all ();
      count++;
      goto again;
#endif

#if 0
    case 1:
      /* Unload unneeded modules.  */
      bl_dl_unload_unneeded ();
      count++;
      goto again;
#endif

    default:
      break;
  }

fail:
  die ("out of memory\n");
  return 0;
}

/* Allocate SIZE bytes and return the pointer.  */
void *
malloc (size_t size)
{
  return memalign (0, size);
}

/* Allocate SIZE bytes, clear them and return the pointer.  */
void *
zalloc (size_t size)
{
  void *ret;

  ret = memalign (0, size);
  if (ret)
    memset (ret, 0, size);

  return ret;
}

/* Deallocate the pointer PTR.  */
void
free (void *ptr)
{
  mm_header_t p;
  mm_region_t r;

  if (! ptr)
    return;

  get_header_from_pointer (ptr, &p, &r);

  if (r->first->magic == MM_ALLOC_MAGIC)
  {
    p->magic = MM_FREE_MAGIC;
    r->first = p->next = p;
  }
  else
  {
    mm_header_t q, s;

    for (s = r->first, q = s->next; q <= p || q->next >= p; s = q, q = s->next)
    {
      if (q->magic != MM_FREE_MAGIC)
        die ("free magic is broken at %p: 0x%lx\n", q, (unsigned long) q->magic);

      if (q <= q->next && (q > p || q->next < p))
        break;
    }

    p->magic = MM_FREE_MAGIC;
    p->next = q->next;
    q->next = p;

    if (p->next + p->next->size == p)
    {
      p->magic = 0;
      p->next->size += p->size;
      q->next = p->next;
      p = p->next;
    }

    r->first = q;

    if (q == p + p->size)
    {
      q->magic = 0;
      p->size += q->size;
      if (q == s)
        s = p;
      s->next = p;
      q = s;
    }

    r->first = q;
  }
}

/* Reallocate SIZE bytes and return the pointer. The contents will be
   the same as that of PTR.  */
void *
realloc (void *ptr, size_t size)
{
  mm_header_t p;
  mm_region_t r;
  void *q;
  size_t n;

  if (! ptr)
    return malloc (size);

  if (! size)
  {
    free (ptr);
    return 0;
  }

  /* FIXME: Not optimal.  */
  n = ((size + MM_ALIGN - 1) >> MM_ALIGN_LOG2) + 1;
  get_header_from_pointer (ptr, &p, &r);

  if (p->size >= n)
    return ptr;

  q = malloc (size);
  if (! q)
    return q;

  /* We've already checked that p->size < n.  */
  memcpy (q, ptr, p->size << MM_ALIGN_LOG2);
  free (ptr);
  return q;
}
