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

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ntboot.h>
#include <charset.h>
#include <efilib.h>

#if defined (__x86_64__)
  #if defined (__code_model_large__)
    #define EFI_MAX_USABLE_ADDRESS 0xffffffff
  #else
    #define EFI_MAX_USABLE_ADDRESS 0x7fffffff
  #endif
#else
  #define EFI_MAX_USABLE_ADDRESS   0xffffffff
#endif

#define NEXT_MEMORY_DESCRIPTOR(desc, size)  \
  ((efi_memory_descriptor_t *) ((char *) (desc) + (size)))

/* The size of a memory map obtained from the firmware. This must be
   a multiplier of 4KB.  */
#define MEMORY_MAP_SIZE   0x3000

/* The minimum and maximum heap size for GRUB itself.  */
#define MIN_HEAP_SIZE     0x100000
#define MAX_HEAP_SIZE     (1600 * 0x100000)

/*
 * We need to roll back EFI allocations on exit. Remember allocations that
 * we'll free on exit.
 */
struct efi_allocation;
struct efi_allocation
{
  efi_physical_address_t address;
  efi_uint64_t pages;
  struct efi_allocation *next;
};
static struct efi_allocation *efi_allocated_memory;

static void
bl_efi_store_alloc (efi_physical_address_t address, efi_uintn_t pages)
{
  efi_boot_services_t *b;
  struct efi_allocation *alloc;
  efi_status_t status;

  b = efi_systab->boot_services;
  status = b->allocate_pool (EFI_LOADER_DATA, sizeof(*alloc), (void**)&alloc);

  if (status == EFI_SUCCESS)
  {
    alloc->next = efi_allocated_memory;
    alloc->address = address;
    alloc->pages = pages;
    efi_allocated_memory = alloc;
  }
  else
    printf ("Could not malloc memory to remember EFI allocation.\n");
}

static void
bl_efi_drop_alloc (efi_physical_address_t address, efi_uintn_t pages)
{
  struct efi_allocation *ea, *eap;
  efi_boot_services_t *b;

  b = efi_systab->boot_services;

  for (eap = NULL, ea = efi_allocated_memory; ea; eap = ea, ea = ea->next)
  {
    if (ea->address != address || ea->pages != pages)
      continue;

    /* Remove the current entry from the list. */
    if (eap)
      eap->next = ea->next;
    else
      efi_allocated_memory = ea->next;

    /* Then free the memory backing it. */
    b->free_pool (ea);

    /* And leave, we're done. */
    break;
  }
}

/* Allocate pages. Return the pointer to the first of allocated pages.  */
void *
efi_allocate_pages_real (efi_physical_address_t address,
                         efi_uintn_t pages,
                         efi_allocate_type_t alloctype,
                         efi_memory_type_t memtype)
{
  efi_status_t status;
  efi_boot_services_t *b;

  /* Limit the memory access to less than 4GB for 32-bit platforms.  */
  if (address > EFI_MAX_USABLE_ADDRESS)
    die ("invalid memory address");

  b = efi_systab->boot_services;
  status = b->allocate_pages (alloctype, memtype, pages, &address);
  if (status != EFI_SUCCESS)
    die ("out of memory");

  if (address == 0)
  {
    /* Uggh, the address 0 was allocated... Reallocate another one.  */
    address = EFI_MAX_USABLE_ADDRESS;
    status = b->allocate_pages (alloctype, memtype, pages, &address);
    efi_free_pages (0, pages);
    if (status != EFI_SUCCESS)
      die ("out of memory");
  }

  bl_efi_store_alloc (address, pages);

  return (void *) ((intptr_t) address);
}

/* Allocate pages below a specified address */
void *
efi_allocate_pages_max (efi_physical_address_t max, efi_uintn_t pages)
{
  return efi_allocate_pages_real (max, pages,
                                  EFI_ALLOCATE_MAX_ADDRESS, EFI_LOADER_DATA);
}

void *
efi_allocate_any_pages (efi_uintn_t pages)
{
  return efi_allocate_pages_real (EFI_MAX_USABLE_ADDRESS, pages,
                                  EFI_ALLOCATE_MAX_ADDRESS, EFI_LOADER_DATA);
}

void *
efi_allocate_fixed (efi_physical_address_t address, efi_uintn_t pages)
{
  return efi_allocate_pages_real (address, pages,
                                  EFI_ALLOCATE_ADDRESS, EFI_LOADER_DATA);
}

/* Free pages starting from ADDRESS.  */
void
efi_free_pages (efi_physical_address_t address, efi_uintn_t pages)
{
  efi_boot_services_t *b = efi_systab->boot_services;
  b->free_pages (address, pages);
  bl_efi_drop_alloc (address, pages);
}

/*
 * To obtain the UEFI memory map, we must pass a buffer of sufficient size
 * to hold the entire map. This function returns a sane start value for
 * buffer size.
 */
efi_uintn_t
bl_efi_find_mmap_size (void)
{
  efi_uintn_t mmap_size = 0;
  efi_uintn_t desc_size;

  if (efi_get_memory_map (&mmap_size, NULL, NULL, &desc_size, 0) < 0)
  {
    printf ("cannot get EFI memory map size\n");
    return 0;
  }

  /*
   * Add an extra page, since UEFI can alter the memory map itself on
   * callbacks or explicit calls, including console output.
   */
  return ALIGN_UP (mmap_size + PAGE_SIZE, PAGE_SIZE);
}

/* Get the memory map as defined in the EFI spec. Return 1 if successful,
   return 0 if partial, or return -1 if an error occurs.  */
int
efi_get_memory_map (efi_uintn_t *memory_map_size,
                    efi_memory_descriptor_t *memory_map,
                    efi_uintn_t *map_key,
                    efi_uintn_t *descriptor_size,
                    efi_uint32_t *descriptor_version)
{
  efi_status_t status;
  efi_boot_services_t *b;
  efi_uintn_t key;
  efi_uint32_t version;
  efi_uintn_t size;

  /* Allow some parameters to be missing.  */
  if (! map_key)
    map_key = &key;
  if (! descriptor_version)
    descriptor_version = &version;
  if (! descriptor_size)
    descriptor_size = &size;

  b = efi_systab->boot_services;
  status = b->get_memory_map (memory_map_size, memory_map, map_key,
                              descriptor_size, descriptor_version);
  if (*descriptor_size == 0)
    *descriptor_size = sizeof (efi_memory_descriptor_t);
  if (status == EFI_SUCCESS)
    return 1;
  else if (status == EFI_BUFFER_TOO_SMALL)
    return 0;
  else
    return -1;
}

/* Sort the memory map in place.  */
static void
sort_memory_map (efi_memory_descriptor_t *memory_map,
                 efi_uintn_t desc_size, efi_memory_descriptor_t *memory_map_end)
{
  efi_memory_descriptor_t *d1;
  efi_memory_descriptor_t *d2;

  for (d1 = memory_map; d1 < memory_map_end;
       d1 = NEXT_MEMORY_DESCRIPTOR (d1, desc_size))
  {
    efi_memory_descriptor_t *max_desc = d1;

    for (d2 = NEXT_MEMORY_DESCRIPTOR (d1, desc_size);
         d2 < memory_map_end; d2 = NEXT_MEMORY_DESCRIPTOR (d2, desc_size))
    {
      if (max_desc->num_pages < d2->num_pages)
        max_desc = d2;
    }

    if (max_desc != d1)
    {
      efi_memory_descriptor_t tmp;
      tmp = *d1;
      *d1 = *max_desc;
      *max_desc = tmp;
    }
  }
}

/* Filter the descriptors. LOADER needs only available memory.  */
static efi_memory_descriptor_t *
filter_memory_map (efi_memory_descriptor_t *memory_map,
                   efi_memory_descriptor_t *filtered_memory_map,
                   efi_uintn_t desc_size,
                   efi_memory_descriptor_t *memory_map_end)
{
  efi_memory_descriptor_t *desc;
  efi_memory_descriptor_t *filtered_desc;

  for (desc = memory_map, filtered_desc = filtered_memory_map;
       desc < memory_map_end;
       desc = NEXT_MEMORY_DESCRIPTOR (desc, desc_size))
  {
    if (desc->type == EFI_CONVENTIONAL_MEMORY
#if 1
        && desc->physical_start <= EFI_MAX_USABLE_ADDRESS
#endif
        && desc->physical_start + PAGES_TO_BYTES (desc->num_pages) > 0x100000
        && desc->num_pages != 0)
    {
      memcpy (filtered_desc, desc, desc_size);
      /* Avoid less than 1MB, because some loaders seem to be confused.  */
      if (desc->physical_start < 0x100000)
      {
        desc->num_pages -= BYTES_TO_PAGES (0x100000 - desc->physical_start);
        desc->physical_start = 0x100000;
      }

#if 1
      if (BYTES_TO_PAGES (filtered_desc->physical_start)
          + filtered_desc->num_pages
          > BYTES_TO_PAGES_DOWN (EFI_MAX_USABLE_ADDRESS))
        filtered_desc->num_pages
          = (BYTES_TO_PAGES_DOWN (EFI_MAX_USABLE_ADDRESS)
          - BYTES_TO_PAGES (filtered_desc->physical_start));
#endif

      if (filtered_desc->num_pages == 0)
        continue;

      filtered_desc = NEXT_MEMORY_DESCRIPTOR (filtered_desc, desc_size);
    }
  }
  return filtered_desc;
}

/* Return the total number of pages.  */
static efi_uint64_t
get_total_pages (efi_memory_descriptor_t *memory_map,
                 efi_uintn_t desc_size,
                 efi_memory_descriptor_t *memory_map_end)
{
  efi_memory_descriptor_t *desc;
  efi_uint64_t total = 0;

  for (desc = memory_map;
       desc < memory_map_end;
       desc = NEXT_MEMORY_DESCRIPTOR (desc, desc_size))
    total += desc->num_pages;

  return total;
}

/* Add memory regions.  */
static void
add_memory_regions (efi_memory_descriptor_t *memory_map,
                    efi_uintn_t desc_size,
                    efi_memory_descriptor_t *memory_map_end,
                    efi_uint64_t required_pages)
{
  efi_memory_descriptor_t *desc;

  for (desc = memory_map;
       desc < memory_map_end;
       desc = NEXT_MEMORY_DESCRIPTOR (desc, desc_size))
  {
    efi_uint64_t pages;
    efi_physical_address_t start;
    void *addr;

    start = desc->physical_start;
    pages = desc->num_pages;
    if (pages > required_pages)
    {
      start += PAGES_TO_BYTES (pages - required_pages);
      pages = required_pages;
    }

    addr = efi_allocate_pages_real (start, pages,
                                    EFI_ALLOCATE_ADDRESS, EFI_LOADER_CODE);
    if (! addr)
      die ("cannot allocate conventional memory %p with %u pages",
           (void *) ((size_t) start), (unsigned) pages);

    mm_init_region (addr, PAGES_TO_BYTES (pages));

    required_pages -= pages;
    if (required_pages == 0)
      break;
  }

  if (required_pages > 0)
    die ("too little memory");
}

void
efi_mm_fini (void)
{
  /*
   * Free all stale allocations. bl_efi_free_pages() will remove
   * the found entry from the list and it will always find the first
   * list entry (efi_allocated_memory is the list start). Hence we
   * remove all entries from the list until none is left altogether.
   */
  while (efi_allocated_memory)
    efi_free_pages (efi_allocated_memory->address,
                    efi_allocated_memory->pages);
}

void
efi_mm_init (void)
{
  efi_memory_descriptor_t *memory_map;
  efi_memory_descriptor_t *memory_map_end;
  efi_memory_descriptor_t *filtered_memory_map;
  efi_memory_descriptor_t *filtered_memory_map_end;
  efi_uintn_t map_size;
  efi_uintn_t desc_size;
  efi_uint64_t total_pages;
  efi_uint64_t required_pages;
  int mm_status;

  /* Prepare a memory region to store two memory maps.  */
  memory_map = efi_allocate_any_pages (2 * BYTES_TO_PAGES (MEMORY_MAP_SIZE));
  if (! memory_map)
    die ("cannot allocate memory");

  /* Obtain descriptors for available memory.  */
  map_size = MEMORY_MAP_SIZE;

  mm_status = efi_get_memory_map (&map_size, memory_map, 0, &desc_size, 0);

  if (mm_status == 0)
  {
    efi_free_pages ((efi_physical_address_t) ((intptr_t) memory_map),
                    2 * BYTES_TO_PAGES (MEMORY_MAP_SIZE));
    /* Freeing/allocating operations may increase memory map size.  */
    map_size += desc_size * 32;
    memory_map = efi_allocate_any_pages (2 * BYTES_TO_PAGES (map_size));
    if (! memory_map)
      die ("cannot allocate memory");

    mm_status = efi_get_memory_map (&map_size, memory_map, 0, &desc_size, 0);
  }

  if (mm_status < 0)
    die ("cannot get memory map");

  memory_map_end = NEXT_MEMORY_DESCRIPTOR (memory_map, map_size);

  filtered_memory_map = memory_map_end;

  filtered_memory_map_end = filter_memory_map (memory_map, filtered_memory_map,
                                               desc_size, memory_map_end);

  /* By default, request a quarter of the available memory.  */
  total_pages = get_total_pages (filtered_memory_map, desc_size,
                                 filtered_memory_map_end);
  required_pages = (total_pages >> 2);
  if (required_pages < BYTES_TO_PAGES (MIN_HEAP_SIZE))
    required_pages = BYTES_TO_PAGES (MIN_HEAP_SIZE);
  else if (required_pages > BYTES_TO_PAGES (MAX_HEAP_SIZE))
    required_pages = BYTES_TO_PAGES (MAX_HEAP_SIZE);

  /* Sort the filtered descriptors, so that GRUB can allocate pages
     from smaller regions.  */
  sort_memory_map (filtered_memory_map, desc_size, filtered_memory_map_end);

  /* Allocate memory regions for GRUB's memory management.  */
  add_memory_regions (filtered_memory_map, desc_size,
                      filtered_memory_map_end, required_pages);

  /* Release the memory maps.  */
  efi_free_pages ((intptr_t) memory_map, 2 * BYTES_TO_PAGES (MEMORY_MAP_SIZE));
}
