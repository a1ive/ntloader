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

#ifndef _MEMORY_HEADER
#define _MEMORY_HEADER    1

#include <stdint.h>

typedef enum memory_type
{
  MEMORY_AVAILABLE = 1,
  MEMORY_RESERVED = 2,
  MEMORY_ACPI = 3,
  MEMORY_NVS = 4,
  MEMORY_BADRAM = 5,
  MEMORY_PERSISTENT = 7,
  MEMORY_PERSISTENT_LEGACY = 12,
  MEMORY_COREBOOT_TABLES = 16,
  MEMORY_CODE = 20,
  /* This one is special: it's used internally but is never reported
     by firmware. Don't use -1 as it's used internally for other purposes. */
  MEMORY_HOLE = -2,
  MEMORY_MAX = 0x10000
}
memory_type_t;

struct mmap_region
{
  struct mmap_region *next;
  uint64_t start;
  uint64_t end;
  memory_type_t type;
  int handle;
  int priority;
};

typedef int (*memory_hook_t) (uint64_t, uint64_t, memory_type_t, void *);

#endif
