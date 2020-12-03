/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020  Free Software Foundation, Inc.
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

#ifndef _BLOCKLIST_H
#define _BLOCKLIST_H

#include <stdint.h>
#include <vdisk.h>

struct block_data
{
  uint64_t offset;
  uint64_t length;
} __attribute__ ((packed));

struct blocklist_data
{
  char magic[8]; /* "blk list" */
  uint64_t size;
  int drive;
  struct block_data block[0];
} __attribute__ ((packed));

struct vdisk_file *blocklist_add_file (const char *name, void *data, size_t len);

#endif
