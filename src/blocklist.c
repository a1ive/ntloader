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

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <bootapp.h>
#include <cmdline.h>
#include <biosdisk.h>
#include <blocklist.h>
#include <wimboot.h>
#include <vdisk.h>

static void
read_blk_file (struct vdisk_file *file, void *data, size_t offset, size_t len)
{
  struct block_data *p;
  struct blocklist_data *blocklist = file->opaque;
  if (offset >= file->len)
    return;
  if (len > file->len - offset)
    len = file->len - offset;
  for (p = &blocklist->block[0]; p->length && len > 0; p++)
  {
    if (offset < p->length)
    {
      size_t size;
      size = len;
      if (offset + size > p->length)
        size = p->length - offset;
      biosdisk_read (0, p->offset + offset, size, data);
      len -= size;
      data += size;
      offset += size;
    }
    else
      offset -= p->length;
  }
}

static int found = 0;

struct vdisk_file *
blocklist_add_file (const char *name, void *data, size_t len)
{
  struct blocklist_data *blocklist = data;
  if (found)
    return NULL;
  if (len < sizeof (struct blocklist_data) + sizeof (struct block_data))
    return NULL;
  if (memcmp (blocklist->magic, "blk list", 8) != 0)
    return NULL;
  found = 1;
  biosdisk_init ();
  biosdisk_open (blocklist->drive);
  return vdisk_add_file (name, blocklist, blocklist->size, read_blk_file);
}
