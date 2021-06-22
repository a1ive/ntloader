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

#ifndef _GPT_PART_H
#define _GPT_PART_H    1

#include <ntboot.h>
#include <stdint.h>

typedef packed_guid_t gpt_part_guid_t;
typedef packed_guid_t gpt_guid_t;

#define GPT_GUID_INIT(a, b, c, d1, d2, d3, d4, d5, d6, d7, d8)  \
  {                    \
    (uint32_t) (a),    \
    (uint16_t) (b),    \
    (uint16_t) (c),    \
    { d1, d2, d3, d4, d5, d6, d7, d8 }    \
  }

#define GPT_PART_TYPE_EMPTY \
  GPT_GUID_INIT (0x0, 0x0, 0x0,  \
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)

#define GPT_PART_TYPE_EFI_SYSTEM \
  GPT_GUID_INIT (0xc12a7328, 0xf81f, 0x11d2, \
      0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b)

#define GPT_PART_TYPE_BIOS_BOOT \
  GPT_GUID_INIT (0x21686148, 0x6449, 0x6e6f, \
      0x74, 0x4e, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49)

#define GPT_PART_TYPE_LDM \
  GPT_GUID_INIT (0x5808c8aa, 0x7e8f, 0x42e0, \
      0x85, 0xd2, 0xe1, 0xe9, 0x04, 0x34, 0xcf, 0xb3)

#define GPT_PART_TYPE_USR_X86_64 \
  GPT_GUID_INIT (0x5dfbf5f4, 0x2848, 0x4bac, \
      0xaa, 0x5e, 0x0d, 0x9a, 0x20, 0xb7, 0x45, 0xa6)

#define GPT_HEADER_MAGIC \
  { 0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54 }

#define GPT_HEADER_VERSION (0x00010000U)

struct gpt_header
{
  uint8_t magic[8];
  uint32_t version;
  uint32_t headersize;
  uint32_t crc32;
  uint32_t unused1;
  uint64_t header_lba;
  uint64_t alternate_lba;
  uint64_t start;
  uint64_t end;
  gpt_guid_t guid;
  uint64_t partitions;
  uint32_t maxpart;
  uint32_t entry_size;
  uint32_t entry_crc32;
} __attribute__ ((packed));

struct gpt_part_entry
{
  gpt_part_guid_t type;
  gpt_part_guid_t guid;
  uint64_t start;
  uint64_t end;
  uint64_t attrib;
  uint16_t name[36];
} __attribute__ ((packed));

extern int
check_gpt_partmap (void *disk,
                   int (*disk_read) (void *disk, uint64_t sector,
                                     size_t len, void *buf));

#endif
