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

#ifndef _ACPI_H
#define _ACPI_H 1

#include <ntboot.h>
#include <stdint.h>

#define EFI_ACPI_TABLE_GUID \
  { 0xeb9d2d30, 0x2d88, 0x11d3, \
    { 0x9a, 0x16, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d } \
  }

#define EFI_ACPI_20_TABLE_GUID  \
  { 0x8868e871, 0xe4f1, 0x11d3, \
    { 0xbc, 0x22, 0x0, 0x80, 0xc7, 0x3c, 0x88, 0x81 } \
  }

#define ACPI_RSDP_SIGNATURE "RSD PTR "
#define ACPI_RSDP_SIGNATURE_SIZE 8

struct acpi_rsdp_v10
{
  uint8_t signature[ACPI_RSDP_SIGNATURE_SIZE];
  uint8_t checksum;
  uint8_t oemid[6];
  uint8_t revision;
  uint32_t rsdt_addr;
} __attribute__ ((packed));

struct acpi_rsdp_v20
{
  struct acpi_rsdp_v10 rsdpv1;
  uint32_t length;
  uint64_t xsdt_addr;
  uint8_t checksum;
  uint8_t reserved[3];
} __attribute__ ((packed));

struct acpi_table_header
{
  uint8_t signature[4];
  uint32_t length;
  uint8_t revision;
  uint8_t checksum;
  uint8_t oemid[6];
  uint8_t oemtable[8];
  uint32_t oemrev;
  uint8_t creator_id[4];
  uint32_t creator_rev;
} __attribute__ ((packed));

#define ACPI_FADT_SIGNATURE "FACP"

struct acpi_fadt
{
  struct acpi_table_header hdr;
  uint32_t facs_addr;
  uint32_t dsdt_addr;
  uint8_t somefields1[20];
  uint32_t pm1a;
  uint8_t somefields2[8];
  uint32_t pmtimer;
  uint8_t somefields3[32];
  uint32_t flags;
  uint8_t somefields4[16];
  uint64_t facs_xaddr;
  uint64_t dsdt_xaddr;
  uint8_t somefields5[96];
} __attribute__ ((packed));

#define ACPI_MADT_SIGNATURE "APIC"

struct acpi_madt_entry_header
{
  uint8_t type;
  uint8_t len;
};

struct acpi_madt
{
  struct acpi_table_header hdr;
  uint32_t lapic_addr;
  uint32_t flags;
  struct acpi_madt_entry_header entries[0];
} __attribute__ ((packed));

enum
{
  ACPI_MADT_ENTRY_TYPE_LAPIC = 0,
  ACPI_MADT_ENTRY_TYPE_IOAPIC = 1,
  ACPI_MADT_ENTRY_TYPE_INTERRUPT_OVERRIDE = 2,
  ACPI_MADT_ENTRY_TYPE_LAPIC_NMI = 4,
  ACPI_MADT_ENTRY_TYPE_SAPIC = 6,
  ACPI_MADT_ENTRY_TYPE_LSAPIC = 7,
  ACPI_MADT_ENTRY_TYPE_PLATFORM_INT_SOURCE = 8
};

struct acpi_madt_entry_lapic
{
  struct acpi_madt_entry_header hdr;
  uint8_t acpiid;
  uint8_t apicid;
  uint32_t flags;
};

struct acpi_madt_entry_ioapic
{
  struct acpi_madt_entry_header hdr;
  uint8_t id;
  uint8_t pad;
  uint32_t address;
  uint32_t global_sys_interrupt;
};

struct acpi_madt_entry_interrupt_override
{
  struct acpi_madt_entry_header hdr;
  uint8_t bus;
  uint8_t source;
  uint32_t global_sys_interrupt;
  uint16_t flags;
} __attribute__ ((packed));


struct acpi_madt_entry_lapic_nmi
{
  struct acpi_madt_entry_header hdr;
  uint8_t acpiid;
  uint16_t flags;
  uint8_t lint;
} __attribute__ ((packed));

struct acpi_madt_entry_sapic
{
  struct acpi_madt_entry_header hdr;
  uint8_t id;
  uint8_t pad;
  uint32_t global_sys_interrupt_base;
  uint64_t addr;
};

struct acpi_madt_entry_lsapic
{
  struct acpi_madt_entry_header hdr;
  uint8_t cpu_id;
  uint8_t id;
  uint8_t eid;
  uint8_t pad[3];
  uint32_t flags;
  uint32_t cpu_uid;
  uint8_t cpu_uid_str[0];
};

struct acpi_madt_entry_platform_int_source
{
  struct acpi_madt_entry_header hdr;
  uint16_t flags;
  uint8_t inttype;
  uint8_t cpu_id;
  uint8_t cpu_eid;
  uint8_t sapic_vector;
  uint32_t global_sys_int;
  uint32_t src_flags;
};

enum
{
  ACPI_MADT_ENTRY_SAPIC_FLAGS_ENABLED = 1
};

#define ACPI_SLP_EN (1 << 13)
#define ACPI_SLP_TYP_OFFSET 10

enum
{
  ACPI_OPCODE_ZERO = 0, ACPI_OPCODE_ONE = 1,
  ACPI_OPCODE_NAME = 8, ACPI_OPCODE_ALIAS = 0x06,
  ACPI_OPCODE_BYTE_CONST = 0x0a,
  ACPI_OPCODE_WORD_CONST = 0x0b,
  ACPI_OPCODE_DWORD_CONST = 0x0c,
  ACPI_OPCODE_STRING_CONST = 0x0d,
  ACPI_OPCODE_SCOPE = 0x10,
  ACPI_OPCODE_BUFFER = 0x11,
  ACPI_OPCODE_PACKAGE = 0x12,
  ACPI_OPCODE_METHOD = 0x14, ACPI_OPCODE_EXTOP = 0x5b,
  ACPI_OPCODE_ADD = 0x72,
  ACPI_OPCODE_CONCAT = 0x73,
  ACPI_OPCODE_SUBTRACT = 0x74,
  ACPI_OPCODE_MULTIPLY = 0x77,
  ACPI_OPCODE_DIVIDE = 0x78,
  ACPI_OPCODE_LSHIFT = 0x79,
  ACPI_OPCODE_RSHIFT = 0x7a,
  ACPI_OPCODE_AND = 0x7b,
  ACPI_OPCODE_NAND = 0x7c,
  ACPI_OPCODE_OR = 0x7d,
  ACPI_OPCODE_NOR = 0x7e,
  ACPI_OPCODE_XOR = 0x7f,
  ACPI_OPCODE_CONCATRES = 0x84,
  ACPI_OPCODE_MOD = 0x85,
  ACPI_OPCODE_INDEX = 0x88,
  ACPI_OPCODE_CREATE_DWORD_FIELD = 0x8a,
  ACPI_OPCODE_CREATE_WORD_FIELD = 0x8b,
  ACPI_OPCODE_CREATE_BYTE_FIELD = 0x8c,
  ACPI_OPCODE_TOSTRING = 0x9c,
  ACPI_OPCODE_IF = 0xa0, ACPI_OPCODE_ONES = 0xff
};
enum
{
  ACPI_EXTOPCODE_MUTEX = 0x01,
  ACPI_EXTOPCODE_EVENT_OP = 0x02,
  ACPI_EXTOPCODE_OPERATION_REGION = 0x80,
  ACPI_EXTOPCODE_FIELD_OP = 0x81,
  ACPI_EXTOPCODE_DEVICE_OP = 0x82,
  ACPI_EXTOPCODE_PROCESSOR_OP = 0x83,
  ACPI_EXTOPCODE_POWER_RES_OP = 0x84,
  ACPI_EXTOPCODE_THERMAL_ZONE_OP = 0x85,
  ACPI_EXTOPCODE_INDEX_FIELD_OP = 0x86,
  ACPI_EXTOPCODE_BANK_FIELD_OP = 0x87,
};

struct acpi_bgrt
{
  struct acpi_table_header header;
  // 2-bytes (16 bit) version ID. This value must be 1.
  uint16_t version;
  // 1-byte status field indicating current status about the table.
  // Bits[7:1] = Reserved (must be zero)
  // Bit [0] = Valid. A one indicates the boot image graphic is valid.
  uint8_t status;
  // 0 = Bitmap
  // 1 - 255  Reserved (for future use)
  uint8_t type;
  // physical address pointing to the firmware's in-memory copy of the image.
  uint64_t addr;
  // (X, Y) display offset of the top left corner of the boot image.
  // The top left corner of the display is at offset (0, 0).
  uint32_t x;
  uint32_t y;
} __attribute__ ((packed));

struct bmp_header
{
  // bmfh
  uint8_t bftype[2];
  uint32_t bfsize;
  uint16_t bfreserved1;
  uint16_t bfreserved2;
  uint32_t bfoffbits;
  // bmih
  uint32_t bisize;
  int32_t biwidth;
  int32_t biheight;
  uint16_t biplanes;
  uint16_t bibitcount;
  uint32_t bicompression;
  uint32_t bisizeimage;
  int32_t bixpelspermeter;
  int32_t biypelspermeter;
  uint32_t biclrused;
  uint32_t biclrimportant;
} __attribute__ ((packed));

extern void
acpi_load_bgrt (void *file, size_t file_len);

extern void
acpi_shutdown (void);

#endif
