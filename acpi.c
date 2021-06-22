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
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ntboot.h>
#include <acpi.h>
#include <efi.h>
#include <efidisk.h>
#include <efilib.h>

static inline uint32_t
decode_length (const uint8_t *ptr, int *numlen)
{
  int num_bytes, i;
  uint32_t ret;
  if (*ptr < 64)
  {
    if (numlen)
      *numlen = 1;
    return *ptr;
  }
  num_bytes = *ptr >> 6;
  if (numlen)
    *numlen = num_bytes + 1;
  ret = *ptr & 0xf;
  ptr++;
  for (i = 0; i < num_bytes; i++)
  {
    ret |= *ptr << (8 * i + 4);
    ptr++;
  }
  return ret;
}

static inline uint32_t
skip_name_string (const uint8_t *ptr, const uint8_t *end)
{
  const uint8_t *ptr0 = ptr;

  while (ptr < end && (*ptr == '^' || *ptr == '\\'))
    ptr++;
  switch (*ptr)
  {
    case '.':
      ptr++;
      ptr += 8;
      break;
    case '/':
      ptr++;
      ptr += 1 + (*ptr) * 4;
      break;
    case 0:
      ptr++;
      break;
    default:
      ptr += 4;
      break;
  }
  return ptr - ptr0;
}

static inline uint32_t
skip_data_ref_object (const uint8_t *ptr, const uint8_t *end)
{
  switch (*ptr)
  {
    case ACPI_OPCODE_PACKAGE:
    case ACPI_OPCODE_BUFFER:
      return 1 + decode_length (ptr + 1, 0);
    case ACPI_OPCODE_ZERO:
    case ACPI_OPCODE_ONES:
    case ACPI_OPCODE_ONE:
      return 1;
    case ACPI_OPCODE_BYTE_CONST:
      return 2;
    case ACPI_OPCODE_WORD_CONST:
      return 3;
    case ACPI_OPCODE_DWORD_CONST:
      return 5;
    case ACPI_OPCODE_STRING_CONST:
    {
      const uint8_t *ptr0 = ptr;
      for (ptr++; ptr < end && *ptr; ptr++)
        ;
      if (ptr == end)
        return 0;
      return ptr - ptr0 + 1;
    }
    default:
      if (*ptr == '^' || *ptr == '\\' || *ptr == '_'
          || (*ptr >= 'A' && *ptr <= 'Z'))
        return skip_name_string (ptr, end);
      DBG ("Unknown opcode 0x%x\n", *ptr);
      return 0;
  }
}

static inline uint32_t
skip_term (const uint8_t *ptr, const uint8_t *end)
{
  uint32_t add;
  const uint8_t *ptr0 = ptr;

  switch(*ptr)
  {
    case ACPI_OPCODE_ADD:
    case ACPI_OPCODE_AND:
    case ACPI_OPCODE_CONCAT:
    case ACPI_OPCODE_CONCATRES:
    case ACPI_OPCODE_DIVIDE:
    case ACPI_OPCODE_INDEX:
    case ACPI_OPCODE_LSHIFT:
    case ACPI_OPCODE_MOD:
    case ACPI_OPCODE_MULTIPLY:
    case ACPI_OPCODE_NAND:
    case ACPI_OPCODE_NOR:
    case ACPI_OPCODE_OR:
    case ACPI_OPCODE_RSHIFT:
    case ACPI_OPCODE_SUBTRACT:
    case ACPI_OPCODE_TOSTRING:
    case ACPI_OPCODE_XOR:
      /*
       * Parameters for these opcodes: TermArg, TermArg Target, see ACPI
       * spec r5.0, page 828f.
       */
      ptr++;
      ptr += add = skip_term (ptr, end);
      if (!add)
        return 0;
      ptr += add = skip_term (ptr, end);
      if (!add)
        return 0;
      ptr += skip_name_string (ptr, end);
      break;
    default:
      return skip_data_ref_object (ptr, end);
  }
  return ptr - ptr0;
}

static inline uint32_t
skip_ext_op (const uint8_t *ptr, const uint8_t *end)
{
  const uint8_t *ptr0 = ptr;
  int add;
  switch (*ptr)
  {
    case ACPI_EXTOPCODE_MUTEX:
      ptr++;
      ptr += skip_name_string (ptr, end);
      ptr++;
      break;
    case ACPI_EXTOPCODE_EVENT_OP:
      ptr++;
      ptr += skip_name_string (ptr, end);
      break;
    case ACPI_EXTOPCODE_OPERATION_REGION:
      ptr++;
      ptr += skip_name_string (ptr, end);
      ptr++;
      ptr += add = skip_term (ptr, end);
      if (!add)
    return 0;
      ptr += add = skip_term (ptr, end);
      if (!add)
    return 0;
      break;
    case ACPI_EXTOPCODE_FIELD_OP:
    case ACPI_EXTOPCODE_DEVICE_OP:
    case ACPI_EXTOPCODE_PROCESSOR_OP:
    case ACPI_EXTOPCODE_POWER_RES_OP:
    case ACPI_EXTOPCODE_THERMAL_ZONE_OP:
    case ACPI_EXTOPCODE_INDEX_FIELD_OP:
    case ACPI_EXTOPCODE_BANK_FIELD_OP:
      ptr++;
      ptr += decode_length (ptr, 0);
      break;
    default:
      DBG ("Unexpected extended opcode: 0x%x\n", *ptr);
      return 0;
  }
  return ptr - ptr0;
}

static int
get_sleep_type (uint8_t *table, uint8_t *ptr, uint8_t *end,
                uint8_t *scope, int scope_len)
{
  uint8_t *prev = table;

  if (!ptr)
    ptr = table + sizeof (struct acpi_table_header);
  while (ptr < end && prev < ptr)
  {
    int add;
    prev = ptr;
    switch (*ptr)
    {
      case ACPI_OPCODE_EXTOP:
        ptr++;
        ptr += add = skip_ext_op (ptr, end);
        if (!add)
          return -1;
        break;
      case ACPI_OPCODE_CREATE_DWORD_FIELD:
      case ACPI_OPCODE_CREATE_WORD_FIELD:
      case ACPI_OPCODE_CREATE_BYTE_FIELD:
      {
        ptr += 5;
        ptr += add = skip_data_ref_object (ptr, end);
        if (!add)
          return -1;
        ptr += 4;
        break;
      }
      case ACPI_OPCODE_NAME:
        ptr++;
        if ((!scope || memcmp ((void *)scope, "\\", scope_len) == 0) &&
            (memcmp ((void *)ptr, "_S5_", 4) == 0 ||
             memcmp ((void *)ptr, "\\_S5_", 4) == 0))
        {
          int ll;
          uint8_t *ptr2 = ptr;
          ptr2 += skip_name_string (ptr, end);
          if (*ptr2 != 0x12)
          {
            DBG ("Unknown opcode in _S5: 0x%x\n", *ptr2);
            return -1;
          }
          ptr2++;
          decode_length (ptr2, &ll);
          ptr2 += ll;
          ptr2++;
          switch (*ptr2)
          {
            case ACPI_OPCODE_ZERO:
              return 0;
            case ACPI_OPCODE_ONE:
              return 1;
            case ACPI_OPCODE_BYTE_CONST:
              return ptr2[1];
            default:
              DBG ("Unknown data type in _S5: 0x%x\n", *ptr2);
              return -1;
          }
        }
        ptr += add = skip_name_string (ptr, end);
        if (!add)
          return -1;
        ptr += add = skip_data_ref_object (ptr, end);
        if (!add)
          return -1;
        break;
      case ACPI_OPCODE_ALIAS:
        ptr++;
        /* We need to skip two name strings */
        ptr += add = skip_name_string (ptr, end);
        if (!add)
          return -1;
        ptr += add = skip_name_string (ptr, end);
        if (!add)
          return -1;
        break;

      case ACPI_OPCODE_SCOPE:
      {
        int scope_sleep_type;
        int ll;
        uint8_t *name;
        int name_len;

        ptr++;
        add = decode_length (ptr, &ll);
        name = ptr + ll;
        name_len = skip_name_string (name, ptr + add);
        if (!name_len)
          return -1;
        scope_sleep_type = get_sleep_type (table, name + name_len,
                           ptr + add, name, name_len);
        if (scope_sleep_type != -2)
          return scope_sleep_type;
        ptr += add;
        break;
      }
      case ACPI_OPCODE_IF:
      case ACPI_OPCODE_METHOD:
      {
        ptr++;
        ptr += decode_length (ptr, 0);
        break;
      }
      default:
        DBG ("Unknown opcode 0x%x\n", *ptr);
        return -1;
    }
  }
  return -2;
}

static void *
efi_acpi_malloc (size_t size)
{
  efi_status_t efirc;
  void *ptr = NULL;
  efirc = efi_allocate_pool (EFI_ACPI_RECLAIM_MEMORY, size, &ptr);
  if (efirc != EFI_SUCCESS || ! ptr)
    die ("Could not allocate memory.\n");
  return ptr;
}

static uint8_t
acpi_byte_checksum (void *base, size_t size)
{
  uint8_t *ptr;
  uint8_t ret = 0;
  for (ptr = (uint8_t *) base; ptr < ((uint8_t *) base) + size; ptr++)
    ret += *ptr;
  return ret;
}

static struct acpi_rsdp_v10 *
efi_acpi_get_rsdpv1 (void)
{
  efi_uintn_t i;
  static efi_packed_guid_t acpi_guid = EFI_ACPI_TABLE_GUID;

  for (i = 0; i < efi_systab->num_table_entries; i++)
  {
    efi_packed_guid_t *guid = &efi_systab->configuration_table[i].vendor_guid;

    if (! memcmp (guid, &acpi_guid, sizeof (efi_packed_guid_t)))
      return efi_systab->configuration_table[i].vendor_table;
  }
  return 0;
}

static struct acpi_rsdp_v20 *
efi_acpi_get_rsdpv2 (void)
{
  efi_uintn_t i;
  static efi_packed_guid_t acpi20_guid = EFI_ACPI_20_TABLE_GUID;

  for (i = 0; i < efi_systab->num_table_entries; i++)
  {
    efi_packed_guid_t *guid = &efi_systab->configuration_table[i].vendor_guid;

    if (! memcmp (guid, &acpi20_guid, sizeof (efi_packed_guid_t)))
      return efi_systab->configuration_table[i].vendor_table;
  }
  return 0;
}

static struct acpi_rsdp_v10 *
bios_acpi_get_rsdpv1 (void)
{
  int ebda_len;
  uint8_t *ebda, *ptr;

  ebda = (uint8_t *) (intptr_t) ((* ((uint16_t *) 0x40e)) << 4);
  ebda_len = * (uint16_t *) ebda;
  if (! ebda_len) /* FIXME do we really need this check? */
    goto scan_bios;
  for (ptr = ebda; ptr < ebda + 0x400; ptr += 16)
    if (memcmp (ptr, ACPI_RSDP_SIGNATURE, ACPI_RSDP_SIGNATURE_SIZE) == 0 &&
        acpi_byte_checksum (ptr, sizeof (struct acpi_rsdp_v10)) == 0 &&
        ((struct acpi_rsdp_v10 *) ptr)->revision == 0)
      return (struct acpi_rsdp_v10 *) ptr;

scan_bios:
  for (ptr = (uint8_t *) 0xe0000; ptr < (uint8_t *) 0x100000; ptr += 16)
    if (memcmp (ptr, ACPI_RSDP_SIGNATURE, ACPI_RSDP_SIGNATURE_SIZE) == 0 &&
        acpi_byte_checksum (ptr, sizeof (struct acpi_rsdp_v10)) == 0 &&
        ((struct acpi_rsdp_v10 *) ptr)->revision == 0)
      return (struct acpi_rsdp_v10 *) ptr;
  return 0;
}

static struct acpi_rsdp_v20 *
bios_acpi_get_rsdpv2 (void)
{
  int ebda_len;
  uint8_t *ebda, *ptr;

  ebda = (uint8_t *) (intptr_t) ((* ((uint16_t *) 0x40e)) << 4);
  ebda_len = * (uint16_t *) ebda;
  if (! ebda_len) /* FIXME do we really need this check? */
    goto scan_bios;
  for (ptr = ebda; ptr < ebda + 0x400; ptr += 16)
    if (memcmp (ptr, ACPI_RSDP_SIGNATURE, ACPI_RSDP_SIGNATURE_SIZE) == 0 &&
        acpi_byte_checksum (ptr, sizeof (struct acpi_rsdp_v10)) == 0 &&
        ((struct acpi_rsdp_v10 *) ptr)->revision != 0 &&
        ((struct acpi_rsdp_v20 *) ptr)->length < 1024 &&
        acpi_byte_checksum (ptr, ((struct acpi_rsdp_v20 *) ptr)->length) == 0)
      return (struct acpi_rsdp_v20 *) ptr;

scan_bios:
  for (ptr = (uint8_t *) 0xe0000; ptr < (uint8_t *) 0x100000; ptr += 16)
    if (memcmp (ptr, ACPI_RSDP_SIGNATURE, ACPI_RSDP_SIGNATURE_SIZE) == 0 &&
        acpi_byte_checksum (ptr, sizeof (struct acpi_rsdp_v10)) == 0 &&
        ((struct acpi_rsdp_v10 *) ptr)->revision != 0 &&
        ((struct acpi_rsdp_v20 *) ptr)->length < 1024 &&
        acpi_byte_checksum (ptr, ((struct acpi_rsdp_v20 *) ptr)->length) == 0)
      return (struct acpi_rsdp_v20 *) ptr;
  return 0;
}

static struct acpi_rsdp_v20 *
acpi_get_rsdpv2 (void)
{
  if (efi_systab)
    return efi_acpi_get_rsdpv2 ();
  return bios_acpi_get_rsdpv2 ();
}

static struct acpi_rsdp_v10 *
acpi_get_rsdpv1 (void)
{
  if (efi_systab)
    return efi_acpi_get_rsdpv1 ();
  return bios_acpi_get_rsdpv1 ();
}

static efi_boolean_t
bmp_sanity_check (char *buf, size_t size)
{
  // check BMP magic
  if (memcmp ("BM", buf, 2) != 0)
  {
    DBG ("Unsupported image file.\n");
    return FALSE;
  }
  // check BMP header size
  struct bmp_header *bmp = (struct bmp_header *) buf;
  if (size < bmp->bfsize)
  {
    DBG ("Bad BMP file.\n");
    return FALSE;
  }

  return TRUE;
}

static void *
acpi_get_bgrt (struct acpi_table_header *xsdt)
{
  struct acpi_table_header *entry;
  unsigned entry_cnt, i;
  uint64_t *entry_ptr;
  entry_cnt = (xsdt->length
               - sizeof (struct acpi_table_header)) / sizeof(uint64_t);
  entry_ptr = (uint64_t *)(xsdt + 1);
  for (i = 0; i < entry_cnt; i++, entry_ptr++)
  {
    entry = (struct acpi_table_header *)(intptr_t)(*entry_ptr);
    if (memcmp (entry->signature, "BGRT", 4) == 0)
    {
      DBG ("found BGRT: %p\n", entry);
      return entry;
    }
  }
  DBG ("BGRT not found.\n");
  return 0;
}

static void
efi_gop_get_best_mode (uint32_t *w, uint32_t *h)
{
  efi_gop_t *gop = 0;
  uint32_t mode, max_val = 0, val;
  struct efi_gop_mode_info *info = 0;
  efi_uintn_t size;
  efi_status_t status;

  *w = 1024;
  *h = 768;
  gop = efi_locate_protocol (&efi_gop_guid, NULL);
  if (!gop)
  {
    DBG ("Graphics Output Protocol not found.\n");
    return;
  }

  DBG ("%d modes detected.\n", gop->mode->max_mode);
  for (mode = 0; mode < gop->mode->max_mode; mode++)
  {
    status = gop->query_mode (gop, mode, &size, &info);
    if (status != EFI_SUCCESS)
    {
      info = 0;
      continue;
    }

    DBG ("mode %d: %dx%d\n", mode, info->width, info->height);
    val = info->width * info->height;
    if (val > max_val)
    {
      max_val = val;
      *w = info->width;
      *h = info->height;
    }
    efi_free_pool (info);
  }
}

static void
acpi_calc_bgrt_xy (struct bmp_header *bmp, uint32_t *x, uint32_t *y)
{
  uint32_t screen_width;
  uint32_t screen_height;
  uint32_t bmp_width = (uint32_t) bmp->biwidth;
  uint32_t bmp_height = (uint32_t) bmp->biheight;

  *x = *y = 0;
  efi_gop_get_best_mode (&screen_width, &screen_height);
  DBG ("screen = %dx%d, image = %dx%d\n",
       screen_width, screen_height, bmp_width, bmp_height);
  if (screen_width > bmp_width)
    *x = (screen_width - bmp_width) / 2;
  if (screen_height > bmp_height)
    *y = (screen_height - bmp_height) / 2;
  DBG ("offset_x=%d, offset_y=%d\n", *x, *y);
}

void
acpi_load_bgrt (void *file, size_t file_len)
{
  struct acpi_bgrt *bgrt = 0;
  struct acpi_table_header *xsdt = 0;
  struct acpi_rsdp_v20 *rsdp = 0;
  struct bmp_header *bgrt_bmp = 0;
  uint32_t x, y;
  rsdp = efi_acpi_get_rsdpv2 ();
  if (!rsdp)
  {
    DBG ("ACPI RSDP v2 not found.\n");
    return;
  }
  xsdt = (struct acpi_table_header *)(intptr_t)(rsdp->xsdt_addr);
  if (memcmp (xsdt->signature, "XSDT", 4) != 0)
  {
    DBG ("invalid XSDT table\n");
    return;
  }
  bgrt = acpi_get_bgrt (xsdt);
  if (!file || !file_len)
  {
    if (bgrt)
      bgrt->status = 0x00;
    return;
  }
  if (!bmp_sanity_check (file, file_len))
    return;
  bgrt_bmp = efi_acpi_malloc (file_len);
  memcpy (bgrt_bmp, file, file_len);
  acpi_calc_bgrt_xy (bgrt_bmp, &x, &y);
  if (!bgrt)
  {
    struct acpi_table_header *new_xsdt = 0;
    uint64_t *new_xsdt_entry;
    uint32_t entry_num;
    new_xsdt = efi_acpi_malloc (xsdt->length + sizeof(uint64_t));
    bgrt = efi_acpi_malloc (sizeof (struct acpi_bgrt));
    memcpy (new_xsdt, xsdt, xsdt->length);
    new_xsdt->length += sizeof (uint64_t);
    new_xsdt_entry = (uint64_t *)(new_xsdt + 1);
    entry_num =
      (new_xsdt->length - sizeof (struct acpi_table_header)) / sizeof(uint64_t);
    new_xsdt_entry[entry_num - 1] = (uint64_t) (size_t) bgrt;
    new_xsdt->checksum = 0;
    new_xsdt->checksum = 1 + ~acpi_byte_checksum (xsdt, xsdt->length);
    rsdp->xsdt_addr = (uint64_t) (size_t) new_xsdt;
    rsdp->checksum = 0;
    rsdp->checksum = 1 + ~acpi_byte_checksum (rsdp, rsdp->length);
  }
  bgrt->x = x;
  bgrt->y = y;
  memcpy (bgrt->header.signature, "BGRT", 4);
  memcpy (bgrt->header.oemid, "A1ive ", 6);
  memcpy (bgrt->header.oemtable, "NTLOADER", 8);
  memcpy (bgrt->header.creator_id, "NTLD", 4);
  bgrt->header.creator_rev = 1;
  bgrt->header.oemrev = 1;
  bgrt->header.length = sizeof (struct acpi_bgrt);
  bgrt->header.revision = 1;
  bgrt->version = 1;
  bgrt->status = 0x01;
  bgrt->type = 0;
  bgrt->addr = (uint64_t)(intptr_t) bgrt_bmp;
  bgrt->header.checksum = 0;
  bgrt->header.checksum = 1 + ~acpi_byte_checksum (bgrt, bgrt->header.length);
}

void
acpi_shutdown (void)
{
  struct acpi_rsdp_v20 *rsdp2 = NULL;
  struct acpi_rsdp_v10 *rsdp1 = NULL;
  struct acpi_table_header *rsdt;
  uint32_t *entry_ptr;
  uint32_t port = 0;
  int sleep_type = -1;

  rsdp2 = acpi_get_rsdpv2 ();
  if (rsdp2)
    rsdp1 = &(rsdp2->rsdpv1);
  else
    rsdp1 = acpi_get_rsdpv1 ();
  if (!rsdp1)
  {
    DBG ("ACPI shutdown not supported.\n");
    return;
  }

  rsdt = (struct acpi_table_header *) (intptr_t) rsdp1->rsdt_addr;
  for (entry_ptr = (uint32_t *) (rsdt + 1);
       entry_ptr < (uint32_t *) (((uint8_t *) rsdt) + rsdt->length);
       entry_ptr++)
  {
    if (memcmp ((void *) (intptr_t) *entry_ptr, "FACP", 4) == 0)
    {
      struct acpi_fadt *fadt
        = ((struct acpi_fadt *) (intptr_t) *entry_ptr);
      struct acpi_table_header *dsdt
        = (struct acpi_table_header *) (intptr_t) fadt->dsdt_addr;
      uint8_t *buf = (uint8_t *) dsdt;

      port = fadt->pm1a;

      if (memcmp ((void *)dsdt->signature, "DSDT", sizeof (dsdt->signature)) == 0
          && sleep_type < 0)
        sleep_type = get_sleep_type (buf, NULL, buf + dsdt->length, NULL, 0);
    }
    else if (memcmp ((void *) (intptr_t) *entry_ptr, "SSDT", 4) == 0
             && sleep_type < 0)
    {
      struct acpi_table_header *ssdt
        = (struct acpi_table_header *) (intptr_t) *entry_ptr;
      uint8_t *buf = (uint8_t *) ssdt;

      sleep_type = get_sleep_type (buf, NULL, buf + ssdt->length, NULL, 0);
    }
  }

  if (port && sleep_type >= 0 && sleep_type < 8)
  {
    asm volatile ("outw %w0,%w1" : :"a" ((unsigned short int)
        (ACPI_SLP_EN | (sleep_type << ACPI_SLP_TYP_OFFSET))),
        "Nd" ((unsigned short int) (port & 0xffff)));
  }

  DBG ("ACPI shutdown failed\n");
}
