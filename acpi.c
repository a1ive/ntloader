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
#include <string.h>
#include <ntboot.h>
#include <acpi.h>
#include <efi.h>
#include <efidisk.h>
#include <efi/Protocol/GraphicsOutput.h>

static void *
efi_acpi_malloc (UINTN size)
{
  EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
  EFI_STATUS efirc;
  void *ptr = NULL;
  efirc = bs->AllocatePool (EfiACPIReclaimMemory, size, &ptr);
  if (efirc != EFI_SUCCESS || ! ptr)
    die ("Could not allocate memory.\n");
  return ptr;
}

#if 0
static struct acpi_rsdp_v10 *
efi_acpi_get_rsdpv1 (void)
{
  UINTN i;
  static EFI_GUID acpi_guid = EFI_ACPI_TABLE_GUID;

  for (i = 0; i < efi_systab->NumberOfTableEntries; i++)
  {
    EFI_GUID *guid = &efi_systab->ConfigurationTable[i].VendorGuid;

    if (! memcmp (guid, &acpi_guid, sizeof (EFI_GUID)))
      return efi_systab->ConfigurationTable[i].VendorTable;
  }
  return 0;
}
#endif

static struct acpi_rsdp_v20 *
efi_acpi_get_rsdpv2 (void)
{
  UINTN i;
  static EFI_GUID acpi20_guid = EFI_ACPI_20_TABLE_GUID;

  for (i = 0; i < efi_systab->NumberOfTableEntries; i++)
  {
    EFI_GUID *guid = &efi_systab->ConfigurationTable[i].VendorGuid;

    if (! memcmp (guid, &acpi20_guid, sizeof (EFI_GUID)))
      return efi_systab->ConfigurationTable[i].VendorTable;
  }
  return 0;
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

static BOOLEAN
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
  EFI_GRAPHICS_OUTPUT_PROTOCOL* gop = 0;
  EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
  EFI_STATUS status;
  uint32_t mode, max_val = 0, val;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info = 0;
  UINTN size;

  *w = 1024;
  *h = 768;
  status = bs->LocateProtocol (&efi_graphics_output_protocol_guid,
                               NULL, (void **) &gop);
  if (status != EFI_SUCCESS)
  {
    DBG ("Graphics Output Protocol not found.\n");
    return;
  }

  DBG ("%d modes detected.\n", gop->Mode->MaxMode);
  for (mode = 0; mode < gop->Mode->MaxMode; mode++)
  {
    status = gop->QueryMode (gop, mode, &size, &info);
    if (status != EFI_SUCCESS)
    {
      info = 0;
      continue;
    }

    DBG ("mode %d: %dx%d\n", mode,
         info->HorizontalResolution, info->VerticalResolution);
    val = info->HorizontalResolution * info->VerticalResolution;
    if (val > max_val)
    {
      max_val = val;
      *w = info->HorizontalResolution;
      *h = info->VerticalResolution;
    }
    efi_free (info);
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

