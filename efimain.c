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

/**
 * @file
 *
 * EFI entry point
 *
 */

#include <stdio.h>
#include <wchar.h>
#include <ntboot.h>
#include <cmdline.h>
#include <efi.h>
#include <efiblock.h>
#include <efidisk.h>
#include <string.h>
#include <strings.h>
#include <cpio.h>
#include <vdisk.h>
#include <lznt1.h>
#include <bcd.h>
#include <charset.h>
#include <acpi.h>
#include <linux.h>
#include <efi/Protocol/BlockIo.h>
#include <efi/Protocol/DevicePath.h>
#include <efi/Protocol/GraphicsOutput.h>
#include <efi/Protocol/LoadedImage.h>
#include <efi/Protocol/SimpleFileSystem.h>

/** EFI system table */
EFI_SYSTEM_TABLE *efi_systab = 0;

/** EFI image handle */
EFI_HANDLE efi_image_handle = 0;

/** Block I/O protocol GUID */
EFI_GUID efi_block_io_protocol_guid
  = EFI_BLOCK_IO_PROTOCOL_GUID;

/** Device path protocol GUID */
EFI_GUID efi_device_path_protocol_guid
  = EFI_DEVICE_PATH_PROTOCOL_GUID;

/** Graphics output protocol GUID */
EFI_GUID efi_graphics_output_protocol_guid
  = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;

/** Loaded image protocol GUID */
EFI_GUID efi_loaded_image_protocol_guid
  = EFI_LOADED_IMAGE_PROTOCOL_GUID;

/** Simple file system protocol GUID */
EFI_GUID efi_simple_file_system_protocol_guid
  = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

/** bootmgfw.efi file */
static struct vdisk_file *bootmgfw = NULL;

#if __x86_64__
  #define BOOT_FILE_NAME  "BOOTX64.EFI"
#elif __i386__
  #define BOOT_FILE_NAME  "BOOTIA32.EFI"
#else
  #error Unknown Processor Type
#endif

static void efi_load_vgashim (void *file, size_t len)
{
  EFI_PHYSICAL_ADDRESS phys;
  void *data;
  unsigned int pages;
  EFI_HANDLE handle;
  EFI_STATUS efirc;
  EFI_BOOT_SERVICES *bs = efi_systab->BootServices;

  if (!file || !len)
    return;
  pages = ((len + PAGE_SIZE - 1) / PAGE_SIZE);
  if ((efirc = bs->AllocatePages (AllocateAnyPages,
                                  EfiBootServicesData, pages, &phys)) != 0)
   return;
  data = ((void *) (intptr_t) phys);
  memcpy (data, file, len);
  DBG ("Loading vgashim\n");
  efirc = bs->LoadImage (FALSE, efi_image_handle, NULL, data, len, &handle);
  if (nt_cmdline->pause)
    pause_boot ();
  if (efirc == EFI_SUCCESS)
    bs->StartImage (handle, NULL, NULL);
  else
    DBG ("Could not load vgashim\n");
  if (nt_cmdline->pause)
    pause_boot ();
}

/**
 * File handler
 *
 * @v name              File name
 * @v data              File data
 * @v len               Length
 * @ret rc              Return status code
 */
static int efi_add_file (const char *name, void *data, size_t len)
{
  /* Check for special-case files */
  if ((strcasecmp (name, "bcdwin") == 0 && nt_cmdline->type == BOOT_WIN) ||
      (strcasecmp (name, "bcdwim") == 0 && nt_cmdline->type == BOOT_WIM) ||
      (strcasecmp (name, "bcdvhd") == 0 && nt_cmdline->type == BOOT_VHD))
  {
    DBG ("...found BCD file %s\n", name);
    vdisk_add_file ("BCD", data, len, read_mem_file);
    nt_cmdline->bcd_data = data;
    nt_cmdline->bcd_len = len;
    bcd_patch_data ();
    if (nt_cmdline->pause)
      pause_boot ();
  }
  else if (strcasecmp (name, "bcd") == 0)
    DBG ("...skip BCD\n");
  else if (strcasecmp (name, BOOT_FILE_NAME) == 0)
  {
    if (nt_cmdline->win7)
      return 0;
    DBG ("...found bootmgfw.efi file %s\n", name);
    bootmgfw = vdisk_add_file (name, data, len, read_mem_file);
  }
  else if (strcasecmp (name, "win7.efi") == 0)
  {
    if (!nt_cmdline->win7)
      return 0;
    DBG ("..found win7 efi loader\n");
    bootmgfw = vdisk_add_file ("bootx64.efi", data, len, read_mem_file);
  }
  else if (strcasecmp (name, "vgashim.efi") == 0)
  {
    if (!nt_cmdline->win7 || !nt_cmdline->vgashim)
      return 0;
    DBG ("..found vgashim\n");
    efi_load_vgashim (data, len);
  }
  else if (strcasecmp (name, "bgrt.bmp") == 0 && nt_cmdline->bgrt)
  {
    DBG ("...load BGRT bmp image\n");
    acpi_load_bgrt (data, len);
  }
  else
    vdisk_add_file (name, data, len, read_mem_file);
  return 0;
}

static void
efi_extract_initrd (void *initrd, uint32_t initrd_len)
{
  void *dst;
  ssize_t dst_len;
  /* Extract files from initrd */
  if (initrd && initrd_len)
  {
    DBG ("initrd=%p+0x%x\n", initrd, initrd_len);
    dst_len = lznt1_decompress (initrd, initrd_len, NULL);
    if (dst_len < 0)
    {
      DBG ("...extracting initrd\n");
      cpio_extract (initrd, initrd_len, efi_add_file);
    }
    else
    {
      DBG ("...extracting LZNT1-compressed initrd\n");
      dst = efi_allocate_pages (BYTES_TO_PAGES (dst_len));
      lznt1_decompress (initrd, initrd_len, dst);
      cpio_extract (dst, dst_len, efi_add_file);
    }
  }
}

/**
 * Extract initrd from EFI file system
 *
 * @v handle    Device handle
 */
static void efi_load_initrd (EFI_HANDLE handle)
{
  EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
  EFI_FILE_PROTOCOL *root;
  EFI_FILE_PROTOCOL *file;
  UINT64 initrd_len = 0;
  UINTN size;
  CHAR16 wname[256];
  EFI_STATUS efirc;
  void *initrd;

  /* Open file system */
  efirc = bs->OpenProtocol (handle, &efi_simple_file_system_protocol_guid,
                            (void *)&fs, efi_image_handle, NULL,
                            EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (efirc != EFI_SUCCESS)
    die ("Could not open simple file system.\n");

  /* Open root directory */
  efirc = fs->OpenVolume (fs, &root);
  if (efirc != EFI_SUCCESS)
    die ("Could not open root directory.\n");

  /* Close file system */
  bs->CloseProtocol (handle, &efi_simple_file_system_protocol_guid,
                     efi_image_handle, NULL);
  memset (wname, 0 ,sizeof (wname));
  grub_utf8_to_utf16 (wname, sizeof (wname),
                      (uint8_t *)nt_cmdline->initrd_path, -1, NULL);
  efirc = root->Open (root, &file, wname, EFI_FILE_MODE_READ, 0);
  if (efirc != EFI_SUCCESS)
    die ("Could not open %ls.\n", wname);
  file->SetPosition (file, 0xFFFFFFFFFFFFFFFF);
  file->GetPosition (file, &initrd_len);
  file->SetPosition (file, 0);
  if (!initrd_len)
    die ("Could not get initrd size\n");
  size = initrd_len;
  initrd = efi_allocate_pages (BYTES_TO_PAGES (size));
  efirc = file->Read (file, &size, initrd);
  if (efirc != EFI_SUCCESS)
    die ("Could not read from file.\n");

  efidisk_init ();
  efidisk_iterate ();
  if (nt_cmdline->pause)
    pause_boot ();

  efi_extract_initrd (initrd, initrd_len);

  if (! bootmgfw)
    die ("FATAL: no bootmgfw.efi\n");

  /* Install virtual disk */
  efi_install ();
  /* Invoke boot manager */
  efi_boot (bootmgfw);
}

/**
 * EFI entry point
 *
 * @v image_handle  Image handle
 * @v systab    EFI system table
 * @ret efirc   EFI status code
 */
EFI_STATUS EFIAPI efi_main (EFI_HANDLE image_handle,EFI_SYSTEM_TABLE *systab)
{
  EFI_BOOT_SERVICES *bs;
  EFI_LOADED_IMAGE_PROTOCOL *loaded;
  EFI_STATUS efirc;
  size_t cmdline_len = 0;
  char *cmdline = 0;

  efi_image_handle = image_handle;
  efi_systab = systab;
  bs = systab->BootServices;

  /* Initialise stack cookie */
  init_cookie ();

  /* Print welcome banner */
  cls ();
  print_banner ();
  /* Get loaded image protocol */
  efirc = bs->OpenProtocol (image_handle, &efi_loaded_image_protocol_guid,
                            (void **)&loaded, image_handle, NULL,
                            EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (efirc != EFI_SUCCESS)
    die ("Could not open loaded image protocol\n");

  cmdline_len = (loaded->LoadOptionsSize / sizeof (wchar_t));
  cmdline = efi_malloc (4 * cmdline_len + 1);

  /* Convert command line to ASCII */
  *grub_utf16_to_utf8 ((uint8_t *) cmdline, loaded->LoadOptions, cmdline_len) = 0;

  /* Process command line */
  process_cmdline (cmdline);
  efi_free (cmdline);
  DBG ("systab=%p image_handle=%p\n", systab, image_handle);
  if (! nt_cmdline->initrd_path[0])
    die ("initrd not found.\n");

  efi_load_initrd (loaded->DeviceHandle);

  return EFI_SUCCESS;
}

void efi_linuxentry (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab,
                     struct linux_kernel_params *bp)
{
  /** initrd */
  void *initrd = NULL;
  /** Length of initrd */
  uint32_t initrd_len;

  uint32_t cmdline_len = 0;
  char *cmdline = 0;

#if __x86_64__
  extern char _bss[];
  extern char _ebss[];
  memset (_bss, 0, _ebss - _bss);
#endif

  efi_image_handle = image_handle;
  efi_systab = systab;

  /* Initialise stack cookie */
  init_cookie ();

  /* Print welcome banner */
  cls ();
  print_banner ();
  if (!bp)
    die ("kernel params not found.\n");

  cmdline_len = bp->cmdline_size;
  cmdline = efi_malloc (cmdline_len + 1);
  memcpy (cmdline, (char *)(intptr_t)bp->cmd_line_ptr, cmdline_len);
  cmdline[cmdline_len] = '\0';

  initrd = (void*)(intptr_t)bp->ramdisk_image;
  initrd_len = bp->ramdisk_size;

  /* Process command line */
  process_cmdline (cmdline);
  efi_free (cmdline);

  DBG ("systab=%p image_handle=%p bp=%p\n", systab, image_handle, bp);
  DBG ("cmdline=0x%x+0x%x, %s\n", bp->cmd_line_ptr, bp->cmdline_size,
       (char *)(intptr_t) bp->cmd_line_ptr);
  DBG ("initrd=0x%x+0x%x\n", bp->ramdisk_image, bp->ramdisk_size);

  efidisk_init ();
  efidisk_iterate ();
  if (nt_cmdline->pause)
    pause_boot ();

  efi_extract_initrd (initrd, initrd_len);

  if (! bootmgfw)
    die ("FATAL: no bootmgfw.efi\n");

  /* Install virtual disk */
  efi_install ();
  /* Invoke boot manager */
  efi_boot (bootmgfw);
}
