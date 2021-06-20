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
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <wchar.h>
#include <ntboot.h>
#include <peloader.h>
#include <int13.h>
#include <vdisk.h>
#include <cpio.h>
#include <cmdline.h>
#include <biosdisk.h>
#include <lznt1.h>
#include <paging.h>
#include <efi.h>
#include <efiblock.h>
#include <efidisk.h>
#include <bcd.h>
#include <charset.h>
#include <acpi.h>
#include <linux.h>
#include <efi/Protocol/BlockIo.h>
#include <efi/Protocol/DevicePath.h>
#include <efi/Protocol/GraphicsOutput.h>
#include <efi/Protocol/LoadedImage.h>
#include <efi/Protocol/SimpleFileSystem.h>

/** Start of our image (defined by linker) */
extern char _start[];

/** End of our image (defined by linker) */
extern char _end[];

/** Command line */
char *cmdline;

/** initrd */
void *initrd;

/** Length of initrd */
size_t initrd_len;

struct linux_kernel_params *bp;

/** bootmgr.exe file */
static struct vdisk_file *bootmgr;

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

/** Minimal length of embedded bootmgr.exe */
#define BOOTMGR_MIN_LEN 16384

#if __x86_64__
  #define BOOT_FILE_NAME  "BOOTX64.EFI"
#elif __i386__
  #define BOOT_FILE_NAME  "BOOTIA32.EFI"
#else
  #error Unknown Processor Type
#endif

/** Memory regions */
enum
{
  WIMBOOT_REGION = 0,
  PE_REGION,
  INITRD_REGION,
  NUM_REGIONS
};

/**
 * Wrap interrupt callback
 *
 * @v params    Parameters
 */
static void call_interrupt_wrapper (struct bootapp_callback_params *params)
{
  struct paging_state state;
  uint16_t *attributes;
  /* Handle/modify/pass-through interrupt as required */
  if (params->vector.interrupt == 0x13)
  {
    /* Enable paging */
    enable_paging (&state);
    /* Intercept INT 13 calls for the emulated drive */
    emulate_int13 (params);
    /* Disable paging */
    disable_paging (&state);
  }
  else if ((params->vector.interrupt == 0x10) &&
           (params->ax == 0x4f01) && (nt_cmdline->text_mode))
  {
    /* Mark all VESA video modes as unsupported */
    attributes = REAL_PTR (params->es, params->di);
    call_interrupt (params);
    *attributes &= ~0x0001;
  }
  else
  {
    /* Pass through interrupt */
    call_interrupt (params);
  }
}

/** Real-mode callback functions */
static struct bootapp_callback_functions callback_fns =
{
  .call_interrupt = call_interrupt_wrapper,
  .call_real = call_real,
};

/** Real-mode callbacks */
static struct bootapp_callback callback =
{
  .fns = &callback_fns,
};

/** Boot application descriptor set */
static struct
{
  /** Boot application descriptor */
  struct bootapp_descriptor bootapp;
  /** Boot application memory descriptor */
  struct bootapp_memory_descriptor memory;
  /** Boot application memory descriptor regions */
  struct bootapp_memory_region regions[NUM_REGIONS];
  /** Boot application entry descriptor */
  struct bootapp_entry_descriptor entry;
  struct bootapp_entry_wtf1_descriptor wtf1;
  struct bootapp_entry_wtf2_descriptor wtf2;
  struct bootapp_entry_wtf3_descriptor wtf3;
  struct bootapp_entry_wtf3_descriptor wtf3_copy;
  /** Boot application callback descriptor */
  struct bootapp_callback_descriptor callback;
  /** Boot application pointless descriptor */
  struct bootapp_pointless_descriptor pointless;
} __attribute__ ((packed)) bootapps =
{
  .bootapp =
  {
    .signature = BOOTAPP_SIGNATURE,
    .version = BOOTAPP_VERSION,
    .len = sizeof (bootapps),
    .arch = BOOTAPP_ARCH_I386,
    .memory = offsetof (typeof (bootapps), memory),
    .entry = offsetof (typeof (bootapps), entry),
    .xxx = offsetof (typeof (bootapps), wtf3_copy),
    .callback = offsetof (typeof (bootapps), callback),
    .pointless = offsetof (typeof (bootapps), pointless),
  },
  .memory =
  {
    .version = BOOTAPP_MEMORY_VERSION,
    .len = sizeof (bootapps.memory),
    .num_regions = NUM_REGIONS,
    .region_len = sizeof (bootapps.regions[0]),
    .reserved_len = sizeof (bootapps.regions[0].reserved),
  },
  .entry =
  {
    .signature = BOOTAPP_ENTRY_SIGNATURE,
    .flags = BOOTAPP_ENTRY_FLAGS,
  },
  .wtf1 =
  {
    .flags = 0x11000001,
    .len = sizeof (bootapps.wtf1),
    .extra_len = (sizeof (bootapps.wtf2) +
                  sizeof (bootapps.wtf3)),
  },
  .wtf3 = {
    .flags = 0x00000006,
    .len = sizeof (bootapps.wtf3),
    .boot_partition_offset = (VDISK_VBR_LBA * VDISK_SECTOR_SIZE),
    .xxx = 0x01,
    .mbr_signature = VDISK_MBR_SIGNATURE,
  },
  .wtf3_copy =
  {
    .flags = 0x00000006,
    .len = sizeof (bootapps.wtf3),
    .boot_partition_offset = (VDISK_VBR_LBA * VDISK_SECTOR_SIZE),
    .xxx = 0x01,
    .mbr_signature = VDISK_MBR_SIGNATURE,
  },
  .callback =
  {
    .callback = &callback,
  },
  .pointless =
  {
    .version = BOOTAPP_POINTLESS_VERSION,
  },
};

/**
 * File handler
 *
 * @v name    File name
 * @v data    File data
 * @v len   Length
 * @ret rc    Return status code
 */
static int add_file (const char *name, void *data, size_t len)
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
  else if (!efi_systab && strcasecmp (name, "bootmgr.exe") == 0)
  {
    DBG ("...found bootmgr.exe\n");
    bootmgr = vdisk_add_file (name, data, len, read_mem_file);;
  }
  else if (efi_systab && !nt_cmdline->win7 &&
           strcasecmp (name, BOOT_FILE_NAME) == 0)
  {
    DBG ("...found bootmgfw.efi file %s\n", name);
    bootmgr = vdisk_add_file (name, data, len, read_mem_file);
  }
  else if (efi_systab && nt_cmdline->win7 &&
           strcasecmp (name, "win7.efi") == 0)
  {
    DBG ("..found win7 efi loader\n");
    bootmgr = vdisk_add_file ("bootx64.efi", data, len, read_mem_file);
  }
  else if (efi_systab && nt_cmdline->bgrt &&
           strcasecmp (name, "bgrt.bmp") == 0)
  {
    DBG ("...load BGRT bmp image\n");
    acpi_load_bgrt (data, len);
  }
  else
    vdisk_add_file (name, data, len, read_mem_file);
  return 0;
}

static void
extract_initrd (void *initrd, uint32_t initrd_len)
{
  void *dst;
  ssize_t dst_len;
  size_t padded_len = 0;
  /* Extract files from initrd */
  if (initrd && initrd_len)
  {
    DBG ("initrd=%p+0x%x\n", initrd, initrd_len);
    dst_len = lznt1_decompress (initrd, initrd_len, NULL);
    if (dst_len < 0)
    {
      DBG ("...extracting initrd\n");
      cpio_extract (initrd, initrd_len, add_file);
    }
    else
    {
      DBG ("...extracting LZNT1-compressed initrd\n");
      if (efi_systab)
      {
        dst = efi_allocate_pages (BYTES_TO_PAGES (dst_len));
      }
      else
      {
        padded_len = ((dst_len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
        if (padded_len + 0x40000 > (intptr_t)initrd)
          die ("out of memory\n");
        dst = initrd - padded_len;
      }
      lznt1_decompress (initrd, initrd_len, dst);
      cpio_extract (dst, dst_len, add_file);
      initrd_len += padded_len;
      initrd = dst;
    }
  }
}

static void efi_load_initrd (EFI_HANDLE handle)
{
  EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
  EFI_FILE_PROTOCOL *root;
  EFI_FILE_PROTOCOL *file;
  UINT64 size;
  CHAR16 wname[256];
  EFI_STATUS efirc;

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
  file->GetPosition (file, &size);
  file->SetPosition (file, 0);
  if (!size)
    die ("Could not get initrd size\n");
  initrd_len = size;
  initrd = efi_allocate_pages (BYTES_TO_PAGES (initrd_len));
  efirc = file->Read (file, (UINTN *)&initrd_len, initrd);
  if (efirc != EFI_SUCCESS)
    die ("Could not read from file.\n");

  efidisk_init ();
  efidisk_iterate ();
  if (nt_cmdline->pause)
    pause_boot ();

  extract_initrd (initrd, initrd_len);

  if (! bootmgr)
    die ("FATAL: no bootmgfw.efi\n");

  /* Install virtual disk */
  efi_install ();
  /* Invoke boot manager */
  efi_boot (bootmgr);
}

EFI_STATUS EFIAPI efi_main (EFI_HANDLE image_handle,EFI_SYSTEM_TABLE *systab)
{
  EFI_BOOT_SERVICES *bs;
  EFI_LOADED_IMAGE_PROTOCOL *loaded;
  EFI_STATUS efirc;
  size_t cmdline_len = 0;

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

/**
 * Main entry point
 *
 */
int main (void)
{
  struct loaded_pe pe;
  struct paging_state state;
  uint64_t initrd_phys;

  /* Initialise stack cookie */
  init_cookie ();

  /* Print welcome banner */
  cls ();
  print_banner ();
  if (efi_systab)
  {
    cmdline = (char *)(intptr_t)bp->cmd_line_ptr;
    initrd = (void*)(intptr_t)bp->ramdisk_image;
    initrd_len = bp->ramdisk_size;
  }

  /* Process command line */
  process_cmdline (cmdline);

  if (efi_systab)
    {
    DBG ("systab=%p img_handle=%p bp=%p\n", efi_systab, efi_image_handle, bp);
    DBG ("cmdline=0x%x+0x%x, %s\n", bp->cmd_line_ptr, bp->cmdline_size,
         (char *)(intptr_t) bp->cmd_line_ptr);
    DBG ("initrd=0x%x+0x%x\n", bp->ramdisk_image, bp->ramdisk_size);
    efidisk_init ();
    efidisk_iterate ();
  }
  else
  {
    /* Initialise paging */
    init_paging ();
    /* Enable paging */
    enable_paging (&state);
    /* Relocate initrd below 2GB if possible, to avoid collisions */
    DBG ("Found initrd at [%p,%p)\n", initrd, (initrd + initrd_len));
    initrd = relocate_memory_low (initrd, initrd_len);
    DBG ("Placing initrd at [%p,%p)\n", initrd, (initrd + initrd_len));
    biosdisk_init ();
    biosdisk_iterate ();
  }

  if (nt_cmdline->pause)
    pause_boot ();

  /* Extract files from initrd */
  extract_initrd (initrd, initrd_len);

  /* Add INT 13 drive */
  callback.drive = initialise_int13 ();
  /* Read bootmgr.exe into memory */
  if (! bootmgr)
    die ("FATAL: no bootmgr.exe | bootmgfw.efi\n");

  if (efi_systab)
  {
    /* Install virtual disk */
    efi_install ();
    /* Invoke boot manager */
    efi_boot (bootmgr);
  }
  else
  {
    /* Load bootmgr.exe into memory */
    if (load_pe (bootmgr->opaque, bootmgr->len, &pe) != 0)
      die ("FATAL: Could not load bootmgr.exe\n");
    /* Relocate initrd above 4GB if possible, to free up 32-bit memory */
    initrd_phys = relocate_memory_high (initrd, initrd_len);
    DBG ("Placing initrd at physical [%#llx,%#llx)\n",
        initrd_phys, (initrd_phys + initrd_len));
    /* Complete boot application descriptor set */
    bootapps.bootapp.pe_base = pe.base;
    bootapps.bootapp.pe_len = pe.len;
    bootapps.regions[WIMBOOT_REGION].start_page = page_start (_start);
    bootapps.regions[WIMBOOT_REGION].num_pages = page_len (_start, _end);
    bootapps.regions[PE_REGION].start_page = page_start (pe.base);
    bootapps.regions[PE_REGION].num_pages =
            page_len (pe.base, (pe.base + pe.len));
    bootapps.regions[INITRD_REGION].start_page =
            (initrd_phys / PAGE_SIZE);
    bootapps.regions[INITRD_REGION].num_pages =
            page_len (initrd, initrd + initrd_len);
    /* Omit initrd region descriptor if located above 4GB */
    if (initrd_phys >= ADDR_4GB)
      bootapps.memory.num_regions--;
    /* Disable paging */
    disable_paging (&state);
    /* Jump to PE image */
    DBG ("Entering bootmgr.exe with parameters at %p\n", &bootapps);
    if (nt_cmdline->pause)
      pause_boot ();
    pe.entry (&bootapps.bootapp);
  }

  die ("FATAL: bootmgr returned\n");
}
