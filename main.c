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

/**
 * @file
 *
 * Main entry point
 *
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

/** bootmgr.exe file */
static struct vdisk_file *bootmgr;

/** Minimal length of embedded bootmgr.exe */
#define BOOTMGR_MIN_LEN 16384

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
  else if (strcasecmp (name, "bootmgr.exe") == 0)
  {
    DBG ("...found bootmgr.exe\n");
    bootmgr = vdisk_add_file (name, data, len, read_mem_file);;
  }
  else
    vdisk_add_file (name, data, len, read_mem_file);
  return 0;
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

  /* Process command line */
  process_cmdline (cmdline);

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
  if (nt_cmdline->pause)
    pause_boot ();

  /* Extract files from initrd */
  if (initrd && initrd_len)
  {
    void *dst;
    ssize_t dst_len = lznt1_decompress (initrd, initrd_len, NULL);
    size_t padded_len = 0;
    if (dst_len <= 0)
    {
      DBG ("...extracting initrd\n");
      cpio_extract (initrd, initrd_len, add_file);
    }
    else
    {
      DBG ("...extracting LZNT1-compressed initrd\n");
      padded_len = ((dst_len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
      if (padded_len + 0x40000 > (intptr_t)initrd)
        die ("out of memory\n");
      dst = initrd - padded_len;
      lznt1_decompress (initrd, initrd_len, dst);
      cpio_extract (dst, dst_len, add_file);
      initrd_len += padded_len;
      initrd = dst;
    }
  }
  /* Add INT 13 drive */
  callback.drive = initialise_int13 ();
  /* Read bootmgr.exe into memory */
  if (! bootmgr)
    die ("FATAL: no bootmgr.exe\n");

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

  /* Disable paging */
  disable_paging (&state);

  /* Jump to PE image */
  DBG ("Entering bootmgr.exe with parameters at %p\n", &bootapps);
  if (nt_cmdline->pause)
    pause_boot ();

  pe.entry (&bootapps.bootapp);
  die ("FATAL: bootmgr.exe returned\n");
}
