#ifndef _LINUX_H
#define _LINUX_H

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

#include <stdint.h>

/* Maximum number of MBR signatures to store. */
#define EDD_MBR_SIG_MAX       16

struct linux_e820_mmap
{
  uint64_t addr;
  uint64_t size;
  uint32_t type;
} __attribute__ ((packed));

/* Boot parameters for Linux based on 2.6.12. This is used by the setup
   sectors of Linux, and must be simulated by GRUB on EFI, because
   the setup sectors depend on BIOS.  */
struct linux_kernel_params
{
  uint8_t video_cursor_x;    /* 0 */
  uint8_t video_cursor_y;

  uint16_t ext_mem;    /* 2 */

  uint16_t video_page;    /* 4 */
  uint8_t video_mode;    /* 6 */
  uint8_t video_width;    /* 7 */

  uint8_t padding1[0xa - 0x8];

  uint16_t video_ega_bx;    /* a */

  uint8_t padding2[0xe - 0xc];

  uint8_t video_height;    /* e */
  uint8_t have_vga;    /* f */
  uint16_t font_size;    /* 10 */

  uint16_t lfb_width;    /* 12 */
  uint16_t lfb_height;    /* 14 */
  uint16_t lfb_depth;    /* 16 */
  uint32_t lfb_base;    /* 18 */
  uint32_t lfb_size;    /* 1c */

  uint16_t cl_magic;    /* 20 */
  uint16_t cl_offset;

  uint16_t lfb_line_len;    /* 24 */
  uint8_t red_mask_size;    /* 26 */
  uint8_t red_field_pos;
  uint8_t green_mask_size;
  uint8_t green_field_pos;
  uint8_t blue_mask_size;
  uint8_t blue_field_pos;
  uint8_t reserved_mask_size;
  uint8_t reserved_field_pos;
  uint16_t vesapm_segment;    /* 2e */
  uint16_t vesapm_offset;    /* 30 */
  uint16_t lfb_pages;    /* 32 */
  uint16_t vesa_attrib;    /* 34 */
  uint32_t capabilities;    /* 36 */
  uint32_t ext_lfb_base;    /* 3a */

  uint8_t padding3[0x40 - 0x3e];

  uint16_t apm_version;    /* 40 */
  uint16_t apm_code_segment;  /* 42 */
  uint32_t apm_entry;    /* 44 */
  uint16_t apm_16bit_code_segment;  /* 48 */
  uint16_t apm_data_segment;  /* 4a */
  uint16_t apm_flags;    /* 4c */
  uint32_t apm_code_len;    /* 4e */
  uint16_t apm_data_len;    /* 52 */

  uint8_t padding4[0x60 - 0x54];

  uint32_t ist_signature;    /* 60 */
  uint32_t ist_command;    /* 64 */
  uint32_t ist_event;    /* 68 */
  uint32_t ist_perf_level;    /* 6c */
  uint64_t acpi_rsdp_addr;    /* 70 */

  uint8_t padding5[0x80 - 0x78];

  uint8_t hd0_drive_info[0x10];  /* 80 */
  uint8_t hd1_drive_info[0x10];  /* 90 */
  uint16_t rom_config_len;    /* a0 */

  uint8_t padding6[0xb0 - 0xa2];

  uint32_t ofw_signature;    /* b0 */
  uint32_t ofw_num_items;    /* b4 */
  uint32_t ofw_cif_handler;  /* b8 */
  uint32_t ofw_idt;    /* bc */

  uint8_t padding7[0x1b8 - 0xc0];

  union
  {
    struct
    {
      uint32_t efi_system_table;  /* 1b8 */
      uint32_t padding7_1;    /* 1bc */
      uint32_t efi_signature;    /* 1c0 */
      uint32_t efi_mem_desc_size;  /* 1c4 */
      uint32_t efi_mem_desc_version;  /* 1c8 */
      uint32_t efi_mmap_size;    /* 1cc */
      uint32_t efi_mmap;    /* 1d0 */
    } v0204;
    struct
    {
      uint32_t padding7_1;    /* 1b8 */
      uint32_t padding7_2;    /* 1bc */
      uint32_t efi_signature;    /* 1c0 */
      uint32_t efi_system_table;  /* 1c4 */
      uint32_t efi_mem_desc_size;  /* 1c8 */
      uint32_t efi_mem_desc_version;  /* 1cc */
      uint32_t efi_mmap;    /* 1d0 */
      uint32_t efi_mmap_size;    /* 1d4 */
    } v0206;
    struct
    {
      uint32_t padding7_1;    /* 1b8 */
      uint32_t padding7_2;    /* 1bc */
      uint32_t efi_signature;    /* 1c0 */
      uint32_t efi_system_table;  /* 1c4 */
      uint32_t efi_mem_desc_size;  /* 1c8 */
      uint32_t efi_mem_desc_version;  /* 1cc */
      uint32_t efi_mmap;    /* 1d0 */
      uint32_t efi_mmap_size;    /* 1d4 */
      uint32_t efi_system_table_hi;  /* 1d8 */
      uint32_t efi_mmap_hi;    /* 1dc */
    } v0208;
  };

  uint32_t alt_mem;    /* 1e0 */

  uint8_t padding8[0x1e8 - 0x1e4];

  uint8_t mmap_size;    /* 1e8 */

  uint8_t padding9[0x1ec - 0x1e9];

  uint8_t secure_boot;             /* 1ec */

  uint8_t padding10[0x1f1 - 0x1ed];

  /* Linux setup header copy - BEGIN. */
  uint8_t setup_sects;    /* The size of the setup in sectors */
  uint16_t root_flags;    /* If the root is mounted readonly */
  uint16_t syssize;    /* obsolete */
  uint16_t swap_dev;    /* obsolete */
  uint16_t ram_size;    /* obsolete */
  uint16_t vid_mode;    /* Video mode control */
  uint16_t root_dev;    /* Default root device number */

  uint8_t padding11;    /* 1fe */
  uint8_t ps_mouse;    /* 1ff */

  uint16_t jump;      /* Jump instruction */
  uint32_t header;      /* Magic signature "HdrS" */
  uint16_t version;    /* Boot protocol version supported */
  uint32_t realmode_swtch;    /* Boot loader hook */
  uint16_t start_sys;    /* The load-low segment (obsolete) */
  uint16_t kernel_version;    /* Points to kernel version string */
  uint8_t type_of_loader;    /* Boot loader identifier */
  uint8_t loadflags;    /* Boot protocol option flags */
  uint16_t setup_move_size;  /* Move to high memory size */
  uint32_t code32_start;    /* Boot loader hook */
  uint32_t ramdisk_image;    /* initrd load address */
  uint32_t ramdisk_size;    /* initrd size */
  uint32_t bootsect_kludge;  /* obsolete */
  uint16_t heap_end_ptr;    /* Free memory after setup end */
  uint8_t ext_loader_ver;    /* Extended loader version */
  uint8_t ext_loader_type;    /* Extended loader type */  
  uint32_t cmd_line_ptr;    /* Points to the kernel command line */
  uint32_t initrd_addr_max;  /* Maximum initrd address */
  uint32_t kernel_alignment;  /* Alignment of the kernel */
  uint8_t relocatable_kernel;  /* Is the kernel relocatable */
  uint8_t pad1[3];
  uint32_t cmdline_size;    /* Size of the kernel command line */
  uint32_t hardware_subarch;
  uint64_t hardware_subarch_data;
  uint32_t payload_offset;
  uint32_t payload_length;
  uint64_t setup_data;
  uint64_t pref_address;
  uint32_t init_size;
  uint32_t handover_offset;
  /* Linux setup header copy - END. */

  uint8_t _pad7[40];
  uint32_t edd_mbr_sig_buffer[EDD_MBR_SIG_MAX];  /* 290 */
  struct linux_e820_mmap e820_map[(0x400 - 0x2d0) / 20];  /* 2d0 */
} __attribute__ ((packed));

#endif
