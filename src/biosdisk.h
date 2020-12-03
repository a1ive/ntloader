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

#ifndef _BIOSDISK_H
#define _BIOSDISK_H

#include <stdint.h>
#include <bootapp.h>

#define  GRUB_CPU_INT_FLAGS_CARRY     0x1
#define  GRUB_CPU_INT_FLAGS_PARITY    0x4
#define  GRUB_CPU_INT_FLAGS_ADJUST    0x10
#define  GRUB_CPU_INT_FLAGS_ZERO      0x40
#define  GRUB_CPU_INT_FLAGS_SIGN      0x80
#define  GRUB_CPU_INT_FLAGS_TRAP      0x100
#define  GRUB_CPU_INT_FLAGS_INTERRUPT 0x200
#define  GRUB_CPU_INT_FLAGS_DIRECTION 0x400
#define  GRUB_CPU_INT_FLAGS_OVERFLOW  0x800

#define GRUB_BIOSDISK_FLAG_LBA          1
#define GRUB_BIOSDISK_FLAG_CDROM        2

#define GRUB_BIOSDISK_CDTYPE_NO_EMUL    0
#define GRUB_BIOSDISK_CDTYPE_1_2_M      1
#define GRUB_BIOSDISK_CDTYPE_1_44_M     2
#define GRUB_BIOSDISK_CDTYPE_2_88_M     3
#define GRUB_BIOSDISK_CDTYPE_HARDDISK   4

#define GRUB_BIOSDISK_CDTYPE_MASK       0xF

/* For readability.  */
#define GRUB_BIOSDISK_READ  0
#define GRUB_BIOSDISK_WRITE 1

#define GRUB_BIOSDISK_CDROM_RETRY_COUNT 3

#define GRUB_DISK_SECTOR_SIZE   0x200
#define GRUB_DISK_SECTOR_BITS   9

/* Drive Parameters.  */
struct biosdisk_drp
{
  uint16_t size;
  uint16_t flags;
  uint32_t cylinders;
  uint32_t heads;
  uint32_t sectors;
  uint64_t total_sectors;
  uint16_t bytes_per_sector;
  /* ver 2.0 or higher */
  union
  {
    uint32_t EDD_configuration_parameters;
    /* Pointer to the Device Parameter Table Extension (ver 3.0+).  */
    uint32_t dpte_pointer;
  };
  /* ver 3.0 or higher */
  uint16_t signature_dpi;
  uint8_t length_dpi;
  uint8_t reserved[3];
  uint8_t name_of_host_bus[4];
  uint8_t name_of_interface_type[8];
  uint8_t interface_path[8];
  uint8_t device_path[16];
  uint8_t reserved2;
  uint8_t checksum;
  /* XXX: This is necessary, because the BIOS of Thinkpad X20
     writes a garbage to the tail of drive parameters,
     regardless of a size specified in a caller.  */
  uint8_t dummy[16];
} __attribute__ ((packed));

struct biosdisk_cdrp
{
  uint8_t size;
  uint8_t media_type;
  uint8_t drive_no;
  uint8_t controller_no;
  uint32_t image_lba;
  uint16_t device_spec;
  uint16_t cache_seg;
  uint16_t load_seg;
  uint16_t length_sec512;
  uint8_t cylinders;
  uint8_t sectors;
  uint8_t heads;
  uint8_t dummy[16];
} __attribute__ ((packed));

/* Disk Address Packet.  */
struct biosdisk_dap
{
  uint8_t length;
  uint8_t reserved;
  uint16_t blocks;
  uint32_t buffer;
  uint64_t block;
} __attribute__ ((packed));

struct biosdisk_data
{
  /* int13h data */
  int drive;
  unsigned long cylinders;
  unsigned long heads;
  unsigned long sectors;
  unsigned long flags;
  /* disk data */
  uint64_t total_sectors;
  unsigned int log_sector_size;
};

struct int_regs
{
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esi;
  uint32_t edi;
  uint16_t ds;
  uint16_t es;
  uint32_t eflags;
};

void biosdisk_open (int drive);
void biosdisk_read (uint64_t sector, uint64_t offset, size_t size, void *buf);
void biosdisk_init (void);

#endif
