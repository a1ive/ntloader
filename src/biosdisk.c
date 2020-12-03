/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010  Free Software Foundation, Inc.
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
#include <string.h>
#include <bootapp.h>
#include <cmdline.h>
#include <biosdisk.h>
#include <wimboot.h>

/* The scratch buffer used in real mode code.  */
uint8_t bios_buf[0x9010];
unsigned SCRATCH_ADDR = 0;
unsigned SCRATCH_SIZE = 0x9000;
unsigned SCRATCH_SEG = 0;

static int cd_drive = 0;
static struct biosdisk_data disk;

static void
call_int13h (struct int_regs *regs)
{
  struct bootapp_callback_params params;
  memset (&params, 0, sizeof (params));
  params.vector.interrupt = 0x13;
  params.eax = regs->eax;
  params.ebx = regs->ebx;
  params.ecx = regs->ecx;
  params.edx = regs->edx;
  params.esi = regs->esi;
  params.edi = regs->edi;
  params.ds = regs->ds;
  params.es = regs->es;
  params.eflags = regs->eflags;
  call_interrupt (&params);
  regs->eax = params.eax;
  regs->ebx = params.ebx;
  regs->ecx = params.ecx;
  regs->edx = params.edx;
  regs->esi = params.esi;
  regs->edi = params.edi;
  regs->ds = params.ds;
  regs->es = params.es;
  regs->eflags = params.eflags;
}

static uint64_t
divmod64 (uint64_t n, uint64_t d, uint64_t *r)
{
  /* This algorithm is typically implemented by hardware. The idea
     is to get the highest bit in N, 64 times, by keeping
     upper(N * 2^i) = (Q * D + M), where upper
     represents the high 64 bits in 128-bits space.  */
  unsigned bits = 64;
  uint64_t q = 0;
  uint64_t m = 0;
  while (bits--)
  {
    m <<= 1;
    if (n & (1ULL << 63))
      m |= 1;
    q <<= 1;
    n <<= 1;
    if (m >= d)
    {
      q |= 1;
      m -= d;
    }
  }
  if (r)
    *r = m;
  return q;
}

/*
 *   Call IBM/MS INT13 Extensions (int 13 %ah=AH) for DRIVE. DAP
 *   is passed for disk address packet. If an error occurs, return
 *   non-zero, otherwise zero.
 */
static int
biosdisk_rw_int13_ext (int ah, int drive, void *dap)
{
  struct int_regs regs;
  regs.eax = ah << 8;
  /* compute the address of disk_address_packet */
  regs.ds = (((size_t) dap) & 0xffff0000) >> 4;
  regs.esi = (((size_t) dap) & 0xffff);
  regs.edx = drive;
  regs.eflags = 0;
  call_int13h (&regs);
  return (regs.eax >> 8) & 0xff;
}

/*
 *   Call standard and old INT13 (int 13 %ah=AH) for DRIVE. Read/write
 *   NSEC sectors from COFF/HOFF/SOFF into SEGMENT. If an error occurs,
 *   return non-zero, otherwise zero.
 */
static int 
biosdisk_rw_std (int ah, int drive, int coff, int hoff,
                 int soff, int nsec, int segment)
{
  int ret, i;
  /* Try 3 times.  */
  for (i = 0; i < 3; i++)
  {
    struct int_regs regs;
    /* set up CHS information */
    /* set %ch to low eight bits of cylinder */
    regs.ecx = (coff << 8) & 0xff00;
    /* set bits 6-7 of %cl to high two bits of cylinder */
    regs.ecx |= (coff >> 2) & 0xc0;
    /* set bits 0-5 of %cl to sector */
    regs.ecx |= soff & 0x3f;
    /* set %dh to head and %dl to drive */  
    regs.edx = (drive & 0xff) | ((hoff << 8) & 0xff00);
    /* set %ah to AH */
    regs.eax = (ah << 8) & 0xff00;
    /* set %al to NSEC */
    regs.eax |= nsec & 0xff;
    regs.ebx = 0;
    regs.es = segment;
    regs.eflags = 0;
    call_int13h (&regs);
    /* check if successful */
    if (!(regs.eflags & GRUB_CPU_INT_FLAGS_CARRY))
      return 0;
    /* save return value */
    ret = regs.eax >> 8;
    /* if fail, reset the disk system */
    regs.eax = 0;
    regs.edx = (drive & 0xff);
    regs.eflags = 0;
    call_int13h (&regs);
  }
  return ret;
}

/*
 *   Check if LBA is supported for DRIVE. If it is supported, then return
 *   the major version of extensions, otherwise zero.
 */
static int
biosdisk_check_int13_ext (int drive)
{
  struct int_regs regs;
  regs.edx = drive & 0xff;
  regs.eax = 0x4100;
  regs.ebx = 0x55aa;
  regs.eflags = 0;
  call_int13h (&regs);
  if (regs.eflags & GRUB_CPU_INT_FLAGS_CARRY)
    return 0;
  if ((regs.ebx & 0xffff) != 0xaa55)
    return 0;
  /* check if AH=0x42 is supported */
  if (!(regs.ecx & 1))
    return 0;
  return (regs.eax >> 8) & 0xff;
}

/*
 *   Return the geometry of DRIVE in CYLINDERS, HEADS and SECTORS. If an
 *   error occurs, then return non-zero, otherwise zero.
 */
static int 
biosdisk_get_diskinfo_std (int drive, unsigned long *cylinders,
                           unsigned long *heads,
                           unsigned long *sectors)
{
  struct int_regs regs;
  regs.eax = 0x0800;
  regs.edx = drive & 0xff;
  regs.eflags = 0;
  call_int13h (&regs);
  /* Check if unsuccessful. Ignore return value if carry isn't set to 
     workaround some buggy BIOSes. */
  if ((regs.eflags & GRUB_CPU_INT_FLAGS_CARRY) && ((regs.eax & 0xff00) != 0))
    return (regs.eax & 0xff00) >> 8;
  /* bogus BIOSes may not return an error number */
  /* 0 sectors means no disk */
  if (!(regs.ecx & 0x3f))
    /* XXX 0x60 is one of the unused error numbers */
    return 0x60;
  /* the number of heads is counted from zero */
  *heads = ((regs.edx >> 8) & 0xff) + 1;
  *cylinders = (((regs.ecx >> 8) & 0xff) | ((regs.ecx << 2) & 0x0300)) + 1;
  *sectors = regs.ecx & 0x3f;
  return 0;
}

static int
biosdisk_get_diskinfo_real (int drive, void *drp, uint16_t ax)
{
  struct int_regs regs;
  regs.eax = ax;
  /* compute the address of drive parameters */
  regs.esi = ((size_t) drp) & 0xf;
  regs.ds = ((size_t) drp) >> 4;
  regs.edx = drive & 0xff;
  regs.eflags = 0;
  call_int13h (&regs);
  /* Check if unsuccessful. Ignore return value if carry isn't set to 
     workaround some buggy BIOSes. */
  if ((regs.eflags & GRUB_CPU_INT_FLAGS_CARRY) && ((regs.eax & 0xff00) != 0))
    return (regs.eax & 0xff00) >> 8;
  return 0;
}

/*
 *   Return the cdrom information of DRIVE in CDRP. If an error occurs,
 *   then return non-zero, otherwise zero.
 */
static int
biosdisk_get_cdinfo_int13_ext (int drive, void *cdrp)
{
  return biosdisk_get_diskinfo_real (drive, cdrp, 0x4b01);
}

/*
 *   Return the geometry of DRIVE in a drive parameters, DRP. If an error
 *   occurs, then return non-zero, otherwise zero.
 */
static int
biosdisk_get_diskinfo_int13_ext (int drive, void *drp)
{
  return biosdisk_get_diskinfo_real (drive, drp, 0x4800);
}

void
biosdisk_open (int drive)
{
  uint64_t total_sectors = 0;
  memset (&disk, 0, sizeof (disk));
  disk.drive = drive;
  if (drive < 0)
    die ("invalid drive %d\n", drive);
  if ((cd_drive) && (drive == cd_drive))
  {
    printf ("is cdrom\n");
    disk.flags = GRUB_BIOSDISK_FLAG_LBA | GRUB_BIOSDISK_FLAG_CDROM;
    disk.sectors = 8;
    disk.log_sector_size = 11;
    total_sectors = 0xffffffffffffffffULL;
  }
  else
  {
    /* HDD */
    printf ("is hdd\n");
    int version = biosdisk_check_int13_ext (drive);
    disk.log_sector_size = 9;
    printf ("version %d\n", version);
    if (version)
    {
      struct biosdisk_drp *drp = (struct biosdisk_drp *) SCRATCH_ADDR;
      /* Clear out the DRP.  */
      memset (drp, 0, sizeof (*drp));
      drp->size = sizeof (*drp);
      if (! biosdisk_get_diskinfo_int13_ext (drive, drp))
      {
        printf ("lba\n");
        disk.flags = GRUB_BIOSDISK_FLAG_LBA;
        if (drp->total_sectors)
          total_sectors = drp->total_sectors;
        else
          /* Some buggy BIOSes doesn't return the total sectors
             correctly but returns zero. So if it is zero, compute
             it by C/H/S returned by the LBA BIOS call.  */
          total_sectors = ((uint64_t) drp->cylinders) * drp->heads * drp->sectors;
        if (drp->bytes_per_sector
            && !(drp->bytes_per_sector & (drp->bytes_per_sector - 1))
            && drp->bytes_per_sector >= 512
            && drp->bytes_per_sector <= 16384)
        {
          for (disk.log_sector_size = 0;
               (1 << disk.log_sector_size) < drp->bytes_per_sector;
               disk.log_sector_size++);
        }
      }
    }
  }

  if (! (disk.flags & GRUB_BIOSDISK_FLAG_CDROM))
  {
    printf ("chs\n");
    if (biosdisk_get_diskinfo_std (drive, &disk.cylinders, &disk.heads,
                                   &disk.sectors) != 0)
    {
      if (total_sectors && (disk.flags & GRUB_BIOSDISK_FLAG_LBA))
      {
        disk.sectors = 63;
        disk.heads = 255;
        disk.cylinders = divmod64 (total_sectors + disk.heads * disk.sectors - 1,
                                   disk.heads * disk.sectors, 0);
      }
      else
        die ("drive %d cannot get C/H/S values.\n", drive);
    }
    if (disk.sectors == 0)
      disk.sectors = 63;
    if (disk.heads == 0)
      disk.heads = 255;
    if (! total_sectors)
      total_sectors = ((uint64_t) disk.cylinders) * disk.heads * disk.sectors;
  }
  disk.total_sectors = total_sectors;
}

static void
biosdisk_rw (int cmd, uint64_t sector, size_t size, unsigned segment)
{
  /* VirtualBox fails with sectors above 2T on CDs.
     Since even BD-ROMS are never that big anyway, return error.  */
  if ((disk.flags & GRUB_BIOSDISK_FLAG_CDROM) && (sector >> 32))
    die ("attempt to read or write outside of drive %d\n", disk.drive);

  if (disk.flags & GRUB_BIOSDISK_FLAG_LBA)
  {
    struct biosdisk_dap *dap;
    dap = (struct biosdisk_dap *)
            (SCRATCH_ADDR + (disk.sectors << disk.log_sector_size));
    dap->length = sizeof (*dap);
    dap->reserved = 0;
    dap->blocks = size;
    dap->buffer = segment << 16;    /* The format SEGMENT:ADDRESS.  */
    dap->block = sector;

    if (disk.flags & GRUB_BIOSDISK_FLAG_CDROM)
    {
      int i;
      if (cmd)
        die ("cannot write to CD-ROM\n");
      for (i = 0; i < GRUB_BIOSDISK_CDROM_RETRY_COUNT; i++)
      {
        if (! biosdisk_rw_int13_ext (0x42, disk.drive, dap))
          break;
      }

      if (i == GRUB_BIOSDISK_CDROM_RETRY_COUNT)
        die ("failure reading sector 0x%llx from drive %d\n", sector, disk.drive);
    }
    else
      if (biosdisk_rw_int13_ext (cmd + 0x42, disk.drive, dap))
      {
        /* Fall back to the CHS mode.  */
        disk.flags &= ~GRUB_BIOSDISK_FLAG_LBA;
        disk.total_sectors = disk.cylinders * disk.heads * disk.sectors;
        return biosdisk_rw (cmd, sector, size, segment);
      }
  }
  else
  {
    unsigned coff, hoff, soff;
    unsigned head;
    /* It is impossible to reach over 8064 MiB (a bit less than LBA24) with
       the traditional CHS access.  */
    if (sector > 1024 /* cylinders */ * 256 /* heads */ * 63 /* spt */)
      die ("attempt to read or write outside of drive %d\n", disk.drive);

    soff = ((uint32_t) sector) % disk.sectors + 1;
    head = ((uint32_t) sector) / disk.sectors;
    hoff = head % disk.heads;
    coff = head / disk.heads;

    if (coff >= disk.cylinders)
      die ("attempt to read or write outside of drive %d\n", disk.drive);

    if (biosdisk_rw_std (cmd + 0x02, disk.drive, coff, hoff, soff, size, segment))
    {
      die ("failure %s sector 0x%llx %s drive %d\n", cmd ? "reading" : "writing",
           sector, cmd ? "from" : "to", disk.drive);
    }
  }
}

/* Return the number of sectors which can be read safely at a time.  */
static size_t
get_safe_sectors (uint64_t sector)
{
  size_t size;
  uint64_t offset;
  uint32_t sectors = disk.sectors;
  /* OFFSET = SECTOR % SECTORS */
  divmod64 (sector, sectors, &offset);
  size = sectors - offset;
  return size;
}

static void
biosdisk_read_real (uint64_t sector, size_t size, void *buf)
{
  while (size)
  {
    size_t len;
    len = get_safe_sectors (sector);
    if (len > size)
      len = size;
    biosdisk_rw (GRUB_BIOSDISK_READ, sector, len, SCRATCH_SEG);
    memcpy (buf, (void *) SCRATCH_ADDR, len << disk.log_sector_size);
    buf = (uint8_t *) buf + (len << disk.log_sector_size);
    sector += len;
    size -= len;
  }
}

/* This function performs two tasks:
   - Normalize offset to be less than the sector size.
   - Verify that the range is inside the disk.  */
static void
disk_adjust_range (uint64_t *sector, uint64_t *offset, size_t size)
{
  uint64_t total_sectors;

  *sector += *offset >> GRUB_DISK_SECTOR_BITS;
  *offset &= GRUB_DISK_SECTOR_SIZE - 1;

  /* Transform total_sectors to number of 512B blocks.  */
  total_sectors = disk.total_sectors
                      << (disk.log_sector_size - GRUB_DISK_SECTOR_BITS);

  /* Some drivers have problems with disks above reasonable.
     Treat unknown as 1EiB disk. While on it, clamp the size to 1EiB.
     Just one condition is enough since GRUB_DISK_UNKNOWN_SIZE << ls is always
     above 9EiB.
  */
  if (total_sectors > (1ULL << 51))
    total_sectors = (1ULL << 51);

  if ((total_sectors <= *sector
       || ((*offset + size + GRUB_DISK_SECTOR_SIZE - 1)
       >> GRUB_DISK_SECTOR_BITS) > total_sectors - *sector))
    die ("attempt to read or write outside of disk %d\n", disk.drive);
}

void
biosdisk_read (uint64_t sector, uint64_t offset, size_t size, void *buf)
{
  unsigned real_offset;
  disk_adjust_range (&sector, &offset, size);
  real_offset = offset;
  while (size)
  {
    char tmp_buf[GRUB_DISK_SECTOR_SIZE];
    size_t len;
    if ((real_offset != 0) || (size < GRUB_DISK_SECTOR_SIZE))
    {
      len = GRUB_DISK_SECTOR_SIZE - real_offset;
      if (len > size)
        len = size;
      biosdisk_read_real (sector, 1, tmp_buf);
      memcpy (buf, tmp_buf + real_offset, len);
      sector++;
      real_offset = 0;
    }
    else
    {
      size_t n;
      len = size & ~(GRUB_DISK_SECTOR_SIZE - 1);
      n = size >> GRUB_DISK_SECTOR_BITS;
      biosdisk_read_real (sector, n, buf);
      sector += n;
    }
    buf = (char *) buf + len;
    size -= len;
  }
}

void
biosdisk_init (void)
{
  uint8_t boot_drive = cmdline_cdrom;
  struct biosdisk_cdrp *cdrp;

  SCRATCH_SEG = ((intptr_t)bios_buf + 0x10) >> 4;
  SCRATCH_ADDR = SCRATCH_SEG << 4;
  printf ("scratch addr 0x%x\n", SCRATCH_ADDR);

  cdrp = (void *) SCRATCH_ADDR;
  memset (cdrp, 0, sizeof (*cdrp));
  cdrp->size = sizeof (*cdrp);
  cdrp->media_type = 0xFF;
  if ((! biosdisk_get_cdinfo_int13_ext (boot_drive, cdrp))
      && ((cdrp->media_type & GRUB_BIOSDISK_CDTYPE_MASK)
      == GRUB_BIOSDISK_CDTYPE_NO_EMUL))
    cd_drive = cdrp->drive_no;
  if (boot_drive >= 0x90)
    cd_drive = boot_drive;
}
