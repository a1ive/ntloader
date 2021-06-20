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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <wchar.h>
#include <ntboot.h>
#include <vdisk.h>
#include <efi.h>
#include <efiblock.h>
#include <efi/Protocol/GraphicsOutput.h>

/** A block I/O device */
struct efi_block
{
  /** EFI block I/O protocol */
  EFI_BLOCK_IO_PROTOCOL block;
  /** Device path */
  EFI_DEVICE_PATH_PROTOCOL *path;
  /** Starting LBA */
  uint64_t lba;
  /** Handle */
  EFI_HANDLE handle;
};

/**
 * Reset block I/O protocol
 *
 * @v this    Block I/O protocol
 * @v extended    Perform extended verification
 * @ret efirc   EFI status code
 */
static EFI_STATUS EFIAPI
efi_reset_blocks (EFI_BLOCK_IO_PROTOCOL *this __unused,
                  BOOLEAN extended __unused)
{
  return EFI_SUCCESS;
}

/**
 * Read blocks
 *
 * @v this    Block I/O protocol
 * @v media   Media ID
 * @v lba   Starting LBA
 * @v len   Length of data
 * @v data    Data buffer
 * @ret efirc   EFI status code
 */
static EFI_STATUS EFIAPI
efi_read_blocks (EFI_BLOCK_IO_PROTOCOL *this, UINT32 media __unused,
                 EFI_LBA lba, UINTN len, VOID *data)
{
  struct efi_block *block = container_of (this, struct efi_block, block);
  vdisk_read ((lba + block->lba), (len / VDISK_SECTOR_SIZE), data);
  return 0;
}

/**
 * Write blocks
 *
 * @v this    Block I/O protocol
 * @v media   Media ID
 * @v lba   Starting LBA
 * @v len   Length of data
 * @v data    Data buffer
 * @ret efirc   EFI status code
 */
static EFI_STATUS EFIAPI
efi_write_blocks (EFI_BLOCK_IO_PROTOCOL *this __unused,
                  UINT32 media __unused, EFI_LBA lba __unused,
                  UINTN len __unused, VOID *data __unused)
{
  return EFI_WRITE_PROTECTED;
}

/**
 * Flush block operations
 *
 * @v this    Block I/O protocol
 * @ret efirc   EFI status code
 */
static EFI_STATUS EFIAPI
efi_flush_blocks (EFI_BLOCK_IO_PROTOCOL *this __unused)
{
  return EFI_SUCCESS;
}

/** GUID used in vendor device path */
#define EFIBLOCK_GUID \
  { 0x1322d197, 0x15dc, 0x4a45, \
    { 0xa6, 0xa4, 0xfa, 0x57, 0x05, 0x4e, 0xa6, 0x14 } \
  }

/**
 * Initialise device path
 *
 * @v name    Variable name
 * @v type    Type
 * @v subtype   Subtype
 */
#define EFI_DEVPATH_INIT(name, type, subtype) \
  {   \
    .Type = (type),           \
    .SubType = (subtype),         \
    .Length[0] = (sizeof (name) & 0xff),      \
    .Length[1] = (sizeof (name) >> 8),      \
  }

/**
 * Initialise device path end
 *
 * @v name    Variable name
 */
#define EFI_DEVPATH_END_INIT(name)        \
  EFI_DEVPATH_INIT (name, END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE)

/**
 * Initialise vendor device path
 *
 * @v name    Variable name
 */
#define EFIBLOCK_DEVPATH_VENDOR_INIT(name) \
  { \
    .Header = EFI_DEVPATH_INIT (name, HARDWARE_DEVICE_PATH, HW_VENDOR_DP), \
    .Guid = EFIBLOCK_GUID, \
  }

/**
 * Initialise ATA device path
 *
 * @v name    Variable name
 */
#define EFIBLOCK_DEVPATH_ATA_INIT(name) \
  { \
    .Header = EFI_DEVPATH_INIT (name, MESSAGING_DEVICE_PATH, MSG_ATAPI_DP), \
    .PrimarySecondary = 0, \
    .SlaveMaster = 0, \
    .Lun = 0, \
  }

/**
 * Initialise hard disk device path
 *
 * @v name    Variable name
 */
#define EFIBLOCK_DEVPATH_HD_INIT(name) \
  { \
    .Header = EFI_DEVPATH_INIT (name, MEDIA_DEVICE_PATH, MEDIA_HARDDRIVE_DP), \
    .PartitionNumber = 1, \
    .PartitionStart = VDISK_PARTITION_LBA, \
    .PartitionSize = VDISK_PARTITION_COUNT, \
    .Signature[0] = ((VDISK_MBR_SIGNATURE >> 0) & 0xff), \
    .Signature[1] = ((VDISK_MBR_SIGNATURE >> 8) & 0xff), \
    .Signature[2] = ((VDISK_MBR_SIGNATURE >> 16) & 0xff), \
    .Signature[3] = ((VDISK_MBR_SIGNATURE >> 24) & 0xff), \
    .MBRType = MBR_TYPE_PCAT, \
    .SignatureType = SIGNATURE_TYPE_MBR, \
  }

/** Virtual disk media */
static EFI_BLOCK_IO_MEDIA efi_vdisk_media =
{
  .MediaId = VDISK_MBR_SIGNATURE,
  .MediaPresent = TRUE,
  .LogicalPartition = FALSE,
  .ReadOnly = TRUE,
  .BlockSize = VDISK_SECTOR_SIZE,
  .LastBlock = (VDISK_COUNT - 1),
};

/** Virtual disk device path */
static struct
{
  VENDOR_DEVICE_PATH vendor;
  ATAPI_DEVICE_PATH ata;
  EFI_DEVICE_PATH_PROTOCOL end;
} __attribute__ ((packed)) efi_vdisk_path =
{
  .vendor = EFIBLOCK_DEVPATH_VENDOR_INIT (efi_vdisk_path.vendor),
  .ata = EFIBLOCK_DEVPATH_ATA_INIT (efi_vdisk_path.ata),
  .end = EFI_DEVPATH_END_INIT (efi_vdisk_path.end),
};

/** Virtual disk device */
static struct efi_block efi_vdisk =
{
  .block =
  {
    .Revision = EFI_BLOCK_IO_PROTOCOL_REVISION,
    .Media = &efi_vdisk_media,
    .Reset = efi_reset_blocks,
    .ReadBlocks = efi_read_blocks,
    .WriteBlocks = efi_write_blocks,
    .FlushBlocks = efi_flush_blocks,
  },
  .path = &efi_vdisk_path.vendor.Header,
  .lba = 0,
  .handle = 0,
};

/** Virtual partition media */
static EFI_BLOCK_IO_MEDIA efi_vpartition_media =
{
  .MediaId = VDISK_MBR_SIGNATURE,
  .MediaPresent = TRUE,
  .LogicalPartition = TRUE,
  .ReadOnly = TRUE,
  .BlockSize = VDISK_SECTOR_SIZE,
  .LastBlock = (VDISK_PARTITION_COUNT - 1),
};

/** Virtual partition device path */
static struct
{
  VENDOR_DEVICE_PATH vendor;
  ATAPI_DEVICE_PATH ata;
  HARDDRIVE_DEVICE_PATH hd;
  EFI_DEVICE_PATH_PROTOCOL end;
} __attribute__ ((packed)) efi_vpartition_path =
{
  .vendor = EFIBLOCK_DEVPATH_VENDOR_INIT (efi_vpartition_path.vendor),
  .ata = EFIBLOCK_DEVPATH_ATA_INIT (efi_vpartition_path.ata),
  .hd = EFIBLOCK_DEVPATH_HD_INIT (efi_vpartition_path.hd),
  .end = EFI_DEVPATH_END_INIT (efi_vpartition_path.end),
};

/** Virtual partition device */
static struct efi_block efi_vpartition =
{
  .block =
  {
    .Revision = EFI_BLOCK_IO_PROTOCOL_REVISION,
    .Media = &efi_vpartition_media,
    .Reset = efi_reset_blocks,
    .ReadBlocks = efi_read_blocks,
    .WriteBlocks = efi_write_blocks,
    .FlushBlocks = efi_flush_blocks,
  },
  .path = &efi_vpartition_path.vendor.Header,
  .lba = VDISK_PARTITION_LBA,
  .handle = 0,
};

/** Install block I/O protocols */
void efi_install (void)
{
  EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
  EFI_STATUS efirc;
  /* Install virtual disk */
  DBG ("Installing block I/O protocol for virtual disk...\n");
  efirc = bs->InstallMultipleProtocolInterfaces (&efi_vdisk.handle,
                       &efi_block_io_protocol_guid, &efi_vdisk.block,
                       &efi_device_path_protocol_guid, efi_vdisk.path,
                       NULL);
  if (efirc != 0)
  {
    die ("Could not install disk block I/O protocols: %#lx\n",
         ((unsigned long) efirc));
  }
  /* Install virtual partition */
  DBG ("Installing block I/O protocol for virtual partition...\n");
  efirc = bs->InstallMultipleProtocolInterfaces (&efi_vpartition.handle,
                       &efi_block_io_protocol_guid, &efi_vpartition.block,
                       &efi_device_path_protocol_guid, efi_vpartition.path,
                       NULL);
  if (efirc != 0)
  {
    die ("Could not install partition block I/O protocols: %#lx\n",
         ((unsigned long) efirc));
  }
}

/** Boot image path */
static struct
{
  VENDOR_DEVICE_PATH vendor;
  ATAPI_DEVICE_PATH ata;
  HARDDRIVE_DEVICE_PATH hd;
  struct
  {
    EFI_DEVICE_PATH header;
    CHAR16 name[sizeof (EFI_REMOVABLE_MEDIA_FILE_NAME) / sizeof (CHAR16)];
  } __attribute__ ((packed)) file;
  EFI_DEVICE_PATH_PROTOCOL end;
} __attribute__ ((packed)) efi_bootmgfw_path =
{
  .vendor = EFIBLOCK_DEVPATH_VENDOR_INIT (efi_bootmgfw_path.vendor),
  .ata = EFIBLOCK_DEVPATH_ATA_INIT (efi_bootmgfw_path.ata),
  .hd = EFIBLOCK_DEVPATH_HD_INIT (efi_bootmgfw_path.hd),
  .file = {
    .header = EFI_DEVPATH_INIT (efi_bootmgfw_path.file,
                                MEDIA_DEVICE_PATH, MEDIA_FILEPATH_DP),
    .name = EFI_REMOVABLE_MEDIA_FILE_NAME,
  },
  .end = EFI_DEVPATH_END_INIT (efi_bootmgfw_path.end),
};

/** Boot image path */
EFI_DEVICE_PATH_PROTOCOL *bootmgfw_path = &efi_bootmgfw_path.vendor.Header;

/** Original OpenProtocol() method */
static EFI_OPEN_PROTOCOL orig_open_protocol;

/**
 * Intercept OpenProtocol()
 *
 * @v handle    EFI handle
 * @v protocol    Protocol GUID
 * @v interface   Opened interface
 * @v agent_handle  Agent handle
 * @v controller_handle Controller handle
 * @v attributes  Attributes
 * @ret efirc   EFI status code
 */
static EFI_STATUS EFIAPI
efi_open_protocol_wrapper (EFI_HANDLE handle, EFI_GUID *protocol,
                           VOID **interface, EFI_HANDLE agent_handle,
                           EFI_HANDLE controller_handle, UINT32 attributes)
{
  static unsigned int count;
  EFI_STATUS efirc;
  /* Open the protocol */
  if ((efirc = orig_open_protocol (handle, protocol, interface,
                                   agent_handle, controller_handle,
                                   attributes)) != 0)
    return efirc;
  /* Block first attempt by bootmgfw.efi to open
   * EFI_GRAPHICS_OUTPUT_PROTOCOL.  This forces error messages
   * to be displayed in text mode (thereby avoiding the totally
   * blank error screen if the fonts are missing).  We must
   * allow subsequent attempts to succeed, otherwise the OS will
   * fail to boot.
   */
  if ((memcmp (protocol, &efi_graphics_output_protocol_guid,
               sizeof (*protocol)) == 0) && (count++ == 0) &&
               (nt_cmdline->text_mode))
  {
    DBG ("Forcing text mode output\n");
    return EFI_INVALID_PARAMETER;
  }
  return 0;
}

static EFI_GET_VARIABLE orig_get_variable = NULL;
static EFI_EXIT_BOOT_SERVICES orig_exit_bs = NULL;
static UINT8 secureboot_status = 0;

static EFI_STATUS EFIAPI
efi_get_variable_wrapper (CHAR16 *varname, EFI_GUID *guid,
                          UINT32 *attr, UINTN *datasize, void *data)
{
  wchar_t sb[] = L"SecureBoot";
  EFI_STATUS status;

  status = orig_get_variable (varname, guid, attr, datasize, data);
  if (wcscmp (sb, varname) == 0)
  {
    if (*datasize)
      memcpy (data, &secureboot_status, 1);
    *datasize = 1;
  }
  return status;
}

static EFI_STATUS EFIAPI
efi_exit_bs_wrapper (EFI_HANDLE image_handle, UINTN map_key)
{
  if (orig_get_variable)
  {
    efi_systab->RuntimeServices->GetVariable = orig_get_variable;
    orig_get_variable = NULL;
  }
  return orig_exit_bs (image_handle, map_key);
}

static void
efi_sb_set (char *sb)
{
  if (!efi_systab || !sb || !sb[0])
    return;
  if (strcasecmp (sb, "yes") == 0 || strcasecmp (sb, "on") == 0 ||
      strcasecmp (sb, "true") == 0 || strcasecmp (sb, "1") == 0)
    secureboot_status = 1;
  else
    secureboot_status = 0;
  DBG ("...set SecureBoot to %d\n", secureboot_status);
  if (orig_get_variable)
  {
    DBG ("GetVariable already installed.\n");
    return;
  }
  orig_get_variable = efi_systab->RuntimeServices->GetVariable;
  efi_systab->RuntimeServices->GetVariable = efi_get_variable_wrapper;
  orig_exit_bs = efi_systab->BootServices->ExitBootServices;
  efi_systab->BootServices->ExitBootServices = efi_exit_bs_wrapper;
}

/**
 * Boot from EFI device
 *
 * @v file    Virtual file
 */
void efi_boot (struct vdisk_file *file)
{
  EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
  union
  {
    EFI_LOADED_IMAGE_PROTOCOL *image;
    void *intf;
  } loaded;
  EFI_PHYSICAL_ADDRESS phys;
  void *data;
  unsigned int pages;
  EFI_HANDLE handle;
  EFI_STATUS efirc;

  efi_sb_set (nt_cmdline->sb);

  /* Allocate memory */
  pages = ((file->len + PAGE_SIZE - 1) / PAGE_SIZE);
  if ((efirc = bs->AllocatePages (AllocateAnyPages,
                                  EfiLoaderCode, pages, &phys)) != 0)
    die ("Could not allocate %d pages: %#lx\n", pages, ((unsigned long) efirc));
  data = ((void *) (intptr_t) phys);
  /* Read image */
  file->read (file, data, 0, file->len);
  DBG ("Read %s\n", file->name);
  /* Load image */
  if ((efirc = bs->LoadImage (FALSE, efi_image_handle, bootmgfw_path, data,
                              file->len, &handle)) != 0)
    die ("Could not load %s: %#lx\n", file->name, ((unsigned long) efirc));
  DBG ("Loaded %s\n", file->name);
  /* Get loaded image protocol */
  if ((efirc = bs->OpenProtocol (handle,
                                 &efi_loaded_image_protocol_guid,
                                 &loaded.intf, efi_image_handle, NULL,
                                 EFI_OPEN_PROTOCOL_GET_PROTOCOL)) != 0)
  {
    die ("Could not get loaded image protocol for %s: %#lx\n",
         file->name, ((unsigned long) efirc));
  }
  /* Force correct device handle */
  if (loaded.image->DeviceHandle != efi_vpartition.handle)
  {
    DBG ("Forcing correct DeviceHandle (%p->%p)\n",
         loaded.image->DeviceHandle, efi_vpartition.handle);
    loaded.image->DeviceHandle = efi_vpartition.handle;
  }
  /* Intercept calls to OpenProtocol() */
  orig_open_protocol =
          loaded.image->SystemTable->BootServices->OpenProtocol;
  loaded.image->SystemTable->BootServices->OpenProtocol =
          efi_open_protocol_wrapper;
  /* Start image */
  if (nt_cmdline->pause)
    pause_boot ();
  if ((efirc = bs->StartImage (handle, NULL, NULL)) != 0)
    die ("Could not start %s: %#lx\n", file->name, ((unsigned long) efirc));
  die ("%s returned\n", file->name);
}
