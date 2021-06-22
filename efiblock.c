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
#include <stdlib.h>
#include <wchar.h>
#include <ntboot.h>
#include <vdisk.h>
#include <efi.h>
#include <efilib.h>
#include <efiblock.h>

/** A block I/O device */
struct efi_block
{
  /** EFI block I/O protocol */
  efi_block_io_t block;
  /** Device path */
  efi_device_path_protocol_t *path;
  /** Starting LBA */
  uint64_t lba;
  /** Handle */
  efi_handle_t handle;
};

static efi_status_t EFIAPI
efi_reset_blocks (efi_block_io_t *this __unused,
                  efi_boolean_t extended __unused)
{
  return EFI_SUCCESS;
}

static efi_status_t EFIAPI
efi_read_blocks (efi_block_io_t *this, efi_uint32_t media __unused,
                 efi_lba_t lba, efi_uintn_t len, void *data)
{
  struct efi_block *block = container_of (this, struct efi_block, block);
  vdisk_read ((lba + block->lba), (len / VDISK_SECTOR_SIZE), data);
  return EFI_SUCCESS;
}

static efi_status_t EFIAPI
efi_write_blocks (efi_block_io_t *this __unused,
                  efi_uint32_t media __unused, efi_lba_t lba __unused,
                  efi_uintn_t len __unused, void *data __unused)
{
  return EFI_WRITE_PROTECTED;
}

static efi_status_t EFIAPI
efi_flush_blocks (efi_block_io_t *this __unused)
{
  return EFI_SUCCESS;
}

/* Virtual disk media */
static efi_block_io_media_t efi_vdisk_media =
{
  .media_id = VDISK_MBR_SIGNATURE,
  .media_present = TRUE,
  .logical_partition = FALSE,
  .read_only = TRUE,
  .block_size = VDISK_SECTOR_SIZE,
  .last_block = VDISK_COUNT - 1,
};

/* Virtual partition media */
static efi_block_io_media_t efi_vpart_media =
{
  .media_id = VDISK_MBR_SIGNATURE,
  .media_present = TRUE,
  .logical_partition = TRUE,
  .read_only = TRUE,
  .block_size = VDISK_SECTOR_SIZE,
  .last_block = VDISK_PARTITION_COUNT - 1,
};

static struct efi_block efi_vdisk =
{
  .block =
  {
    .revision = EFI_BLOCK_IO_PROTOCOL_REVISION,
    .media = &efi_vdisk_media,
    .reset = efi_reset_blocks,
    .read_blocks = efi_read_blocks,
    .write_blocks = efi_write_blocks,
    .flush_blocks = efi_flush_blocks,
  },
  .path = NULL,
  .lba = 0,
  .handle = 0,
};

/* Virtual partition device */
static struct efi_block efi_vpart =
{
  .block =
  {
    .revision = EFI_BLOCK_IO_PROTOCOL_REVISION,
    .media = &efi_vpart_media,
    .reset = efi_reset_blocks,
    .read_blocks = efi_read_blocks,
    .write_blocks = efi_write_blocks,
    .flush_blocks = efi_flush_blocks,
  },
  .path = NULL,
  .lba = VDISK_PARTITION_LBA,
  .handle = 0,
};

/* Install block I/O protocols */
void efi_install (void)
{
  efi_boot_services_t *bs = efi_systab->boot_services;
  efi_status_t efirc;
  efi_device_path_t *tmp_dp;

  tmp_dp = efi_create_device_node (EFI_HARDWARE_DEVICE_PATH_TYPE,
                                   EFI_VENDOR_DEVICE_PATH_SUBTYPE,
                                   sizeof(efi_vendor_device_path_t));
  efi_gen_guid (&((efi_vendor_device_path_t *)tmp_dp)->vendor_guid);
  efi_vdisk.path = efi_append_device_node (NULL, tmp_dp);
  free (tmp_dp);
  /* Install virtual disk */
  DBG ("Installing block I/O protocol for virtual disk...\n");
  efirc = bs->install_multiple_protocol_interfaces (&efi_vdisk.handle,
                       &efi_block_io_guid, &efi_vdisk.block,
                       &efi_device_path_guid, efi_vdisk.path,
                       NULL);
  if (efirc != 0)
  {
    die ("Could not install disk block I/O protocols: %#lx\n",
         ((unsigned long) efirc));
  }
  tmp_dp = efi_create_device_node (EFI_MEDIA_DEVICE_PATH_TYPE,
                                   EFI_HARD_DRIVE_DEVICE_PATH_SUBTYPE,
                                   sizeof (efi_hard_drive_device_path_t));
  ((efi_hard_drive_device_path_t*)tmp_dp)->partition_number = 1;
  ((efi_hard_drive_device_path_t*)tmp_dp)->partition_start = VDISK_PARTITION_LBA;
  ((efi_hard_drive_device_path_t*)tmp_dp)->partition_size = VDISK_PARTITION_COUNT;
  ((efi_hard_drive_device_path_t*)tmp_dp)
        ->partition_signature[0] = ((VDISK_MBR_SIGNATURE >> 0) & 0xff);
  ((efi_hard_drive_device_path_t*)tmp_dp)
        ->partition_signature[1] = ((VDISK_MBR_SIGNATURE >> 8) & 0xff);
  ((efi_hard_drive_device_path_t*)tmp_dp)
        ->partition_signature[2] = ((VDISK_MBR_SIGNATURE >> 16) & 0xff);
  ((efi_hard_drive_device_path_t*)tmp_dp)
        ->partition_signature[3] = ((VDISK_MBR_SIGNATURE >> 24) & 0xff);
  ((efi_hard_drive_device_path_t*)tmp_dp)->partmap_type = 0x01;
  ((efi_hard_drive_device_path_t*)tmp_dp)->signature_type = 0x01;
  efi_vpart.path = efi_append_device_node (efi_vdisk.path, tmp_dp);
  free (tmp_dp);
  /* Install virtual partition */
  DBG ("Installing block I/O protocol for virtual partition...\n");
  efirc = bs->install_multiple_protocol_interfaces (&efi_vpart.handle,
                       &efi_block_io_guid, &efi_vpart.block,
                       &efi_device_path_guid, efi_vpart.path,
                       NULL);
  if (efirc != 0)
  {
    die ("Could not install partition block I/O protocols: %#lx\n",
         ((unsigned long) efirc));
  }
}

/* Original OpenProtocol() method */
static efi_status_t EFIAPI
(*orig_open_protocol) (efi_handle_t handle, efi_guid_t *protocol,
                       void **interface, efi_handle_t agent_handle,
                       efi_handle_t controller_handle,
                       efi_uint32_t attributes) = NULL;

static efi_status_t EFIAPI
(*orig_get_variable) (efi_char16_t *varname, const efi_guid_t *guid,
                      efi_uint32_t *attr, efi_uintn_t *data_size,
                      void *data) = NULL;

static efi_status_t EFIAPI
(*orig_exit_bs) (efi_handle_t image_handle, efi_uintn_t map_key) = NULL;

static efi_status_t EFIAPI
efi_open_protocol_wrapper (efi_handle_t handle, efi_guid_t *protocol,
                           void **interface, efi_handle_t agent_handle,
                           efi_handle_t controller_handle, efi_uint32_t attributes)
{
  static unsigned int count;
  efi_status_t efirc;
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
  if ((memcmp (protocol, &efi_gop_guid,
               sizeof (*protocol)) == 0) && (count++ == 0) &&
               (nt_cmdline->text_mode))
  {
    DBG ("Forcing text mode output\n");
    return EFI_INVALID_PARAMETER;
  }
  return 0;
}

static efi_uint8_t secureboot_status = 0;

static efi_status_t EFIAPI
efi_get_variable_wrapper (efi_char16_t *varname, const efi_guid_t *guid,
                          efi_uint32_t *attr, efi_uintn_t *datasize, void *data)
{
  wchar_t sb[] = L"SecureBoot";
  efi_status_t status;

  status = orig_get_variable (varname, guid, attr, datasize, data);
  if (wcscmp (sb, varname) == 0)
  {
    if (*datasize)
      memcpy (data, &secureboot_status, 1);
    *datasize = 1;
  }
  return status;
}

static efi_status_t EFIAPI
efi_exit_bs_wrapper (efi_handle_t image_handle, efi_uintn_t map_key)
{
  if (orig_get_variable)
  {
    efi_systab->runtime_services->get_variable = orig_get_variable;
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
    DBG ("GetVariable already hooked.\n");
    return;
  }
  orig_get_variable = efi_systab->runtime_services->get_variable;
  efi_systab->runtime_services->get_variable = efi_get_variable_wrapper;
  orig_exit_bs = efi_systab->boot_services->exit_boot_services;
  efi_systab->boot_services->exit_boot_services = efi_exit_bs_wrapper;
}

/**
 * Boot from EFI device
 *
 * @v file    Virtual file
 */
void efi_boot (struct vdisk_file *file)
{
  efi_boot_services_t *bs = efi_systab->boot_services;
  efi_loaded_image_t *loaded = NULL;
  efi_physical_address_t phys;
  void *data;
  unsigned int pages;
  efi_handle_t handle;
  efi_status_t efirc;
  efi_device_path_t *path = NULL;

  efi_sb_set (nt_cmdline->sb);

  /* Allocate memory */
  pages = ((file->len + PAGE_SIZE - 1) / PAGE_SIZE);
  if ((efirc = bs->allocate_pages (EFI_ALLOCATE_ANY_PAGES,
                                   EFI_LOADER_CODE, pages, &phys)) != 0)
    die ("Could not allocate %d pages\n", pages);
  data = ((void *) (intptr_t) phys);
  /* Read image */
  file->read (file, data, 0, file->len);
  DBG ("Read %s\n", file->name);
  /* Device Path */
  path = efi_file_device_path (efi_vdisk.path, EFI_REMOVABLE_MEDIA_FILE_NAME);
  /* Load image */
  if ((efirc = bs->load_image (FALSE, efi_image_handle, path, data,
                               file->len, &handle)) != 0)
    die ("Could not load %s\n", file->name);
  DBG ("Loaded %s\n", file->name);
  /* Get loaded image protocol */
  loaded = efi_get_loaded_image (handle);
  if (!loaded)
    die ("no loaded image available\n");
  /* Force correct device handle */
  if (loaded->device_handle != efi_vpart.handle)
  {
    DBG ("Forcing correct DeviceHandle (%p->%p)\n",
         loaded->device_handle, efi_vpart.handle);
    loaded->device_handle = efi_vpart.handle;
  }
  /* Intercept calls to OpenProtocol() */
  orig_open_protocol = loaded->system_table->boot_services->open_protocol;
  loaded->system_table->boot_services->open_protocol = efi_open_protocol_wrapper;
  /* Start image */
  if (nt_cmdline->pause)
    pause_boot ();
  if ((efirc = bs->start_image (handle, NULL, NULL)) != 0)
    die ("Could not start %s: %#lx\n", file->name, ((unsigned long) efirc));
  die ("%s returned\n", file->name);
}
