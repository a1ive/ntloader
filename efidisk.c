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
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ntboot.h>
#include <efi.h>
#include <efilib.h>
#include <efidisk.h>
#include <msdos.h>
#include <gpt.h>

static struct efidisk_data *efi_hd = 0;
static struct efidisk_data *efi_cd = 0;
static struct efidisk_data *efi_fd = 0;

static struct efidisk_data *
make_devices (void)
{
  efi_uintn_t num_handles;
  efi_handle_t *handles;
  efi_handle_t *handle;
  struct efidisk_data *devices = 0;

  /* Find handles which support the disk io interface.  */
  handles = efi_locate_handle (EFI_BY_PROTOCOL, &efi_block_io_guid,
                               0, &num_handles);
  if (! handles)
    return 0;

  for (handle = handles; num_handles--; handle++)
  {
    efi_device_path_t *dp;
    efi_device_path_t *ldp;
    efi_block_io_t *bio;
    struct efidisk_data *d;

    dp = efi_get_device_path (*handle);
    if (! dp)
      continue;
    ldp = efi_find_last_device_path (dp);
    if (! ldp)
      continue;

    bio = efi_open_protocol (*handle, &efi_block_io_guid,
                             EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (! bio || !bio->media)
      continue;

    /* iPXE adds stub Block IO protocol to loaded image device handle. It is
       completely non-functional and simply returns an error for every method.
       So attempt to detect and skip it. Magic number is literal "iPXE" and
       check block size as well */
    if (bio->media->media_id == 0x69505845U && bio->media->block_size == 1)
      continue;
    if (bio->media->block_size & (bio->media->block_size - 1) ||
        bio->media->block_size < 512)
      continue;

    d = malloc (sizeof (*d));
    d->handle = *handle;
    d->dp = dp;
    d->ldp = ldp;
    d->bio = bio;
    d->next = devices;
    devices = d;
  }

  free (handles);

  return devices;
}

/* Find the parent device.  */
static struct efidisk_data *
find_parent_device (struct efidisk_data *devices, struct efidisk_data *d)
{
  efi_device_path_t *dp, *ldp;
  struct efidisk_data *parent;
  dp = efi_duplicate_device_path (d->dp);
  if (! dp)
    return 0;
  ldp = efi_find_last_device_path (dp);
  if (! ldp)
    return 0;
  ldp->type = EFI_END_DEVICE_PATH_TYPE;
  ldp->subtype = EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
  ldp->length = sizeof (*ldp);
  for (parent = devices; parent; parent = parent->next)
  {
    /* Ignore itself.  */
    if (parent == d)
      continue;
    if (efi_compare_device_paths (parent->dp, dp) == 0)
      break;
  }
  free (dp);
  return parent;
}

#if 0
static int
is_child (struct efidisk_data *child, struct efidisk_data *parent)
{
  efi_device_path_t *dp, *ldp;
  int ret;
  dp = efi_duplicate_device_path (child->dp);
  if (! dp)
    return 0;
  ldp = efi_find_last_device_path (dp);
  if (! ldp)
    return 0;
  ldp->type = EFI_END_DEVICE_PATH_TYPE;
  ldp->subtype = EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
  ldp->length = sizeof (*ldp);
  ret = (efi_compare_device_paths (dp, parent->dp) == 0);
  free (dp);
  return ret;
}

#define FOR_CHILDREN(p, dev) for (p = dev; p; p = p->next) if (is_child (p, d))
#endif

/* Add a device into a list of devices in an ascending order.  */
static void
add_device (struct efidisk_data **devices, struct efidisk_data *d)
{
  struct efidisk_data **p;
  struct efidisk_data *n;
  for (p = devices; *p; p = &((*p)->next))
  {
    int ret;
    ret = efi_compare_device_paths (efi_find_last_device_path ((*p)->dp),
                                    efi_find_last_device_path (d->dp));
    if (ret == 0)
      ret = efi_compare_device_paths ((*p)->dp, d->dp);
    if (ret == 0)
      return;
    else if (ret > 0)
      break;
  }
  n = malloc (sizeof (*n));
  if (! n)
    return;
  memcpy (n, d, sizeof (*n));
  n->next = (*p);
  (*p) = n;
}

/* Name the devices.  */
static void
name_devices (struct efidisk_data *devices)
{
  struct efidisk_data *d;

  /* First, identify devices by media device paths.  */
  for (d = devices; d; d = d->next)
  {
    efi_device_path_t *dp;
    dp = d->ldp;
    if (! dp)
      continue;
    if (EFI_DEVICE_PATH_TYPE (dp) == EFI_MEDIA_DEVICE_PATH_TYPE)
    {
      int is_hard_drive = 0;
      switch (EFI_DEVICE_PATH_SUBTYPE (dp))
      {
        case EFI_HARD_DRIVE_DEVICE_PATH_SUBTYPE:
          is_hard_drive = 1;
          /* Intentionally fall through.  */
        case EFI_CDROM_DEVICE_PATH_SUBTYPE:
        {
          struct efidisk_data *parent, *parent2;
          parent = find_parent_device (devices, d);
          if (!parent)
            break;
          parent2 = find_parent_device (devices, parent);
          if (parent2)
          {
            /* Mark itself as used.  */
            d->ldp = 0;
            break;
          }
          if (!parent->ldp)
          {
            d->ldp = 0;
            break;
          }
          if (is_hard_drive)
            add_device (&efi_hd, parent);
          else
            add_device (&efi_cd, parent);
          /* Mark the parent as used.  */
          parent->ldp = 0;
          /* Mark itself as used.  */
          d->ldp = 0;
          break;
        }
        default:
          break;
      }
    }
  }

  /* Let's see what can be added more.  */
  for (d = devices; d; d = d->next)
  {
    efi_device_path_t *dp;
    efi_block_io_media_t *m;
    int is_floppy = 0;

    dp = d->ldp;
    if (! dp)
      continue;

    /* Ghosts proudly presented by Apple.  */
    if (EFI_DEVICE_PATH_TYPE (dp) == EFI_MEDIA_DEVICE_PATH_TYPE &&
        EFI_DEVICE_PATH_SUBTYPE (dp) == EFI_VENDOR_MEDIA_DEVICE_PATH_SUBTYPE)
    {
      efi_vendor_device_path_t *vendor = (efi_vendor_device_path_t *) dp;
      const efi_guid_t apple = EFI_VENDOR_APPLE_GUID;

      if (EFI_DEVICE_PATH_LENGTH (&vendor->header) == sizeof (*vendor) &&
          memcmp (&vendor->vendor_guid, &apple,
                  sizeof (vendor->vendor_guid)) == 0 &&
          find_parent_device (devices, d))
        continue;
    }

    m = d->bio->media;
    if (EFI_DEVICE_PATH_TYPE (dp) == EFI_ACPI_DEVICE_PATH_TYPE &&
        EFI_DEVICE_PATH_SUBTYPE (dp) == EFI_ACPI_DEVICE_PATH_SUBTYPE)
    {
      efi_acpi_device_path_t *acpi = (void *) dp;
      /* Floppy EISA ID.  */
      if (acpi->hid == 0x60441d0 || acpi->hid == 0x70041d0 ||
          acpi->hid == 0x70141d1)
        is_floppy = 1;
    }
    if (is_floppy)
      add_device (&efi_hd, d);
    else if (m->read_only && m->block_size > 512)
    {
      /* This check is too heuristic, but assume that this is a
         CDROM drive.  */
      add_device (&efi_cd, d);
    }
    else
    {
      /* The default is a hard drive.  */
      add_device (&efi_hd, d);
    }
  }
}

static void
free_devices (struct efidisk_data *devices)
{
  struct efidisk_data *p, *q;
  for (p = devices; p; p = q)
  {
    q = p->next;
    free (p);
  }
}

int
efidisk_read (void *disk, uint64_t sector, size_t len, void *buf)
{
  struct efidisk_data *d = disk;
  efi_block_io_t *bio;
  efi_status_t status;
  size_t io_align;
  char *aligned_buf;

  bio = d->bio;

  /* Set alignment to 1 if 0 specified */
  io_align = bio->media->io_align ? bio->media->io_align : 1;
  if (io_align & (io_align - 1))
  {
    DBG ("invalid buffer alignment %ld\n", (unsigned long) io_align);
    return 0;
  }
  if ((intptr_t) buf & (io_align - 1))
  {
    aligned_buf = memalign (io_align, len);
    if (! aligned_buf)
      return 0;
  }
  else
  {
    aligned_buf = buf;
  }

  status = bio->read_blocks (bio, bio->media->media_id,
                             sector, len, aligned_buf);
  if ((intptr_t) buf & (io_align - 1))
  {
    memcpy (buf, aligned_buf, len);
    free (aligned_buf);
  }

  if (status != EFI_SUCCESS)
  {
    DBG ("failure reading sector 0x%llx from %s\n", sector, d->name);
    return 0;
  }

  return 1;
}

void
efidisk_iterate (void)
{
  struct efidisk_data *d;
  int count;
  for (d = efi_hd, count = 0; d; d = d->next, count++)
  {
    snprintf (d->name, 16, "hd%d", count);
    DBG ("%s\n", d->name);
    if (check_msdos_partmap (d, efidisk_read))
      break;
    if (check_gpt_partmap (d, efidisk_read))
      break;
  }
}

void
efidisk_init (void)
{
  struct efidisk_data *devices;
  devices = make_devices ();
  if (! devices)
    return;
  name_devices (devices);
  free_devices (devices);
}

void
efidisk_fini (void)
{
  free_devices (efi_fd);
  free_devices (efi_hd);
  free_devices (efi_cd);
}
