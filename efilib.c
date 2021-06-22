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
#include <stdlib.h>
#include <string.h>
#include <ntboot.h>
#include <charset.h>
#include <efilib.h>

efi_handle_t efi_image_handle = 0;
efi_system_table_t *efi_systab = 0;

efi_guid_t efi_block_io_guid = EFI_BLOCK_IO_GUID;
efi_guid_t efi_device_path_guid = EFI_DEVICE_PATH_GUID;
efi_guid_t efi_gop_guid = EFI_GOP_GUID;
efi_guid_t efi_loaded_image_guid = EFI_LOADED_IMAGE_GUID;
efi_guid_t efi_sfs_protocol_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

void *
efi_locate_protocol (efi_guid_t *protocol, void *registration)
{
  void *interface;
  efi_status_t status;
  status = efi_systab->boot_services->locate_protocol (protocol,
                                                       registration, &interface);
  if (status != EFI_SUCCESS)
    return 0;
  return interface;
}

efi_handle_t *
efi_locate_handle (efi_locate_search_type_t search_type,
                   efi_guid_t *protocol, void *search_key,
                   efi_uintn_t *num_handles)
{
  efi_boot_services_t *b;
  efi_status_t status;
  efi_handle_t *buffer;
  efi_uintn_t buffer_size = 8 * sizeof (efi_handle_t);

  buffer = malloc (buffer_size);

  b = efi_systab->boot_services;
  status = b->locate_handle (search_type,
                             protocol, search_key, &buffer_size, buffer);
  if (status == EFI_BUFFER_TOO_SMALL)
  {
    free (buffer);
    buffer = malloc (buffer_size);

    status = b->locate_handle (search_type, protocol, search_key,
                               &buffer_size, buffer);
  }

  if (status != EFI_SUCCESS)
  {
    free (buffer);
    return 0;
  }

  *num_handles = buffer_size / sizeof (efi_handle_t);
  return buffer;
}

void *
efi_open_protocol (efi_handle_t handle, efi_guid_t *protocol,
                   efi_uint32_t attributes)
{
  efi_boot_services_t *b;
  efi_status_t status;
  void *interface;

  b = efi_systab->boot_services;
  status = b->open_protocol (handle, protocol, &interface,
                             efi_image_handle, 0, attributes);
  if (status != EFI_SUCCESS)
    return 0;

  return interface;
}

efi_loaded_image_t *
efi_get_loaded_image (efi_handle_t image_handle)
{
  return efi_open_protocol (image_handle, &efi_loaded_image_guid,
                            EFI_OPEN_PROTOCOL_GET_PROTOCOL);
}

efi_status_t
efi_allocate_pool (efi_memory_type_t pool_type,
                   efi_uintn_t buffer_size, void **buffer)
{
  efi_boot_services_t *b;
  efi_status_t status;

  b = efi_systab->boot_services;
  status = b->allocate_pool (pool_type, buffer_size, buffer);
  return status;
}

efi_status_t
efi_free_pool (void *buffer)
{
  efi_boot_services_t *b;
  efi_status_t status;

  b = efi_systab->boot_services;
  status = b->free_pool (buffer);
  return status;
}

efi_device_path_t *
efi_get_device_path (efi_handle_t handle)
{
  return efi_open_protocol (handle, &efi_device_path_guid,
                            EFI_OPEN_PROTOCOL_GET_PROTOCOL);
}

/* Return the device path node right before the end node.  */
efi_device_path_t *
efi_find_last_device_path (const efi_device_path_t *dp)
{
  efi_device_path_t *next, *p;

  if (EFI_END_ENTIRE_DEVICE_PATH (dp))
    return 0;

  for (p = (efi_device_path_t *) dp, next = EFI_NEXT_DEVICE_PATH (p);
       ! EFI_END_ENTIRE_DEVICE_PATH (next);
       p = next, next = EFI_NEXT_DEVICE_PATH (next))
    ;

  return p;
}

/* Duplicate a device path.  */
efi_device_path_t *
efi_duplicate_device_path (const efi_device_path_t *dp)
{
  efi_device_path_t *p;
  size_t total_size = 0;

  for (p = (efi_device_path_t *) dp; ; p = EFI_NEXT_DEVICE_PATH (p))
  {
    size_t len = EFI_DEVICE_PATH_LENGTH (p);

    /*
     * In the event that we find a node that's completely garbage, for
     * example if we get to 0x7f 0x01 0x02 0x00 ... (EndInstance with a size
     * of 2), EFI_END_ENTIRE_DEVICE_PATH() will be true and
     * EFI_NEXT_DEVICE_PATH() will return NULL, so we won't continue,
     * and neither should our consumers, but there won't be any error raised
     * even though the device path is junk.
     *
     * This keeps us from passing junk down back to our caller.
     */
    if (len < 4)
    {
      printf ("malformed EFI Device Path node has length=%ld\n",
              (unsigned long) len);
      return NULL;
    }

    total_size += len;
    if (EFI_END_ENTIRE_DEVICE_PATH (p))
      break;
  }

  p = malloc (total_size);

  memcpy (p, dp, total_size);
  return p;
}

static uint32_t next = 1;

static uint32_t rand (void)
{
  next = next * 1103515245 + 12345;
  return (next << 16) | ((next >> 16) & 0xFFFF);
}

static void srand (uint32_t seed)
{
  next = seed;
}

void
efi_gen_guid (efi_packed_guid_t *guid)
{
  int i;
  uint32_t r;
  efi_status_t status;
  struct efi_time tm;
  efi_runtime_services_t *rt;

  rt = efi_systab->runtime_services;
  status = rt->get_time (&tm, 0);
  if (status != EFI_SUCCESS)
    srand (0x14530529);
  else
    srand (tm.nanosecond);

  for (i = 0; i < 4; i++)
  {
    r = rand ();
    memcpy ((uint32_t *)guid + i, &r, sizeof (uint32_t));
  }
}

efi_packed_guid_t *
efi_copy_guid (efi_packed_guid_t *dest, const efi_packed_guid_t *src)
{
  set_unaligned64 ((efi_uint64_t *)dest,
                        get_unaligned64 ((const efi_uint64_t *)src));
  set_unaligned64 ((efi_uint64_t *)dest + 1,
                        get_unaligned64 ((const efi_uint64_t*)src + 1));
  return dest;
}

efi_boolean_t
efi_compare_guid (const efi_packed_guid_t *g1, const efi_packed_guid_t *g2)
{
  efi_uint64_t g1_low, g2_low;
  efi_uint64_t g1_high, g2_high;
  g1_low = get_unaligned64 ((const efi_uint64_t *)g1);
  g2_low = get_unaligned64 ((const efi_uint64_t *)g2);
  g1_high = get_unaligned64 ((const efi_uint64_t *)g1 + 1);
  g2_high = get_unaligned64 ((const efi_uint64_t *)g2 + 1);
  return (efi_boolean_t) (g1_low == g2_low && g1_high == g2_high);
}

/* Compare device paths.  */
int
efi_compare_device_paths (const efi_device_path_t *dp1,
                          const efi_device_path_t *dp2)
{
  if (! dp1 || ! dp2)
    /* Return non-zero.  */
    return 1;

  if (dp1 == dp2)
    return 0;

  while (EFI_DEVICE_PATH_VALID (dp1) && EFI_DEVICE_PATH_VALID (dp2))
  {
    efi_uint8_t type1, type2;
    efi_uint8_t subtype1, subtype2;
    efi_uint16_t len1, len2;
    int ret;

    type1 = EFI_DEVICE_PATH_TYPE (dp1);
    type2 = EFI_DEVICE_PATH_TYPE (dp2);

    if (type1 != type2)
      return (int) type2 - (int) type1;

    subtype1 = EFI_DEVICE_PATH_SUBTYPE (dp1);
    subtype2 = EFI_DEVICE_PATH_SUBTYPE (dp2);

    if (subtype1 != subtype2)
      return (int) subtype1 - (int) subtype2;

    len1 = EFI_DEVICE_PATH_LENGTH (dp1);
    len2 = EFI_DEVICE_PATH_LENGTH (dp2);

    if (len1 != len2)
      return (int) len1 - (int) len2;

    ret = memcmp (dp1, dp2, len1);
    if (ret != 0)
      return ret;

    if (EFI_END_ENTIRE_DEVICE_PATH (dp1))
      break;

    dp1 = (efi_device_path_t *) ((char *) dp1 + len1);
    dp2 = (efi_device_path_t *) ((char *) dp2 + len2);
  }

  /*
   * There's no "right" answer here, but we probably don't want to call a valid
   * dp and an invalid dp equal, so pick one way or the other.
   */
  if (EFI_DEVICE_PATH_VALID (dp1) && !EFI_DEVICE_PATH_VALID (dp2))
    return 1;
  else if (!EFI_DEVICE_PATH_VALID (dp1) && EFI_DEVICE_PATH_VALID (dp2))
    return -1;

  return 0;
}

static void
copy_file_path (efi_file_path_device_path_t *fp,
                const char *str, efi_uint16_t len)
{
  efi_char16_t *p, *path_name;
  efi_uint16_t size;

  fp->header.type = EFI_MEDIA_DEVICE_PATH_TYPE;
  fp->header.subtype = EFI_FILE_PATH_DEVICE_PATH_SUBTYPE;

  path_name = malloc (len * MAX_UTF16_PER_UTF8 * sizeof (*path_name));

  size = utf8_to_utf16 (path_name, len * MAX_UTF16_PER_UTF8,
                        (const uint8_t *) str, len, 0);
  for (p = path_name; p < path_name + size; p++)
    if (*p == '/')
      *p = '\\';

  memcpy (fp->path_name, path_name, size * sizeof (*fp->path_name));
  /* File Path is NULL terminated */
  fp->path_name[size++] = '\0';
  fp->header.length = size * sizeof (efi_char16_t) + sizeof (*fp);
  free (path_name);
}

efi_device_path_t *
efi_file_device_path (efi_device_path_t *dp, const char *filename)
{
  char *dir_start;
  char *dir_end;
  size_t size;
  efi_device_path_t *d;
  efi_device_path_t *file_path;

  dir_start = strchr (filename, ')');
  if (! dir_start)
    dir_start = (char *) filename;
  else
    dir_start++;

  dir_end = strrchr (dir_start, '/');
  if (! dir_end)
  {
    printf ("invalid EFI file path\n");
    return 0;
  }

  size = 0;
  d = dp;
  while (d)
  {
    size_t len = EFI_DEVICE_PATH_LENGTH (d);

    if (len < 4)
    {
      printf ("malformed EFI Device Path node has length=%ld\n",
              (unsigned long) len);
      return NULL;
    }

    size += len;
    if ((EFI_END_ENTIRE_DEVICE_PATH (d)))
      break;
    d = EFI_NEXT_DEVICE_PATH (d);
  }

  /* File Path is NULL terminated. Allocate space for 2 extra characters */
  /* FIXME why we split path in two components? */
  file_path = malloc (size + ((strlen (dir_start) + 2) * MAX_UTF16_PER_UTF8
                      * sizeof (efi_char16_t))
                      + sizeof (efi_file_path_device_path_t) * 2);

  memcpy (file_path, dp, size);

  /* Fill the file path for the directory.  */
  d = (efi_device_path_t *) ((char *) file_path + ((char *) d - (char *) dp));

  copy_file_path ((void *) d, dir_start, dir_end - dir_start);

  /* Fill the file path for the file.  */
  d = EFI_NEXT_DEVICE_PATH (d);
  copy_file_path ((void *) d, dir_end + 1, strlen (dir_end + 1));

  /* Fill the end of device path nodes.  */
  d = EFI_NEXT_DEVICE_PATH (d);
  d->type = EFI_END_DEVICE_PATH_TYPE;
  d->subtype = EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
  d->length = sizeof (*d);

  return file_path;
}

static efi_uintn_t
device_path_node_length (const void *node)
{
  return get_unaligned16 ((efi_uint16_t *)
                          &((efi_device_path_protocol_t *)(node))->length);
}

static void
set_device_path_node_length (void *node, efi_uintn_t len)
{
  set_unaligned16 ((efi_uint16_t *)
                   &((efi_device_path_protocol_t *)(node))->length,
                   (efi_uint16_t)(len));
}

efi_uintn_t
efi_get_dp_size (const efi_device_path_protocol_t *dp)
{
  efi_device_path_t *p;
  efi_uintn_t total_size = 0;
  for (p = (efi_device_path_t *) dp; ; p = EFI_NEXT_DEVICE_PATH (p))
  {
    total_size += EFI_DEVICE_PATH_LENGTH (p);
    if (EFI_END_ENTIRE_DEVICE_PATH (p))
      break;
  }
  return total_size;
}

efi_device_path_protocol_t*
efi_create_device_node (efi_uint8_t node_type, efi_uintn_t node_subtype,
                        efi_uint16_t node_length)
{
  efi_device_path_protocol_t *dp;
  if (node_length < sizeof (efi_device_path_protocol_t))
    return NULL;
  dp = zalloc (node_length);
  dp->type = node_type;
  dp->subtype = node_subtype;
  set_device_path_node_length (dp, node_length);
  return dp;
}

efi_device_path_protocol_t*
efi_append_device_path (const efi_device_path_protocol_t *dp1,
                        const efi_device_path_protocol_t *dp2)
{
  efi_uintn_t size;
  efi_uintn_t size1;
  efi_uintn_t size2;
  efi_device_path_protocol_t *new_dp;
  efi_device_path_protocol_t *tmp_dp;
  // If there's only 1 path, just duplicate it.
  if (dp1 == NULL)
  {
    if (dp2 == NULL)
      return efi_create_device_node (EFI_END_DEVICE_PATH_TYPE,
                                     EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE,
                                     sizeof (efi_device_path_protocol_t));
    else
      return efi_duplicate_device_path (dp2);
  }
  if (dp2 == NULL)
    efi_duplicate_device_path (dp1);
  // Allocate space for the combined device path. It only has one end node of
  // length EFI_DEVICE_PATH_PROTOCOL.
  size1 = efi_get_dp_size (dp1);
  size2 = efi_get_dp_size (dp2);
  size = size1 + size2 - sizeof (efi_device_path_protocol_t);
  new_dp = malloc (size);

  new_dp = memcpy (new_dp, dp1, size1);
  // Over write FirstDevicePath EndNode and do the copy
  tmp_dp = (efi_device_path_protocol_t *)
           ((char *) new_dp + (size1 - sizeof (efi_device_path_protocol_t)));
  memcpy (tmp_dp, dp2, size2);

  return new_dp;
}

efi_device_path_protocol_t*
efi_append_device_node (const efi_device_path_protocol_t *device_path,
                        const efi_device_path_protocol_t *device_node)
{
  efi_device_path_protocol_t *tmp_dp;
  efi_device_path_protocol_t *next_node;
  efi_device_path_protocol_t *new_dp;
  efi_uintn_t node_length;
  if (device_node == NULL)
  {
    if (device_path == NULL)
      return efi_create_device_node (EFI_END_DEVICE_PATH_TYPE,
                                     EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE,
                                     sizeof (efi_device_path_protocol_t));
    else
      return efi_duplicate_device_path (device_path);
  }
  // Build a Node that has a terminator on it
  node_length = device_path_node_length (device_node);

  tmp_dp = malloc (node_length + sizeof (efi_device_path_protocol_t));

  tmp_dp = memcpy (tmp_dp, device_node, node_length);
  // Add and end device path node to convert Node to device path
  next_node = EFI_NEXT_DEVICE_PATH (tmp_dp);
  next_node->type = EFI_END_DEVICE_PATH_TYPE;
  next_node->subtype = EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
  next_node->length = sizeof (efi_device_path_protocol_t);
  // Append device paths
  new_dp = efi_append_device_path (device_path, tmp_dp);
  free (tmp_dp);
  return new_dp;
}

int
efi_is_child_dp (const efi_device_path_t *child,
                 const efi_device_path_t *parent)
{
  efi_device_path_t *dp, *ldp;
  int ret = 0;

  dp = efi_duplicate_device_path (child);
  if (! dp)
    return 0;

  while (!ret)
  {
    ldp = efi_find_last_device_path (dp);
    if (!ldp)
      break;

    ldp->type = EFI_END_DEVICE_PATH_TYPE;
    ldp->subtype = EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
    ldp->length = sizeof (*ldp);

    ret = (efi_compare_device_paths (dp, parent) == 0);
  }

  free (dp);
  return ret;
}
