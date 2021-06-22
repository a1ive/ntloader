#ifndef _EFILIB_H
#define _EFILIB_H

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

#include "efi.h"

extern efi_system_table_t *efi_systab;
extern efi_handle_t efi_image_handle;

extern efi_guid_t efi_block_io_guid;
extern efi_guid_t efi_device_path_guid;
extern efi_guid_t efi_gop_guid;
extern efi_guid_t efi_loaded_image_guid;
extern efi_guid_t efi_sfs_protocol_guid;

void *
efi_allocate_pages_real (efi_physical_address_t address,
                         efi_uintn_t pages,
                         efi_allocate_type_t alloctype,
                         efi_memory_type_t memtype);
void *
efi_allocate_pages_max (efi_physical_address_t max, efi_uintn_t pages);
void *
efi_allocate_fixed (efi_physical_address_t address, efi_uintn_t pages);
void *
efi_allocate_any_pages (efi_uintn_t pages);
void efi_free_pages (efi_physical_address_t address, efi_uintn_t pages);
efi_uintn_t efi_find_mmap_size (void);
int efi_get_memory_map (efi_uintn_t *memory_map_size,
                        efi_memory_descriptor_t *memory_map,
                        efi_uintn_t *map_key,
                        efi_uintn_t *descriptor_size,
                        efi_uint32_t *descriptor_version);
void efi_mm_init (void);
void efi_mm_fini (void);

void *
efi_locate_protocol (efi_guid_t *protocol, void *registration);
efi_handle_t *
efi_locate_handle (efi_locate_search_type_t search_type,
                   efi_guid_t *protocol, void *search_key,
                   efi_uintn_t *num_handles);
void *
efi_open_protocol (efi_handle_t handle, efi_guid_t *protocol,
                   efi_uint32_t attributes);
efi_loaded_image_t *
efi_get_loaded_image (efi_handle_t image_handle);
efi_status_t
efi_allocate_pool (efi_memory_type_t pool_type,
                   efi_uintn_t buffer_size, void **buffer);
efi_status_t
efi_free_pool (void *buffer);
efi_device_path_t *
efi_get_device_path (efi_handle_t handle);
efi_device_path_t *
efi_find_last_device_path (const efi_device_path_t *dp);
efi_device_path_t *
efi_duplicate_device_path (const efi_device_path_t *dp);
void
efi_gen_guid (efi_packed_guid_t *guid);
efi_packed_guid_t *
efi_copy_guid (efi_packed_guid_t *dest, const efi_packed_guid_t *src);
efi_boolean_t
efi_compare_guid (const efi_packed_guid_t *g1, const efi_packed_guid_t *g2);
int
efi_compare_device_paths (const efi_device_path_t *dp1,
                          const efi_device_path_t *dp2);
efi_device_path_t *
efi_file_device_path (efi_device_path_t *dp, const char *filename);
efi_uintn_t
efi_get_dp_size (const efi_device_path_protocol_t *dp);
efi_device_path_protocol_t*
efi_create_device_node (efi_uint8_t node_type, efi_uintn_t node_subtype,
                        efi_uint16_t node_length);
efi_device_path_protocol_t*
efi_append_device_path (const efi_device_path_protocol_t *dp1,
                        const efi_device_path_protocol_t *dp2);
efi_device_path_protocol_t*
efi_append_device_node (const efi_device_path_protocol_t *device_path,
                        const efi_device_path_protocol_t *device_node);
int
efi_is_child_dp (const efi_device_path_t *child,
                 const efi_device_path_t *parent);


#endif /* _EFI_H */
