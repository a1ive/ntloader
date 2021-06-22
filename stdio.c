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

#include <stdio.h>
#include <string.h>
#include <bootapp.h>
#include <ntboot.h>
#include <efi.h>
#include <efilib.h>

/**
 * Print character to console
 *
 * @v character   Character to print
 */
int putchar (int character)
{
  efi_simple_text_output_interface_t *conout;
  struct bootapp_callback_params params;
  wchar_t wbuf[2];
  /* Convert LF to CR,LF */
  if (character == '\n')
  {
    putchar ('\r');
  }
  /* Print character to EFI/BIOS console as applicable */
  if (efi_systab)
  {
    conout = efi_systab->con_out;
    wbuf[0] = character;
    wbuf[1] = 0;
    conout->output_string (conout, wbuf);
  }
  else
  {
    memset (&params, 0, sizeof (params));
    params.vector.interrupt = 0x10;
    params.eax = (0x0e00 | character);
    params.ebx = 0x0007;
    call_interrupt (&params);
  }
  return 0;
}

/**
 * Get character from console
 *
 * @ret character Character
 */
int getchar (void)
{
  efi_boot_services_t *bs;
  efi_simple_input_interface_t *conin;
  efi_input_key_t key;
  efi_uintn_t index;
  struct bootapp_callback_params params;
  int character;
  /* Get character */
  if (efi_systab)
  {
    bs = efi_systab->boot_services;
    conin = efi_systab->con_in;
    bs->wait_for_event (1, &conin->wait_for_key, &index);
    conin->read_key_stroke (conin, &key);
    character = key.unicode_char;
  }
  else
  {
    memset (&params, 0, sizeof (params));
    params.vector.interrupt = 0x16;
    call_interrupt (&params);
    character = params.al;
  }
  return character;
}
