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
#include <stdlib.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <wchar.h>
#include <ntboot.h>
#include <reg.h>
#include <bcd.h>
#include <cmdline.h>
#include <charset.h>
#include <efi.h>

#define BCD_DP_MAGIC "GNU GRUB2 NTBOOT"


static void
bcd_print_hex (const void *data, size_t len)
{
  const uint8_t *p = data;
  size_t i;
  for (i = 0; i < len; i++)
    DBG2 ("%02x ", p[i]);
}

static void
bcd_replace_hex (const void *search, uint32_t search_len,
                 const void *replace, uint32_t replace_len, int count)
{
  uint8_t *p = nt_cmdline->bcd_data;
  uint32_t offset;
  int cnt = 0;
  for (offset = 0; offset + search_len < nt_cmdline->bcd_len; offset++)
  {
    if (memcmp (p + offset, search, search_len) == 0)
    {
      cnt++;

      DBG2 ("0x%08x ", offset);
      bcd_print_hex (search, search_len);
      DBG2 ("\n---> ");
      bcd_print_hex (replace, replace_len);
      DBG2 ("\n");

      memcpy (p + offset, replace, replace_len);
      DBG ("...patched BCD at %#x len %d\n", offset, replace_len);
      if (count && cnt == count)
        break;
    }
  }
}

static void
bcd_patch_path (void)
{
  const char *search = "\\PATH_SIGN";
  size_t len;
  len = 2 * (strlen (nt_cmdline->path) + 1);
  /* UTF-8 to UTF-16le */
  grub_utf8_to_utf16 (nt_cmdline->path16, len,
                      (uint8_t *)nt_cmdline->path, -1, NULL);

  bcd_replace_hex (search, strlen (search), nt_cmdline->path16, len, 0);
}

static void
bcd_patch_hive (reg_hive_t *hive, const wchar_t *keyname, void *val)
{
  HKEY root, objects, osloader, elements, key;
  uint8_t *data = NULL;
  uint32_t data_len = 0, type;
  hive->find_root (hive, &root);
  hive->find_key (hive, root, BCD_REG_ROOT, &objects);
  if (wcscasecmp (keyname, BCDOPT_TIMEOUT) == 0)
    hive->find_key (hive, objects, GUID_BOOTMGR, &osloader);
  else if (wcscasecmp (keyname, BCDOPT_DISPLAY) == 0)
    hive->find_key (hive, objects, GUID_BOOTMGR, &osloader);
  else if (wcscasecmp (keyname, BCDOPT_IMGOFS) == 0)
    hive->find_key (hive, objects, GUID_RAMDISK, &osloader);
  else
    hive->find_key (hive, objects, GUID_OSENTRY, &osloader);
  hive->find_key (hive, osloader, BCD_REG_HKEY, &elements);
  hive->find_key (hive, elements, keyname, &key);
  hive->query_value_no_copy (hive, key, BCD_REG_HVAL,
                             (void **)&data, &data_len, &type);
  memcpy (data, val, data_len);
  DBG ("...patched %p len %d\n", data, data_len);
}

static void
bcd_parse_bool (reg_hive_t *hive, const wchar_t *keyname, const char *s)
{
  uint8_t val = 0;
  if (strcasecmp (s, "yes") == 0 || strcasecmp (s, "on") == 0 ||
      strcasecmp (s, "true") == 0 || strcasecmp (s, "1") == 0)
    val = 1;
  DBG ("...patching key %ls value %d\n", keyname, val);
  bcd_patch_hive (hive, keyname, &val);
}

static void
bcd_parse_u64 (reg_hive_t *hive, const wchar_t *keyname, const char *s)
{
  uint64_t val = 0;
  val = strtoul (s, NULL, 0);
  bcd_patch_hive (hive, keyname, &val);
}

static void
bcd_parse_str (reg_hive_t *hive, const wchar_t *keyname,
               uint8_t resume, const char *s)
{
  HKEY root, objects, osloader, elements, key;
  uint16_t *data = NULL;
  uint32_t data_len = 0, type;
  DBG ("...patching key %ls value %s\n", keyname, s);
  hive->find_root (hive, &root);
  hive->find_key (hive, root, BCD_REG_ROOT, &objects);
  if (resume)
    hive->find_key (hive, objects, GUID_REENTRY, &osloader);
  else
    hive->find_key (hive, objects, GUID_OSENTRY, &osloader);
  hive->find_key (hive, osloader, BCD_REG_HKEY, &elements);
  hive->find_key (hive, elements, keyname, &key);
  hive->query_value_no_copy (hive, key, BCD_REG_HVAL,
                             (void **)&data, &data_len, &type);
  memset (data, 0, data_len);
  grub_utf8_to_utf16 (data, data_len, (uint8_t *)s, -1, NULL);
}

void
bcd_patch_data (void)
{
  static const wchar_t a[] = L".exe";
  static const wchar_t b[] = L".efi";
  reg_hive_t *hive = NULL;
  if (open_hive (nt_cmdline->bcd_data, nt_cmdline->bcd_len, &hive) || !hive)
    die ("BCD hive load error.\n");
  else
    DBG ("BCD hive load OK.\n");

  if (nt_cmdline->type != BOOT_WIN)
    bcd_patch_path ();

  bcd_replace_hex (BCD_DP_MAGIC, strlen (BCD_DP_MAGIC),
                   &nt_cmdline->info, sizeof (struct bcd_disk_info), 0);

  /* display menu
   * default:   no */
  bcd_parse_bool (hive, BCDOPT_DISPLAY, "yes");
  /* timeout
   * default:   1 */
  bcd_parse_u64 (hive, BCDOPT_TIMEOUT, "0");
  /* testsigning
   * default:   no */
  if (nt_cmdline->test_mode[0])
    bcd_parse_bool (hive, BCDOPT_TESTMODE, nt_cmdline->test_mode);
  else
    bcd_parse_bool (hive, BCDOPT_TESTMODE, "no");
  /* force highest resolution
   * default:   no */
  if (nt_cmdline->hires[0])
    bcd_parse_bool (hive, BCDOPT_HIGHEST, nt_cmdline->hires);
  else
    bcd_parse_bool (hive, BCDOPT_HIGHEST, "no");
  /* detect hal and kernel
   * default:   yes */
  if (nt_cmdline->detecthal[0])
    bcd_parse_bool (hive, BCDOPT_DETHAL, nt_cmdline->detecthal);
  else
    bcd_parse_bool (hive, BCDOPT_DETHAL, "yes");
  /* winpe mode
   * default:
   *      OS  - no
   *      VHD - no
   *      WIM - yes */
  if (nt_cmdline->minint[0])
    bcd_parse_bool (hive, BCDOPT_WINPE, nt_cmdline->minint);
  else
  {
    if (nt_cmdline->type == BOOT_WIM)
      bcd_parse_bool (hive, BCDOPT_WINPE, "yes");
    else
      bcd_parse_bool (hive, BCDOPT_WINPE, "no");
  }
  /* disable vesa
   * default:   no */
  if (nt_cmdline->novesa[0])
    bcd_parse_bool (hive, BCDOPT_NOVESA, nt_cmdline->novesa);
  else
    bcd_parse_bool (hive, BCDOPT_NOVESA, "no");
  /* disable vga
   * default:   no */
  if (nt_cmdline->novga[0])
    bcd_parse_bool (hive, BCDOPT_NOVGA, nt_cmdline->novga);
  else
    bcd_parse_bool (hive, BCDOPT_NOVGA, "no");
  /* nx policy
   * default:   OptIn */
  if (nt_cmdline->nx[0])
  {
    uint64_t nx = 0;
    if (strcasecmp (nt_cmdline->nx, "OptIn") == 0)
      nx = NX_OPTIN;
    else if (strcasecmp (nt_cmdline->nx, "OptOut") == 0)
      nx = NX_OPTOUT;
    else if (strcasecmp (nt_cmdline->nx, "AlwaysOff") == 0)
      nx = NX_ALWAYSOFF;
    else if (strcasecmp (nt_cmdline->nx, "AlwaysOn") == 0)
      nx = NX_ALWAYSON;
    bcd_patch_hive (hive, BCDOPT_NX, &nx);
  }
  /* pae
   * default:   Default */
  if (nt_cmdline->pae[0])
  {
    uint64_t pae = 0;
    if (strcasecmp (nt_cmdline->pae, "Default") == 0)
      pae = PAE_DEFAULT;
    else if (strcasecmp (nt_cmdline->pae, "Enable") == 0)
      pae = PAE_ENABLE;
    else if (strcasecmp (nt_cmdline->pae, "Disable") == 0)
      pae = PAE_DISABLE;
    bcd_patch_hive (hive, BCDOPT_PAE, &pae);
  }
  /* load options
   * default:   DDISABLE_INTEGRITY_CHECKS */
  if (nt_cmdline->loadopt[0])
    bcd_parse_str (hive, BCDOPT_CMDLINE, 0, nt_cmdline->loadopt);
  else
    bcd_parse_str (hive, BCDOPT_CMDLINE, 0, BCD_DEFAULT_CMDLINE);
  /* winload.efi
   * default:
   *      OS  - \\Windows\\System32\\winload.efi
   *      VHD - \\Windows\\System32\\winload.efi
   *      WIM - \\Windows\\System32\\boot\\winload.efi */
  if (nt_cmdline->winload[0])
    bcd_parse_str (hive, BCDOPT_WINLOAD, 0, nt_cmdline->winload);
  else
  {
    if (nt_cmdline->type == BOOT_WIM)
      bcd_parse_str (hive, BCDOPT_WINLOAD, 0, BCD_LONG_WINLOAD);
    else
      bcd_parse_str (hive, BCDOPT_WINLOAD, 0, BCD_SHORT_WINLOAD);
  }
  /* windows system root
   * default:   \\Windows */
  if (nt_cmdline->sysroot[0])
    bcd_parse_str (hive, BCDOPT_SYSROOT, 0, nt_cmdline->sysroot);
  else
    bcd_parse_str (hive, BCDOPT_SYSROOT, 0, BCD_DEFAULT_SYSROOT);
  /* windows resume */
  if (nt_cmdline->type == BOOT_WIN)
  {
    bcd_parse_str (hive, BCDOPT_REPATH, 1, BCD_DEFAULT_WINRESUME);
    bcd_parse_str (hive, BCDOPT_REHIBR, 1, BCD_DEFAULT_HIBERFIL);
  }

  if (efi_systab)
    bcd_replace_hex (a, 8, b, 8, 0);
  else
    bcd_replace_hex (b, 8, a, 8, 0);
}
