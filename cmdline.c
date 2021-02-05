/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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

/**
 * @file
 *
 * Command line
 *
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <ntboot.h>
#include <bcd.h>
#include <cmdline.h>

static struct nt_args args;

struct nt_args *nt_cmdline;

static void convert_path (char *str, int backslash)
{
  char *p = str;
  while (*p)
  {
    if (*p == '/' && backslash)
      *p = '\\';
    if (*p == ':')
      *p = ' ';
    if (*p == '\r' || *p == '\n')
      *p = '\0';
    p++;
  }
}

/**
 * Process command line
 *
 * @v cmdline   Command line
 */
void process_cmdline (char *cmdline)
{
  char *tmp = cmdline;
  char *key;
  char *value;
  nt_cmdline = &args;
  memset (&args, 0, sizeof (args));
  args.type = BOOT_WIN;
  /* Do nothing if we have no command line */
  if ((cmdline == NULL) || (cmdline[0] == '\0'))
    return;
  /* Parse command line */
  while (*tmp)
  {
    /* Skip whitespace */
    while (isspace (*tmp))
      tmp++;
    /* Find value (if any) and end of this argument */
    key = tmp;
    value = NULL;
    while (*tmp)
    {
      if (isspace (*tmp))
      {
        * (tmp++) = '\0';
        break;
      }
      else if (*tmp == '=')
      {
        * (tmp++) = '\0';
        value = tmp;
      }
      else
        tmp++;
    }
    /* Process this argument */
    if (strcmp (key, "text") == 0)
      args.text_mode = 1;
    else if (strcmp (key, "quiet") == 0)
      args.quiet = 1;
    else if (strcmp (key, "linear") == 0)
      args.linear = 1;
    else if (strcmp (key, "pause") == 0)
    {
      args.pause = 1;
      if (value && (strcmp (value, "quiet") == 0))
        args.pause_quiet = 1;
    }
    else if (strcmp (key, "uuid") == 0)
    {
      if (! value || ! value[0])
        die ("Argument \"uuid\" needs a value\n");
      strncpy (args.uuid, value, 17);
    }
    else if (strcmp (key, "file") == 0)
    {
      char ext;
      if (! value || ! value[0])
        die ("Argument \"file\" needs a value\n");
      strncpy (args.path, value, 256);
      convert_path (args.path, 1);
      ext = value[strlen (value) - 1];
      if (ext == 'm' || ext == 'M')
        args.type = BOOT_WIM;
      else
        args.type = BOOT_VHD;
    }
    else if (strcmp (key, "initrdfile") == 0 || strcmp (key, "initrd") == 0)
    {
      if (! value || ! value[0])
        die ("Invalid initrd path\n");
      strncpy (args.initrd_path, value, 256);
      convert_path (args.initrd_path, 1);
    }
    else if (strcmp (key, "testmode") == 0)
    {
      if (! value || ! value[0])
        snprintf (args.test_mode, 6, "true");
      else
        snprintf (args.test_mode, 6, "%s", value);
    }
    else if (strcmp (key, "hires") == 0)
    {
      if (! value || ! value[0])
        snprintf (args.hires, 6, "true");
      else
        snprintf (args.hires, 6, "%s", value);
    }
    else if (strcmp (key, "nx") == 0)
    {
      if (! value || ! value[0])
        snprintf (args.nx, 10, "OptIn");
      else
        snprintf (args.nx, 10, "%s", value);
    }
    else if (strcmp (key, "pae") == 0)
    {
      if (! value || ! value[0])
        snprintf (args.pae, 8, "Default");
      else
        snprintf (args.pae, 8, "%s", value);
    }
    else if (strcmp (key, "loadopt") == 0)
    {
      if (! value || ! value[0])
        snprintf (args.loadopt, 128, "DDISABLE_INTEGRITY_CHECKS");
      else
      {
        snprintf (args.loadopt, 128, "%s", value);
        convert_path (args.loadopt, 0);
      }
    }
    else if (strcmp (key, "winload") == 0)
    {
      if (! value || ! value[0])
        snprintf (args.winload, 64, "\\Windows\\System32\\boot\\winload.efi");
      else
      {
        snprintf (args.winload, 64, "%s", value);
        convert_path (args.winload, 1);
      }
    }
    else if (strcmp (key, "sysroot") == 0)
    {
      if (! value || ! value[0])
        snprintf (args.sysroot, 32, "\\Windows");
      else
      {
        snprintf (args.sysroot, 32, "%s", value);
        convert_path (args.sysroot, 1);
      }
    }
    else if (strcmp (key, "secureboot") == 0)
    {
      if (! value || ! value[0])
        snprintf (args.sb, 6, "off");
      else
        snprintf (args.sb, 6, "%s", value);
    }
    else if (strcmp (key, "bgrt") == 0)
      args.bgrt = 1;
    else if (key == cmdline)
    {
      /* Ignore unknown initial arguments, which may
       * be the program name.
       */
    }
    else
      die ("Unrecognised argument \"%s%s%s\"\n", key,
           (value ? "=" : ""), (value ? value : ""));
  }
  DBG ("Command line: %s\n", cmdline);
}
