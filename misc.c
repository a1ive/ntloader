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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ntboot.h>
#include <acpi.h>
#include <efi.h>

/** Stack cookie */
unsigned long __stack_chk_guard;

/**
 * Construct stack cookie value
 *
 */
static __attribute__ ((noinline)) unsigned long make_cookie (void)
{
  union
  {
    struct
    {
      uint32_t eax;
      uint32_t edx;
    } __attribute__ ((packed));
    unsigned long tsc;
  } u;
  unsigned long cookie;

  /* We have no viable source of entropy.  Use the CPU timestamp
   * counter, which will have at least some minimal randomness
   * in the low bits by the time we are invoked.
   */
  __asm__ ("rdtsc" : "=a" (u.eax), "=d" (u.edx));
  cookie = u.tsc;

  /* Ensure that the value contains a NUL byte, to act as a
   * runaway string terminator.  Construct the NUL using a shift
   * rather than a mask, to avoid losing valuable entropy in the
   * lower-order bits.
   */
  cookie <<= 8;

  return cookie;
}

/**
 * Initialise stack cookie
 *
 * This function must not itself use stack guard
 */
void init_cookie (void)
{
  /* Set stack cookie value
   *
   * This function must not itself use stack protection, since
   * the change in the stack guard value would trigger a false
   * positive.
   *
   * There is unfortunately no way to annotate a function to
   * exclude the use of stack protection.  We must therefore
   * rely on correctly anticipating the compiler's decision on
   * the use of stack protection.
   */
  __stack_chk_guard = make_cookie ();
}

/**
 * Abort on stack check failure
 *
 */
void __stack_chk_fail (void)
{
  /* Abort program */
  die ("Stack check failed\n");
}

/**
 * Handle fatal errors
 *
 * @v fmt Error message format string
 * @v ... Arguments
 */
void die (const char *fmt, ...)
{
  EFI_RUNTIME_SERVICES *rs;
  va_list args;
  /* Print message */
  va_start (args, fmt);
  vprintf (fmt, args);
  va_end (args);
  /* Wait for keypress */
  printf ("Press a key to reboot...");
  getchar();
  printf ("\n");
  /* Reboot */
  acpi_shutdown ();
  if (efi_systab)
  {
    rs = efi_systab->RuntimeServices;
    rs->ResetSystem (EfiResetWarm, 0, 0, NULL);
    printf ("Failed to reboot\\n");
  }
  else
    reboot();
  /* Should be impossible to reach this */
  __builtin_unreachable();
}

/**
 * Pause before booting
 *
 */
void pause_boot (void)
{
  /* Wait for keypress, prompting unless inhibited */
  if (nt_cmdline->pause_quiet)
    getchar();
  else
  {
    printf ("Press any key to continue booting...");
    getchar();
    printf ("\n");
  }
}

static void gotoxy (uint16_t x, uint16_t y)
{
  struct bootapp_callback_params params;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout;
  if (efi_systab)
  {
    conout = efi_systab->ConOut;
    conout->SetCursorPosition (conout, x, y);
  }
  else
  {
    memset (&params, 0, sizeof (params));
    params.vector.interrupt = 0x10;
    params.eax = 0x0200;
    params.ebx = 0;
    params.edx = (y << 8) | x;
    call_interrupt (&params);
  }
}

void cls (void)
{
  struct bootapp_callback_params params;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout;
  uint8_t ch = ' ';
  INT32 orig_attr;
  if (efi_systab)
  {
    conout = efi_systab->ConOut;
    orig_attr = conout->Mode->Attribute;
    conout->SetAttribute (conout, 0x00);
    conout->ClearScreen (conout);
    conout->SetAttribute (conout, orig_attr);
  }
  else
  {
    gotoxy (0, 0);
    memset (&params, 0, sizeof (params));
    params.vector.interrupt = 0x10;
    params.eax = ch | 0x0900;
    params.ebx = 0x0007 & 0xff;
    params.ecx = 80 * 25;
    call_interrupt (&params);
    gotoxy (0, 0);
  }
}

static char nt_ascii_art[] =
"      ___       ___          ___   ___          ___     \n"
"     /\\__\\     /\\  \\        /\\__\\ /\\  \\        /\\  \\    \n"
"    /::|  |    \\:\\  \\      /:/  //::\\  \\      /::\\  \\   \n"
"   /:|:|  |     \\:\\  \\    /:/  //:/\\:\\  \\    /:/\\:\\  \\  \n"
"  /:/|:|  |__   /::\\  \\  /:/  //:/  \\:\\__\\  /::\\~\\:\\  \\ \n"
" /:/ |:| /\\__\\ /:/\\:\\__\\/:/__//:/__/ \\:|__|/:/\\:\\ \\:\\__\\\n"
" \\/__|:|/:/  //:/  \\/__/\\:\\  \\\\:\\  \\ /:/  /\\/_|::\\/:/  /\n"
"     |:/:/  //:/  /      \\:\\  \\\\:\\  /:/  /    |:|::/  / \n"
"     |::/  / \\/__/        \\:\\  \\\\:\\/:/  /     |:|\\/__/  \n"
"     /:/  /                \\:\\__\\\\::/__/      |:|  |    \n"
"     \\/__/                  \\/__/ ~~           \\|__|    \n"
"\n  NTloader " VERSION " -- Windows NT6+ OS/VHD/WIM loader"
"\n          Copyright (C) 2021 A1ive.\n";

void print_banner (void)
{
  printf ("%s", nt_ascii_art);
}

