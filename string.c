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

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <wctype.h>

void *memmove (void *dest, const void *src, size_t len)
{
  char *d = (char *) dest;
  const char *s = (const char *) src;

  if (d < s)
    while (len--)
      *d++ = *s++;
  else
  {
    d += len;
    s += len;

    while (len--)
      *--d = *--s;
  }

  return dest;
}

#ifdef __clang__
#define VOLATILE_CLANG volatile
#else
#define VOLATILE_CLANG
#endif

void *memset (void *dest, int c, size_t len)
{
  void *p = dest;
  uint8_t pattern8 = c;

  if (len >= 3 * sizeof (unsigned long))
  {
    unsigned long patternl = 0;
    size_t i;

    for (i = 0; i < sizeof (unsigned long); i++)
      patternl |= ((unsigned long) pattern8) << (8 * i);

    while (len > 0 && (((intptr_t) p) & (sizeof (unsigned long) - 1)))
    {
      *(VOLATILE_CLANG uint8_t *) p = pattern8;
      p = (uint8_t *) p + 1;
      len--;
    }
    while (len >= sizeof (unsigned long))
    {
      *(VOLATILE_CLANG unsigned long *) p = patternl;
      p = (unsigned long *) p + 1;
      len -= sizeof (unsigned long);
    }
  }

  while (len > 0)
  {
    *(VOLATILE_CLANG uint8_t *) p = pattern8;
    p = (uint8_t *) p + 1;
    len--;
  }

  return dest;
}

/**
 * Compare memory areas
 *
 * @v src1    First source area
 * @v src2    Second source area
 * @v len   Length
 * @ret diff    Difference
 */
int memcmp (const void *src1, const void *src2, size_t len)
{
  const uint8_t *bytes1 = src1;
  const uint8_t *bytes2 = src2;
  int diff;
  while (len--)
  {
    if ((diff = (* (bytes1++) - * (bytes2++))))
    {
      return diff;
    }
  }
  return 0;
}

/**
 * Compare two strings
 *
 * @v str1    First string
 * @v str2    Second string
 * @ret diff    Difference
 */
int strcmp (const char *str1, const char *str2)
{
  int c1;
  int c2;
  do
  {
    c1 = * (str1++);
    c2 = * (str2++);
  }
  while ((c1 != '\0') && (c1 == c2));
  return (c1 - c2);
}

/**
 * Compare two strings, case-insensitively
 *
 * @v str1    First string
 * @v str2    Second string
 * @ret diff    Difference
 */
int strcasecmp (const char *str1, const char *str2)
{
  int c1;
  int c2;
  do
  {
    c1 = toupper (* (str1++));
    c2 = toupper (* (str2++));
  }
  while ((c1 != '\0') && (c1 == c2));
  return (c1 - c2);
}

/**
 * Compare two wide-character strings
 *
 * @v str1    First string
 * @v str2    Second string
 * @ret diff    Difference
 */
int wcscmp (const wchar_t *str1, const wchar_t *str2)
{
  int c1;
  int c2;
  do
  {
    c1 = * (str1++);
    c2 = * (str2++);
  }
  while ((c1 != L'\0') && (c1 == c2));
  return (c1 - c2);
}

/**
 * Compare two wide-character strings, case-insensitively
 *
 * @v str1    First string
 * @v str2    Second string
 * @ret diff    Difference
 */
int wcscasecmp (const wchar_t *str1, const wchar_t *str2)
{
  int c1;
  int c2;
  do
  {
    c1 = towupper (* (str1++));
    c2 = towupper (* (str2++));
  }
  while ((c1 != L'\0') && (c1 == c2));
  return (c1 - c2);
}

/**
 * Get length of string
 *
 * @v str   String
 * @ret len   Length
 */
size_t strlen (const char *str)
{
  size_t len = 0;
  while (* (str++))
  {
    len++;
  }
  return len;
}

/**
 * Get length of wide-character string
 *
 * @v str   String
 * @ret len   Length (in characters)
 */
size_t wcslen (const wchar_t *str)
{
  size_t len = 0;
  while (* (str++))
  {
    len++;
  }
  return len;
}

/**
 * Find character in wide-character string
 *
 * @v str   String
 * @v c     Wide character
 * @ret first   First occurrence of wide character in string, or NULL
 */
wchar_t *wcschr (const wchar_t *str, wchar_t c)
{
  for (; *str ; str++)
  {
    if (*str == c)
    {
      return ((wchar_t *)str);
    }
  }
  return NULL;
}

/**
 * Check to see if character is a space
 *
 * @v c                 Character
 * @ret isspace         Character is a space
 */
int isspace (int c)
{
  switch (c)
  {
    case ' ' :
    case '\f' :
    case '\n' :
    case '\r' :
    case '\t' :
    case '\v' :
      return 1;
    default:
      return 0;
  }
}

/**
 * Convert a string to an unsigned integer
 *
 * @v nptr    String
 * @v endptr    End pointer to fill in (or NULL)
 * @v base    Numeric base
 * @ret val   Value
 */
unsigned long strtoul (const char *nptr, char **endptr, int base)
{
  unsigned long val = 0;
  int negate = 0;
  unsigned int digit;
  /* Skip any leading whitespace */
  while (isspace (*nptr))
  {
    nptr++;
  }
  /* Parse sign, if present */
  if (*nptr == '+')
  {
    nptr++;
  }
  else if (*nptr == '-')
  {
    nptr++;
    negate = 1;
  }
  /* Parse base */
  if (base == 0)
  {
    /* Default to decimal */
    base = 10;
    /* Check for octal or hexadecimal markers */
    if (*nptr == '0')
    {
      nptr++;
      base = 8;
      if ((*nptr | 0x20) == 'x')
      {
        nptr++;
        base = 16;
      }
    }
  }
  /* Parse digits */
  for (; ; nptr++)
  {
    digit = *nptr;
    if (digit >= 'a')
    {
      digit = (digit - 'a' + 10);
    }
    else if (digit >= 'A')
    {
      digit = (digit - 'A' + 10);
    }
    else if (digit <= '9')
    {
      digit = (digit - '0');
    }
    if (digit >= (unsigned int) base)
    {
      break;
    }
    val = ((val * base) + digit);
  }
  /* Record end marker, if applicable */
  if (endptr)
  {
    *endptr = ((char *) nptr);
  }
  /* Return value */
  return (negate ? -val : val);
}
