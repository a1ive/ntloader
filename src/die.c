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
 * Fatal errors
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include "wimboot.h"

/**
 * Handle fatal errors
 *
 * @v fmt	Error message format string
 * @v ...	Arguments
 */
void die ( const char *fmt, ... ) {
	va_list args;

	/* Print message */
	va_start ( args, fmt );
	vprintf ( fmt, args );
	va_end ( args );

	/* Wait for keypress */
	printf ( "Press a key to reboot..." );
	getchar();
	printf ( "\n" );

	/* Reboot system */
	reboot();

	/* Should be impossible to reach this */
	__builtin_unreachable();
}
