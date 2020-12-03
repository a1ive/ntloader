SECTIONS {

	/* bzImage prefix */
	.prefix : AT ( 0 ) {
		_prefix = .;
		*(.prefix)
		*(.prefix.*)
		_eprefix = .;
	}
	_prefix_len = ABSOLUTE ( _eprefix ) - ABSOLUTE ( _prefix );

	/* Payload code executes at 0x20000 */
	. = 0x20000;
	_start = .;

	/* Real-mode uninitialised data section */
	.bss16 ( NOLOAD ) : {
		_bss16 = .;
		*(.stack16)
		*(.stack16.*)
		*(.bss16)
		*(.bss16.*)
		_ebss16 = .;
	}
	_bss16_len = ABSOLUTE ( _ebss16 ) - ABSOLUTE ( _bss16 );

	/* Payload section */
	.payload : AT ( _prefix_len ) {
		_payload = .;
		/* Portions that must be accessible in 16-bit modes */
		*(.text16)
		*(.text16.*)
		*(.rodata16)
		*(.rodata16.*)
		*(.data16)
		*(.data16.*)
		/* Portions that need not be accessible in 16-bit modes */
		*(.text)
		*(.text.*)
		*(.rodata)
		*(.rodata.*)
		*(.data)
		*(.data.*)
		_epayload = .;
	}
	_payload_len = ABSOLUTE ( _epayload ) - ABSOLUTE ( _payload );

	/* bootmgr.exe hardcodes the address 0x30000 for use as a
	 * buffer accessible by real-mode code.  We can't fit our
	 * .text, .data, and .bss below this region, so explicitly
	 * place the .bss higher in memory.
	 */
	_forbidden_start = 0x30000;
	_forbidden_end = 0x40000;

	/* Uninitialised data section */
	.bss ( NOLOAD ) : {
		_bss = .;
		ASSERT ( ABSOLUTE ( . ) <= ABSOLUTE ( _forbidden_start ),
			 "Binary is too large" );
		. = ABSOLUTE ( _forbidden_end );
		*(.bss)
		*(.bss.*)
		*(COMMON)
		*(.stack)
		*(.stack.*)
		_ebss = .;
	}
	_bss_len = ABSOLUTE ( _ebss ) - ABSOLUTE ( _bss );

	_end = .;

	/* Symbols required by i386.x86_64 objects */
	__i386__start = _start;
	__i386__end = _end;

	/DISCARD/ : {
		*(.comment)
		*(.comment.*)
		*(.note)
		*(.note.*)
		*(.eh_frame)
		*(.eh_frame.*)
		*(.rel)
		*(.rel.*)
	}
}
