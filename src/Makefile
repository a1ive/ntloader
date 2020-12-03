VERSION := v2.6.0

OBJECTS := prefix.o startup.o callback.o main.o vsprintf.o string.o peloader.o
OBJECTS += int13.o vdisk.o cpio.o stdio.o lznt1.o xca.o die.o cmdline.o
OBJECTS += huffman.o pause.o biosdisk.o blocklist.o

OBJECTS_i386 := $(patsubst %.o,%.i386.o,$(OBJECTS))
OBJECTS_x86_64 := $(patsubst %.o,%.x86_64.o,$(OBJECTS))
OBJECTS_i386_x86_64 := $(patsubst %.o,%.i386.x86_64.o,$(OBJECTS))

HEADERS := $(wildcard *.h)

HOST_CC		:= $(CC)
AS		:= $(AS)
ECHO		:= echo
OBJCOPY 	:= objcopy
AR		:= ar
RANLIB		:= ranlib
CP		:= cp
RM		:= rm
DIFF		:= diff
CUT		:= cut

HOST_CFLAGS += -Wall -W -Werror

CFLAGS += -Os -ffreestanding -Wall -W -Werror -nostdinc -I. -fshort-wchar
CFLAGS += -DVERSION="\"$(VERSION)\""

CFLAGS += -m32 -march=i386 -malign-double -fno-pic

# Inhibit -fno-stack-protector
SP_TEST = $(CC) -fno-stack-protector -x c -c /dev/null \
                -o /dev/null >/dev/null 2>&1
SP_FLAGS := $(shell $(SP_TEST) && $(ECHO) '-fno-stack-protector')
WORKAROUND_CFLAGS += $(SP_FLAGS)

# Inhibit unwanted debugging information
CFI_TEST = $(CC) -fno-dwarf2-cfi-asm -fno-exceptions -fno-unwind-tables \
		 -fno-asynchronous-unwind-tables -x c -c /dev/null \
		 -o /dev/null >/dev/null 2>&1
CFI_FLAGS := $(shell $(CFI_TEST) && \
	       $(ECHO) '-fno-dwarf2-cfi-asm -fno-exceptions ' \
		    '-fno-unwind-tables -fno-asynchronous-unwind-tables')
WORKAROUND_CFLAGS += $(CFI_FLAGS)

CFLAGS += $(WORKAROUND_CFLAGS)
CFLAGS += $(EXTRA_CFLAGS)

ifneq ($(DEBUG),)
CFLAGS += -DDEBUG=$(DEBUG)
endif

CFLAGS += -include compiler.h

###############################################################################
#
# Final targets

all : wimboot

wimboot : wimboot.elf
	$(OBJCOPY) -Obinary $< $@
	cp $@ ../$@

wimboot.elf : $(OBJECTS) script.lds
	$(LD) -m elf_i386 -T script.lds -o $@ $(OBJECTS)

%.o : %.S $(HEADERS) Makefile
	$(CC) $(CFLAGS) -DASSEMBLY -Ui386 -E $< | as --32 -o $@

%.o : %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

clean :
	rm -f *.o *.elf wimboot ../wimboot
