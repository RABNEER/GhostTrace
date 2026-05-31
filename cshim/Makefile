CC ?= gcc
AR ?= ar
CFLAGS ?= -fno-stack-protector -O2 -fPIC -Wall -Werror

ASM_OBJS = ../asm/trampolines_x86_64.o ../asm/scanner_avx2.o ../asm/pmu_tap.o

all: libghosttrace_shim.a

shim.o: shim.c shim.h
	$(CC) $(CFLAGS) -c -o $@ shim.c

libghosttrace_shim.a: shim.o $(ASM_OBJS)
	$(AR) rcs $@ shim.o $(ASM_OBJS)

clean:
	rm -f shim.o libghosttrace_shim.a
