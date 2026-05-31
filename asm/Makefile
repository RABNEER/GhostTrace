NASM ?= nasm
AS   ?= aarch64-linux-gnu-as

NASMFLAGS ?= -f elf64 -Wall

all: trampolines_x86_64.o scanner_avx2.o pmu_tap.o

trampolines_x86_64.o: trampolines_x86_64.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

scanner_avx2.o: scanner_avx2.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

pmu_tap.o: pmu_tap.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

trampolines_arm64.o: trampolines_arm64.asm
	$(AS) -o $@ $<

clean:
	rm -f *.o
