#################################
# RISCV Toolchain
#################################

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

INCLUDEDIR = $(ROOT_DIR)include
SRCDIR = $(ROOT_DIR)src
DRIVERDIR = $(ROOT_DIR)driver
OBJDIR = $(ROOT_DIR)obj
BINDIR = $(ROOT_DIR)build
LINKDIR = $(ROOT_DIR)linker

CC=$(RISCV)/bin/riscv64-unknown-elf-gcc
OBJCOPY=$(RISCV)/bin/riscv64-unknown-elf-objcopy
OBJDUMP=$(RISCV)/bin/riscv64-unknown-elf-objdump

# RV32IMAC for 32-bit Rocket core
CFLAGS=-march=rv32imac_zicsr_zifencei -mcmodel=medany -O2 -std=gnu11 -Wall -nostartfiles -nostdlib -nodefaultlibs
CFLAGS+= -fno-common -g -mabi=ilp32
CFLAGS+= -I $(ROOT_DIR)include -I $(ROOT_DIR)driver
LFLAGS=-static -L $(ROOT_DIR)linker -T main.lds

# Default
default : elf bin dump

# Source Files
CSOURCES = $(wildcard $(SRCDIR)/*.c)
# Ensure libc_stubs.c is included
CSOURCES += $(SRCDIR)/libc_stubs.c
#CSOURCES := $(SRCDIR)/main.c
SSOURCES = $(wildcard $(SRCDIR)/*.S)

# Object Files
COBJECTS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(filter $(SRCDIR)/%.c, $(CSOURCES)))
#COBJECTS := $(OBJDIR)/main.o
SOBJECTS = $(patsubst $(SRCDIR)/%.S, $(OBJDIR)/%.o, $(SSOURCES))

# Compile
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.S
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

elf := $(BINDIR)/main.elf
$(elf): $(SOBJECTS) $(COBJECTS) 
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(LFLAGS) $^ -o $@
	rm -rf $(OBJDIR)

.PHONY: elf
elf: $(elf)

bin := $(BINDIR)/main.bin
$(bin): $(elf)
	mkdir -p $(BINDIR)
	$(OBJCOPY) -O binary $< $@

.PHONY: bin
bin: $(bin)

dump := $(BINDIR)/main.dump
$(dump): $(elf)
	$(OBJDUMP) -D -S $< > $@

.PHONY: dump
dump: $(dump)

.PHONY: clean
clean::
	rm -rf $(BINDIR)
