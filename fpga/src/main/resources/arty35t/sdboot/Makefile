# RISCV environment variable must be set
ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR := $(ROOT_DIR)/build

# XLEN is passed from Scala config (32 or 64)
XLEN ?= 64

CC=$(RISCV)/bin/riscv64-unknown-elf-gcc
OBJCOPY=$(RISCV)/bin/riscv64-unknown-elf-objcopy
OBJDUMP=$(RISCV)/bin/riscv64-unknown-elf-objdump

# Architecture flags based on XLEN
ifeq ($(XLEN),32)
  ARCH_FLAGS = -march=rv32imac_zicsr_zifencei -mabi=ilp32
else
  ARCH_FLAGS = -march=rv64imac_zicsr_zifencei -mabi=lp64
endif

CFLAGS=$(ARCH_FLAGS) -mcmodel=medany -O2 -std=gnu11 -Wall -nostartfiles -nostdlib -nodefaultlibs
CFLAGS+= -fno-common -g -DENTROPY=0 -DNONSMP_HART=0
CFLAGS+= -I $(ROOT_DIR)/include -I.
LFLAGS=-static -nostdlib -L $(ROOT_DIR)/linker -T sdboot.elf.lds

PBUS_CLK ?= 1000000 # default to 1MHz but really should be overridden

default: elf bin dump

elf := $(BUILD_DIR)/sdboot.elf
$(elf): head.S kprintf.c sd.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LFLAGS) -o $@ head.S sd.c kprintf.c

.PHONY: elf
elf: $(elf)

bin := $(BUILD_DIR)/sdboot.bin
$(bin): $(elf)
	mkdir -p $(BUILD_DIR)
	$(OBJCOPY) -O binary --change-addresses=-0x10000 $< $@

.PHONY: bin
bin: $(bin)

dump := $(BUILD_DIR)/sdboot.dump
$(dump): $(elf)
	$(OBJDUMP) -D -S $< > $@

.PHONY: dump
dump: $(dump)

.PHONY: clean
clean::
	rm -rf $(BUILD_DIR)
