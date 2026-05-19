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

PBUS_CLK ?= 1000000 # default to 1MHz but really should be overridden

# SRAM_SIZE: target scratchpad size in bytes (hex).
# 0x20000 = 128 kB (SmallRocket32M3Config — pure-SW EDHOC, default)
# 0x10000 =  64 kB (SmallRocket32Config / SmallRocket32M3HWConfig — hardware-accelerated EDHOC M3)
# 0x2000  =   8 kB (reserved / minimal)
SRAM_SIZE ?= 0x10000
CFLAGS += -DSRAM_SIZE=$(SRAM_SIZE)

# Choose linker script that matches the target SRAM region.
ifeq ($(SRAM_SIZE),0x2000)
  LFLAGS=-static -nostdlib -L $(ROOT_DIR)/linker -T sdboot_m3.elf.lds
else
  LFLAGS=-static -nostdlib -L $(ROOT_DIR)/linker -T sdboot.elf.lds
endif

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
