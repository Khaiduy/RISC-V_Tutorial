bmarkdir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

TARGET := riscv64-unknown-elf
CFLAGS := -mcmodel=medany -std=gnu99 -O3 -fno-common -fno-builtin-printf -Wall -fno-tree-loop-distribute-patterns -march=rv64imac -mabi=lp64
LDFLAGS := -static -nostdlib -nostartfiles -lgcc

PROGRAMS := ntt-rocc

objs := crt.o syscalls.o fips202.o indcpa.o poly.o polyvec.o ntt.o reduce.o symmetric-shake.o cbd.o kem.o verify.o
ldscript := link.ld

include $(bmarkdir)/../common.mk
