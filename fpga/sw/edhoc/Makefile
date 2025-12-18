CC = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-gcc
OBJCOPY = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-objcopy
SIZE = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-size

TARGET = main
BUILD_DIR = build

# RV32IMAC for 32-bit Rocket core
ARCH_FLAGS = -march=rv32imac_zicsr_zifencei -mabi=ilp32 -mcmodel=medany

CFLAGS = $(ARCH_FLAGS) -Os -g0 -ffunction-sections -fdata-sections -Wunused-function
CFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
CFLAGS += -nostartfiles -nostdlib -nodefaultlibs
CFLAGS += -Wall -Wextra -DASCON -DCOMPACT25519 -DMESSAGE_4

LDFLAGS = $(ARCH_FLAGS) -T linker/main.lds -Llinker
LDFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
LDFLAGS += -nostartfiles -nostdlib -nodefaultlibs
LDFLAGS += -Wl,--gc-sections -Wl,-Map=$(BUILD_DIR)/$(TARGET).map
LDFLAGS += -Wl,--allow-multiple-definition

# EDHOC library selection (default: PSK-only)
# Use 'make EDHOC_MODE=original' for original Method 0-3
# Use 'make EDHOC_MODE=psk' for PSK-only (default)
EDHOC_MODE ?= psk

# PSK mode uses smaller credential buffers for reduced stack/code size
ifeq ($(EDHOC_MODE),psk)
CFLAGS += -DEDHOC_PSK_ONLY
endif

ifeq ($(EDHOC_MODE),original)
    EDHOC_LIB_DIR = uoscore-uedhoc
else
    EDHOC_LIB_DIR = uoscore-uedhoc-psk
endif

INCLUDES = -I. -Iinclude -I$(EDHOC_LIB_DIR)/inc
INCLUDES += -I$(EDHOC_LIB_DIR)/inc/common
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/zcbor/include
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/ascon-c/crypto_aead/asconaead128/asm_rv32i
# Use bi32_lowsize for hash (32-bit optimized, no libgcc needed)
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/ascon-c/crypto_hash/asconhash256/bi32_lowsize
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/ascon-c/tests
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/compact25519/src

C_SOURCES = src/main.c src/kprintf.c src/libc_stubs.c src/csprng_stub.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_common.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_encode.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_decode.c
ASCON_AEAD_DIR = $(EDHOC_LIB_DIR)/externals/ascon-c/crypto_aead/asconaead128/asm_rv32i
ASCON_HASH_DIR = $(EDHOC_LIB_DIR)/externals/ascon-c/crypto_hash/asconhash256/bi32_lowsize
# Ascon-AEAD128 (RV32I assembly - ~1.6KB)
C_SOURCES += $(ASCON_AEAD_DIR)/encrypt.c
C_SOURCES += $(ASCON_AEAD_DIR)/decrypt.c
# Ascon-Hash256 (bi32_lowsize - 32-bit optimized, no libgcc, ~1.4KB)
C_SOURCES += $(ASCON_HASH_DIR)/hash.c
C_SOURCES += $(ASCON_HASH_DIR)/permutations.c
C_SOURCES += $(ASCON_HASH_DIR)/interleave.c
C_SOURCES += $(ASCON_HASH_DIR)/constants.c
# Ascon-HMAC (built on Ascon-Hash256 for HKDF)
C_SOURCES += $(EDHOC_LIB_DIR)/src/common/ascon_hmac.c
# Compact25519 X25519 only (no Ed25519, no SHA-512)
C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_x25519.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_wipe.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/c25519.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/f25519.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/fprime.c

ASM_SOURCES = src/crt0.S $(ASCON_AEAD_DIR)/ascon.S
LIBS = -L$(EDHOC_LIB_DIR)/build -luoscore-uedhoc

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.S=.o)))

vpath %.c $(sort $(dir $(C_SOURCES)))
vpath %.S $(sort $(dir $(ASM_SOURCES)))

all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).bin
	@echo "Build complete!"
	@$(SIZE) $(BUILD_DIR)/$(TARGET).elf

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@echo "[CC] $<"
	@$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

$(BUILD_DIR)/%.o: %.S | $(BUILD_DIR)
	@echo "[AS] $<"
	@$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS)
	@echo "[LD] $@"
	@$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	@echo "[OBJCOPY] $@"
	@$(OBJCOPY) -O binary $< $@

$(BUILD_DIR):
	@mkdir -p $@

# EDHOC test targets (Pure Ascon + Compact25519 X25519)
edhoc_initiator: TARGET = edhoc_initiator
edhoc_initiator: C_SOURCES = src/edhoc_initiator_suite0.c src/kprintf.c src/libc_stubs.c src/csprng_stub.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_common.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_encode.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_decode.c
# Ascon-AEAD (RV32I assembly)
edhoc_initiator: C_SOURCES += $(ASCON_AEAD_DIR)/encrypt.c $(ASCON_AEAD_DIR)/decrypt.c
# Ascon-Hash256 (bi32_lowsize - no libgcc)
edhoc_initiator: C_SOURCES += $(ASCON_HASH_DIR)/hash.c $(ASCON_HASH_DIR)/permutations.c
edhoc_initiator: C_SOURCES += $(ASCON_HASH_DIR)/interleave.c $(ASCON_HASH_DIR)/constants.c
# Ascon-HMAC
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/src/common/ascon_hmac.c
# Compact25519 X25519 only (no Ed25519, no SHA-512)
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_x25519.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_wipe.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/c25519.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/f25519.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/fprime.c
edhoc_initiator:
	@echo "Building EDHOC library..."
	@$(MAKE) -C $(EDHOC_LIB_DIR) clean
	@$(MAKE) -C $(EDHOC_LIB_DIR)
	@echo "Building initiator..."
	@$(MAKE) all TARGET=edhoc_initiator C_SOURCES="$(C_SOURCES)"

edhoc_responder: TARGET = edhoc_responder
edhoc_responder: C_SOURCES = src/edhoc_responder_suite0.c src/kprintf.c src/libc_stubs.c src/csprng_stub.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_common.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_encode.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_decode.c
# Ascon-AEAD (RV32I assembly)
edhoc_responder: C_SOURCES += $(ASCON_AEAD_DIR)/encrypt.c $(ASCON_AEAD_DIR)/decrypt.c
# Ascon-Hash256 (bi32_lowsize - no libgcc)
edhoc_responder: C_SOURCES += $(ASCON_HASH_DIR)/hash.c $(ASCON_HASH_DIR)/permutations.c
edhoc_responder: C_SOURCES += $(ASCON_HASH_DIR)/interleave.c $(ASCON_HASH_DIR)/constants.c
# Ascon-HMAC
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/src/common/ascon_hmac.c
# Compact25519 X25519 only (no Ed25519, no SHA-512)
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_x25519.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_wipe.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/c25519.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/f25519.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/fprime.c
edhoc_responder:
	@echo "Building EDHOC library..."
	@$(MAKE) -C $(EDHOC_LIB_DIR) clean
	@$(MAKE) -C $(EDHOC_LIB_DIR)
	@echo "Building responder..."
	@$(MAKE) all TARGET=edhoc_responder C_SOURCES="$(C_SOURCES)"

clean:
	@echo "Cleaning all build artifacts..."
	@rm -rf $(BUILD_DIR) build_initiator build_responder obj
	@$(MAKE) -C uoscore-uedhoc clean
	@$(MAKE) -C uoscore-uedhoc-psk clean
	@echo "Clean complete!"

.PHONY: all clean edhoc_initiator edhoc_responder
