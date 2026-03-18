CC = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-gcc
AR = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-ar
OBJCOPY = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-objcopy
SIZE = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-size

TARGET = main
BUILD_DIR = build

# RV32IMAC for 32-bit Rocket core
ARCH_FLAGS = -march=rv32imac_zicsr_zifencei -mabi=ilp32 -mcmodel=medany

# Debug output control: set DEBUG=1 to enable all debug prints
# DEBUG=0 (default) gives clean timing measurements
DEBUG ?= 0

CFLAGS = $(ARCH_FLAGS) -Os  -g0 -ffunction-sections -fdata-sections -Wunused-function
CFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
CFLAGS += -nostartfiles -nostdlib -nodefaultlibs -fno-builtin
CFLAGS += -Wall -Wextra -DMONOCYPHER -DMESSAGE_4 -DZCBOR_CANONICAL -DTIMING_BREAKDOWN
ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG_PRINT
endif

# Crypto Suite Selection:
#   CRYPTO_SUITE=0: Suite 0 - AES-CCM-16-64-128 + SHA256 (8-byte tag, 13-byte nonce)
#   CRYPTO_SUITE=1: Suite 1 - AES-CCM-16-128-128 + SHA256 (16-byte tag, 13-byte nonce)
#   CRYPTO_SUITE=7: Suite 7 - Ascon-AEAD-128 + Ascon-Hash256 (16-byte tag, 16-byte nonce) [default]
CRYPTO_SUITE ?= 7

ifeq ($(CRYPTO_SUITE),0)
$(info Building with Suite 0: AES-CCM-16-64-128 (8-byte tag))
CFLAGS += -DTINYCRYPT -DEDHOC_CRYPTO_SUITE=0
else ifeq ($(CRYPTO_SUITE),1)
$(info Building with Suite 1: AES-CCM-16-128-128 (16-byte tag))
CFLAGS += -DTINYCRYPT -DEDHOC_CRYPTO_SUITE=1
else ifeq ($(CRYPTO_SUITE),7)
$(info Building with Suite 7: Ascon-AEAD-128 + Ascon-Hash256)
CFLAGS += -DASCON -DEDHOC_CRYPTO_SUITE=7
else
$(error Invalid CRYPTO_SUITE=$(CRYPTO_SUITE). Use 0, 1, or 7)
endif

LDFLAGS = $(ARCH_FLAGS) -T linker/main.lds  -Llinker
LDFLAGS += -fno-builtin -fno-unwind-tables -fno-asynchronous-unwind-tables
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

INCLUDES += -I$(EDHOC_LIB_DIR)/externals/Monocypher/src

# Suite-specific includes
ifeq ($(filter $(CRYPTO_SUITE),0 1),$(CRYPTO_SUITE))
# Suite 0/1: TinyCrypt (AES-CCM + HMAC-SHA256)
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/tinycrypt/lib/include
else ifeq ($(CRYPTO_SUITE),7)
# Suite 7: Ascon (AEAD + Hash + HMAC) - using ref (reference) pure C implementation
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/ascon-c/crypto_aead/asconaead128/ref
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/ascon-c/crypto_hash/asconhash256/ref
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/ascon-c/tests
endif

# Common sources
C_SOURCES = src/main.c src/kprintf.c src/libc_stubs.c src/csprng_stub.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_common.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_encode.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_decode.c

# Compact25519 X25519 (common to both suites)







# Suite-specific crypto sources
TINYCRYPT_DIR = $(EDHOC_LIB_DIR)/externals/tinycrypt/lib/source
# Use opt32 implementation - optimized for 32-bit RISC-V
ASCON_AEAD_DIR = $(EDHOC_LIB_DIR)/externals/ascon-c/crypto_aead/asconaead128/opt32
ASCON_HASH_DIR = $(EDHOC_LIB_DIR)/externals/ascon-c/crypto_hash/asconhash256/opt32

ifeq ($(filter $(CRYPTO_SUITE),0 1),$(CRYPTO_SUITE))
# Suite 0/1: TinyCrypt (AES-CCM + HMAC-SHA256)
C_SOURCES += $(TINYCRYPT_DIR)/aes_encrypt.c
C_SOURCES += $(TINYCRYPT_DIR)/ccm_mode.c
C_SOURCES += $(TINYCRYPT_DIR)/sha256.c
C_SOURCES += $(TINYCRYPT_DIR)/hmac.c
C_SOURCES += $(TINYCRYPT_DIR)/utils.c
ASM_SOURCES = src/crt0.S
else ifeq ($(CRYPTO_SUITE),7)
# Suite 7: Ascon-AEAD128 + Ascon-Hash256 + Ascon-HMAC
# Using opt32: optimized 32-bit implementation for RISC-V
C_SOURCES += $(ASCON_AEAD_DIR)/aead.c
C_SOURCES += $(ASCON_AEAD_DIR)/permutations.c
C_SOURCES += $(ASCON_HASH_DIR)/hash.c
C_SOURCES += $(ASCON_HASH_DIR)/permutations.c
C_SOURCES += $(EDHOC_LIB_DIR)/src/common/ascon_hmac.c
ASM_SOURCES = src/crt0.S
endif
# Link libraries: EDHOC library and libgcc (for 64-bit operations like __ashldi3)
LIBS = -L$(EDHOC_LIB_DIR)/build -luoscore-uedhoc -lgcc

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.S=.o)))

vpath %.c $(sort $(dir $(C_SOURCES)))
vpath %.S $(sort $(dir $(ASM_SOURCES)))

all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).bin
	@echo "Build complete!"
	@$(SIZE) $(BUILD_DIR)/$(TARGET).elf

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@echo "[CC] $<"
	@$(CC) -c $(CFLAGS) $(INCLUDES) $(EXTRA_INCLUDES) $< -o $@

$(BUILD_DIR)/%.o: %.S | $(BUILD_DIR)
	@echo "[AS] $<"
	@$(CC) -c $(CFLAGS) $(INCLUDES) $(EXTRA_INCLUDES) $< -o $@

$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS)
	@echo "[LD] $@"
	@$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	@echo "[OBJCOPY] $@"
	@$(OBJCOPY) -O binary $< $@

$(BUILD_DIR):
	@mkdir -p $@

# EDHOC test targets - respects CRYPTO_SUITE setting
# Usage: make edhoc_initiator CRYPTO_SUITE=1  (for AES-CCM/SHA256)
#        make edhoc_initiator CRYPTO_SUITE=2  (for Ascon, default)

# Common sources for edhoc targets
EDHOC_COMMON_SRC = src/kprintf.c src/libc_stubs.c src/csprng_stub.c
EDHOC_COMMON_SRC += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_common.c
EDHOC_COMMON_SRC += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_encode.c
EDHOC_COMMON_SRC += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_decode.c
# Compact25519 X25519 (common to both suites)
# EDHOC_COMMON_SRC +=
# EDHOC_COMMON_SRC +=
# EDHOC_COMMON_SRC +=
# EDHOC_COMMON_SRC +=
# EDHOC_COMMON_SRC +=
EDHOC_COMMON_SRC += $(EDHOC_LIB_DIR)/externals/Monocypher/src/monocypher.c $(EDHOC_LIB_DIR)/externals/Monocypher/src/optional/monocypher-ed25519.c

# Suite-specific crypto sources for edhoc targets
ifeq ($(filter $(CRYPTO_SUITE),0 1),$(CRYPTO_SUITE))
EDHOC_CRYPTO_SRC = $(TINYCRYPT_DIR)/aes_encrypt.c $(TINYCRYPT_DIR)/ccm_mode.c
EDHOC_CRYPTO_SRC += $(TINYCRYPT_DIR)/sha256.c $(TINYCRYPT_DIR)/hmac.c $(TINYCRYPT_DIR)/utils.c
EDHOC_ASM_SRC =
else ifeq ($(CRYPTO_SUITE),7)
# ref (reference) implementation - just aead.c and hash.c with inline permutations
EDHOC_CRYPTO_SRC = $(ASCON_AEAD_DIR)/aead.c
EDHOC_CRYPTO_SRC += $(ASCON_HASH_DIR)/hash.c
EDHOC_CRYPTO_SRC += $(EDHOC_LIB_DIR)/src/common/ascon_hmac.c
# ref is pure C - no assembly needed
EDHOC_ASM_SRC =
endif

edhoc_initiator:
	@echo "Building EDHOC library with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(EDHOC_LIB_DIR) clean
	@$(MAKE) -C $(EDHOC_LIB_DIR) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE)
	@echo "Building initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_initiator \
		C_SOURCES="src/edhoc_initiator_suite0.c $(EDHOC_COMMON_SRC) $(EDHOC_CRYPTO_SRC) driver/x25519/x25519.c" \
		ASM_SOURCES="src/crt0.S $(EDHOC_ASM_SRC)" \
		EXTRA_INCLUDES="-Idriver/x25519"

edhoc_responder:
	@echo "Building EDHOC library with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(EDHOC_LIB_DIR) clean
	@$(MAKE) -C $(EDHOC_LIB_DIR) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE)
	@echo "Building responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_responder \
		C_SOURCES="src/edhoc_responder_suite0.c $(EDHOC_COMMON_SRC) $(EDHOC_CRYPTO_SRC) driver/x25519/x25519.c" \
		ASM_SOURCES="src/crt0.S $(EDHOC_ASM_SRC)" \
		EXTRA_INCLUDES="-Idriver/x25519"

# X25519 hardware test program (compares hardware vs software)
x25519_test:
	@echo "Building X25519 hardware test program..."
	@$(MAKE) all TARGET=x25519_test \
		C_SOURCES="src/x25519_test.c src/kprintf.c src/libc_stubs.c driver/x25519/x25519.c" \
		ASM_SOURCES="src/crt0.S" \
		EXTRA_INCLUDES="-Idriver/x25519"

# ============================================================================
# EDHOC Hardware-Accelerated Targets
# These use the EDHOC hardware accelerator (edhoc_top) for full protocol
# ============================================================================

# Hardware-accelerated EDHOC initiator (no software crypto needed)
edhoc_hw_initiator:
	@echo "Building EDHOC hardware-accelerated initiator..."
	@$(MAKE) all TARGET=edhoc_hw_initiator \
		C_SOURCES="src/edhoc_hw_initiator.c src/kprintf.c src/libc_stubs.c driver/edhoc/edhoc_hw.c" \
		ASM_SOURCES="src/crt0.S" \
		EXTRA_INCLUDES="-Idriver/edhoc" \
		LIBS="-lgcc"

# Hardware-accelerated EDHOC responder (no software crypto needed)
edhoc_hw_responder:
	@echo "Building EDHOC hardware-accelerated responder..."
	@$(MAKE) all TARGET=edhoc_hw_responder \
		C_SOURCES="src/edhoc_hw_responder.c src/kprintf.c src/libc_stubs.c driver/edhoc/edhoc_hw.c" \
		ASM_SOURCES="src/crt0.S" \
		EXTRA_INCLUDES="-Idriver/edhoc" \
		LIBS="-lgcc"

# ============================================================================
# EDHOC Method 3 Targets (Static DH / Static DH)
# Uses the full uoscore-uedhoc library (not PSK-only)
# Only supports Suite 0 and Suite 1 (X25519 + AES-CCM + SHA256)
# ============================================================================

# Method 3 common sources (using full uoscore-uedhoc library)
M3_EDHOC_LIB = uoscore-uedhoc
M3_COMMON_SRC = src/kprintf.c src/libc_stubs.c src/csprng_stub.c
M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_common.c
M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_encode.c
M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_decode.c
# M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/curve25519-donna/curve25519-donna.c
# M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/compact25519/src/compact_x25519.c
# M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/compact25519/src/compact_wipe.c
# M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/compact25519/src/c25519/c25519.c
# M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/compact25519/src/c25519/f25519.c
# M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/compact25519/src/c25519/fprime.c
M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/Monocypher/src/monocypher.c $(M3_EDHOC_LIB)/externals/Monocypher/src/optional/monocypher-ed25519.c






# Method 3 crypto sources (Suite 0/1 only - TinyCrypt)
M3_TINYCRYPT_DIR = $(M3_EDHOC_LIB)/externals/tinycrypt/lib/source
M3_CRYPTO_SRC = $(M3_TINYCRYPT_DIR)/aes_encrypt.c $(M3_TINYCRYPT_DIR)/ccm_mode.c
M3_CRYPTO_SRC += $(M3_TINYCRYPT_DIR)/tc_sha256.c $(M3_TINYCRYPT_DIR)/hmac.c $(M3_TINYCRYPT_DIR)/utils.c

# Method 3 includes
M3_INCLUDES = -I. -Iinclude -I$(M3_EDHOC_LIB)/inc
M3_INCLUDES += -I$(M3_EDHOC_LIB)/inc/common
M3_INCLUDES += -I$(M3_EDHOC_LIB)/externals/zcbor/include

M3_INCLUDES += -I$(M3_EDHOC_LIB)/externals/Monocypher/src
M3_INCLUDES += -I$(M3_EDHOC_LIB)/externals/tinycrypt/lib/include

edhoc_m0_initiator:
	@echo "Building EDHOC Method 0 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 0 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m0_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m0.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(INCLUDES) $(M3_INCLUDES)"

edhoc_m0_responder:
	@echo "Building EDHOC Method 0 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 0 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m0_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m0.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(INCLUDES) $(M3_INCLUDES)"

edhoc_m1_initiator:
	@echo "Building EDHOC Method 1 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 1 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m1_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m1.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(INCLUDES) $(M3_INCLUDES)"

edhoc_m1_responder:
	@echo "Building EDHOC Method 1 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 1 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m1_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m1.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(INCLUDES) $(M3_INCLUDES)"

edhoc_m2_initiator:
	@echo "Building EDHOC Method 2 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 2 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m2_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m2.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(INCLUDES) $(M3_INCLUDES)"

edhoc_m2_responder:
	@echo "Building EDHOC Method 2 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 2 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m2_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m2.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(INCLUDES) $(M3_INCLUDES)"

edhoc_m3_initiator:
	@echo "Building EDHOC Method 3 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 3 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m3_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m3.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(INCLUDES) $(M3_INCLUDES)"

edhoc_m3_responder:
	@echo "Building EDHOC Method 3 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 3 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m3_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m3.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(INCLUDES) $(M3_INCLUDES)"

debug_make:
	@echo $(C_SOURCES)

clean:
	@echo "Cleaning all build artifacts..."
	@rm -rf $(BUILD_DIR)
	-@$(MAKE) -C $(EDHOC_LIB_DIR) clean
	-@$(MAKE) -C $(HW_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@echo "Clean complete!"

.PHONY: all clean edhoc_initiator edhoc_responder x25519_test edhoc_hw_initiator edhoc_hw_responder edhoc_m0_initiator edhoc_m0_responder edhoc_m1_initiator edhoc_m1_responder edhoc_m2_initiator edhoc_m2_responder edhoc_m3_initiator edhoc_m3_responder
