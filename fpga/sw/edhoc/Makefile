CC = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-gcc
AR = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-gcc-ar
OBJCOPY = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-objcopy
SIZE = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-size

TARGET = main
BUILD_DIR = build

# RV32IMAC for 32-bit Rocket core
ARCH_FLAGS = -march=rv32imac_zicsr_zifencei -mabi=ilp32 -mcmodel=medany

# Debug output control: set DEBUG=1 to enable all debug prints
# DEBUG=0 (default) gives clean timing measurements
DEBUG ?= 0

CFLAGS = $(ARCH_FLAGS) -Os -flto -g0 -ffunction-sections -fdata-sections -Wunused-function
CFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
CFLAGS += -nostartfiles -nostdlib -nodefaultlibs -fno-builtin -fno-tree-loop-distribute-patterns
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

LDFLAGS = $(ARCH_FLAGS) -flto -T linker/main.lds  -Llinker
LDFLAGS += -fno-builtin -fno-tree-loop-distribute-patterns -fno-unwind-tables -fno-asynchronous-unwind-tables
LDFLAGS += -nostartfiles -nostdlib -nodefaultlibs
LDFLAGS += -Wl,--gc-sections -Wl,-Map=$(BUILD_DIR)/$(TARGET).map
LDFLAGS += -Wl,--allow-multiple-definition
LDFLAGS += -Wl,--undefined=memset -Wl,--undefined=memcpy -Wl,--undefined=memmove

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
# EDHOC Method 3 Hardware-Accelerated Targets (SmallRocket32M3Config)
# edhoc_m3_top handles all crypto in hardware (X25519, AES-CCM, HMAC-SHA256).
# No software crypto library needed — binary is small enough for 8 kB scratchpad.
# Base address must match WithEDHOCM3(address = 0x64004000) in Scala config.
# ============================================================================
M3_HW_CFLAGS = $(ARCH_FLAGS) -Os -flto -g0 -ffunction-sections -fdata-sections
M3_HW_CFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
M3_HW_CFLAGS += -nostartfiles -nostdlib -nodefaultlibs -fno-builtin -fno-tree-loop-distribute-patterns
M3_HW_CFLAGS += -Wall -Wextra -DEDHOC_M3_BASE=0x64004000UL -DINCLUDE_OSCORE

M3_HW_LDFLAGS = $(ARCH_FLAGS) -flto -T linker/main_m3.lds -Llinker
M3_HW_LDFLAGS += -fno-builtin -fno-tree-loop-distribute-patterns -fno-unwind-tables -fno-asynchronous-unwind-tables
M3_HW_LDFLAGS += -nostartfiles -nostdlib -nodefaultlibs
M3_HW_LDFLAGS += -Wl,--gc-sections -Wl,-Map=$(BUILD_DIR)/$(TARGET).map

edhoc_m3_initiator_hw:
	@echo "Building EDHOC Method 3 hardware-accelerated initiator (8 kB, no SW crypto)..."
	@$(MAKE) all TARGET=edhoc_m3_initiator_hw \
		CFLAGS="$(M3_HW_CFLAGS)" \
		LDFLAGS="$(M3_HW_LDFLAGS)" \
		C_SOURCES="src/edhoc_m3_initiator_hw.c src/kprintf.c src/libc_stubs.c" \
		ASM_SOURCES="src/crt0.S" \
		EXTRA_INCLUDES="-Idriver/edhoc_m3" \
		LIBS="-lgcc"

edhoc_m3_responder_hw:
	@echo "Building EDHOC Method 3 hardware-accelerated responder (8 kB, no SW crypto)..."
	@$(MAKE) all TARGET=edhoc_m3_responder_hw \
		CFLAGS="$(M3_HW_CFLAGS)" \
		LDFLAGS="$(M3_HW_LDFLAGS)" \
		C_SOURCES="src/edhoc_m3_responder_hw.c src/kprintf.c src/libc_stubs.c" \
		ASM_SOURCES="src/crt0.S" \
		EXTRA_INCLUDES="-Idriver/edhoc_m3" \
		LIBS="-lgcc"

# Hardware OSCORE benchmark: runs EDHOC handshake then sweeps payload sizes
# using ext_aead. Compare results with: make oscore_benchmark (SW baseline)
oscore_benchmark_hw:
	@echo "Building OSCORE hardware benchmark (ext_aead, 8 kB, no SW crypto)..."
	@$(MAKE) all TARGET=oscore_benchmark_hw \
		CFLAGS="$(M3_HW_CFLAGS)" \
		LDFLAGS="$(M3_HW_LDFLAGS)" \
		C_SOURCES="src/oscore_benchmark_hw.c src/kprintf.c src/libc_stubs.c" \
		ASM_SOURCES="src/crt0.S" \
		EXTRA_INCLUDES="-Idriver/edhoc_m3" \
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
M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/Monocypher/src/monocypher.c
# Ed25519 only needed for methods 0/1/2 (signature-based auth); not needed for M3 (static DH only)
M_ED25519_SRC = $(M3_EDHOC_LIB)/externals/Monocypher/src/optional/monocypher-ed25519.c






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
		C_SOURCES="src/edhoc_initiator_m0.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

edhoc_m0_responder:
	@echo "Building EDHOC Method 0 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 0 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m0_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m0.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

edhoc_m1_initiator:
	@echo "Building EDHOC Method 1 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 1 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m1_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m1.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

edhoc_m1_responder:
	@echo "Building EDHOC Method 1 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 1 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m1_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m1.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

edhoc_m2_initiator:
	@echo "Building EDHOC Method 2 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 2 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m2_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m2.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

edhoc_m2_responder:
	@echo "Building EDHOC Method 2 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 2 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m2_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m2.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

edhoc_m3_initiator:
	@echo "Building EDHOC Method 3 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 3 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m3_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m3.c src/ed25519_stubs.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

edhoc_m3_responder:
	@echo "Building EDHOC Method 3 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 3 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m3_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m3.c src/ed25519_stubs.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

# ============================================================================
# EDHOC compact25519 Targets (baseline library — replaces Monocypher with shim)
#
# The EDHOC library is still compiled with -DMONOCYPHER (same protocol logic).
# The shim (compact25519_shim.c) provides Monocypher-named crypto functions
# implemented via compact25519 / c25519, resolved at link time.
#
# These targets produce EDHOC-level timing data using the original library,
# directly comparable to the original paper's ARM Cortex-M results.
#
# Usage: make edhoc_m0_initiator_compact CRYPTO_SUITE=0
# ============================================================================

# Common sources WITHOUT Monocypher (shim replaces it)
M3_COMMON_SRC_NOMONO = src/kprintf.c src/libc_stubs.c src/csprng_stub.c
M3_COMMON_SRC_NOMONO += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_common.c
M3_COMMON_SRC_NOMONO += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_encode.c
M3_COMMON_SRC_NOMONO += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_decode.c

# Shim + all compact25519 / c25519 sources (Methods 0-2: need Ed25519)
COMPACT25519_SHIM_SRC  = src/compact25519_shim.c
COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/compact_x25519.c
COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/compact_ed25519.c
COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/compact_wipe.c
COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/c25519.c
COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/f25519.c
COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/fprime.c
COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/ed25519.c
COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/edsign.c
COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/_sha512.c

# X25519-only shim + sources (Method 3: no Ed25519, no SHA-512)
# Use with ed25519_stubs.c to satisfy linker without pulling in Ed25519 code.
COMPACT25519_X25519_ONLY_SRC  = src/compact25519_shim_x25519_only.c
COMPACT25519_X25519_ONLY_SRC += $(COMPACT25519_DIR)/compact_x25519.c
COMPACT25519_X25519_ONLY_SRC += $(COMPACT25519_DIR)/compact_wipe.c
COMPACT25519_X25519_ONLY_SRC += $(COMPACT25519_DIR)/c25519/c25519.c
COMPACT25519_X25519_ONLY_SRC += $(COMPACT25519_DIR)/c25519/f25519.c

# Includes: same as M3_INCLUDES plus compact25519 headers
M3_COMPACT_INCLUDES = $(M3_INCLUDES) -I$(COMPACT25519_DIR)

edhoc_m0_initiator_compact:
	@echo "Building EDHOC Method 0 Initiator (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@$(MAKE) all TARGET=edhoc_m0_initiator_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m0.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

edhoc_m0_responder_compact:
	@echo "Building EDHOC Method 0 Responder (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@$(MAKE) all TARGET=edhoc_m0_responder_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m0.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

edhoc_m1_initiator_compact:
	@echo "Building EDHOC Method 1 Initiator (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@$(MAKE) all TARGET=edhoc_m1_initiator_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m1.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

edhoc_m1_responder_compact:
	@echo "Building EDHOC Method 1 Responder (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@$(MAKE) all TARGET=edhoc_m1_responder_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m1.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

edhoc_m2_initiator_compact:
	@echo "Building EDHOC Method 2 Initiator (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@$(MAKE) all TARGET=edhoc_m2_initiator_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m2.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

edhoc_m2_responder_compact:
	@echo "Building EDHOC Method 2 Responder (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@$(MAKE) all TARGET=edhoc_m2_responder_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m2.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

# M3 compact: X25519-only shim + ed25519_stubs.c
# Ed25519 and SHA-512 sources are excluded entirely; stubs resolve linker
# references from the EDHOC library without pulling in any curve code.
edhoc_m3_initiator_compact:
	@echo "Building EDHOC Method 3 Initiator (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@$(MAKE) all TARGET=edhoc_m3_initiator_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m3.c src/ed25519_stubs.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_X25519_ONLY_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

edhoc_m3_responder_compact:
	@echo "Building EDHOC Method 3 Responder (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@$(MAKE) all TARGET=edhoc_m3_responder_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m3.c src/ed25519_stubs.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_X25519_ONLY_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

# ============================================================================
# Crypto Micro-Benchmark
# Measures cycle costs of individual X25519 and Ed25519 primitives.
# Does NOT link the EDHOC library or zcbor — Monocypher only.
# Usage: make crypto_bench CRYPTO_SUITE=0
# ============================================================================
BENCH_MONO_SRC = $(M3_EDHOC_LIB)/externals/Monocypher/src/monocypher.c
BENCH_MONO_SRC += $(M3_EDHOC_LIB)/externals/Monocypher/src/optional/monocypher-ed25519.c
BENCH_INCLUDES = -I. -Iinclude -I$(M3_EDHOC_LIB)/externals/Monocypher/src

crypto_bench:
	@echo "Building crypto micro-benchmark (Monocypher)..."
	@$(MAKE) all TARGET=crypto_bench \
		C_SOURCES="src/crypto_bench.c src/kprintf.c src/libc_stubs.c $(BENCH_MONO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(BENCH_INCLUDES)" \
		LIBS="-lgcc"

# ============================================================================
# Crypto Micro-Benchmark: compact25519 (original baseline library)
# Mirrors crypto_bench but uses compact25519 / c25519 (Daniel Beer).
# No CRYPTO_SUITE needed — compact25519 has no suite dependency.
# Usage: make crypto_bench_compact
# ============================================================================
COMPACT25519_DIR = $(M3_EDHOC_LIB)/externals/compact25519/src
BENCH_COMPACT_SRC  = $(COMPACT25519_DIR)/compact_x25519.c
BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/compact_ed25519.c
BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/compact_wipe.c
BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/c25519.c
BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/f25519.c
BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/fprime.c
BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/ed25519.c
BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/edsign.c
BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/_sha512.c
BENCH_COMPACT_INCLUDES = -I. -Iinclude -I$(COMPACT25519_DIR)

crypto_bench_compact:
	@echo "Building crypto micro-benchmark (compact25519 baseline)..."
	@$(MAKE) all TARGET=crypto_bench_compact \
		C_SOURCES="src/crypto_bench_compact.c src/kprintf.c src/libc_stubs.c $(BENCH_COMPACT_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(BENCH_COMPACT_INCLUDES)" \
		LIBS="-lgcc"

# ============================================================================
# OSCORE Standalone Benchmark
# Measures oscore_context_init(), coap2oscore(), oscore2coap() in isolation.
# Uses RFC 8613 Appendix C.1 test vectors — no EDHOC dependency.
# ALWAYS built with Suite 0 (AES-CCM-16-64-128 + HMAC-SHA256): RFC 8613
# mandatory cipher suite. CRYPTO_SUITE variable is intentionally ignored here.
#
# Usage: make oscore_benchmark
#        make oscore_benchmark BENCHMARK_CPU_HZ=65000000UL   (65 MHz Arty 35T)
# ============================================================================

# OSCORE CFLAGS: Suite 0 forced, no Monocypher (not needed for OSCORE)
OSCORE_CFLAGS  = $(ARCH_FLAGS) -Os -flto -g0 -ffunction-sections -fdata-sections -Wunused-function
OSCORE_CFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
OSCORE_CFLAGS += -nostartfiles -nostdlib -nodefaultlibs -fno-builtin -fno-tree-loop-distribute-patterns
OSCORE_CFLAGS += -Wall -Wextra -DMESSAGE_4 -DZCBOR_CANONICAL
OSCORE_CFLAGS += -DTINYCRYPT -DEDHOC_CRYPTO_SUITE=0
ifdef BENCHMARK_CPU_HZ
OSCORE_CFLAGS += -DBENCHMARK_CPU_HZ=$(BENCHMARK_CPU_HZ)
endif

# Application + platform sources (no Monocypher — OSCORE uses TinyCrypt only)
OSCORE_BENCH_SRC  = src/oscore_benchmark.c src/kprintf.c src/libc_stubs.c src/csprng_stub.c
OSCORE_BENCH_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_common.c
OSCORE_BENCH_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_encode.c
OSCORE_BENCH_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_decode.c
OSCORE_BENCH_SRC += $(M3_TINYCRYPT_DIR)/aes_encrypt.c
OSCORE_BENCH_SRC += $(M3_TINYCRYPT_DIR)/ccm_mode.c
OSCORE_BENCH_SRC += $(M3_TINYCRYPT_DIR)/tc_sha256.c
OSCORE_BENCH_SRC += $(M3_TINYCRYPT_DIR)/hmac.c
OSCORE_BENCH_SRC += $(M3_TINYCRYPT_DIR)/utils.c

oscore_benchmark:
	@echo "Building uoscore-uedhoc library for OSCORE benchmark (Suite 0)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(OSCORE_CFLAGS)" CRYPTO_SUITE=0 DEBUG=$(DEBUG)
	@echo "Building OSCORE benchmark (AES-CCM-16-64-128 + HMAC-SHA256)..."
	@$(MAKE) all TARGET=oscore_benchmark EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		CFLAGS="$(OSCORE_CFLAGS)" \
		C_SOURCES="$(OSCORE_BENCH_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

debug_make:
	@echo $(C_SOURCES)

clean:
	@echo "Cleaning all build artifacts..."
	@rm -rf $(BUILD_DIR)
	-@$(MAKE) -C $(EDHOC_LIB_DIR) clean
	-@$(MAKE) -C $(HW_EDHOC_LIB) clean
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@echo "Clean complete!"

.PHONY: all clean edhoc_initiator edhoc_responder x25519_test edhoc_hw_initiator edhoc_hw_responder \
        edhoc_m3_initiator_hw edhoc_m3_responder_hw oscore_benchmark_hw \
        edhoc_m0_initiator edhoc_m0_responder edhoc_m1_initiator edhoc_m1_responder \
        edhoc_m2_initiator edhoc_m2_responder edhoc_m3_initiator edhoc_m3_responder \
        edhoc_m0_initiator_compact edhoc_m0_responder_compact \
        edhoc_m1_initiator_compact edhoc_m1_responder_compact \
        edhoc_m2_initiator_compact edhoc_m2_responder_compact \
        edhoc_m3_initiator_compact edhoc_m3_responder_compact \
        crypto_bench crypto_bench_compact oscore_benchmark
