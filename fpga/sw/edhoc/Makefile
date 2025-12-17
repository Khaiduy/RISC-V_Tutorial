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
CFLAGS += -Wall -Wextra -DTINYCRYPT -DCOMPACT25519 -DMESSAGE_4

LDFLAGS = $(ARCH_FLAGS) -T linker/main.lds -Llinker
LDFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
LDFLAGS += -nostartfiles -nostdlib -nodefaultlibs
LDFLAGS += -Wl,--gc-sections -Wl,-Map=$(BUILD_DIR)/$(TARGET).map
LDFLAGS += -Wl,--allow-multiple-definition

# EDHOC library selection (default: PSK-only)
# Use 'make EDHOC_MODE=original' for original Method 0-3
# Use 'make EDHOC_MODE=psk' for PSK-only (default)
EDHOC_MODE ?= psk

ifeq ($(EDHOC_MODE),original)
    EDHOC_LIB_DIR = uoscore-uedhoc
else
    EDHOC_LIB_DIR = uoscore-uedhoc-psk
endif

INCLUDES = -I. -Iinclude -I$(EDHOC_LIB_DIR)/inc
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/zcbor/include
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/tinycrypt/lib/include
INCLUDES += -I$(EDHOC_LIB_DIR)/externals/compact25519/src

C_SOURCES = src/main.c src/kprintf.c src/libc_stubs.c src/csprng_stub.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_common.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_encode.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_decode.c
TINYCRYPT_DIR = $(EDHOC_LIB_DIR)/externals/tinycrypt/lib/source
C_SOURCES += $(TINYCRYPT_DIR)/aes_encrypt.c
C_SOURCES += $(TINYCRYPT_DIR)/ccm_mode.c
C_SOURCES += $(TINYCRYPT_DIR)/sha256.c
C_SOURCES += $(TINYCRYPT_DIR)/hmac.c
C_SOURCES += $(TINYCRYPT_DIR)/utils.c
C_SOURCES += $(TINYCRYPT_DIR)/ecc.c
C_SOURCES += $(TINYCRYPT_DIR)/ecc_dh.c
# PSK mode: No signing needed, exclude ecc_dsa.c
# C_SOURCES += $(TINYCRYPT_DIR)/ecc_dsa.c
C_SOURCES += $(TINYCRYPT_DIR)/ecc_platform_specific.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_x25519.c
# PSK mode: No EdDSA signing needed, exclude compact_ed25519.c
# C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_ed25519.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_wipe.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/c25519.c
# PSK mode: No Ed25519 signing needed, exclude ed25519.c and edsign.c
# C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/ed25519.c
# C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/edsign.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/f25519.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/fprime.c
# PSK mode: No SHA-512 needed (used for Ed25519 signing only)
# C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/sha512.c

ASM_SOURCES = src/crt0.S
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

# EDHOC test targets
edhoc_initiator: TARGET = edhoc_initiator
edhoc_initiator: C_SOURCES = src/edhoc_initiator_suite0.c src/kprintf.c src/libc_stubs.c src/csprng_stub.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_common.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_encode.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_decode.c
edhoc_initiator: C_SOURCES += $(TINYCRYPT_DIR)/aes_encrypt.c $(TINYCRYPT_DIR)/ccm_mode.c
edhoc_initiator: C_SOURCES += $(TINYCRYPT_DIR)/sha256.c $(TINYCRYPT_DIR)/hmac.c $(TINYCRYPT_DIR)/utils.c
edhoc_initiator: C_SOURCES += $(TINYCRYPT_DIR)/ecc.c $(TINYCRYPT_DIR)/ecc_dh.c $(TINYCRYPT_DIR)/ecc_dsa.c $(TINYCRYPT_DIR)/ecc_platform_specific.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_x25519.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_ed25519.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_wipe.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/c25519.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/ed25519.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/edsign.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/f25519.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/fprime.c
edhoc_initiator: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/sha512.c
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
edhoc_responder: C_SOURCES += $(TINYCRYPT_DIR)/aes_encrypt.c $(TINYCRYPT_DIR)/ccm_mode.c
edhoc_responder: C_SOURCES += $(TINYCRYPT_DIR)/sha256.c $(TINYCRYPT_DIR)/hmac.c $(TINYCRYPT_DIR)/utils.c
edhoc_responder: C_SOURCES += $(TINYCRYPT_DIR)/ecc.c $(TINYCRYPT_DIR)/ecc_dh.c $(TINYCRYPT_DIR)/ecc_dsa.c $(TINYCRYPT_DIR)/ecc_platform_specific.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_x25519.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_ed25519.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/compact_wipe.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/c25519.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/ed25519.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/edsign.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/f25519.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/fprime.c
edhoc_responder: C_SOURCES += $(EDHOC_LIB_DIR)/externals/compact25519/src/c25519/sha512.c
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
