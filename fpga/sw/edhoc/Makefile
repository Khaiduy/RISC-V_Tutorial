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
TIMING ?= 0
CFLAGS += -Wall -Wextra -DMESSAGE_4 -DZCBOR_CANONICAL
ifeq ($(TIMING),1)
CFLAGS += -DTIMING_BREAKDOWN
endif
ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG_PRINT
endif

# Crypto Suite Selection:
#   CRYPTO_SUITE=0: Suite 0 - AES-CCM-16-64-128 + SHA256 (8-byte tag, 13-byte nonce)
#   CRYPTO_SUITE=1: Suite 1 - AES-CCM-16-128-128 + SHA256 (16-byte tag, 13-byte nonce)
#   CRYPTO_SUITE=7: Suite 7 - Ascon-AEAD-128 + Ascon-Hash256 (16-byte tag, 16-byte nonce) [default]
CRYPTO_SUITE ?= 2

# Crypto backend dispatch.
#   EDHOC_BACKEND=wolfssl (default): all suites use wolfCrypt.
#   EDHOC_BACKEND=legacy  : suites 0/1/4/5/7 + PSK use Monocypher + TinyCrypt
#                           (+ Ascon-c for Suite 7). Suites 6/24/25 always stay
#                           on wolfCrypt because they need primitives the
#                           legacy stack doesn't provide (AES-GCM, P-384,
#                           SHA-384, X448, Ed448, SHAKE-256, KMAC-256).
EDHOC_BACKEND ?= wolfssl
export EDHOC_BACKEND   # propagate to recursive make ($(MAKE) -C ...)

# For legacy backend on suites 0/1/4/5/7, swap WOLFCRYPT for MONOCYPHER+TINYCRYPT.
_LEGACY_SUITES := 0 1 4 5 7
ifeq ($(EDHOC_BACKEND),legacy)
ifneq ($(filter $(CRYPTO_SUITE),$(_LEGACY_SUITES)),)
_USE_LEGACY := 1
endif
endif

ifeq ($(CRYPTO_SUITE),0)
$(info Building with Suite 0: AES-CCM-16-64-128 (8-byte tag))
ifeq ($(_USE_LEGACY),1)
$(info   backend: legacy [Monocypher + TinyCrypt])
CFLAGS += -DMONOCYPHER -DTINYCRYPT -DEDHOC_CRYPTO_SUITE=0
else
CFLAGS += -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=0
endif
else ifeq ($(CRYPTO_SUITE),1)
$(info Building with Suite 1: AES-CCM-16-128-128 (16-byte tag))
ifeq ($(_USE_LEGACY),1)
$(info   backend: legacy [Monocypher + TinyCrypt])
CFLAGS += -DMONOCYPHER -DTINYCRYPT -DEDHOC_CRYPTO_SUITE=1
else
CFLAGS += -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=1
endif
else ifeq ($(CRYPTO_SUITE),2)
$(info Building with Suite 2: AES-CCM-16-64-128 + P-256 + ES256)
CFLAGS += -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=2
else ifeq ($(CRYPTO_SUITE),3)
$(info Building with Suite 3: AES-CCM-16-128-128 + P-256 + ES256)
CFLAGS += -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=3
else ifeq ($(CRYPTO_SUITE),4)
$(info Building with Suite 4: ChaCha20/Poly1305 + X25519 + EdDSA)
ifeq ($(_USE_LEGACY),1)
$(info   backend: legacy [Monocypher + TinyCrypt])
CFLAGS += -DMONOCYPHER -DTINYCRYPT -DEDHOC_CRYPTO_SUITE=4
else
CFLAGS += -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=4
endif
else ifeq ($(CRYPTO_SUITE),5)
$(info Building with Suite 5: ChaCha20/Poly1305 + P-256 + ES256)
ifeq ($(_USE_LEGACY),1)
$(info   backend: legacy [Monocypher ChaCha + TinyCrypt P-256/SHA-256])
CFLAGS += -DMONOCYPHER -DTINYCRYPT -DEDHOC_CRYPTO_SUITE=5
else
CFLAGS += -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=5
endif
else ifeq ($(CRYPTO_SUITE),7)
$(info Building with Suite 7: Ascon-AEAD-128 + Ascon-Hash256)
ifeq ($(_USE_LEGACY),1)
$(info   backend: legacy [Monocypher X25519/Ed25519 + Ascon-c AEAD/Hash + Ascon-HMAC])
CFLAGS += -DMONOCYPHER -DASCON -DEDHOC_CRYPTO_SUITE=7
else
CFLAGS += -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=7
endif
else ifeq ($(CRYPTO_SUITE),6)
$(info Building with Suite 6: AES-128-GCM + X25519 + EdDSA [wolfCrypt])
CFLAGS += -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=6
else ifeq ($(CRYPTO_SUITE),24)
$(info Building with Suite 24: AES-256-GCM + P-384 + ES384 [wolfCrypt])
CFLAGS += -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=24
else ifeq ($(CRYPTO_SUITE),25)
$(info Building with Suite 25: ChaCha20/Poly1305 + X448 + Ed448 [wolfCrypt])
CFLAGS += -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=25
else
$(error Invalid CRYPTO_SUITE=$(CRYPTO_SUITE). Use 0, 1, 2, 3, 4, 5, 6, 7, 24, or 25)
endif

# Suite classification: which suites use P-256/uECC vs X25519/Monocypher
SUITE_USES_P256 := $(filter 2 3 5,$(CRYPTO_SUITE))

# wolfCrypt library root
WOLFSSL_ROOT    = $(CURDIR)/wolfssl
WOLFCRYPT_DIR   = $(WOLFSSL_ROOT)/wolfcrypt/src
WOLFCRYPT_CFLAGS = -DWOLFSSL_USER_SETTINGS \
                   -I$(WOLFSSL_ROOT) \
                   -include $(WOLFSSL_ROOT)/user_settings.h

# ── wolfCrypt component source sets ────────────────────────────────────
# Core: always needed (math, hash base, KDF/MAC, entropy)
_WC_CORE = \
    $(WOLFCRYPT_DIR)/wc_port.c \
    $(WOLFCRYPT_DIR)/wolfmath.c \
    $(WOLFCRYPT_DIR)/sp_int.c \
    $(WOLFCRYPT_DIR)/sp_c32.c \
    $(WOLFCRYPT_DIR)/hash.c \
    $(WOLFCRYPT_DIR)/sha256.c \
    $(WOLFCRYPT_DIR)/hmac.c \
    $(WOLFCRYPT_DIR)/kdf.c \
    $(WOLFCRYPT_DIR)/random.c \
    $(WOLFCRYPT_DIR)/error.c

# SHA-512: needed by Ed25519 (suites 0,1,4,6,7) and SHA-384 (suite 24)
_WC_SHA512   = $(WOLFCRYPT_DIR)/sha512.c
# SHA-3 / SHAKE-256: Suite 25 only
_WC_SHA3     = $(WOLFCRYPT_DIR)/sha3.c
_WC_KMAC     = $(WOLFCRYPT_DIR)/kmac.c

# AEAD
_WC_AES      = $(WOLFCRYPT_DIR)/aes.c
_WC_CHACHA   = $(WOLFCRYPT_DIR)/chacha.c \
               $(WOLFCRYPT_DIR)/poly1305.c \
               $(WOLFCRYPT_DIR)/chacha20_poly1305.c
_WC_ASCON    = $(WOLFCRYPT_DIR)/ascon.c

# ECDH
_WC_X25519   = $(WOLFCRYPT_DIR)/curve25519.c \
               $(WOLFCRYPT_DIR)/fe_operations.c \
               $(WOLFCRYPT_DIR)/fe_low_mem.c
_WC_ECC      = $(WOLFCRYPT_DIR)/ecc.c
_WC_X448     = $(WOLFCRYPT_DIR)/curve448.c \
               $(WOLFCRYPT_DIR)/fe_448.c

# Signing (excluded for Method 3; Ed25519 requires _WC_SHA512)
_WC_ED25519  = $(WOLFCRYPT_DIR)/ed25519.c \
               $(WOLFCRYPT_DIR)/ge_low_mem.c
_WC_ED448    = $(WOLFCRYPT_DIR)/ed448.c \
               $(WOLFCRYPT_DIR)/ge_448.c

# ── Legacy backend source sets (Monocypher + TinyCrypt + Ascon-c) ───────
# Used when EDHOC_BACKEND=legacy AND CRYPTO_SUITE in {0,1,4,5,7}.
MONOCYPHER_DIR = $(M3_EDHOC_LIB)/externals/Monocypher/src
TINYCRYPT_DIR  = $(M3_EDHOC_LIB)/externals/tinycrypt/lib/source
ASCON_C_DIR    = $(M3_EDHOC_LIB)/externals/ascon-c

# Note: $(M3_EDHOC_LIB) and TINYCRYPT_DIR may not be re-defined here on
# every code path — the variables also appear in the per-target sections
# further below. The legacy assignments here are the ones used by the
# top-level `all:` build when EDHOC_BACKEND=legacy.

_MONO_CORE   = $(MONOCYPHER_DIR)/monocypher.c \
               $(MONOCYPHER_DIR)/optional/monocypher-ed25519.c
_TC_CCM_SHA  = $(TINYCRYPT_DIR)/aes_encrypt.c \
               $(TINYCRYPT_DIR)/ccm_mode.c \
               $(TINYCRYPT_DIR)/tc_sha256.c \
               $(TINYCRYPT_DIR)/hmac.c \
               $(TINYCRYPT_DIR)/utils.c

# TinyCrypt P-256 (used by Suite 5 = ChaCha-Poly + P-256 + ES256).
# Provides uECC_make_key, uECC_shared_secret, uECC_sign, uECC_verify.
# Note: ecc_platform_specific.c defines default_CSPRNG; we already have
# our own in src/csprng_stub.c. LDFLAGS already includes
# -Wl,--allow-multiple-definition so the linker resolves the duplicate
# cleanly — keep our bare-metal CSPRNG.
_TC_P256     = $(TINYCRYPT_DIR)/ecc.c \
               $(TINYCRYPT_DIR)/ecc_dh.c \
               $(TINYCRYPT_DIR)/ecc_dsa.c

# ── Per-suite WOLFCRYPT_SRCS assembly ──────────────────────────────────
# WOLFCRYPT_SRCS: AEAD + hash + ECDH only — NO signing sources.
# WOLFCRYPT_SIGN_SRCS: Edwards-curve signing — set per-suite below.
# Methods 0-2 link both; Method 3 (StaticDH/StaticDH) links WOLFCRYPT_SRCS only.
ifeq ($(CRYPTO_SUITE),0)
ifeq ($(_USE_LEGACY),1)
# Suite 0 (legacy): Monocypher X25519+Ed25519+SHA-512 + TinyCrypt AES-CCM+SHA-256+HMAC
WOLFCRYPT_SRCS = $(_MONO_CORE) $(_TC_CCM_SHA)
else
# Suite 0 (wolfssl): AES-128-CCM (tag=8) + SHA-256 + SHA-512 + X25519
WOLFCRYPT_SRCS = $(_WC_CORE) $(_WC_SHA512) $(_WC_AES) $(_WC_X25519)
endif
endif
ifeq ($(CRYPTO_SUITE),1)
ifeq ($(_USE_LEGACY),1)
# Suite 1 (legacy): same crypto as Suite 0; only AEAD tag length differs.
WOLFCRYPT_SRCS = $(_MONO_CORE) $(_TC_CCM_SHA)
else
# Suite 1 (wolfssl): AES-128-CCM (tag=16) + SHA-256 + SHA-512 + X25519
WOLFCRYPT_SRCS = $(_WC_CORE) $(_WC_SHA512) $(_WC_AES) $(_WC_X25519)
endif
endif
ifeq ($(CRYPTO_SUITE),2)
# Suite 2: AES-128-CCM + SHA-256 + P-256 (ECC covers DHE + ES256 sign)
WOLFCRYPT_SRCS = $(_WC_CORE) $(_WC_AES) $(_WC_ECC)
endif
ifeq ($(CRYPTO_SUITE),3)
# Suite 3: AES-128-CCM (tag=16) + SHA-256 + P-256
WOLFCRYPT_SRCS = $(_WC_CORE) $(_WC_AES) $(_WC_ECC)
endif
ifeq ($(CRYPTO_SUITE),4)
ifeq ($(_USE_LEGACY),1)
# Suite 4 (legacy): Monocypher ChaCha-Poly + X25519 + Ed25519 + TinyCrypt SHA-256/HMAC.
# Drop tinycrypt aes_encrypt.c + ccm_mode.c (no AES needed); keep tc_sha256+hmac+utils.
WOLFCRYPT_SRCS = $(_MONO_CORE) $(TINYCRYPT_DIR)/tc_sha256.c $(TINYCRYPT_DIR)/hmac.c $(TINYCRYPT_DIR)/utils.c
else
# Suite 4 (wolfssl): ChaCha20/Poly1305 + SHA-256 + SHA-512 + X25519
WOLFCRYPT_SRCS = $(_WC_CORE) $(_WC_SHA512) $(_WC_CHACHA) $(_WC_X25519)
endif
endif
ifeq ($(CRYPTO_SUITE),5)
ifeq ($(_USE_LEGACY),1)
# Suite 5 (legacy): Monocypher ChaCha-Poly + TinyCrypt P-256/ES256/SHA-256/HMAC.
# Also includes AES + CCM + CTR-PRNG: TinyCrypt's ecc_dsa uses CTR-DRBG (AES-CTR)
# to generate the per-signature ECDSA nonce. ciphertext.c in the EDHOC library
# also still references AES-CCM symbols even though Suite 5 itself uses ChaCha-Poly.
WOLFCRYPT_SRCS = $(_MONO_CORE) $(_TC_CCM_SHA) $(_TC_P256) $(TINYCRYPT_DIR)/ctr_prng.c
else
# Suite 5 (wolfssl): ChaCha20/Poly1305 + SHA-256 + P-256
WOLFCRYPT_SRCS = $(_WC_CORE) $(_WC_CHACHA) $(_WC_ECC)
endif
endif
ifeq ($(CRYPTO_SUITE),6)
# Suite 6 (RFC 9528 Table 6): A128GCM + SHA-256 + X25519 ECDH + ES256 sign.
# Needs X25519 (curve25519.c) for ECDH + ECC (ecc.c) for ES256 sign/verify.
# NO SHA-512: ES256 = ECDSA-with-SHA-256, and the EDHOC suite hash is SHA-256.
WOLFCRYPT_SRCS = $(_WC_CORE) $(_WC_AES) $(_WC_X25519) $(_WC_ECC)
endif
ifeq ($(CRYPTO_SUITE),7)
ifeq ($(_USE_LEGACY),1)
# Suite 7 (legacy): Monocypher X25519+Ed25519 ONLY. Ascon-c sources (aead.c,
# hash.c, ascon_hmac.c) are added inside the library via -DASCON. App-level
# (main, etc.) needs no extra Ascon objects.
WOLFCRYPT_SRCS = $(_MONO_CORE)
else
# Suite 7 (wolfssl): Ascon-AEAD-128 + Ascon-Hash256 + SHA-512 + X25519
WOLFCRYPT_SRCS = $(_WC_CORE) $(_WC_SHA512) $(_WC_ASCON) $(_WC_X25519)
endif
endif
ifeq ($(CRYPTO_SUITE),24)
# Suite 24: AES-256-GCM + SHA-384 + SHA-512 + P-384 (ECC covers ES384)
WOLFCRYPT_SRCS = $(_WC_CORE) $(_WC_SHA512) $(_WC_AES) $(_WC_ECC)
endif
ifeq ($(CRYPTO_SUITE),25)
# Suite 25: ChaCha20/Poly1305 + SHAKE-256 + X448 + Ed448.
# NO SHA-512: RFC 8032 §5.2 says Ed448 uses SHAKE256 internally; audit of
# wolfSSL ed448.c + ed448.h confirms zero SHA-512 references. The defensive
# `#error "ED448 requires SHA-512"` in wolfSSL settings.h is patched out by
# setup-wolfssl.sh — see that script for details.
# KMAC256 is required by RFC 9528 §4.1.1 for EDHOC_Extract/Expand.
WOLFCRYPT_SRCS = $(_WC_CORE) $(_WC_SHA3) $(_WC_KMAC) $(_WC_CHACHA) $(_WC_X448)
endif

# Sign: Edwards-curve sign/verify — excluded for Method 3 (StaticDH/StaticDH).
# ECC suites (2,3,5,6,24) need no separate sign sources; P-256/P-384 in _WC_ECC
# already provides ECDSA sign/verify.
# RFC 9528 Table 6: Suite 6 signs with ES256, not Ed25519, despite using X25519 ECDH.
WOLFCRYPT_SIGN_SRCS =
ifneq ($(_USE_LEGACY),1)
ifneq ($(filter $(CRYPTO_SUITE),0 1 4 7),)
WOLFCRYPT_SIGN_SRCS = $(_WC_ED25519)
endif
ifeq ($(CRYPTO_SUITE),25)
WOLFCRYPT_SIGN_SRCS = $(_WC_ED448)
endif
endif
# (Legacy backend handles Ed25519 via monocypher-ed25519.c already in _MONO_CORE.)

# Backend-specific compile flags. wolfCrypt always gets its USER_SETTINGS
# include; legacy backend gets -I paths for Monocypher + TinyCrypt headers.
ifeq ($(_USE_LEGACY),1)
CFLAGS += -I$(MONOCYPHER_DIR) -I$(M3_EDHOC_LIB)/externals/tinycrypt/lib/include
else
CFLAGS += $(WOLFCRYPT_CFLAGS)
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

# All suites use wolfCrypt
INCLUDES += -I$(WOLFSSL_ROOT)

# Common sources
C_SOURCES = src/main.c src/kprintf.c src/libc_stubs.c src/csprng_stub.c src/rng_port.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_common.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_encode.c
C_SOURCES += $(EDHOC_LIB_DIR)/externals/zcbor/src/zcbor_decode.c

# All suites: wolfCrypt handles all crypto (sign sources always included here)
C_SOURCES += $(WOLFCRYPT_SRCS) $(WOLFCRYPT_SIGN_SRCS)
ASM_SOURCES = src/crt0.S


# Link libraries: EDHOC library and libgcc (for 64-bit operations like __ashldi3)
LIBS = -L$(EDHOC_LIB_DIR)/build -luoscore-uedhoc -lgcc

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.S=.o)))

vpath %.c $(sort $(dir $(C_SOURCES)))
vpath %.S $(sort $(dir $(ASM_SOURCES)))

all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).bin
	@echo "Build complete!"
	@$(SIZE) $(BUILD_DIR)/$(TARGET).elf

# Stamp file: detects CRYPTO_SUITE and EDHOC_AUTH_SK changes so objects are
# rebuilt when either changes without requiring a manual `make clean`.
_SK_SUFFIX = $(if $(findstring EDHOC_AUTH_SK,$(CFLAGS)),_auth,)$(if $(findstring EDHOC_PEER_SK,$(CFLAGS)),_peer,)
CFLAGS_STAMP = $(BUILD_DIR)/.suite$(CRYPTO_SUITE)$(_SK_SUFFIX).stamp

$(CFLAGS_STAMP): | $(BUILD_DIR)
	@find $(BUILD_DIR) -maxdepth 1 -name '.suite*.stamp' -delete 2>/dev/null || true
	@touch $@

$(BUILD_DIR)/%.o: %.c $(CFLAGS_STAMP)
	@echo "[CC] $<"
	@$(CC) -c $(CFLAGS) $(INCLUDES) $(EXTRA_INCLUDES) $< -o $@

# sp_c32.c and ecc.c must NOT be compiled with -flto: LTO whole-program
# analysis eliminates sp_ecc_sign_256/sp_ecc_make_key_256 because the
# indirect call chains from wc_ecc_sign_hash_ex are constant-propagated
# away.  Compiling these two files without LTO gives them real ELF symbols
# that the linker keeps when directly referenced.
#
# These rules apply ONLY under the wolfSSL backend. Under EDHOC_BACKEND=legacy
# we use TinyCrypt's own ecc.c (different file, same basename) — the generic
# pattern rule above + vpath find TinyCrypt's source from C_SOURCES.
ifneq ($(_USE_LEGACY),1)
$(BUILD_DIR)/sp_c32.o: $(WOLFCRYPT_DIR)/sp_c32.c $(CFLAGS_STAMP)
	@echo "[CC-nolto] $<"
	@$(CC) -c $(filter-out -flto,$(CFLAGS)) $(INCLUDES) $(EXTRA_INCLUDES) $< -o $@

$(BUILD_DIR)/ecc.o: $(WOLFCRYPT_DIR)/ecc.c $(CFLAGS_STAMP)
	@echo "[CC-nolto] $<"
	@$(CC) -c $(filter-out -flto,$(CFLAGS)) $(INCLUDES) $(EXTRA_INCLUDES) $< -o $@
endif

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
EDHOC_COMMON_SRC += src/rng_port.c

# All suites use wolfCrypt; signing sources needed for Methods 0-2
EDHOC_CRYPTO_SRC = $(WOLFCRYPT_SRCS) $(WOLFCRYPT_SIGN_SRCS)
EDHOC_ASM_SRC =

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

# Ascon-c KAT self-test on RV32. Verifies whether the Ascon-c ref impl produces
# correct KAT outputs when built for RISC-V. PASS → bug is in EDHOC integration;
# FAIL → bug is RV32 build-specific (alignment, 32-bit, LTO).
ascon_kat:
	@echo "Building Ascon-c KAT self-test for RV32..."
	@$(MAKE) all TARGET=ascon_kat \
		C_SOURCES="src/ascon_kat_main.c src/kprintf.c src/libc_stubs.c uoscore-uedhoc/externals/ascon-c/crypto_aead/asconaead128/ref/aead.c uoscore-uedhoc/externals/ascon-c/crypto_hash/asconhash256/ref/hash.c uoscore-uedhoc/src/common/ascon_hmac.c" \
		ASM_SOURCES="src/crt0.S" \
		EXTRA_INCLUDES="-Iuoscore-uedhoc/externals/ascon-c/crypto_aead/asconaead128/ref -Iuoscore-uedhoc/externals/ascon-c/tests -Iuoscore-uedhoc/inc" \
		LIBS="-lgcc"

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
M3_COMMON_SRC += src/edhoc_transport.c src/edhoc_cred_builder.c
M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_common.c
M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_encode.c
M3_COMMON_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_decode.c

# All suites now use wolfCrypt — no Monocypher or TinyCrypt
M3_COMMON_SRC += src/rng_port.c
M_ED25519_SRC =






# EDHOC_AUTH_SK: this role signs with Ed25519.
# EDHOC_PEER_SK: the peer signs; this role must verify (needs Ed25519 + SHA-512).
# M0 (SK-SK):   both roles sign and verify → AUTH_SK + PEER_SK.
# M1 (SK-SDHK): init signs (AUTH_SK); resp verifies peer (PEER_SK).
# M2 (SDHK-SK): init verifies peer (PEER_SK); resp signs (AUTH_SK).
# M3 (SDHK-SDHK): neither role signs or verifies Ed25519.
M3_CRYPTO_SRC        = $(WOLFCRYPT_SRCS) $(WOLFCRYPT_SIGN_SRCS)
M3_CRYPTO_SRC_NOSIGN = $(WOLFCRYPT_SRCS)

# ============================================================================
# EDHOC PSK (Method 4) - separate library uoscore-uedhoc-psk/
# Crypto backend: wolfcrypt (shared with the standard library — uoscore-uedhoc/wolfssl).
# Suite 7 (X25519 + Ascon) is the primary target; Suite 0 also supported.
# ============================================================================
PSK_EDHOC_LIB     = uoscore-uedhoc-psk

# wolfcrypt source set: reuse per-suite WOLFCRYPT_SRCS variable already gated by CRYPTO_SUITE
# upstream in this Makefile (Suite 7 → Ascon+X25519, Suite 0 → AES+X25519, etc.)
PSK_WOLFCRYPT_SRCS = $(WOLFCRYPT_SRCS)

PSK_COMMON_SRC    = src/kprintf.c src/libc_stubs.c src/csprng_stub.c
PSK_COMMON_SRC   += src/edhoc_transport.c src/rng_port.c
PSK_COMMON_SRC   += $(PSK_EDHOC_LIB)/externals/zcbor/src/zcbor_common.c
PSK_COMMON_SRC   += $(PSK_EDHOC_LIB)/externals/zcbor/src/zcbor_encode.c
PSK_COMMON_SRC   += $(PSK_EDHOC_LIB)/externals/zcbor/src/zcbor_decode.c

PSK_INCLUDES  = -I. -Iinclude -I$(PSK_EDHOC_LIB)/inc
PSK_INCLUDES += -I$(PSK_EDHOC_LIB)/inc/edhoc
PSK_INCLUDES += -I$(PSK_EDHOC_LIB)/inc/common
PSK_INCLUDES += -I$(PSK_EDHOC_LIB)/externals/zcbor/include
PSK_INCLUDES += -I$(WOLFSSL_ROOT)

# Extra defines for PSK lib build (overrides PSK lib's default TinyCrypt/ASCON gates).
PSK_LIB_CFLAGS = $(CFLAGS) $(WOLFCRYPT_CFLAGS)

edhoc_psk_initiator:
	@echo "Building EDHOC PSK Initiator (Method 4, CRYPTO_SUITE=$(CRYPTO_SUITE), wolfcrypt backend)..."
	-@$(MAKE) -C $(PSK_EDHOC_LIB) clean
	@$(MAKE) -C $(PSK_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(PSK_LIB_CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE)
	@echo "Building PSK initiator app (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_psk_initiator EDHOC_LIB_DIR=$(PSK_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_psk.c $(PSK_COMMON_SRC) $(PSK_WOLFCRYPT_SRCS)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(PSK_INCLUDES)" EDHOC_MODE=psk \
		"CFLAGS=$(CFLAGS) $(WOLFCRYPT_CFLAGS)"

edhoc_psk_responder:
	@echo "Building EDHOC PSK Responder (Method 4, CRYPTO_SUITE=$(CRYPTO_SUITE), wolfcrypt backend)..."
	-@$(MAKE) -C $(PSK_EDHOC_LIB) clean
	@$(MAKE) -C $(PSK_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(PSK_LIB_CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE)
	@echo "Building PSK responder app (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_psk_responder EDHOC_LIB_DIR=$(PSK_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_psk.c $(PSK_COMMON_SRC) $(PSK_WOLFCRYPT_SRCS)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(PSK_INCLUDES)" EDHOC_MODE=psk \
		"CFLAGS=$(CFLAGS) $(WOLFCRYPT_CFLAGS)"

# ---------------------------------------------------------------------------
# PSK legacy backend (Monocypher X25519 + TinyCrypt AES-CCM/SHA-256 [S0] or
# Ascon-c [S7]). Invoke with EDHOC_BACKEND=legacy CRYPTO_SUITE=0|7 (+TIMING=1).
# Under EDHOC_BACKEND=legacy, $(CFLAGS) already carries -DMONOCYPHER plus
# -DTINYCRYPT (S0) / -DASCON (S7), and $(PSK_WOLFCRYPT_SRCS) resolves to the
# Monocypher(+TinyCrypt) source set. No -DWOLFCRYPT, so the wolfcrypt
# crypto_wrapper.c stays guarded out and crypto_wrapper_legacy.c emits.
# Monocypher headers/sources are shared from the M3 lib via $(MONOCYPHER_DIR).
# ---------------------------------------------------------------------------
# Absolute Monocypher include: the PSK lib build runs in uoscore-uedhoc-psk/,
# so a top-relative path would not resolve. abspath anchors it at $(CURDIR).
PSK_MONO_INC := -I$(abspath $(MONOCYPHER_DIR))
PSK_LEGACY_CFLAGS = $(CFLAGS) $(PSK_MONO_INC)

edhoc_psk_initiator_legacy:
	@echo "Building EDHOC PSK Initiator (Method 4, CRYPTO_SUITE=$(CRYPTO_SUITE), LEGACY backend)..."
	-@$(MAKE) -C $(PSK_EDHOC_LIB) clean
	@$(MAKE) -C $(PSK_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(PSK_LEGACY_CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE)
	@echo "Building PSK initiator app (Suite $(CRYPTO_SUITE), legacy)..."
	@$(MAKE) all TARGET=edhoc_psk_initiator EDHOC_LIB_DIR=$(PSK_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_psk.c $(PSK_COMMON_SRC) $(PSK_WOLFCRYPT_SRCS)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(PSK_INCLUDES) $(PSK_MONO_INC)" EDHOC_MODE=psk \
		"CFLAGS=$(PSK_LEGACY_CFLAGS)"

edhoc_psk_responder_legacy:
	@echo "Building EDHOC PSK Responder (Method 4, CRYPTO_SUITE=$(CRYPTO_SUITE), LEGACY backend)..."
	-@$(MAKE) -C $(PSK_EDHOC_LIB) clean
	@$(MAKE) -C $(PSK_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(PSK_LEGACY_CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE)
	@echo "Building PSK responder app (Suite $(CRYPTO_SUITE), legacy)..."
	@$(MAKE) all TARGET=edhoc_psk_responder EDHOC_LIB_DIR=$(PSK_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_psk.c $(PSK_COMMON_SRC) $(PSK_WOLFCRYPT_SRCS)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(PSK_INCLUDES) $(PSK_MONO_INC)" EDHOC_MODE=psk \
		"CFLAGS=$(PSK_LEGACY_CFLAGS)"

# Method 3 includes — wolfSSL only
M3_INCLUDES = -I. -Iinclude -I$(M3_EDHOC_LIB)/inc
M3_INCLUDES += -I$(M3_EDHOC_LIB)/inc/common
M3_INCLUDES += -I$(M3_EDHOC_LIB)/externals/zcbor/include
M3_INCLUDES += -I$(WOLFSSL_ROOT)

# M0: SK-SK — both roles sign and verify Ed25519
edhoc_m0_initiator:
	@echo "Building EDHOC Method 0 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS) -DEDHOC_AUTH_SK -DEDHOC_PEER_SK" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 0 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m0_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m0.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original \
		"CFLAGS=$(CFLAGS) -DEDHOC_AUTH_SK -DEDHOC_PEER_SK"

edhoc_m0_responder:
	@echo "Building EDHOC Method 0 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS) -DEDHOC_AUTH_SK -DEDHOC_PEER_SK" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 0 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m0_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m0.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original \
		"CFLAGS=$(CFLAGS) -DEDHOC_AUTH_SK -DEDHOC_PEER_SK"

# M1: SK-SDHK — initiator signs (SK), responder uses SDHK
edhoc_m1_initiator:
	@echo "Building EDHOC Method 1 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS) -DEDHOC_AUTH_SK" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 1 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m1_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m1.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original \
		"CFLAGS=$(CFLAGS) -DEDHOC_AUTH_SK"

edhoc_m1_responder:
	@echo "Building EDHOC Method 1 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS) -DEDHOC_PEER_SK" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 1 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m1_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m1.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original \
		"CFLAGS=$(CFLAGS) -DEDHOC_PEER_SK"

# M2: SDHK-SK — initiator uses SDHK, responder signs (SK)
edhoc_m2_initiator:
	@echo "Building EDHOC Method 2 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS) -DEDHOC_PEER_SK" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 2 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m2_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m2.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original \
		"CFLAGS=$(CFLAGS) -DEDHOC_PEER_SK"

edhoc_m2_responder:
	@echo "Building EDHOC Method 2 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS) -DEDHOC_AUTH_SK" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 2 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m2_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m2.c $(M3_COMMON_SRC) $(M_ED25519_SRC) $(M3_CRYPTO_SRC)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original \
		"CFLAGS=$(CFLAGS) -DEDHOC_AUTH_SK"

# M3: SDHK-SDHK — neither role signs
edhoc_m3_initiator:
	@echo "Building EDHOC Method 3 Initiator with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 3 initiator (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m3_initiator EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_initiator_m3.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC_NOSIGN)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

edhoc_m3_responder:
	@echo "Building EDHOC Method 3 Responder with CRYPTO_SUITE=$(CRYPTO_SUITE)..."
	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
	@echo "Building Method 3 responder (Suite $(CRYPTO_SUITE))..."
	@$(MAKE) all TARGET=edhoc_m3_responder EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_responder_m3.c $(M3_COMMON_SRC) $(M3_CRYPTO_SRC_NOSIGN)" \
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

# # Common sources WITHOUT Monocypher (shim replaces it)
# M3_COMMON_SRC_NOMONO = src/kprintf.c src/libc_stubs.c src/csprng_stub.c
# M3_COMMON_SRC_NOMONO += src/edhoc_transport.c src/edhoc_cred_builder.c
# M3_COMMON_SRC_NOMONO += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_common.c
# M3_COMMON_SRC_NOMONO += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_encode.c
# M3_COMMON_SRC_NOMONO += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_decode.c
# M3_COMMON_SRC_NOMONO += src/rng_port.c

# # Shim + all compact25519 / c25519 sources (Methods 0-2: need Ed25519)
# COMPACT25519_SHIM_SRC  = src/compact25519_shim.c
# COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/compact_x25519.c
# COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/compact_ed25519.c
# COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/compact_wipe.c
# COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/c25519.c
# COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/f25519.c
# COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/fprime.c
# COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/ed25519.c
# COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/edsign.c
# COMPACT25519_SHIM_SRC += $(COMPACT25519_DIR)/c25519/_sha512.c

# # X25519-only shim + sources (Method 3: no Ed25519, no SHA-512)
# # Use with ed25519_stubs.c to satisfy linker without pulling in Ed25519 code.
# COMPACT25519_X25519_ONLY_SRC  = src/compact25519_shim_x25519_only.c
# COMPACT25519_X25519_ONLY_SRC += $(COMPACT25519_DIR)/compact_x25519.c
# COMPACT25519_X25519_ONLY_SRC += $(COMPACT25519_DIR)/compact_wipe.c
# COMPACT25519_X25519_ONLY_SRC += $(COMPACT25519_DIR)/c25519/c25519.c
# COMPACT25519_X25519_ONLY_SRC += $(COMPACT25519_DIR)/c25519/f25519.c

# # Includes: same as M3_INCLUDES plus compact25519 headers
# M3_COMPACT_INCLUDES = $(M3_INCLUDES) -I$(COMPACT25519_DIR)

# edhoc_m0_initiator_compact:
# 	@echo "Building EDHOC Method 0 Initiator (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
# 	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
# 	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
# 	@$(MAKE) all TARGET=edhoc_m0_initiator_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
# 		C_SOURCES="src/edhoc_initiator_m0.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

# edhoc_m0_responder_compact:
# 	@echo "Building EDHOC Method 0 Responder (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
# 	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
# 	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
# 	@$(MAKE) all TARGET=edhoc_m0_responder_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
# 		C_SOURCES="src/edhoc_responder_m0.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

# edhoc_m1_initiator_compact:
# 	@echo "Building EDHOC Method 1 Initiator (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
# 	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
# 	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
# 	@$(MAKE) all TARGET=edhoc_m1_initiator_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
# 		C_SOURCES="src/edhoc_initiator_m1.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

# edhoc_m1_responder_compact:
# 	@echo "Building EDHOC Method 1 Responder (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
# 	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
# 	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
# 	@$(MAKE) all TARGET=edhoc_m1_responder_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
# 		C_SOURCES="src/edhoc_responder_m1.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

# edhoc_m2_initiator_compact:
# 	@echo "Building EDHOC Method 2 Initiator (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
# 	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
# 	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
# 	@$(MAKE) all TARGET=edhoc_m2_initiator_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
# 		C_SOURCES="src/edhoc_initiator_m2.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

# edhoc_m2_responder_compact:
# 	@echo "Building EDHOC Method 2 Responder (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
# 	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
# 	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
# 	@$(MAKE) all TARGET=edhoc_m2_responder_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
# 		C_SOURCES="src/edhoc_responder_m2.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_SHIM_SRC) $(M3_CRYPTO_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

# # M3 compact: X25519-only shim + ed25519_stubs.c
# # Ed25519 and SHA-512 sources are excluded entirely; stubs resolve linker
# # references from the EDHOC library without pulling in any curve code.
# edhoc_m3_initiator_compact:
# 	@echo "Building EDHOC Method 3 Initiator (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
# 	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
# 	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
# 	@$(MAKE) all TARGET=edhoc_m3_initiator_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
# 		C_SOURCES="src/edhoc_initiator_m3.c src/ed25519_stubs.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_X25519_ONLY_SRC) $(M3_CRYPTO_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

# edhoc_m3_responder_compact:
# 	@echo "Building EDHOC Method 3 Responder (compact25519 baseline) CRYPTO_SUITE=$(CRYPTO_SUITE)..."
# 	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
# 	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)" CRYPTO_SUITE=$(CRYPTO_SUITE) DEBUG=$(DEBUG)
# 	@$(MAKE) all TARGET=edhoc_m3_responder_compact EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
# 		C_SOURCES="src/edhoc_responder_m3.c src/ed25519_stubs.c $(M3_COMMON_SRC_NOMONO) $(COMPACT25519_X25519_ONLY_SRC) $(M3_CRYPTO_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(M3_COMPACT_INCLUDES)" EDHOC_MODE=original

# ============================================================================
# X25519 Micro-Benchmark: wolfSSL vs Monocypher vs compact25519
# Compares scalar-mult cycle counts of three pure-C X25519 implementations
# on identical inputs, and cross-checks DH output equality.
# Usage: make bench_x25519
# ============================================================================
BENCH_X25519_MONO    = $(M3_EDHOC_LIB)/externals/Monocypher/src/monocypher.c
BENCH_X25519_COMPACT = $(M3_EDHOC_LIB)/externals/compact25519/src/c25519/c25519.c \
                       $(M3_EDHOC_LIB)/externals/compact25519/src/c25519/f25519.c
BENCH_X25519_WOLF    = $(WOLFCRYPT_DIR)/curve25519.c \
                       $(WOLFCRYPT_DIR)/fe_operations.c \
                       $(WOLFCRYPT_DIR)/fe_low_mem.c
BENCH_X25519_INCLUDES = -I. -Iinclude \
                        -I$(M3_EDHOC_LIB)/externals/Monocypher/src \
                        -I$(M3_EDHOC_LIB)/externals/compact25519/src \
                        -I$(WOLFSSL_ROOT) \
                        -include $(WOLFSSL_ROOT)/user_settings.h

bench_x25519:
	@echo "Building X25519 micro-benchmark (wolfSSL + Monocypher + compact25519)..."
	@$(MAKE) all TARGET=bench_x25519 EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
		C_SOURCES="src/bench_x25519.c src/kprintf.c src/libc_stubs.c $(BENCH_X25519_MONO) $(BENCH_X25519_COMPACT) $(BENCH_X25519_WOLF)" \
		ASM_SOURCES="src/crt0.S" \
		INCLUDES="$(BENCH_X25519_INCLUDES)" \
		"CFLAGS=$(CFLAGS) -DWOLFSSL_USER_SETTINGS" \
		LIBS="-lgcc"

# # ============================================================================
# # Crypto Micro-Benchmark
# # Measures cycle costs of individual X25519 and Ed25519 primitives.
# # Does NOT link the EDHOC library or zcbor — Monocypher only.
# # Usage: make crypto_bench CRYPTO_SUITE=0
# # ============================================================================
# BENCH_MONO_SRC = $(M3_EDHOC_LIB)/externals/Monocypher/src/monocypher.c
# BENCH_MONO_SRC += $(M3_EDHOC_LIB)/externals/Monocypher/src/optional/monocypher-ed25519.c
# BENCH_INCLUDES = -I. -Iinclude -I$(M3_EDHOC_LIB)/externals/Monocypher/src

# crypto_bench:
# 	@echo "Building crypto micro-benchmark (Monocypher)..."
# 	@$(MAKE) all TARGET=crypto_bench \
# 		C_SOURCES="src/crypto_bench.c src/kprintf.c src/libc_stubs.c $(BENCH_MONO_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(BENCH_INCLUDES)" \
# 		LIBS="-lgcc"

# # ============================================================================
# # Crypto Micro-Benchmark: compact25519 (original baseline library)
# # Mirrors crypto_bench but uses compact25519 / c25519 (Daniel Beer).
# # No CRYPTO_SUITE needed — compact25519 has no suite dependency.
# # Usage: make crypto_bench_compact
# # ============================================================================
# COMPACT25519_DIR = $(M3_EDHOC_LIB)/externals/compact25519/src
# BENCH_COMPACT_SRC  = $(COMPACT25519_DIR)/compact_x25519.c
# BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/compact_ed25519.c
# BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/compact_wipe.c
# BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/c25519.c
# BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/f25519.c
# BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/fprime.c
# BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/ed25519.c
# BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/edsign.c
# BENCH_COMPACT_SRC += $(COMPACT25519_DIR)/c25519/_sha512.c
# BENCH_COMPACT_INCLUDES = -I. -Iinclude -I$(COMPACT25519_DIR)

# crypto_bench_compact:
# 	@echo "Building crypto micro-benchmark (compact25519 baseline)..."
# 	@$(MAKE) all TARGET=crypto_bench_compact \
# 		C_SOURCES="src/crypto_bench_compact.c src/kprintf.c src/libc_stubs.c $(BENCH_COMPACT_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(BENCH_COMPACT_INCLUDES)" \
# 		LIBS="-lgcc"

# # ============================================================================
# # OSCORE Standalone Benchmark
# # Measures oscore_context_init(), coap2oscore(), oscore2coap() in isolation.
# # Uses RFC 8613 Appendix C.1 test vectors — no EDHOC dependency.
# # ALWAYS built with Suite 0 (AES-CCM-16-64-128 + HMAC-SHA256): RFC 8613
# # mandatory cipher suite. CRYPTO_SUITE variable is intentionally ignored here.
# #
# # Usage: make oscore_benchmark
# #        make oscore_benchmark BENCHMARK_CPU_HZ=65000000UL   (65 MHz Arty 35T)
# # ============================================================================

# # OSCORE CFLAGS: Suite 0 forced, wolfCrypt (AES-CCM + HMAC-SHA256)
# OSCORE_CFLAGS  = $(ARCH_FLAGS) -Os -flto -g0 -ffunction-sections -fdata-sections -Wunused-function
# OSCORE_CFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
# OSCORE_CFLAGS += -nostartfiles -nostdlib -nodefaultlibs -fno-builtin -fno-tree-loop-distribute-patterns
# OSCORE_CFLAGS += -Wall -Wextra -DMESSAGE_4 -DZCBOR_CANONICAL
# OSCORE_CFLAGS += $(WOLFCRYPT_CFLAGS) -DWOLFCRYPT -DEDHOC_CRYPTO_SUITE=0
# ifdef BENCHMARK_CPU_HZ
# OSCORE_CFLAGS += -DBENCHMARK_CPU_HZ=$(BENCHMARK_CPU_HZ)
# endif

# # OSCORE benchmark uses Suite 0 (AES-CCM + SHA-256).  Explicitly list the
# # wolfCrypt sources for Suite 0 so this target is independent of CRYPTO_SUITE.
# OSCORE_WC_SRCS = $(_WC_CORE) $(_WC_SHA512) $(_WC_AES) $(_WC_X25519) $(_WC_ED25519)

# # Application + platform sources (wolfCrypt — no TinyCrypt)
# OSCORE_BENCH_SRC  = src/oscore_benchmark.c src/kprintf.c src/libc_stubs.c src/csprng_stub.c src/rng_port.c
# OSCORE_BENCH_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_common.c
# OSCORE_BENCH_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_encode.c
# OSCORE_BENCH_SRC += $(M3_EDHOC_LIB)/externals/zcbor/src/zcbor_decode.c
# OSCORE_BENCH_SRC += $(OSCORE_WC_SRCS)

# oscore_benchmark:
# 	@echo "Building uoscore-uedhoc library for OSCORE benchmark (Suite 0)..."
# 	-@$(MAKE) -C $(M3_EDHOC_LIB) clean
# 	@$(MAKE) -C $(M3_EDHOC_LIB) CC="$(CC)" AR="$(AR)" CFLAGS="$(OSCORE_CFLAGS)" CRYPTO_SUITE=0 DEBUG=$(DEBUG)
# 	@echo "Building OSCORE benchmark (AES-CCM-16-64-128 + HMAC-SHA256)..."
# 	@$(MAKE) all TARGET=oscore_benchmark EDHOC_LIB_DIR=$(M3_EDHOC_LIB) \
# 		CFLAGS="$(OSCORE_CFLAGS)" \
# 		C_SOURCES="$(OSCORE_BENCH_SRC)" \
# 		ASM_SOURCES="src/crt0.S" \
# 		INCLUDES="$(M3_INCLUDES)" EDHOC_MODE=original

# debug_make:
# 	@echo $(C_SOURCES)

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
