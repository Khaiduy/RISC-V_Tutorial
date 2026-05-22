################################################################################
# Toolchain
################################################################################
# RISC-V cross-compiler configuration
CC = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-gcc
AR = /home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-ar
#CC = gcc
#AR = ar
#CC = /opt/arm-gnu-toolchain-12.2.rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-gcc
#AR = /opt/arm-gnu-toolchain-12.2.rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-ar
#CC = clang-13


################################################################################
# Architecture
################################################################################
# RISC-V architecture flags
# RV32IMAC for 32-bit Rocket core
ARCH = -march=rv32imac_zicsr_zifencei -mabi=ilp32 -mcmodel=medany
# see for arm flags: https://gcc.gnu.org/onlinedocs/gcc/ARM-Options.html
#ARCH = -m32
#ARCH = -mtune=cortex-m3


################################################################################ 
# Compiler optimization
################################################################################ 
# Size optimization - most reliable
OPT = -Os


################################################################################
# Print helpful debug messages
################################################################################
# Disabled for bare-metal RISC-V (kprintf doesn't support %s format specifier)
# DEBUG_PRINT += -DDEBUG_PRINT

################################################################################
# Print timing measurements (independent of DEBUG_PRINT)
################################################################################
# TIMING_PRINT += -DTIMING_PRINT

################################################################################
# Use Address Sanitizer, e.g. with native_posix
################################################################################
#ASAN += -DASAN

################################################################################
# Unit testing
################################################################################
# Uncomment this to enable building the unit tests
# Disabled for embedded/bare-metal RISC-V
#UNIT_TEST += -DUNIT_TEST


################################################################################
# CBOR engine
################################################################################
# currently only ZCBOR is supported
CBOR_ENGINE += -DZCBOR

# Uncomment to enable Non-volatile memory (NVM) support for storing security context between device reboots
# Disabled for simple embedded demo
#OSCORE_NVM_SUPPORT += -DOSCORE_NVM_SUPPORT

################################################################################
# RAM optimization
################################################################################
# Compute the length of buffers at runtime (variable length array VLA)
# Please note that: we do not support this feature under Windows with MSVC (lack of support for VLA).
#FEATURES += -DVLA

################################################################################
# RAM optimization EDHOC
################################################################################
# In deployments where no protected application message is sent from the 
# Responder to the Initiator, message_4 MUST be used.
FEATURES += -DMESSAGE_4

# PSK-only mode: exclude certificate-based Method 0-3 code paths
# This removes th34_calculate and related unused functions
FEATURES += -DEDHOC_PSK_ONLY

# If EAD is not used set its buffer size to 0
FEATURES += -DEAD_SIZE=0

# Size of the connection identifier of the initiator C_I
FEATURES += -DC_I_SIZE=1

# Size of the connection identifier of the initiator C_R
FEATURES += -DC_R_SIZE=1

# Size of ID_CRED_R (PSK mode uses compact encoding: ~4-8 bytes)
FEATURES += -DID_CRED_R_SIZE=16 

# Size of ID_CRED_I (PSK mode uses compact encoding: ~4-8 bytes)
FEATURES += -DID_CRED_I_SIZE=16 

# Size of CRED_R (PSK mode: CWT Claims Set with 8-byte subject + COSE_Key, 38 bytes)
FEATURES += -DCRED_R_SIZE=38 

# Size of CRED_I (PSK mode: CWT Claims Set with 8-byte subject + COSE_Key, 38 bytes)
FEATURES += -DCRED_I_SIZE=38 

# Number of supported suites by the initiator
FEATURES += -DSUITES_I_SIZE=1 

################################################################################
# RAM optimization OSCORE
################################################################################
# Max size of an OSCORE plaintext (reduced for bare-metal stack constraints)
FEATURES += -DOSCORE_MAX_PLAINTEXT_LEN=128

# Max size of the E options buffer
FEATURES += -DE_OPTIONS_BUFF_MAX_LEN=100

# Max size of the I options buffer
FEATURES += -DI_OPTIONS_BUFF_MAX_LEN=100


################################################################################
# Crypto engine / Suite Selection
################################################################################
# Crypto Suite Selection (passed from parent Makefile or set here):
#   CRYPTO_SUITE=0: Suite 0 - AES-CCM-16-64-128 (8-byte tag, 13-byte nonce)
#   CRYPTO_SUITE=1: Suite 1 - AES-CCM-16-128-128 (16-byte tag, 13-byte nonce)
#   CRYPTO_SUITE=7: Suite 7 - Ascon-AEAD-128 (16-byte tag, 16-byte nonce) [default]
#
# The uoscore-uedhoc can be used with different crypto engines. 
# The user can provide as well additional crypto engines by providing 
# implementations of the function defined (as week) in the crypto_wrapper file.
# Currently we have build in support for the following engines which 
# allow fowling modes of operation and suites:
#
# EDHOC suites: 
# Value: 0
#    Array: 10, -16, 8, 4, -8, 10, -16
#    Desc: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA,
#          AES-CCM-16-64-128, SHA-256

#    Value: 1
#    Array: 30, -16, 16, 4, -8, 10, -16
#    Desc: AES-CCM-16-128-128, SHA-256, 16, X25519, EdDSA,
#          AES-CCM-16-64-128, SHA-256

#    Value: 2
#    Array: 10, -16, 8, 1, -7, 10, -16
#    Desc: AES-CCM-16-64-128, SHA-256, 8, P-256, ES256,
#          AES-CCM-16-64-128, SHA-256

#    Value: 3
#    Array: 30, -16, 16, 1, -7, 10, -16
#    Desc: AES-CCM-16-128-128, SHA-256, 16, P-256, ES256,
#          AES-CCM-16-64-128, SHA-256

#    Value: 4
#    Array: 24, -16, 16, 4, -8, 24, -16
#    Desc: ChaCha20/Poly1305, SHA-256, 16, X25519, EdDSA,
#          ChaCha20/Poly1305, SHA-256


# EDHOC methods: 
# +-------+-------------------+-------------------+-------------------+
# | Value | Initiator         | Responder         | Reference         |
# +-------+-------------------+-------------------+-------------------+
# |     0 | Signature Key     | Signature Key     | [[this document]] |
# |     1 | Signature Key     | Static DH Key     | [[this document]] |
# |     2 | Static DH Key     | Signature Key     | [[this document]] |
# |     3 | Static DH Key     | Static DH Key     | [[this document]] |
# +-------+-------------------+-------------------+-------------------+
#
#
#
# +--------+---------+---------+-------------------------------------------
# protocol | suite   | method  | ENGINE
# +--------+---------+---------+-------------------------------------------
# | OSCORE |         |         | TINYCRYPT or MBEDTLS
# | EDHOC  | 0/1     | 0/1/2   | COMPACT25519 with (TINYCRYPT or MBEDTLS)
# | EDHOC  | 0/1     | 3       | MBEDTLS or (COMPACT25519 with TINYCRYPT)
# | EDHOC  | 2/3     | 0/1/2/3 | MBEDTLS
# | EDHOC  | 0/1/2/3 | 0/1/2/3 | MBEDTLS and COMPACT25519

CRYPTO_SUITE ?= 7

ifeq ($(CRYPTO_SUITE),0)
# Suite 0: TinyCrypt (AES-CCM-16-64-128, 8-byte tag)
CRYPTO_ENGINE += -DTINYCRYPT
CRYPTO_ENGINE += -DMONOCYPHER

CRYPTO_ENGINE += 

CRYPTO_ENGINE += -DEDHOC_CRYPTO_SUITE=0
else ifeq ($(CRYPTO_SUITE),1)
# Suite 1: TinyCrypt (AES-CCM-16-128-128, 16-byte tag)
CRYPTO_ENGINE += -DTINYCRYPT
CRYPTO_ENGINE += -DMONOCYPHER

CRYPTO_ENGINE += 

CRYPTO_ENGINE += -DEDHOC_CRYPTO_SUITE=1
else ifeq ($(CRYPTO_SUITE),7)
# Suite 7: Pure Ascon (Ascon-AEAD-128 + Ascon-HMAC)
CRYPTO_ENGINE += -DASCON

CRYPTO_ENGINE += 

CRYPTO_ENGINE += -DEDHOC_CRYPTO_SUITE=7
endif

#CRYPTO_ENGINE += -DUSE_HW_X25519
#CRYPTO_ENGINE += -DMBEDTLS